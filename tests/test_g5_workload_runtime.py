"""RP-06 runtime tests use fixture workloads and a single inventory witness."""
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from lbt_g5.workload_runtime import Mode, Resources, Runtime, Unsafe, Workload


class WorkloadRuntimeTests(unittest.TestCase):
    def setUp(self):
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        self.root = Path(workspace.name)
        self.run = SimpleNamespace(execution=SimpleNamespace(terminal_state="FINISHED"))
        owner = self.root.stat().st_uid
        if owner == 0:
            self.skipTest("runtime requires an ordinary user")
        for name, kwargs in (
            ("UnifiedCollectorEngine", {}),
            ("build_canonical", {"return_value": {"completion_state": "COMPLETE"}}),
            ("read_private_inventory", {"return_value": {"facts": []}}),
        ):
            patcher = patch("lbt_g5.workload_runtime." + name, **kwargs)
            self.addCleanup(patcher.stop)
            fixture = patcher.start()
            if name == "UnifiedCollectorEngine":
                self.engine = fixture
        self.engine.return_value.run.return_value = self.run

    def workloads(self, *items):
        return Runtime(items, limits=Resources(2, 1024, 8192), disk_reserve_bytes=0)

    def test_one_plan_for_all_modes(self):
        run = lambda context: {"count": 1}
        standard = Workload("short", "cpu", Mode.STANDARD, Resources(), run)
        extended = Workload("sustained", "cpu", Mode.EXTENDED, Resources(), run)
        explicit = Workload("media", "optical", Mode.EXTENDED, Resources(), run, True)
        runtime = self.workloads(standard, extended, explicit)
        self.assertEqual(runtime.plan(Mode.DISCOVERY), ())
        self.assertEqual(runtime.plan(Mode.STANDARD), (standard,))
        self.assertEqual(runtime.plan(Mode.EXTENDED), (standard, extended))
        self.assertEqual(runtime.plan(Mode.INTERACTIVE, selections=("media", "group:cpu")),
                         (standard, extended, explicit))
        with self.assertRaises(ValueError):
            runtime.plan(Mode.INTERACTIVE, selections=("group:optical",))

    def test_reservation_failure_and_noncritical_failure_continue(self):
        def fail(context):
            raise RuntimeError("fixture failure")

        def succeed(context):
            self.assertEqual(context.inventory, {"facts": []})
            (context.scratch / "toolkit-file").write_bytes(b"a")
            return {"bytes": 1}

        runtime = self.workloads(
            Workload("reserved", "cpu", Mode.STANDARD, Resources(3), fail),
            Workload("error", "cpu", Mode.STANDARD, Resources(), fail),
            Workload("done", "cpu", Mode.STANDARD, Resources(), succeed),
        )
        session = runtime.execute(self.root, Mode.STANDARD, collectors=("COL-MEM",))
        self.engine.return_value.run.assert_called_once()
        self.assertEqual(session.state, "PARTIAL")
        self.assertEqual([row["status"] for row in session.results],
                         ["UNAVAILABLE", "FAILED", "COMPLETE"])
        self.assertEqual(list(session.directory.glob("done-*")), [])
        self.assertEqual(json.loads((session.directory / "workloads.json").read_text())["results"],
                         session.results)

    def test_cancellation_preserves_prior_results_and_skips_remaining_work(self):
        stop = False

        def first(context):
            nonlocal stop
            stop = True
            return {"count": 1}

        runtime = self.workloads(
            Workload("first", "cpu", Mode.STANDARD, Resources(), first),
            Workload("later", "cpu", Mode.STANDARD, Resources(), self.fail),
        )
        session = runtime.execute(self.root, Mode.STANDARD, cancelled=lambda: stop)
        self.assertEqual(session.state, "INTERRUPTED")
        self.assertEqual([row["status"] for row in session.results], ["COMPLETE", "SKIPPED"])

    def test_unsafe_workload_stops_future_work(self):
        def unsafe(context):
            raise Unsafe("THERMAL_LIMIT")

        runtime = self.workloads(
            Workload("first", "cpu", Mode.STANDARD, Resources(), unsafe),
            Workload("later", "cpu", Mode.STANDARD, Resources(), self.fail),
        )
        session = runtime.execute(self.root, Mode.STANDARD)
        self.assertEqual(session.state, "FAILED")
        self.assertEqual([row["reason"] for row in session.results], ["THERMAL_LIMIT", "SAFETY_STOP"])
