"""IC-01 hardware registry contract and regression tests (no host collection)."""

from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import subprocess
import sys
import tempfile
import unittest

from discovery.core import (
    CollectionStatus, CollectorResult, DiscoveryContext, run_collector,
)
from discovery.probes import ProbeResult
from discovery.registry import (
    COLLECTORS, EXPECTED_COLLECTOR_IDS, CollectorRegistryError,
    all_collectors, get_collector, resolve_collector, validate_registry,
)
from validation.requirements import APPROVED_IDS


class HardwareRegistryTests(unittest.TestCase):
    def test_exact_ids_and_order(self):
        self.assertEqual(tuple(s.collector_id for s in all_collectors()),
                         EXPECTED_COLLECTOR_IDS)
        self.assertEqual(len(all_collectors()), 10)
        self.assertEqual(len(set(EXPECTED_COLLECTOR_IDS)), 10)
        self.assertIsNone(validate_registry())

    def test_metadata_is_immutable_and_inspectable(self):
        specs = all_collectors()
        self.assertIsInstance(specs, tuple)
        self.assertIs(specs, COLLECTORS)
        with self.assertRaises(FrozenInstanceError):
            specs[0].category = "modified"
        self.assertTrue(all(s.phase == 2 and s.read_only and
                            not s.requires_privilege and s.applicability == "linux"
                            for s in specs))
        self.assertEqual(
            {s.collector_id for s in specs if s.optional_tools},
            {"vaapi"},
        )
        self.assertEqual(get_collector("vaapi").optional_tools, ("vainfo",))

    def test_import_and_inspection_do_not_import_collectors(self):
        script = (
            "import sys; from discovery.registry import all_collectors, "
            "get_collector, validate_registry; "
            "validate_registry(); get_collector('cpu'); all_collectors(); "
            "ids=('system','cpu','memory','storage','optical','gpu','vaapi',"
            "'network','thermal','power'); "
            "assert not any('discovery.'+name in sys.modules for name in ids)"
        )
        run = subprocess.run(
            [sys.executable, "-c", script],
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True, text=True, timeout=10, check=False,
        )
        self.assertEqual(run.returncode, 0, run.stderr)

    def test_metadata_lookup_never_resolves_callable(self):
        with patch("discovery.registry.import_module") as importer:
            self.assertEqual(get_collector("system").collector_id, "system")
            self.assertEqual(len(all_collectors()), 10)
            validate_registry()
            importer.assert_not_called()

    def test_unknown_id_is_explicit_error(self):
        for identifier in ("missing", "CPU", "", None, 3):
            with self.subTest(identifier=identifier):
                with self.assertRaises(CollectorRegistryError):
                    get_collector(identifier)
                with self.assertRaises(CollectorRegistryError):
                    resolve_collector(identifier)

    def test_resolve_every_collector_without_execution(self):
        for spec in COLLECTORS:
            with self.subTest(collector_id=spec.collector_id):
                self.assertTrue(callable(resolve_collector(spec.collector_id)))

    def test_fixture_keyword_invocation_preserved(self):
        with tempfile.TemporaryDirectory(prefix="lbt-ic01-") as folder:
            kwargs = {
                "system": {"etc_root": folder, "sys_root": folder},
                "cpu": {"proc_root": folder, "sys_root": folder},
                "memory": {"proc_root": folder},
                "storage": {"sys_root": folder, "proc_root": folder},
                "optical": {"sys_root": folder, "proc_root": folder},
                "gpu": {"sys_root": folder},
                "vaapi": {"probe": lambda command, **options: ProbeResult(
                    CollectionStatus.TOOL_MISSING, tuple(command),
                    reason="fixture tool unavailable")},
                "network": {"sys_root": folder},
                "thermal": {"sys_root": folder},
                "power": {"sys_root": folder},
            }
            for spec in COLLECTORS:
                with self.subTest(collector_id=spec.collector_id):
                    collect = resolve_collector(spec.collector_id)
                    arguments = kwargs[spec.collector_id]
                    outcome = run_collector(
                        spec.collector_id,
                        lambda context: collect(context, **arguments),
                        DiscoveryContext(),
                    )
                    self.assertIsInstance(outcome, CollectorResult)
                    self.assertEqual(outcome.collector_id, spec.collector_id)
                    self.assertNotEqual(outcome.status, CollectionStatus.FAILED,
                                        outcome.reason)
                    self.assertEqual(outcome.to_dict()["collector_id"],
                                     spec.collector_id)
                    if spec.collector_id == "vaapi":
                        self.assertEqual(outcome.status, CollectionStatus.TOOL_MISSING)
                    if spec.collector_id == "optical":
                        self.assertEqual(outcome.status, CollectionStatus.UNAVAILABLE)

    def test_collection_failure_isolated_by_existing_wrapper(self):
        invoked = []
        def broken(context):
            invoked.append("cpu")
            raise RuntimeError("controlled fixture error")
        def healthy(context):
            invoked.append("memory")
            return CollectorResult("memory", CollectionStatus.COMPLETE)
        first = run_collector("cpu", broken, DiscoveryContext())
        second = run_collector("memory", healthy, DiscoveryContext())
        self.assertEqual(invoked, ["cpu", "memory"])
        self.assertEqual(first.status, CollectionStatus.FAILED)
        self.assertEqual(second.status, CollectionStatus.COMPLETE)

    def test_missing_module_is_explicit_error(self):
        with patch("discovery.registry.import_module",
                   side_effect=ModuleNotFoundError("fixture absent")):
            with self.assertRaisesRegex(CollectorRegistryError, "module unavailable"):
                resolve_collector("system")

    def test_missing_or_noncallable_entrypoint_rejected(self):
        for module in (SimpleNamespace(), SimpleNamespace(collect=None)):
            with self.subTest(module=module):
                with patch("discovery.registry.import_module", return_value=module):
                    with self.assertRaisesRegex(CollectorRegistryError,
                                                "entrypoint unavailable"):
                        resolve_collector("cpu")

    def test_incompatible_signatures_rejected(self):
        candidates = (
            lambda: None,
            lambda context, extra: None,
            lambda other_context, *, fixture=None: None,
        )
        for func in candidates:
            with self.subTest(func=func):
                with patch("discovery.registry.import_module",
                           return_value=SimpleNamespace(collect=func)):
                    with self.assertRaisesRegex(CollectorRegistryError,
                                                "incompatible callable signature"):
                        resolve_collector("system")

    def test_registry_rejects_duplicate_or_missing_ids(self):
        with self.assertRaisesRegex(CollectorRegistryError, "duplicate"):
            validate_registry((COLLECTORS[0], COLLECTORS[0], *COLLECTORS[2:]))
        with self.assertRaisesRegex(CollectorRegistryError, "coverage or order"):
            validate_registry(COLLECTORS[:-1])
        with self.assertRaisesRegex(CollectorRegistryError, "coverage or order"):
            validate_registry(tuple(reversed(COLLECTORS)))

    def test_registry_rejects_invalid_metadata(self):
        bad_fields = (
            {"collector_id": "bad-id"},
            {"module": "os"},
            {"module": "discovery.other"},
            {"entrypoint": "execute"},
            {"phase": 3},
            {"category": ""},
            {"read_only": False},
            {"requires_privilege": True},
            {"optional_tools": ["vainfo"]},
            {"optional_tools": ("vainfo", "vainfo")},
            {"applicability": "any"},
            {"related_requirements": ("INVALID",)},
            {"related_requirements": ()},
        )
        for updates in bad_fields:
            with self.subTest(updates=updates):
                with self.assertRaises(CollectorRegistryError):
                    validate_registry((replace(COLLECTORS[0], **updates),
                                       *COLLECTORS[1:]))
        with self.assertRaises(CollectorRegistryError):
            validate_registry((object(), *COLLECTORS[1:]))

    def test_requirement_references_are_approved_and_nonassertive(self):
        for spec in COLLECTORS:
            with self.subTest(collector_id=spec.collector_id):
                self.assertTrue(spec.related_requirements)
                self.assertTrue(set(spec.related_requirements).issubset(APPROVED_IDS))
        # A related requirement is evidence linkage, not verified acceptance.
        self.assertNotIn("verified", vars(COLLECTORS[0]))
        self.assertNotIn("status", vars(COLLECTORS[0]))


if __name__ == "__main__":
    unittest.main()
