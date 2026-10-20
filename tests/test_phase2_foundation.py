"""Unit tests for the Phase 2 shared collector/probe foundation."""
import subprocess
import unittest
from types import SimpleNamespace

from discovery.core import (
    CollectionStatus, CollectorResult, DiscoveryContext, run_collector,
)
from discovery.probes import run_probe


class FoundationTests(unittest.TestCase):
    def test_default_policy_protects_identifiers_and_privileges(self):
        context = DiscoveryContext()
        self.assertFalse(context.include_identifiers)
        self.assertFalse(context.allow_privileged)

    def test_detailed_policy_must_be_explicit(self):
        context = DiscoveryContext(include_identifiers=True, allow_privileged=True)
        self.assertTrue(context.include_identifiers)
        self.assertTrue(context.allow_privileged)

    def test_status_serialization(self):
        result = CollectorResult("cpu", CollectionStatus.COMPLETE,
                                 {"cores": 4}, [{"tool": "lscpu"}])
        self.assertEqual(result.to_dict()["status"], "COMPLETE")
        self.assertEqual(result.to_dict()["sources"][0]["tool"], "lscpu")

    def test_successful_collector(self):
        result = run_collector(
            "cpu", lambda ctx: CollectorResult("cpu", CollectionStatus.COMPLETE,
                                               {"identifiers": ctx.include_identifiers}))
        self.assertEqual(result.data["identifiers"], False)

    def test_collector_failure_isolated(self):
        def broken(context):
            raise RuntimeError("sensitive data should not appear in error")
        result = run_collector("cpu", broken)
        self.assertEqual(result.status, CollectionStatus.FAILED)
        self.assertEqual(result.reason, "collector error: RuntimeError")
        self.assertNotIn("sensitive", result.reason)

    def test_rejects_mismatched_collector_result(self):
        result = run_collector("cpu", lambda _: CollectorResult(
            "gpu", CollectionStatus.COMPLETE))
        self.assertEqual(result.status, CollectionStatus.FAILED)

    def test_missing_tool(self):
        result = run_probe(["absent-tool"], which=lambda name: None)
        self.assertEqual(result.status, CollectionStatus.TOOL_MISSING)

    def test_probe_success(self):
        def fake_runner(args, **kwargs):
            self.assertEqual(args, ["fake", "--json"])
            self.assertFalse(kwargs["check"])
            self.assertEqual(kwargs["env"]["LC_ALL"], "C")
            return SimpleNamespace(returncode=0, stdout="abc", stderr="")
        result = run_probe(["fake", "--json"], which=lambda _: "/usr/bin/fake",
                           runner=fake_runner)
        self.assertEqual(result.status, CollectionStatus.COMPLETE)
        self.assertEqual(result.stdout, "abc")

    def test_probe_output_limits(self):
        result = run_probe(
            ["fake"], which=lambda _: "fake",
            runner=lambda *a, **kw: SimpleNamespace(
                returncode=0, stdout="x" * 100, stderr="y" * 100),
            max_stdout=10, max_stderr=5)
        self.assertEqual((len(result.stdout), len(result.stderr)), (10, 5))

    def test_probe_permission_denied(self):
        def forbidden(*args, **kwargs):
            raise PermissionError("private path")
        result = run_probe(["fake"], which=lambda _: "fake", runner=forbidden)
        self.assertEqual(result.status, CollectionStatus.PERMISSION_DENIED)
        self.assertNotIn("private path", result.reason)

    def test_probe_timeout(self):
        def timed_out(*args, **kwargs):
            raise subprocess.TimeoutExpired(cmd="fake", timeout=5)
        result = run_probe(["fake"], which=lambda _: "fake", runner=timed_out)
        self.assertEqual(result.status, CollectionStatus.FAILED)
        self.assertEqual(result.reason, "timeout")

    def test_probe_nonzero_and_permission_stderr(self):
        def failure(*args, **kwargs):
            return SimpleNamespace(returncode=1, stdout="", stderr="Permission denied")
        result = run_probe(["fake"], which=lambda _: "fake", runner=failure)
        self.assertEqual(result.status, CollectionStatus.PERMISSION_DENIED)

    def test_invalid_probe_arguments(self):
        for command in ([], ["fake", ""], [None]):
            with self.assertRaises(ValueError):
                run_probe(command)


if __name__ == "__main__":
    unittest.main()
