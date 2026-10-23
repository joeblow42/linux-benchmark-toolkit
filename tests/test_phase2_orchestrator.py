"""IC-02 deterministic discovery orchestration contract tests; no real host probes."""

from datetime import datetime, timezone, timedelta
from unittest import TestCase
from unittest.mock import Mock

from discovery.core import CollectionStatus, CollectorResult, DiscoveryContext
from discovery.orchestrator import _collect_inventory, collect_inventory
from discovery.registry import EXPECTED_COLLECTOR_IDS


class DiscoveryOrchestratorTests(TestCase):
    def setUp(self):
        self.context = DiscoveryContext()
        self.ids = EXPECTED_COLLECTOR_IDS
        self.invoked = []
        self.t0 = datetime(2026, 10, 23, 18, 0, tzinfo=timezone.utc)

    def run_fixture(self, entries=None, selected=None, *, resolver=None,
                    clock=None, platform_name=None):
        entries = {} if entries is None else entries
        def fixture_resolver(cid):
            if resolver is not None:
                return resolver(cid)
            def collect(context):
                self.invoked.append((cid, context))
                response = entries.get(cid, CollectionStatus.COMPLETE)
                if isinstance(response, BaseException):
                    raise response
                if callable(response):
                    return response(context)
                if isinstance(response, CollectorResult):
                    return response
                return CollectorResult(cid, response, data={"fixture": cid},
                                       sources=[{"tool": "fixture"}], reason="")
            return collect
        return _collect_inventory(
            self.context, selected, resolver=fixture_resolver,
            monotonic=clock or (lambda: 42.5),
            utc_now=lambda: self.t0,
            platform_name=platform_name or (lambda: "Linux"),
        )

    def test_ic02_t01_all_collectors_complete(self):
        session = self.run_fixture()
        self.assertEqual(session["contract_version"], "1.0")
        self.assertEqual(session["scope"], "full")
        self.assertEqual(session["summary"]["outcome"], "COMPLETE")
        self.assertTrue(session["summary"]["minimum_inventory_met"])
        self.assertEqual(session["summary"]["selected"], 10)
        self.assertEqual(session["summary"]["attempted"], 10)
        self.assertEqual(session["summary"]["executed"], 10)
        self.assertEqual(session["summary"]["status_counts"]["COMPLETE"], 10)
        self.assertEqual(list(session["results"]), list(self.ids))
        self.assertEqual([cid for cid, _ in self.invoked], list(self.ids))

    def test_ic02_t02_subsets_execute_in_canonical_order(self):
        order_a = ["thermal", "cpu", "system"]
        order_b = list(reversed(order_a))
        a = self.run_fixture(selected=order_a)
        invoked_a = [cid for cid, _ in self.invoked]
        self.invoked.clear()
        b = self.run_fixture(selected=order_b)
        self.assertEqual(invoked_a, ["system", "cpu", "thermal"])
        self.assertEqual([cid for cid, _ in self.invoked], invoked_a)
        self.assertEqual(a["execution_order"], b["execution_order"])
        self.assertEqual(a["requested_collector_ids"], order_a)
        self.assertEqual(b["requested_collector_ids"], order_b)
        self.assertEqual(a["scope"], "selected")

    def test_ic02_t03_subset_only_executes_requested(self):
        session = self.run_fixture(selected=["memory"])
        self.assertEqual(list(session["results"]), ["memory"])
        self.assertEqual(session["summary"]["selected"], 1)
        self.assertEqual(session["summary"]["outcome"], "COMPLETE")
        self.assertEqual(len(self.invoked), 1)

    def test_ic02_t04_invalid_and_duplicate_ids_rejected_before_execution(self):
        for selected in ([], "cpu", ("cpu",), ["cpu", "cpu"],
                         ["cpu", "unknown"], [None]):
            with self.subTest(selected=selected):
                self.invoked.clear()
                with self.assertRaises((ValueError, TypeError)):
                    self.run_fixture(selected=selected)
                self.assertEqual(self.invoked, [])

    def test_ic02_t05_optional_absence_is_not_failure(self):
        session = self.run_fixture(entries={
            "optical": CollectionStatus.UNAVAILABLE,
            "gpu": CollectionStatus.UNAVAILABLE,
            "thermal": CollectionStatus.UNAVAILABLE,
            "power": CollectionStatus.UNAVAILABLE,
        })
        self.assertEqual(session["summary"]["outcome"], "COMPLETE")
        self.assertEqual(session["summary"]["status_counts"]["UNAVAILABLE"], 4)
        self.assertEqual(session["errors"], [])

    def test_ic02_t06_vainfo_missing_is_not_failure(self):
        session = self.run_fixture(entries={"vaapi": CollectionStatus.TOOL_MISSING})
        self.assertEqual(session["summary"]["outcome"], "COMPLETE")
        self.assertEqual(session["results"]["vaapi"]["status"], "TOOL_MISSING")
        self.assertEqual(session["summary"]["status_counts"]["TOOL_MISSING"], 1)

    def test_ic02_t07_exception_isolated_and_later_collectors_run(self):
        session = self.run_fixture(entries={"cpu": RuntimeError("private exception")})
        self.assertEqual(session["summary"]["outcome"], "PARTIAL")
        self.assertEqual(session["results"]["cpu"]["status"], "FAILED")
        self.assertEqual(session["results"]["cpu"]["reason"],
                         "collector error: RuntimeError")
        self.assertEqual(session["results"]["power"]["status"], "COMPLETE")
        self.assertEqual(len(self.invoked), 10)
        self.assertNotIn("private exception", str(session))
        self.assertEqual(session["errors"], [
            {"collector_id": "cpu", "kind": "COLLECTOR_FAILURE"}])

    def test_ic02_t08_malformed_result_is_replaced_by_recorded_failure(self):
        bad = CollectorResult("cpu", CollectionStatus.COMPLETE, data=[])
        session = self.run_fixture(entries={"cpu": bad})
        self.assertEqual(session["results"]["cpu"]["status"], "FAILED")
        self.assertEqual(session["results"]["cpu"]["reason"],
                         "collector error: invalid result structure")
        self.assertEqual(session["summary"]["outcome"], "PARTIAL")
        self.assertEqual(session["errors"][0]["kind"], "INVALID_RESULT")
        self.assertEqual(session["results"]["memory"]["status"], "COMPLETE")

    def test_ic02_t09_full_minimum_inventory_missing(self):
        session = self.run_fixture(entries={"system": CollectionStatus.UNAVAILABLE})
        self.assertEqual(session["summary"]["outcome"], "FAILED")
        self.assertFalse(session["summary"]["minimum_inventory_met"])
        session = self.run_fixture(entries={
            "cpu": CollectionStatus.UNAVAILABLE,
            "memory": CollectionStatus.UNAVAILABLE,
            "storage": CollectionStatus.UNAVAILABLE,
        })
        self.assertEqual(session["summary"]["outcome"], "FAILED")

    def test_ic02_t10_interrupted_results_preserved(self):
        session = self.run_fixture(entries={"cpu": KeyboardInterrupt()})
        self.assertEqual(session["summary"]["outcome"], "INTERRUPTED")
        self.assertEqual(list(session["results"]), ["system"])
        self.assertEqual(session["summary"]["attempted"], 2)
        self.assertEqual(session["summary"]["executed"], 1)
        self.assertIn("cpu", session["timings"])
        self.assertEqual(session["errors"],
                         [{"collector_id": "cpu", "kind": "INTERRUPTED"}])
        self.assertEqual([cid for cid, _ in self.invoked], ["system", "cpu"])

    def test_ic02_t11_utc_and_monotonic_time_are_deterministic(self):
        values = iter((4.0, 4.0075))
        session = self.run_fixture(selected=["cpu"], clock=lambda: next(values))
        self.assertEqual(session["started_utc"], "2026-10-23T18:00:00.000Z")
        self.assertEqual(session["completed_utc"], session["started_utc"])
        self.assertEqual(session["timings"]["cpu"]["elapsed_ms"], 7.5)

    def test_ic02_t12_original_payload_and_provenance_preserved(self):
        sources = [{"tool": "fixture", "state": "COMPLETE"}]
        data = {"cpu": "synthetic"}
        item = CollectorResult("cpu", CollectionStatus.COMPLETE, data=data,
                               sources=sources, reason="fixture-only reason")
        session = self.run_fixture(selected=["cpu"], entries={"cpu": item})
        self.assertEqual(session["results"]["cpu"], item.to_dict())
        self.assertIs(session["results"]["cpu"]["data"], data)
        self.assertIs(session["results"]["cpu"]["sources"], sources)
        self.assertEqual(session["summary"]["outcome"], "COMPLETE")

    def test_ic02_t13_default_privacy_context_passes_unchanged(self):
        self.run_fixture()
        self.assertEqual(len(self.invoked), 10)
        self.assertTrue(all(ctx is self.context for _, ctx in self.invoked))
        self.assertFalse(self.context.include_identifiers)
        self.assertFalse(self.context.allow_privileged)

    def test_ic02_t14_nonlinux_skips_resolution(self):
        resolver = Mock(side_effect=AssertionError("should not be resolved"))
        session = self.run_fixture(selected=["optical"], resolver=resolver,
                                   platform_name=lambda: "Darwin")
        resolver.assert_not_called()
        self.assertEqual(session["results"]["optical"]["status"], "UNSUPPORTED")
        self.assertEqual(session["summary"]["outcome"], "COMPLETE")

    def test_unresolvable_collector_is_recorded_and_isolated(self):
        def resolve(cid):
            if cid == "cpu":
                raise ModuleNotFoundError("private/path")
            return lambda ctx: CollectorResult(cid, CollectionStatus.COMPLETE)
        session = self.run_fixture(resolver=resolve)
        self.assertEqual(session["summary"]["outcome"], "PARTIAL")
        self.assertEqual(session["results"]["cpu"]["reason"],
                         "collector dispatch error: ModuleNotFoundError")
        self.assertNotIn("private/path", str(session))
        self.assertEqual(session["errors"][0]["kind"], "DISPATCH_FAILURE")

    def test_permission_denial_is_partial_when_minimum_survives(self):
        session = self.run_fixture(entries={"network": CollectionStatus.PERMISSION_DENIED})
        self.assertEqual(session["summary"]["outcome"], "PARTIAL")
        self.assertEqual(session["errors"][0]["kind"], "ACCESS_DENIED")

    def test_subset_failure_without_usable_result_is_failed(self):
        session = self.run_fixture(selected=["cpu"], entries={
            "cpu": CollectionStatus.FAILED,
        })
        self.assertEqual(session["summary"]["outcome"], "FAILED")
        self.assertFalse(session["summary"]["minimum_inventory_met"])

    def test_empty_context_and_unaware_clock_rejected(self):
        with self.assertRaises(TypeError):
            _collect_inventory(None, resolver=lambda cid: None)
        with self.assertRaises(ValueError):
            _collect_inventory(
                self.context, ["cpu"], resolver=lambda cid: None,
                utc_now=lambda: datetime(2026, 10, 23, 18, 0),
            )

    def test_fixture_resolver_noncallable_does_not_terminate_session(self):
        def resolve(cid):
            if cid == "cpu":
                return None
            return lambda ctx: CollectorResult(cid, CollectionStatus.COMPLETE)
        session = self.run_fixture(resolver=resolve)
        self.assertEqual(session["results"]["cpu"]["status"], "FAILED")
        self.assertEqual(session["results"]["memory"]["status"], "COMPLETE")

    def test_original_public_interface_is_stable(self):
        from inspect import signature
        self.assertEqual(tuple(signature(collect_inventory).parameters),
                         ("context", "collector_ids"))
        self.assertEqual(collect_inventory.__module__, "discovery.orchestrator")


if __name__ == "__main__":
    import unittest
    unittest.main()
