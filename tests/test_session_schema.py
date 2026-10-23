"""IC-03 schema acceptance tests, all data synthetic and offline."""
from copy import deepcopy
import json
import unittest

from discovery.registry import EXPECTED_COLLECTOR_IDS
from reporting.session_schema import (
    SCHEMA_VERSION, SessionSchemaError, build_system_document,
    validate_system_document,
)


def make_inventory(ids=None, statuses=None, data=None, sources=None):
    order = ([cid for cid in EXPECTED_COLLECTOR_IDS if cid in ids]
             if ids is not None else list(EXPECTED_COLLECTOR_IDS))
    statuses = statuses or {}
    data = data or {}
    sources = sources or {}
    entries = {
        cid: {
            "collector_id": cid,
            "status": statuses.get(cid, "COMPLETE"),
            "data": data.get(cid, {}),
            "sources": sources.get(cid, []),
            "reason": "",
        } for cid in order
    }
    counts = {s: 0 for s in ("COMPLETE", "UNAVAILABLE", "UNSUPPORTED",
                            "PERMISSION_DENIED", "TOOL_MISSING", "FAILED")}
    for item in entries.values():
        if item["status"] in counts:
            counts[item["status"]] += 1
    scope = "selected" if ids is not None else "full"
    minimum = (entries.get("system", {}).get("status") == "COMPLETE"
               and any(entries.get(cid, {}).get("status") == "COMPLETE"
                       for cid in ("cpu", "memory", "storage"))) if scope == "full" else any(
        item["status"] in ("COMPLETE", "UNAVAILABLE", "UNSUPPORTED", "TOOL_MISSING")
        for item in entries.values())
    outcome = ("FAILED" if not minimum else
               "PARTIAL" if any(x["status"] in ("FAILED", "PERMISSION_DENIED")
                                for x in entries.values()) else "COMPLETE")
    return {
        "contract_version": "1.0", "scope": scope,
        "started_utc": "2026-10-23T18:00:01Z",
        "completed_utc": "2026-10-23T18:00:02Z",
        "requested_collector_ids": list(ids) if ids is not None else list(order),
        "execution_order": order, "results": entries,
        "timings": {cid: {"elapsed_ms": 1.25} for cid in order},
        "summary": {"outcome": outcome, "minimum_inventory_met": minimum,
                    "selected": len(order), "attempted": len(order),
                    "executed": len(order), "status_counts": counts},
        "errors": [],
    }


def make_document(inventory=None, host=None):
    return build_system_document(
        "session_TEST123", make_inventory() if inventory is None else inventory,
        host={"system": "Linux", "architecture": "x86_64", "kernel": "6.12.1"}
             if host is None else host,
        session_started_utc="2026-10-23T18:00:00Z",
    )


class SessionSchemaTests(unittest.TestCase):
    def test_ic03_t01_envelope_version_and_collector_mapping(self):
        doc = make_document()
        self.assertEqual(doc["schema_version"], SCHEMA_VERSION)
        self.assertEqual(doc["session_id"], "session_TEST123")
        self.assertEqual(list(doc["discovery"]["collectors"]), list(EXPECTED_COLLECTOR_IDS))
        self.assertNotIn("results", doc["discovery"])
        validate_system_document(doc, "session_TEST123")

    def test_ic03_t02_preserves_valid_status_timing_and_provenance(self):
        inv = make_inventory(
            ids=["system", "cpu"],
            data={"cpu": {"architecture": "x86_64", "logical_processors_visible": 8}},
            sources={"cpu": [{"path": "/proc/cpuinfo", "status": "COMPLETE"}]},
        )
        before = deepcopy(inv)
        doc = make_document(inv)
        self.assertEqual(inv, before)
        self.assertEqual(doc["discovery"]["collectors"]["cpu"]["sources"],
                         [{"status": "COMPLETE", "path": "procfs:cpuinfo"}])
        self.assertEqual(doc["discovery"]["timings"]["cpu"]["elapsed_ms"], 1.25)
        self.assertEqual(doc["discovery"]["collectors"]["cpu"]["data"]["logical_processors_visible"], 8)

    def test_ic03_t03_private_fixture_source_path_is_redacted(self):
        inv = make_inventory(ids=["system", "cpu"], sources={
            "cpu": [{"path": "/tmp/alice/private/sys/devices/cpu", "status": "COMPLETE"}]})
        doc = make_document(inv)
        self.assertEqual(doc["discovery"]["collectors"]["cpu"]["sources"][0]["path"],
                         "[REDACTED]")
        self.assertNotIn("alice", json.dumps(doc))

    def test_ic03_t04_all_nested_identifiers_suppressed(self):
        inv = make_inventory(ids=["system", "network"], data={
            "network": {"interfaces": [{"name": "eth0",
                                        "mac_address": "aa:bb:cc:dd:ee:ff",
                                        "ip_address": "192.168.1.99",
                                        "meta": {"username": "alice"}}]}})
        doc = make_document(inv)
        payload = json.dumps(doc)
        self.assertNotIn("aa:bb:cc:dd:ee:ff", payload)
        self.assertNotIn("192.168.1.99", payload)
        self.assertNotIn("alice", payload)
        self.assertIn("eth0", payload)

    def test_ic03_t05_sensitive_reasons_and_strings(self):
        inv = make_inventory(ids=["system", "cpu"], data={
            "cpu": {"vendor": "Intel /home/alice/private",
                    "model": "Intel Core"}})
        inv["results"]["cpu"]["reason"] = "path /home/alice/private"
        doc = make_document(inv)
        self.assertEqual(doc["discovery"]["collectors"]["cpu"]["reason"], "[REDACTED]")
        self.assertEqual(doc["discovery"]["collectors"]["cpu"]["data"]["vendor"], "[REDACTED]")
        self.assertEqual(doc["discovery"]["collectors"]["cpu"]["data"]["model"], "Intel Core")

    def test_ic03_t06_unknown_schema_and_mismatched_id(self):
        doc = make_document()
        for change in ({"schema_version": "1.0.0"}, {"schema_version": "3.0.0"},
                       {"session_id": "session_OTHER"}):
            candidate = {**doc, **change}
            with self.subTest(change=change), self.assertRaises(SessionSchemaError):
                validate_system_document(candidate, "session_TEST123")
        with self.assertRaises(SessionSchemaError):
            validate_system_document({**doc, "discovery": {}}, "session_TEST123")
        with self.assertRaises(SessionSchemaError):
            make_document(make_inventory(), host={"system": "Linux", "hostname": "private"})

    def test_ic03_t07_reject_unknown_collector_and_invalid_status(self):
        inv = make_inventory(ids=["system", "cpu"])
        inv["results"]["cpu"]["status"] = "PASS"
        with self.assertRaises(SessionSchemaError):
            make_document(inv)
        inv = make_inventory(ids=["system", "cpu"])
        inv["results"]["cpu"]["collector_id"] = "unregistered"
        with self.assertRaises(SessionSchemaError):
            make_document(inv)

    def test_ic03_t08_reject_inconsistent_counts_and_minimum(self):
        inv = make_inventory()
        inv["summary"]["status_counts"]["COMPLETE"] -= 1
        with self.assertRaises(SessionSchemaError):
            make_document(inv)
        inv = make_inventory()
        inv["summary"]["minimum_inventory_met"] = False
        with self.assertRaises(SessionSchemaError):
            make_document(inv)
        inv = make_inventory()
        inv["summary"]["outcome"] = "PARTIAL"
        with self.assertRaises(SessionSchemaError):
            make_document(inv)

    def test_ic03_t09_invalid_json_nan_and_cycle(self):
        inv = make_inventory()
        inv["results"]["cpu"]["data"]["architecture"] = float("nan")
        with self.assertRaises(SessionSchemaError):
            make_document(inv)
        inv = make_inventory()
        a = {}
        a["cycle"] = a
        inv["results"]["cpu"]["data"]["architecture"] = a
        with self.assertRaises(SessionSchemaError):
            make_document(inv)
        inv = make_inventory()
        inv["results"]["cpu"]["data"]["architecture"] = object()
        with self.assertRaises(SessionSchemaError):
            make_document(inv)

    def test_ic03_t10_absent_optical_and_missing_vainfo_preserved(self):
        inv = make_inventory(statuses={"optical": "UNAVAILABLE",
                                       "vaapi": "TOOL_MISSING"})
        doc = make_document(inv)
        self.assertEqual(doc["discovery"]["summary"]["outcome"], "COMPLETE")
        self.assertEqual(doc["discovery"]["collectors"]["optical"]["status"], "UNAVAILABLE")
        self.assertEqual(doc["discovery"]["collectors"]["vaapi"]["status"], "TOOL_MISSING")

    def test_ic03_t11_selected_scope_is_explicit(self):
        inv = make_inventory(ids=["optical"], statuses={"optical": "UNAVAILABLE"})
        doc = make_document(inv)
        self.assertEqual(doc["discovery"]["scope"], "selected")
        self.assertEqual(doc["discovery"]["summary"]["outcome"], "COMPLETE")
        self.assertEqual(doc["discovery"]["requested_collector_ids"], ["optical"])

    def test_host_privacy_review_rejects_or_redacts(self):
        doc = make_document(host={"system": "Linux", "architecture": "x86_64",
                                  "kernel": "/home/alice/custom"})
        self.assertEqual(doc["host"]["kernel"], "[REDACTED]")
        bad = deepcopy(doc)
        bad["host"]["kernel"] = "/home/alice/custom"
        with self.assertRaises(SessionSchemaError):
            validate_system_document(bad)

    def test_no_fabricated_benchmarks_or_assessments(self):
        doc = make_document()
        self.assertNotIn("benchmarks", doc)
        self.assertNotIn("assessments", doc)
        self.assertNotIn("tests", doc)

    def test_strict_json_roundtrip_is_idempotent(self):
        doc = make_document(make_inventory(ids=["system", "cpu"], sources={
            "system": [{"path": "/sys/class/dmi/id/product_name", "status": "COMPLETE"}],
        }))
        self.assertEqual(json.loads(json.dumps(doc, sort_keys=True)), doc)
        validate_system_document(doc)

    def test_unreviewed_top_level_hardware_field_rejected(self):
        inv = make_inventory(ids=["cpu"])
        inv["results"]["cpu"]["data"]["arbitrary_private_detail"] = "alice"
        with self.assertRaises(SessionSchemaError):
            make_document(inv)

    def test_untrusted_filename_does_not_become_session_id(self):
        with self.assertRaises(SessionSchemaError):
            build_system_document("../session_TEST123", make_inventory(),
                                  host={"system": "Linux"},
                                  session_started_utc="2026-10-23T18:00:00Z")

    def test_invalid_source_fields_are_rejected(self):
        inv = make_inventory(ids=["cpu"], sources={
            "cpu": [{"path": "/proc/cpuinfo", "status": "COMPLETE",
                     "raw_stdout": "private"}]})
        with self.assertRaises(SessionSchemaError):
            make_document(inv)


if __name__ == "__main__":
    unittest.main()
