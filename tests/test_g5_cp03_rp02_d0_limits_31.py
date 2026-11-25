"""RP-02.1 source-first D0 events. Synthetic only; not independent CP-02 acceptance."""
import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lbt_g5.passive_worker import collect, MAX_PER_FILE
from lbt_g5.evidence import EvidenceWriter
from lbt_g5.engine import EngineRun, CollectorRun
from lbt_g5.runtime import ProbeSlots, SourceCallBudget, TransportCapture
from lbt_g5.safety import SourceRequest, initial_source_policies
from lbt_g5.receipt_dispatch import capture_and_record
from lbt_g5.canonical_session import build_canonical
from lbt_g5.records import build_attempt

RUN = "run-2026317130000"
SRC = "SRC-12"


class D0WorkerEventOracle(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "block"
        (self.root / "sda").mkdir(parents=True)

    def records(self, *, byte_limit=32*1024*1024, entry_limit=4096):
        return list(collect(SRC, roots={SRC: str(self.root)},
                            max_bytes=byte_limit, max_entries=entry_limit))

    def test_d03101_file_limit_identifies_applied_max_not_guessed_missing_bytes(self):
        (self.root / "sda" / "size").write_bytes(b"X" * (MAX_PER_FILE+1))
        records = self.records()
        first = next(r for r in records if "bytes_b64" in r)
        self.assertEqual(len(base64.b64decode(first["bytes_b64"])), MAX_PER_FILE)
        self.assertTrue(first["limited"])
        self.assertEqual(first["limit_events"], [{
            "dimension": "file_bytes", "threshold": MAX_PER_FILE,
            "observed_extent": MAX_PER_FILE
        }])

    def test_d03102_worker_entry_count_on_next_candidate(self):
        (self.root / "sda" / "size").write_text("2\n")
        records = self.records(entry_limit=1)
        self.assertTrue(records[-1]["limited"])
        self.assertEqual(records[-1]["limit_events"], [{
            "dimension": "source_entries", "threshold": 1,
            "observed_extent": 1
        }])

    def test_d03103_source_total_bytes_on_next_candidate(self):
        (self.root / "sda" / "size").write_bytes(b"123")
        records = self.records(byte_limit=3)
        self.assertTrue(records[-1]["limited"])
        self.assertEqual(records[-1]["limit_events"], [{
            "dimension": "source_bytes", "threshold": 3,
            "observed_extent": 3
        }])

    def test_d03104_coincident_source_entry_and_byte_bound_preserves_both(self):
        (self.root / "sda" / "size").write_bytes(b"123")
        records = self.records(byte_limit=3, entry_limit=1)
        dims = {v["dimension"] for v in records[-1]["limit_events"]}
        self.assertEqual(dims, {"source_bytes", "source_entries"})

    def test_d03107_unreached_bounds_produce_no_events(self):
        # One nonempty candidate, plus optional absent source paths.
        (self.root / "sda" / "size").write_bytes(b"1\n")
        records = self.records()
        self.assertFalse(records[-1]["limited"])
        self.assertNotIn("limit_events", records[-1])


class D0PrivateReceiptOracle(unittest.TestCase):
    def one(self, payload, *, timed_out=False):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        folder = Path(temp.name) / RUN
        folder.mkdir(mode=0o700)
        pol = {p.source_id:p for p in initial_source_policies()}[SRC]
        request = SourceRequest(RUN, SRC, pol.operation_id)
        writer = EvidenceWriter(str(folder), RUN)
        blob = b"".join((json.dumps(v, sort_keys=True)+"\n").encode() for v in payload)
        t = TransportCapture(blob, b"", None if timed_out else 0, .05,
                             timed_out, False, 0, 0)
        with patch("lbt_g5.passive._resolve_executable", return_value="/usr/bin/python3"):
            with patch("lbt_g5.passive._capture_child", return_value=t) as invoked:
                rec = capture_and_record(request, "01", writer,
                                         ProbeSlots(), SourceCallBudget())
        receipt = json.loads((folder / rec.receipt_private_path).read_text())
        run = EngineRun(RUN, (CollectorRun(pol.collector_id, (rec,)),))
        return folder, receipt, run, invoked

    def file_message(self):
        content = b"1" * MAX_PER_FILE
        event = {"dimension":"file_bytes","threshold":MAX_PER_FILE,
                 "observed_extent":MAX_PER_FILE}
        return ({"path":"/sys/class/block/sda/size",
                 "bytes_b64":base64.b64encode(content).decode(),
                 "limited":True, "limit_events":[event]},
                {"end":True,"entries":1,"bytes":len(content),"limited":False})

    def test_d03101_v06_file_limit_receipt_and_canonical_existing_fields(self):
        folder, receipt, run, invoked = self.one(self.file_message())
        self.assertEqual(receipt["schema_version"], "g5-02-attempt-0.6")
        self.assertNotIn("limit_witness", receipt)
        self.assertEqual(receipt["limit_witnesses"][0]["unit"], "bytes")
        self.assertEqual(receipt["limit_witnesses"][0]["threshold"], MAX_PER_FILE)
        self.assertEqual(receipt["limit_witnesses"][0]["missing_extent"], None)
        build_canonical(folder, run)
        limits = json.loads((folder / "private/system.json").read_text())["capture_limits"]
        self.assertEqual(len(limits), 1)
        self.assertEqual(limits[0]["unit"], "bytes")
        self.assertEqual(limits[0]["affected_scope"], SRC + ":call0001:item0001:file")

    def test_d03105_time_and_file_limit_both_have_independent_ids(self):
        folder, receipt, run, invoked = self.one(self.file_message(), timed_out=True)
        units = [b["unit"] for b in receipt["limit_witnesses"]]
        self.assertEqual(units, ["bytes", "seconds"])
        self.assertEqual(receipt["limit_witnesses"][-1]["threshold"],
                         invoked.call_args.args[3])
        build_canonical(folder, run)
        limits = json.loads((folder / "private/system.json").read_text())["capture_limits"]
        self.assertEqual(len(limits), 2)
        status = json.loads((folder / "private/status_records.json").read_text())["status_records"][0]
        self.assertEqual(len(status["limit_record_ids"]), 2)
        self.assertEqual(len({v["limit_id"] for v in limits}), 2)

    def test_d03111_v06_unknown_unit_or_duplicated_scope_refused(self):
        good = dict(unit="entries", threshold=2, observed_extent=2,
                    missing_extent=None,
                    affected_scope=SRC+":call0001:source:entries",
                    reason="CAPTURE_LIMIT")
        for bad in (dict(good,unit="widgets"),
                    dict(good,threshold=-1),
                    dict(good,affected_scope="/etc/shadow")):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                build_attempt(RUN,SRC,"01","ALLOW","PARTIAL","CAPTURE_LIMIT",
                              limit_witnesses=[bad],capture_limited=True)
        with self.assertRaises(ValueError):
            build_attempt(RUN,SRC,"01","ALLOW","PARTIAL","CAPTURE_LIMIT",
                          limit_witnesses=[good,good],capture_limited=True)


if __name__ == "__main__":
    unittest.main()
