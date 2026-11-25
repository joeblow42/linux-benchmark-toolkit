"""RP-02 SRC-15 source count boundary: synthetic source-first, CP-02 open."""
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from lbt_g5.evidence import EvidenceWriter
from lbt_g5.records import build_attempt, commit_attempt
from lbt_g5.engine import CollectorRun,EngineRun
from lbt_g5.receipt_dispatch import capture_and_record
from lbt_g5.runtime import TransportCapture,ProbeSlots,SourceCallBudget
from lbt_g5.safety import SourceRequest,initial_source_policies
from lbt_g5.canonical_session import build_canonical,CanonicalContractError

RUN="run-2026318160030"
SRC="SRC-15"
POL={p.source_id:p for p in initial_source_policies()}


def paths(count):
    return tuple("/mnt/f04_"+str(i).zfill(3) for i in range(count))

def source14(mounts):
    return ("".join(f"{i+1} 1 8:1 / {mount} rw - ext4 /dev/loop0 rw\n"
                    for i,mount in enumerate(mounts))).encode()

def stat(mount):
    return (json.dumps(dict(mount=mount,fragment_size=4096,block_size=4096,
               blocks=10,free_blocks=5,available_blocks=4,
               files=1000,free_files=800),sort_keys=True)+"\n").encode()


class SRC15SourceEntryBoundary(unittest.TestCase):
    def run_case(self, count, *, stop_at=None, sealed_mount_count=None):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        folder=Path(temp.name)/RUN
        folder.mkdir(mode=0o700)
        writer=EvidenceWriter(str(folder),RUN)
        mounts=paths(count)
        actual_mounts=paths(count if sealed_mount_count is None else sealed_mount_count)
        raw14=source14(actual_mounts)
        source14_original=writer.seal_chunks(POL["SRC-14"],"01","item0001",(raw14,)).receipt
        receipt14=build_attempt(RUN,"SRC-14","01","ALLOW","CAPTURED","BYTES_PRESERVED",
                                evidence=(source14_original,),
                                bytes_count=source14_original.byte_count,
                                invocation="MOUNTINFO",
                                source_paths=("/proc/self/mountinfo",))
        source14_record=SimpleNamespace(receipt_private_path=commit_attempt(str(folder),receipt14),
                                        outcome=SimpleNamespace(artifacts=(source14_original,)))
        called=[]
        def worker(argv, *args):
            called.append(argv[-1])
            index=len(called)
            return TransportCapture(stat(argv[-1]),b"",None if index==stop_at else 0,
                                    2.03 if index==stop_at else .004,
                                    index==stop_at,False,0,0)
        with patch("lbt_g5.additional.decide_source",
                   return_value=SimpleNamespace(allowed=True,reason="APPROVED")):
            with patch("lbt_g5.additional.eligible_mounts",return_value=mounts):
                with patch("lbt_g5.additional._resolve_executable",
                           return_value="/usr/bin/python3"):
                    with patch("lbt_g5.additional._capture_child",side_effect=worker):
                        source15_record=capture_and_record(
                            SourceRequest(RUN,SRC,"FS_STAT"),"01",writer,
                            ProbeSlots(),SourceCallBudget(),
                            source14_evidence=source14(mounts))
        receipt15=json.loads((folder/source15_record.receipt_private_path).read_text())
        run=EngineRun(RUN,(CollectorRun("COL-FS",(source14_record,source15_record)),))
        return folder,receipt15,run,called

    def test_36_01_129_candidates_and_128_actual_calls_evidence_count(self):
        folder,receipt,run,calls=self.run_case(129)
        self.assertEqual(len(calls),128)
        self.assertEqual(receipt["schema_version"],"g5-02-attempt-0.6")
        self.assertEqual(len(receipt["evidence_ids"]),128)
        self.assertEqual(receipt["limit_witnesses"],[{
            "unit":"entries","threshold":128,"observed_extent":128,
            "missing_extent":None,
            "affected_scope":"SRC-15:call0001:source:entries",
            "reason":"CAPTURE_LIMIT"}])
        build_canonical(folder,run)
        limits=json.loads((folder/"private/system.json").read_text())["capture_limits"]
        self.assertEqual(len(limits),1)
        self.assertEqual(limits[0]["unit"],"entries")
        self.assertEqual(limits[0]["threshold"],128)

    def test_36_02_exact_128_candidates_proves_no_omission(self):
        folder,receipt,run,calls=self.run_case(128)
        self.assertEqual(len(calls),128)
        self.assertEqual(receipt["schema_version"],"g5-02-attempt-0.4")
        self.assertNotIn("limit_witnesses",receipt)
        build_canonical(folder,run)

    def test_36_03_abort_early_does_not_fabricate_entry_count(self):
        folder,receipt,run,calls=self.run_case(129,stop_at=2)
        self.assertEqual(len(calls),2)
        self.assertEqual(receipt["schema_version"],"g5-02-attempt-0.6")
        self.assertEqual(len(receipt["limit_witnesses"]),1)
        self.assertEqual(receipt["limit_witnesses"][0]["unit"],"seconds")
        self.assertNotIn("source:entries",str(receipt["limit_witnesses"]))
        build_canonical(folder,run)

    def test_36_04_same_run_mountinfo_disproves_extra_candidates(self):
        folder,receipt,run,calls=self.run_case(129,sealed_mount_count=128)
        self.assertEqual(receipt["limit_witnesses"][0]["unit"],"entries")
        with self.assertRaisesRegex(CanonicalContractError,
                                     "source entry count not evidenced"):
            build_canonical(folder,run)

    def test_36_05_invalid_count_or_missing_extent_rejected(self):
        valid=dict(unit="entries",threshold=128,observed_extent=128,
                   missing_extent=None,
                   affected_scope="SRC-15:call0001:source:entries",
                   reason="CAPTURE_LIMIT")
        for bad in (dict(valid,threshold=127),dict(valid,observed_extent=129),
                    dict(valid,missing_extent=0),
                    dict(valid,affected_scope="SRC-15:call0002:source:entries")):
            with self.subTest(bad=bad),self.assertRaises(ValueError):
                build_attempt(RUN,SRC,"01","ALLOW","PARTIAL","CAPTURE_LIMIT",
                              capture_limited=True,limit_witnesses=[bad])

if __name__=="__main__":
    unittest.main()
