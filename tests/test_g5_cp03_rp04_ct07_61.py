"""LBT RP-04 Increment 61: exact original CT-07 provenance candidate checks.

Only existing G5-02 sealed synthetic originals and actual G5-04 producer/
validator. Read-only simulated wrong-run references or accidentally corrupted
read views never modify immutable original files or rehash any manifest.
Not CP-02 independent acceptance or physical-host FAT.
"""
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import test_g5_cp03_rp03_multioriginal_46 as prior
import lbt_g5.canonical_session as canonical
from lbt_g5.canonical_contract import CanonicalContractError, validate_status_record
from lbt_g5.engine import CollectorRun, EngineRun

class RP04CT07Candidate61(unittest.TestCase):
    def helper(self):
        fixture=prior.MultiOriginalProvenance46("runTest")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        return fixture

    def test_61_01_CT_07_P1_semantic_value_cites_two_originals(self):
        fixture=self.helper()
        manifest,files,mountinfo,stats=fixture.fs_session()
        system=files["system.json"]
        self.assertEqual(len(stats),2)
        for stat in stats:
            matching=[x for x in system["observations"]
                      if x["observation_id"]=="obs:"+stat.evidence_id+":sem:0"]
            self.assertEqual(len(matching),1)
            obs=matching[0]
            self.assertEqual(obs["datum_path"],"storage.fs_stat.snapshot")
            self.assertEqual(obs["evidence_refs"],[stat.evidence_id,mountinfo.evidence_id])
            self.assertEqual(obs["source_attempt_ids"],["SRC-15-01","SRC-14-01"])
            self.assertEqual(len(set(obs["evidence_refs"])),2)
            for item in (stat,mountinfo):
                entry=manifest["evidence"][item.evidence_id]
                raw=(fixture.folder/entry["restricted_relative_path"]).read_bytes()
                self.assertEqual(len(raw),entry["byte_count"])
                self.assertEqual(hashlib.sha256(raw).hexdigest(),entry["sha256"])
                self.assertEqual(entry["sha256"],item.sha256)
        self.assertEqual(canonical.validate_canonical(fixture.folder),manifest)

    def test_61_02_CT_07_P2_identical_bytes_distinct_attempt_ids(self):
        fixture=self.helper()
        raw=b"MemTotal: 1024 kB\nMemFree: 128 kB\n"
        first,orig1=fixture.sealed("SRC-08",raw,slot="01")
        second,orig2=fixture.sealed("SRC-08",raw,slot="02")
        self.assertNotEqual(orig1.evidence_id,orig2.evidence_id)
        self.assertEqual(orig1.sha256,orig2.sha256)
        self.assertEqual(orig1.byte_count,orig2.byte_count)
        self.assertEqual(
            (fixture.folder/orig1.private_relative_path).read_bytes(),raw)
        self.assertEqual(
            (fixture.folder/orig2.private_relative_path).read_bytes(),raw)
        run=EngineRun(prior.RUN,(CollectorRun("COL-MEM",(first,second)),))
        manifest=canonical.build_canonical(fixture.folder,run)
        self.assertEqual(canonical.validate_canonical(fixture.folder),manifest)
        for eid,aid in ((orig1.evidence_id,"SRC-08-01"),
                        (orig2.evidence_id,"SRC-08-02")):
            self.assertEqual(manifest["evidence"][eid]["source_attempt_id"],aid)
        obs=json.loads((fixture.folder/"private/system.json").read_text())["observations"]
        for eid,aid in ((orig1.evidence_id,"SRC-08-01"),
                        (orig2.evidence_id,"SRC-08-02")):
            rows=[x for x in obs if x["instance_key"]==eid]
            self.assertTrue(rows)
            self.assertTrue(all(x["evidence_refs"]==[eid] and
                                x["source_attempt_ids"]==[aid] for x in rows))

    def test_61_03_CT_07_N1_stale_or_missing_provenance_rejected(self):
        fixture=self.helper()
        manifest,files,src14,src15=fixture.fs_session()
        acquisitions=files["status_records.json"]["status_records"]
        source=next(x for x in acquisitions if x["domain"]=="acquisition"
                    and x["subject_id"]=="SRC-15")
        # Wrong-run/stale selection of an attempt universe, not hostile editing.
        with self.assertRaises(CanonicalContractError):
            validate_status_record(source,
                evidence_ids=set(manifest["evidence"]),
                attempt_ids={"SRC-14-01"},limit_ids=set())
        # Ordinary missing original in the operator's selected evidence set.
        with self.assertRaises(CanonicalContractError):
            validate_status_record(source,
                evidence_ids={src14.evidence_id},
                attempt_ids={"SRC-15-01","SRC-14-01"},limit_ids=set())
        # Test-only ordinary consumer regression: resolved memory view cites
        # stale attempt. All committed canonical/source/original files stay
        # identical; no malicious record or digest rewrite is used.
        original_load=canonical._json_load
        def wrong_attempt_view(raw):
            result=original_load(raw)
            if type(result) is dict and "observations" in result:
                for row in result["observations"]:
                    if row.get("datum_path")=="storage.fs_stat.snapshot":
                        row["source_attempt_ids"]=["SRC-15-99","SRC-14-01"]
                        break
            return result
        with patch("lbt_g5.canonical_session._json_load",
                   side_effect=wrong_attempt_view):
            with self.assertRaises(CanonicalContractError):
                canonical.validate_canonical(fixture.folder)
        self.assertEqual(canonical.validate_canonical(fixture.folder),manifest)

    def test_61_04_CT_07_N2_accidental_corrupt_read_fails_digest(self):
        fixture=self.helper()
        manifest,files,src14,src15=fixture.fs_session()
        target=fixture.folder/src15[0].private_relative_path
        original=target.read_bytes()
        digest=hashlib.sha256(original).hexdigest()
        read=canonical._read_restricted
        def corrupted_read(path,ceiling):
            raw=read(path,ceiling)
            if Path(path)==target and raw:
                # Simulated transient bit error on read only.
                return bytes((raw[0]^1,))+raw[1:]
            return raw
        with patch("lbt_g5.canonical_session._read_restricted",
                   side_effect=corrupted_read):
            with self.assertRaisesRegex(CanonicalContractError,
                                        "sealed original altered"):
                canonical.validate_canonical(fixture.folder)
        self.assertEqual(target.read_bytes(),original)
        self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(),digest)
        self.assertEqual(canonical.validate_canonical(fixture.folder),manifest)


if __name__=="__main__":
    unittest.main()
