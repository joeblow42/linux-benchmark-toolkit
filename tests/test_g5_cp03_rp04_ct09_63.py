"""LBT RP-04 Increment 63: original CT-09 typed/lossless and strict D-02 cases.

Synthetic sealed original bytes only. Unknown acquired datum paths are allowed
within canonical observations; undeclared D-02 object members are not.
A deliberately missing observation is injected in memory, never by rewriting
source originals, receipts or canonical files. No FAT acceptance is inferred.
"""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import lbt_g5.canonical_session as canonical
from lbt_g5.canonical_contract import CanonicalContractError
from lbt_g5.d02_schema import validate_d02_entity, validate_d02_file
from lbt_g5.engine import EngineRun, CollectorRun
from lbt_g5.evidence import EvidenceWriter
from lbt_g5.records import build_attempt, commit_attempt
from lbt_g5.safety import initial_source_policies

RUN="run-2026320205900"
POL={p.source_id:p for p in initial_source_policies()}

class RP04CT09Candidate63(unittest.TestCase):
    def materialize(self,sid,raw):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        folder=Path(tmp.name)/RUN
        folder.mkdir(mode=0o700)
        writer=EvidenceWriter(str(folder),RUN)
        item=writer.seal_chunks(POL[sid],"01","item0001",(raw,)).receipt
        self.assertIsNotNone(item)
        receipt=build_attempt(RUN,sid,"01","ALLOW","CAPTURED","BYTES_PRESERVED",
                              evidence=(item,),bytes_count=item.byte_count)
        loc=commit_attempt(str(folder),receipt)
        rec=SimpleNamespace(receipt_private_path=loc,
                            outcome=SimpleNamespace(artifacts=(item,)))
        run=EngineRun(RUN,(CollectorRun(POL[sid].collector_id,(rec,)),))
        manifest=canonical.build_canonical(folder,run)
        self.assertEqual(canonical.validate_canonical(folder),manifest)
        system=json.loads((folder/"private/system.json").read_text())
        self.assertEqual((folder/item.private_relative_path).read_bytes(),raw)
        self.assertEqual(hashlib.sha256(raw).hexdigest(),item.sha256)
        return folder,item,manifest,system

    def test_63_01_CT_09_P1_unknown_attribute_typed_or_byte_ref(self):
        raw=b"ID=bodhi\nEXPERIMENTAL_FIELD=arbitrary\n"
        folder,item,manifest,system=self.materialize("SRC-02",raw)
        semantic=[o for o in system["observations"]
                  if o["datum_path"]=="os.release.EXPERIMENTAL_FIELD"]
        self.assertEqual(len(semantic),1)
        observed=semantic[0]
        self.assertEqual(observed["normalized_value"],"arbitrary")
        self.assertEqual(observed["value_type"],"STRING")
        self.assertEqual(observed["evidence_refs"],[item.evidence_id])
        self.assertEqual(observed["source_attempt_ids"],["SRC-02-01"])
        self.assertIn("SOURCE_PARSER_SUCCEEDED",observed["parser_findings"])
        self.assertEqual(manifest["counts"]["observations"],3)
        # Real byte-unsafe input must still have a lossless original fallback,
        # not a fabricated typed normalized value.
        invalid=b"ID=bodhi\nEXPERIMENTAL_FIELD=\xff\n"
        other,item2,manifest2,system2=self.materialize("SRC-02",invalid)
        self.assertEqual(manifest2["counts"]["observations"],1)
        raw_row=system2["observations"][0]
        self.assertEqual(raw_row["value_type"],"BYTES_REF")
        self.assertEqual(raw_row["observed_value"],
                         {"sealed_bytes_ref":item2.evidence_id})
        self.assertIsNone(raw_row["normalized_value"])
        self.assertEqual(raw_row["evidence_refs"],[item2.evidence_id])
        self.assertIn("PARSER_FAILED:PARSER_NON_UTF8_INPUT",
                      raw_row["parser_findings"])

    def test_63_02_CT_09_P2_known_semantics_have_type_unit_and_provenance(self):
        raw=b"MemTotal: 1024 kB\nMemFree: 256 kB\n"
        folder,item,manifest,system=self.materialize("SRC-08",raw)
        semantic=next(o for o in system["observations"]
                      if o["datum_path"]=="memory.meminfo.MemTotal")
        self.assertEqual(semantic["normalized_value"],1024*1024)
        self.assertEqual(semantic["observed_value"],"1024 kB")
        self.assertEqual(semantic["value_type"],"INTEGER")
        self.assertEqual(semantic["unit"],"bytes")
        self.assertEqual(semantic["source_attempt_ids"],["SRC-08-01"])
        self.assertEqual(semantic["evidence_refs"],[item.evidence_id])
        self.assertTrue(semantic["transformation_ids"])
        self.assertEqual(semantic["parser_findings"],["SOURCE_PARSER_SUCCEEDED"])
        self.assertEqual(manifest["counts"]["observations"],3)

    def test_63_03_CT_09_N1_undeclared_canonical_fields_are_rejected(self):
        _,_,_,system=self.materialize("SRC-08",b"MemTotal: 1024 kB\n")
        injected=copy.deepcopy(system)
        injected["invented_canonical_top_level"]=True
        with self.assertRaises(CanonicalContractError):
            validate_d02_file("system.json",injected)
        injected=copy.deepcopy(system["observations"][1])
        injected["unapproved_extra_datum"]=1
        with self.assertRaises(CanonicalContractError):
            validate_d02_entity("CanonicalObservation",injected)

    def test_63_04_CT_09_N2_silent_drop_of_unknown_semantic_is_detected(self):
        raw=b"ID=bodhi\nEXPERIMENTAL_FIELD=not_in_static_schema\n"
        folder,item,manifest,system=self.materialize("SRC-02",raw)
        self.assertTrue(any(o["datum_path"]=="os.release.EXPERIMENTAL_FIELD"
                            for o in system["observations"]))
        original_loader=canonical._json_load
        def missing_semantic_view(data):
            result=original_loader(data)
            if type(result) is dict and "observations" in result:
                result["observations"]=[x for x in result["observations"]
                  if x.get("datum_path")!="os.release.EXPERIMENTAL_FIELD"]
            return result
        with patch("lbt_g5.canonical_session._json_load",
                   side_effect=missing_semantic_view):
            with self.assertRaises(CanonicalContractError):
                canonical.validate_canonical(folder)
        self.assertEqual(canonical.validate_canonical(folder),manifest)
        self.assertEqual((folder/item.private_relative_path).read_bytes(),raw)


if __name__=="__main__":
    unittest.main()
