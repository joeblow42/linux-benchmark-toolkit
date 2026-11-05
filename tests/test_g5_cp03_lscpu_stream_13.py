"""CP-03 Increment 13: D1 lscpu stdout/stderr provenance and row parsing.

Oracles specified before implementation at cp03_lscpu_stream_oracle_13.json.
All artifacts are synthetic, sealed original bytes; no host command runs.
"""
from contextlib import contextmanager
from dataclasses import replace
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

from lbt_g5.canonical_contract import CanonicalContractError
from lbt_g5.canonical_session import build_canonical, validate_canonical
from lbt_g5.engine import CollectorRun, EngineRun
from lbt_g5.evidence import EvidenceWriter
from lbt_g5.normalization import (
    SourceParseError, normalize_sealed_source, parser_available,
)
from lbt_g5.records import build_attempt, commit_attempt
from lbt_g5.runtime import command_plan
from lbt_g5.safety import initial_source_policies

RUN = "run-2026305120000"


class LscpuD1SourceFirstOracles(unittest.TestCase):
    @contextmanager
    def sealed(self, items, *, source_paths=(), invocation="lscpu",
               cross_run=False, outcome="CAPTURED", reason="BYTES_PRESERVED",
               exit_code=0, names=None):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / RUN
            folder.mkdir(mode=0o700)
            pol = {x.source_id:x for x in initial_source_policies()}["SRC-05"]
            writer = EvidenceWriter(str(folder), RUN)
            names = names or [label for label, raw in items]
            self.assertEqual(len(names), len(items))
            originals = []
            for (label, raw), artifact_name in zip(items, names):
                sealed = writer.seal_chunks(
                    pol, "01", artifact_name, (raw,)).receipt
                self.assertIsNotNone(sealed)
                originals.append(sealed)
            attempt = build_attempt(
                RUN, "SRC-05", "01", "ALLOW", outcome, reason,
                evidence=tuple(originals),
                bytes_count=sum(x.byte_count for x in originals),
                source_paths=source_paths, invocation=invocation,
                exit_code=exit_code)
            path = commit_attempt(str(folder), attempt)
            if cross_run:
                originals[0] = replace(originals[0], run_id="run-2026305120001")
            rec = SimpleNamespace(
                receipt_private_path=path,
                outcome=SimpleNamespace(artifacts=tuple(originals)))
            yield folder, EngineRun(
                RUN, (CollectorRun("COL-CPU", (rec,)),)), tuple(originals)

    def test_approved_command_and_data_stream_only(self):
        self.assertEqual(command_plan("SRC-05").argv, ("lscpu",))
        self.assertTrue(parser_available("SRC-05"))
        self.assertTrue(parser_available("SRC-13"))  # CP03-17 O1 verified stdout
        parsed = normalize_sealed_source(
            "SRC-05", b"Architecture:   x86_64\nCPU(s): 4\n",
            source_stream="stdout")
        self.assertEqual(parsed.values[0].datum_path, "cpu.lscpu.rows")
        self.assertEqual(parsed.values[0].value_type, "ARRAY")
        self.assertEqual(parsed.values[0].normalized_value, [
            {"label":"Architecture", "value":"x86_64"},
            {"label":"CPU(s)", "value":"4"}])
        with self.assertRaises(SourceParseError):
            normalize_sealed_source("SRC-05", b"architecture: x86_64\n")
        with self.assertRaises(SourceParseError):
            normalize_sealed_source("SRC-05", b"stderr warning\n",
                                    source_stream="stderr")

    def test_stdout_and_stderr_both_originals_only_stdout_is_semantic(self):
        items = (("call0001-stdout", b"Architecture: x86_64\nCPU(s): 4\n"),
                 ("call0001-stderr", b"warning: synthetic diagnostic\n"))
        with self.sealed(items) as (folder, run, originals):
            manifest = build_canonical(folder, run)
            self.assertEqual(manifest["observation_count"], 3)
            self.assertEqual(validate_canonical(folder), manifest)
            obs = json.loads((folder/"private/system.json").read_text())["observations"]
            typed = [x for x in obs if x["transformation_ids"]]
            self.assertEqual(len(typed), 1)
            self.assertEqual(typed[0]["evidence_refs"], [originals[0].evidence_id])
            self.assertEqual(typed[0]["source_attempt_ids"], ["SRC-05-01"])
            self.assertTrue(any("DIAGNOSTIC_ORIGINAL_PRESERVED"
                                in x["parser_findings"] for x in obs))
            state = json.loads((folder/"private/status_records.json").read_text())
            self.assertEqual(state["status_records"][0]["reason_code"], "OK")
            for (_, raw), artifact in zip(items, originals):
                self.assertEqual((folder/artifact.private_relative_path).read_bytes(), raw)
                self.assertEqual(hashlib.sha256(raw).hexdigest(), artifact.sha256)

    def test_localized_labels_are_opaque_and_duplicate_order_preserved(self):
        fields = normalize_sealed_source(
            "SRC-05", "Architektur: x86_64\nKern(e): 2\nKern(e): 2\n".encode(),
            source_stream="stdout").values[0].normalized_value
        self.assertEqual([x["label"] for x in fields],
                         ["Architektur", "Kern(e)", "Kern(e)"])
        self.assertEqual([x["value"] for x in fields],
                         ["x86_64", "2", "2"])

    def test_missing_stdout_never_finalizes_as_cpu_observation(self):
        with self.sealed((("call0001-stderr", b"error text\n"),)
        ) as (folder, run, _):
            with self.assertRaises(CanonicalContractError):
                build_canonical(folder, run)
            self.assertFalse((folder/"private/session_manifest.json").exists())

    def test_wrong_stream_order_name_subcall_and_invocation_rejected(self):
        valid = b"Architecture: x86_64\n"
        bad = [
            (("call0001-stderr", b"warning\n"), ("call0001-stdout", valid)),
            (("call0002-stdout", valid),),
        ]
        for items in bad:
            with self.subTest(items=items):
                with self.sealed(items) as (folder, run, _):
                    with self.assertRaises(CanonicalContractError):
                        build_canonical(folder, run)
                    self.assertFalse((folder/"private/session_manifest.json").exists())
        with self.sealed((("call0001-stdout", valid),),
                         invocation="lsblk") as (folder, run, _):
            with self.assertRaises(CanonicalContractError):
                build_canonical(folder, run)
        with self.sealed((("call0001-stdout", valid),),
                         source_paths=("/proc/cpuinfo",)) as (folder, run, _):
            with self.assertRaises(CanonicalContractError):
                build_canonical(folder, run)

    def test_writer_refuses_duplicate_original_artifact_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / RUN
            folder.mkdir(mode=0o700)
            pol = {x.source_id:x for x in initial_source_policies()}["SRC-05"]
            writer = EvidenceWriter(str(folder), RUN)
            first = writer.seal_chunks(
                pol, "01", "call0001-stdout",
                (b"Architecture: x86_64\n",))
            self.assertIsNotNone(first.receipt)
            duplicate = writer.seal_chunks(
                pol, "01", "call0001-stdout",
                (b"Architecture: x86_64\n",))
            self.assertIsNone(duplicate.receipt)
            self.assertIsNotNone(duplicate.failure)

    def test_malformed_stdout_fails_real_parser_not_stderr(self):
        for raw in (b"not key value\n", b"\xff\n", b": missing label\n",
                    b"Name: okay\nwrong\n", b"Key: " + b"x"*9000 + b"\n"):
            with self.subTest(raw=raw[:18]), self.assertRaises(SourceParseError):
                normalize_sealed_source("SRC-05", raw, source_stream="stdout")
        with self.sealed((("call0001-stdout", b"not key value\n"),)
        ) as (folder, run, originals):
            manifest = build_canonical(folder, run)
            self.assertEqual(manifest["observation_count"], 1)
            states = json.loads((folder/"private/status_records.json").read_text())
            self.assertEqual(states["status_records"][0]["reason_code"], "PARSE_FAILED")
            self.assertEqual((folder/originals[0].private_relative_path).read_bytes(),
                             b"not key value\n")
            self.assertEqual(validate_canonical(folder), manifest)

    def test_approved_nonzero_command_exit_is_partial_and_not_complete(self):
        with self.sealed((("call0001-stdout", b"CPU(s): 1\n"),),
                         outcome="PARTIAL", reason="EXIT_NONZERO",
                         exit_code=2) as (folder, run, originals):
            manifest = build_canonical(folder, run)
            self.assertEqual(validate_canonical(folder), manifest)
            status = json.loads(
                (folder/"private/status_records.json").read_text())["status_records"][0]
            self.assertEqual((status["status"], status["reason_code"]),
                             ("PARTIAL", "SOURCE_INCOMPLETE"))
            self.assertIn("transport=PARTIAL/EXIT_NONZERO", status["detail"])
            self.assertIn("exit_code=2", status["detail"])
            self.assertNotIn("PARSE_FAILED", status["reason_code"])
            self.assertEqual(manifest["observation_count"], 2)
            self.assertEqual((folder / originals[0].private_relative_path).read_bytes(),
                             b"CPU(s): 1\n")

    def test_wrong_run_evidence_rejected(self):
        with self.sealed((("call0001-stdout", b"CPU(s): 4\n"),),
                         cross_run=True) as (folder, run, _):
            with self.assertRaises(CanonicalContractError):
                build_canonical(folder, run)


if __name__ == "__main__":
    unittest.main()
