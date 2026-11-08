"""CP03-19 source-first SRC-15 FS_STAT oracle fixtures; no host probes.

Expected values derive from G4-07, the pinned G5-03 worker output fields,
Python statvfs_result documentation, and the independent oracle JSON.
The same AI authors fixtures and implementation: human review remains open.
"""
from contextlib import contextmanager
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
from lbt_g5.normalization import SourceParseError, normalize_sealed_source, parser_available
from lbt_g5.records import build_attempt, commit_attempt
from lbt_g5.safety import initial_source_policies

RUN = "run-2026305120000"
MOUNTINFO = (b"1 0 8:1 / / rw - ext4 /dev/sda1 rw\n"
             b"2 1 8:2 / /mnt/local\\040drive rw - xfs /dev/sdb1 rw\n"
             b"3 1 0:2 / /mnt/remote rw - nfs server:/data rw\n")
MOUNT = "/"
FIELDS = dict(mount=MOUNT, fragment_size=4096, block_size=4096, blocks=100,
              free_blocks=30, available_blocks=20, files=1000, free_files=900)
POLICY = {p.source_id: p for p in initial_source_policies()}

def encoded(obj=FIELDS):
    return (json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n").encode()

class FSStatSourceOracles(unittest.TestCase):
    @contextmanager
    def session(self, raw=None, *, stdout_mount="/", label_mount=None,
                names=None, labels=None, include_source14=True, corrupt=False,
                invocation="FS_STAT", target=None, outcome="CAPTURED",
                reason="BYTES_PRESERVED", limited=False):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / RUN
            folder.mkdir(mode=0o700)
            writer = EvidenceWriter(str(folder), RUN)
            entries = []
            source14 = None
            if include_source14:
                m = writer.seal_chunks(POLICY["SRC-14"], "01", "item0001",
                                       (MOUNTINFO,)).receipt
                r = build_attempt(RUN, "SRC-14", "01", "ALLOW",
                                  "CAPTURED", "BYTES_PRESERVED",
                                  evidence=(m,), bytes_count=m.byte_count,
                                  invocation="MOUNTINFO",
                                  source_paths=("/proc/self/mountinfo",))
                source14 = SimpleNamespace(receipt_private_path=commit_attempt(str(folder), r),
                                           outcome=SimpleNamespace(artifacts=(m,)))
                entries.append(source14)
            if names is None:
                names = ("call0001-stdout",)
            if labels is None:
                labels = ((label_mount or stdout_mount) + ":stdout",)
            if raw is None:
                obj = dict(FIELDS, mount=stdout_mount)
                raw = encoded(obj)
            artifacts = []
            for name in names:
                part = raw if name.endswith("stdout") else b"diagnostic original\n"
                item = writer.seal_chunks(POLICY["SRC-15"], "01", name, (part,)).receipt
                artifacts.append(item)
            rec = build_attempt(RUN, "SRC-15", "01", "ALLOW", outcome, reason,
                                evidence=tuple(artifacts),
                                bytes_count=sum(a.byte_count for a in artifacts),
                                source_paths=tuple(labels),
                                invocation=invocation, target=target,
                                capture_limited=limited)
            loc = commit_attempt(str(folder), rec)
            if corrupt and artifacts:
                (folder / artifacts[0].private_relative_path).write_bytes(b"tampered\n")
            entries.append(SimpleNamespace(receipt_private_path=loc,
                                           outcome=SimpleNamespace(artifacts=tuple(artifacts))))
            yield folder, EngineRun(RUN, (CollectorRun("COL-FS", tuple(entries)),)), artifacts

    def test_authorized_source_contract_and_parser_registered(self):
        p = POLICY["SRC-15"]
        self.assertEqual((p.collector_id, p.authorization_class, p.operation_id),
                         ("COL-FS", "D1", "FS_STAT"))
        self.assertEqual((p.max_entries, p.max_seconds, p.max_bytes), (128, 15, 2*1024*1024))
        self.assertTrue(parser_available("SRC-15"))

    def test_single_mount_fields_and_raw_evidence_lineage(self):
        with self.session() as (folder, run, artifacts):
            manifest = build_canonical(folder, run)
            self.assertEqual(validate_canonical(folder), manifest)
            rows = json.loads((folder / "private/system.json").read_text())["observations"]
            derived = [x for x in rows if x["transformation_ids"] and x["datum_path"] == "storage.fs_stat.snapshot"]
            self.assertEqual(len(derived), 1)
            self.assertEqual(derived[0]["evidence_refs"], [artifacts[0].evidence_id])
            self.assertEqual(derived[0]["normalized_value"], FIELDS)
            self.assertEqual(derived[0]["value_type"], "OBJECT")
            self.assertEqual(artifacts[0].sha256, hashlib.sha256(encoded()).hexdigest())
            self.assertEqual((folder / artifacts[0].private_relative_path).read_bytes(), encoded())
            status = json.loads((folder / "private/status_records.json").read_text())
            src15 = next(s for s in status["status_records"] if s["subject_id"] == "SRC-15")
            self.assertEqual((src15["status"], src15["reason_code"]), ("COMPLETE", "OK"))

    def test_second_mount_escaped_kernel_path_no_host_probe(self):
        path = "/mnt/local drive"
        parsed = normalize_sealed_source("SRC-15", encoded(dict(FIELDS, mount=path)),
                                         source_stream="stdout", source_path=path)
        self.assertEqual(parsed.values[0].normalized_value["mount"], path)
        with self.session(stdout_mount=path) as (folder, run, artifacts):
            build_canonical(folder, run)
            self.assertEqual(validate_canonical(folder)["source_count"], 2)

    def test_diagnostic_stderr_retained_but_not_semantically_parsed(self):
        with self.session(names=("call0001-stdout", "call0001-stderr"),
                          labels=("/:stdout", "/:stderr")) as (folder, run, artifacts):
            build_canonical(folder, run)
            obs = json.loads((folder / "private/system.json").read_text())["observations"]
            derived = [x for x in obs if x["transformation_ids"]]
            self.assertEqual(len([x for x in derived if x["datum_path"] == "storage.fs_stat.snapshot"]), 1)
            stderr_obs = [x for x in obs if x["evidence_refs"] == [artifacts[1].evidence_id]]
            self.assertEqual(len(stderr_obs), 1)
            self.assertFalse(stderr_obs[0]["transformation_ids"])

    def test_zero_counters_not_fabricated_as_health_or_capacity(self):
        obj = dict(FIELDS, blocks=0, free_blocks=0, available_blocks=0,
                   files=0, free_files=0, fragment_size=0)
        result = normalize_sealed_source("SRC-15", encoded(obj),
                                         source_stream="stdout", source_path="/")
        self.assertEqual(result.values[0].normalized_value, obj)
        self.assertEqual([v.datum_path for v in result.values], ["storage.fs_stat.snapshot"])

    def test_invalid_json_duplicate_keys_and_untrusted_constants(self):
        for raw in (b"not-json\n", b'{"mount":"/","mount":"/"}\n',
                    b'{"mount":"/","blocks":NaN}\n', b"", b"{}\n\n",
                    b"\xff\n", b"[]\n"):
            with self.subTest(raw=raw[:40]), self.assertRaises(SourceParseError):
                normalize_sealed_source("SRC-15", raw, source_stream="stdout",
                                        source_path="/")

    def test_missing_extra_and_wrong_type_fields(self):
        for obj in (dict(FIELDS, surprise=1),
                    {k:v for k,v in FIELDS.items() if k != "block_size"},
                    dict(FIELDS, blocks=True), dict(FIELDS, blocks=3.4),
                    dict(FIELDS, blocks="100"), dict(FIELDS, blocks=-1),
                    dict(FIELDS, blocks=2**64),
                    dict(FIELDS, fragment_size=None)):
            with self.subTest(obj=obj), self.assertRaises(SourceParseError):
                normalize_sealed_source("SRC-15", encoded(obj),
                                        source_stream="stdout", source_path="/")

    def test_wrong_stream_path_and_command_attribution(self):
        raw = encoded()
        for kwargs in ({}, {"source_path": "/"}, {"source_stream": "stdout"},
                       {"source_path": "/", "source_stream": "stderr"},
                       {"source_path": "/other", "source_stream": "stdout"},
                       {"source_path": "/", "source_stream": "stdout", "source_command": "python3"},
                       {"source_path": "/", "source_stream": "stdout", "source_target": "/"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(SourceParseError):
                normalize_sealed_source("SRC-15", raw, **kwargs)

    def test_parser_size_and_mount_field_bounds(self):
        for raw in (encoded(dict(FIELDS, mount="/"+"x"*5000)),
                    encoded()+b" "* (1024*1024),
                    encoded().rstrip(b"\n")):
            with self.subTest(size=len(raw)), self.assertRaises(SourceParseError):
                normalize_sealed_source("SRC-15", raw, source_stream="stdout",
                                        source_path="/")

    def test_malformed_json_falls_back_original_and_parse_failed(self):
        with self.session(raw=b"{not json}\n") as (folder, run, artifacts):
            build_canonical(folder, run)
            status=json.loads((folder/"private/status_records.json").read_text())
            src15 = next(s for s in status["status_records"] if s["subject_id"] == "SRC-15")
            self.assertEqual((src15["status"], src15["reason_code"]),
                             ("PARTIAL","PARSE_FAILED"))
            obs=json.loads((folder/"private/system.json").read_text())["observations"]
            self.assertTrue(any(o["evidence_refs"] == [artifacts[0].evidence_id]
                                and not o["transformation_ids"] for o in obs))

    def test_wrong_mount_and_remote_mount_rejected_at_provenance_boundary(self):
        for path in ("/forged", "/mnt/remote"):
            with self.subTest(path=path), self.session(stdout_mount=path) as (folder, run, _):
                with self.assertRaises(CanonicalContractError):
                    build_canonical(folder, run)

    def test_receipt_path_invocation_and_target_attack_rejected(self):
        for case in ({"label_mount":"/forged"},
                     {"labels":()},
                     {"invocation":"statvfs /"},
                     {"target":"/"}):
            with self.subTest(case=case), self.session(**case) as (folder, run, _):
                with self.assertRaises(CanonicalContractError):
                    build_canonical(folder, run)

    def test_wrong_artifact_call_ordinal_and_stream_rejected(self):
        for names, labels in ((("call0002-stdout",),("/:stdout",)),
                              (("item0001",),("/:stdout",)),
                              (("call0001-stderr",),("/:stdout",)),
                              (("call0001-stderr","call0001-stdout"),
                               ("/:stderr","/:stdout"))):
            with self.subTest(names=names), self.session(names=names,labels=labels) as (folder,run,_):
                with self.assertRaises(CanonicalContractError):
                    build_canonical(folder,run)

    def test_missing_upstream_capture_denies_semantic_claim(self):
        with self.session(include_source14=False) as (folder,run,_):
            with self.assertRaises(CanonicalContractError):
                build_canonical(folder,run)

    def test_sealed_original_hash_tamper_blocks_entire_session(self):
        with self.session(corrupt=True) as (folder,run,_):
            with self.assertRaises(CanonicalContractError):
                build_canonical(folder,run)

    def test_partial_capture_precedence(self):
        with self.session(outcome="PARTIAL", reason="CAPTURE_LIMIT",
                          limited=True) as (folder,run,_):
            build_canonical(folder,run)
            status=json.loads((folder/"private/status_records.json").read_text())
            src15 = next(s for s in status["status_records"] if s["subject_id"] == "SRC-15")
            self.assertEqual((src15["status"], src15["reason_code"]),
                             ("PARTIAL","CAPTURE_LIMIT"))

if __name__ == "__main__":
    unittest.main()
