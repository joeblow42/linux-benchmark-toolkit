"""IC-03 safe persistence tests: temp directories only, no host collection."""
from copy import deepcopy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from reporting.session_schema import build_system_document, validate_system_document
from reporting.session_store import (
    SessionPersistenceError, build_session_manifest, read_session_manifest,
    write_system_document,
)
from test_session_schema import make_document, make_inventory


class SessionStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="lbt-ic03-")
        self.addCleanup(self.tmp.cleanup)
        self.session = Path(self.tmp.name) / "session_TEST123"
        self.session.mkdir(mode=0o700)
        (self.session / "logs").mkdir(mode=0o700)
        self.document = make_document()

    def test_ic03_t12_successful_write_read_roundtrip(self):
        write_system_document(self.session, self.document)
        target = self.session / "system.json"
        self.assertEqual(json.loads(target.read_text(encoding="utf-8")), self.document)
        validate_system_document(json.loads(target.read_text()), self.session.name)
        self.assertEqual(os.stat(target).st_mode & 0o777, 0o600)
        self.assertTrue(target.read_bytes().endswith(b"\n"))

    def test_ic03_t13_atomic_replace_failure_preserves_prior_v2(self):
        write_system_document(self.session, self.document)
        target = self.session / "system.json"
        before = target.read_bytes()
        updated = deepcopy(self.document)
        updated["host"]["kernel"] = "6.99-test"
        with patch("reporting.session_store.os.replace",
                   side_effect=OSError("test-only simulated rename failure")):
            with self.assertRaises(SessionPersistenceError) as raised:
                write_system_document(self.session, updated)
        self.assertEqual(raised.exception.category, "IO_FAILURE")
        self.assertEqual(target.read_bytes(), before)
        self.assertEqual(list(self.session.glob(".system-json-*.tmp")), [])

    def test_write_failure_before_replace_preserves_existing(self):
        write_system_document(self.session, self.document)
        target = self.session / "system.json"
        before = target.read_bytes()
        with patch("reporting.session_store.tempfile.mkstemp",
                   side_effect=OSError("disk full fixture")):
            with self.assertRaises(SessionPersistenceError):
                write_system_document(self.session, self.document)
        self.assertEqual(target.read_bytes(), before)

    def test_invalid_document_rejected_without_any_write(self):
        bad = deepcopy(self.document)
        bad["schema_version"] = "1.0.0"
        with self.assertRaises(SessionPersistenceError) as raised:
            write_system_document(self.session, bad)
        self.assertEqual(raised.exception.category, "VALIDATION_ERROR")
        self.assertFalse((self.session / "system.json").exists())

    def test_existing_legacy_phase1_system_json_is_protected(self):
        target = self.session / "system.json"
        legacy = b'{"schema_version":"1.0.0","session_id":"session_TEST123"}\n'
        target.write_bytes(legacy)
        with self.assertRaises(SessionPersistenceError) as raised:
            write_system_document(self.session, self.document)
        self.assertEqual(raised.exception.category, "LEGACY_SESSION_PROTECTED")
        self.assertEqual(target.read_bytes(), legacy)

    def test_private_data_rejected_during_write(self):
        bad = deepcopy(self.document)
        bad["discovery"]["collectors"]["system"]["reason"] = "/home/alice/private"
        with self.assertRaises(SessionPersistenceError) as raised:
            write_system_document(self.session, bad)
        self.assertEqual(raised.exception.category, "PRIVACY_REJECTION")
        self.assertFalse((self.session / "system.json").exists())

    def test_session_directory_id_must_match_document(self):
        other = self.session.parent / "session_OTHER"
        other.mkdir(mode=0o700)
        with self.assertRaises(SessionPersistenceError):
            write_system_document(other, self.document)
        self.assertFalse((other / "system.json").exists())

    def test_writer_refuses_session_directory_symlink(self):
        alias = self.session.parent / "session_SYMLINK"
        alias.symlink_to(self.session, target_is_directory=True)
        with self.assertRaises(SessionPersistenceError):
            write_system_document(alias, self.document)

    def test_writer_refuses_canonical_target_symlink(self):
        outside = self.session.parent / "other"
        outside.write_text("do not overwrite")
        (self.session / "system.json").symlink_to(outside)
        with self.assertRaises(SessionPersistenceError):
            write_system_document(self.session, self.document)
        self.assertEqual(outside.read_text(), "do not overwrite")

    def test_ic03_t14_optional_manifest_absent_is_not_failure(self):
        self.assertIsNone(read_session_manifest(self.session))
        partial = build_session_manifest(self.session)
        self.assertEqual(partial["state"], "INCOMPLETE")
        self.assertEqual(partial["files"], {})

    def test_manifest_cannot_claim_complete_without_all_outputs(self):
        write_system_document(self.session, self.document)
        with self.assertRaises(SessionPersistenceError):
            build_session_manifest(self.session, state="COMPLETE")

    def test_manifest_complete_is_hash_based_with_required_files(self):
        write_system_document(self.session, self.document)
        for name in ("benchmarks.json", "assessments.json", "discovery.csv", "report.html"):
            (self.session / name).write_text("{}")
        manifest = build_session_manifest(self.session, state="COMPLETE")
        self.assertEqual(manifest["state"], "COMPLETE")
        self.assertEqual(set(manifest["files"]), {
            "system.json", "benchmarks.json", "assessments.json",
            "discovery.csv", "report.html"})
        self.assertEqual(manifest["files"]["system.json"]["bytes"],
                         (self.session / "system.json").stat().st_size)
        self.assertFalse((self.session / "session.manifest.json").exists())

    def test_manifest_reader_validates_checksums_and_complete_state(self):
        write_system_document(self.session, self.document)
        for name in ("benchmarks.json", "assessments.json", "discovery.csv", "report.html"):
            (self.session / name).write_text("{}")
        manifest = build_session_manifest(self.session, state="COMPLETE")
        path = self.session / "session.manifest.json"
        path.write_text(json.dumps(manifest))
        self.assertEqual(read_session_manifest(self.session), manifest)
        (self.session / "report.html").write_text("changed")
        with self.assertRaises(SessionPersistenceError):
            read_session_manifest(self.session)

    def test_manifest_reader_rejects_fabricated_complete_state(self):
        write_system_document(self.session, self.document)
        model = build_session_manifest(self.session)
        model["state"] = "COMPLETE"
        (self.session / "session.manifest.json").write_text(json.dumps(model))
        with self.assertRaises(SessionPersistenceError):
            read_session_manifest(self.session)

    def test_manifest_incomplete_only_hashes_existing_artifacts(self):
        write_system_document(self.session, self.document)
        record = build_session_manifest(self.session, state="INTERRUPTED")
        self.assertEqual(record["state"], "INTERRUPTED")
        self.assertEqual(set(record["files"]), {"system.json"})

    def test_manifest_refuses_symlink_evidence(self):
        outside = self.session.parent / "outside"
        outside.write_text("secret")
        (self.session / "benchmarks.json").symlink_to(outside)
        with self.assertRaises(SessionPersistenceError):
            build_session_manifest(self.session)

    def test_legacy_v1_session_without_manifest_remains_acceptable(self):
        (self.session / "system.json").write_text('{"schema_version":"1.0.0"}')
        self.assertIsNone(read_session_manifest(self.session))

    def test_ic03_t17_no_benchmark_or_assessment_created(self):
        write_system_document(self.session, self.document)
        self.assertFalse((self.session / "benchmarks.json").exists())
        self.assertFalse((self.session / "assessments.json").exists())
        self.assertFalse((self.session / "discovery.csv").exists())
        self.assertFalse((self.session / "report.html").exists())

    def test_deterministic_json_serialization(self):
        write_system_document(self.session, self.document)
        first = (self.session / "system.json").read_bytes()
        write_system_document(self.session, self.document)
        second = (self.session / "system.json").read_bytes()
        self.assertEqual(first, second)

    def test_manifest_cannot_claim_complete_for_legacy_v1(self):
        (self.session / "system.json").write_text('{"schema_version":"1.0.0"}')
        for name in ("benchmarks.json", "assessments.json", "discovery.csv", "report.html"):
            (self.session / name).write_text("{}")
        with self.assertRaises(SessionPersistenceError):
            build_session_manifest(self.session, state="COMPLETE")


if __name__ == "__main__":
    unittest.main()
