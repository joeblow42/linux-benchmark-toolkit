"""CT-11-N1 offline candidate: no second source acquisition while canonicalizing.

Uses sealed SRC-02 original and receipt from a disposable fixture. Test-only
tripwires detect mistaken /proc, /sys, command, or collector access. No host
probe, production guard, formal CP-02 case execution or FAT acceptance.
"""
import builtins
from contextlib import ExitStack, contextmanager
import hashlib
import io
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import lbt_g5.canonical_session as canonical
from lbt_g5.engine import CollectorRun, EngineRun, UnifiedCollectorEngine
from lbt_g5.evidence import EvidenceWriter
from lbt_g5.private_inventory import read_private_inventory
from lbt_g5.records import build_attempt, commit_attempt
from lbt_g5.safety import initial_source_policies

RUN = "run-2026320223348"
RAW = b"ID=bodhi\nNAME=Bodhi\n"


class DuplicateAcquisition(AssertionError):
    pass


def is_source(path):
    try:
        value = os.fsdecode(path)
    except (TypeError, ValueError):
        return False
    return any(value == p or value.startswith(p + "/")
               for p in ("/proc", "/sys"))


class CT11N1Candidate65(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.folder = Path(temp.name) / RUN
        self.folder.mkdir(mode=0o700)
        writer = EvidenceWriter(str(self.folder), RUN)
        policy = {p.source_id: p for p in initial_source_policies()}["SRC-02"]
        original = writer.seal_chunks(
            policy, "01", "item0001", (RAW,)).receipt
        self.assertIsNotNone(original)
        receipt = build_attempt(
            RUN, "SRC-02", "01", "ALLOW", "CAPTURED", "BYTES_PRESERVED",
            evidence=(original,), bytes_count=original.byte_count)
        receipt_path = commit_attempt(str(self.folder), receipt)
        record = SimpleNamespace(
            receipt_private_path=receipt_path,
            outcome=SimpleNamespace(artifacts=(original,)))
        self.run = EngineRun(RUN, (CollectorRun("COL-OS", (record,)),))
        self.originals = {
            receipt_path: (self.folder / receipt_path).read_bytes(),
            original.private_relative_path:
                (self.folder / original.private_relative_path).read_bytes(),
        }

    def assert_originals_unchanged(self):
        for path, content in self.originals.items():
            actual = (self.folder / path).read_bytes()
            self.assertEqual(actual, content)
            self.assertEqual(hashlib.sha256(actual).digest(),
                             hashlib.sha256(content).digest())

    @contextmanager
    def trap_reacquisition(self, alarms):
        def guarded(label, original):
            def check(path, *args, **kwargs):
                if is_source(path):
                    alarms.append(label)
                    raise DuplicateAcquisition("second host source access: " + label)
                return original(path, *args, **kwargs)
            return check

        def deny(label):
            def reject(*args, **kwargs):
                alarms.append(label)
                raise DuplicateAcquisition("second source dispatch: " + label)
            return reject

        with ExitStack() as stack:
            stack.enter_context(patch.object(
                Path, "open", new=guarded("pathlib.Path.open", Path.open)))
            for module, names in (
                    (os, ("open", "listdir", "scandir", "stat", "lstat", "readlink")),
                    (builtins, ("open",)), (io, ("open",))):
                for name in names:
                    stack.enter_context(patch.object(
                        module, name, new=guarded(
                            module.__name__ + "." + name,
                            getattr(module, name))))
            for name in ("run", "Popen", "check_output", "check_call"):
                stack.enter_context(patch.object(
                    subprocess, name, new=deny("subprocess." + name)))
            stack.enter_context(patch.object(
                UnifiedCollectorEngine, "run", new=deny("engine.run")))
            yield

    def test_65_01_CT_11_N1_actual_canonical_private_replay_no_acquisition(self):
        alarms = []
        with self.trap_reacquisition(alarms):
            manifest = canonical.build_canonical(self.folder, self.run)
            self.assertEqual(canonical.validate_canonical(self.folder), manifest)
            inventory = read_private_inventory(self.folder)
        self.assertEqual(alarms, [])
        self.assertTrue(manifest["integrity_verified"])
        self.assertEqual(manifest["counts"]["attempts"], 1)
        self.assertEqual(inventory["sealed_original_artifact_count"], 1)
        self.assertIn("os.release.ID",
                      {row["datum_path"] for row in inventory["facts"]})
        self.assert_originals_unchanged()
        self.assertFalse((self.folder / "public").exists())

    def test_65_02_CT_11_N1_injected_duplicate_source_is_detected(self):
        render = canonical._render
        # Faults are introduced into the real canonicalizer call chain.
        # Tripwires abort *before* executing any host access or collector.
        injections = {
            "proc": lambda: os.open("/proc/meminfo", os.O_RDONLY),
            "sys": lambda: Path("/sys/devices/system/cpu/online").read_bytes(),
            "command": lambda: subprocess.run(("uname",), check=True),
            "collector": lambda: UnifiedCollectorEngine.run(None, ("COL-OS",)),
        }
        for label, trigger in injections.items():
            alarms = []

            def injected_render(obj, action=trigger):
                action()
                return render(obj)

            with self.subTest(label=label), patch.object(
                    canonical, "_render", side_effect=injected_render):
                with self.trap_reacquisition(alarms):
                    with self.assertRaises(DuplicateAcquisition):
                        canonical.build_canonical(self.folder, self.run)
                self.assertEqual(len(alarms), 1)
                self.assert_originals_unchanged()
                self.assertFalse(
                    (self.folder / "private/session_manifest.json").exists())


if __name__ == "__main__":
    unittest.main()
