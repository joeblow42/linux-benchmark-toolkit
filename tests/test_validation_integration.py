"""Increment 6: launcher integration, compatibility, and distribution contracts."""
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "benchmark"


def invoke(*args: str, timeout: int = 45):
    return subprocess.run(["bash", str(LAUNCHER), *args],
                          cwd=ROOT, capture_output=True, text=True, timeout=timeout)


class LauncherValidationTests(unittest.TestCase):
    def test_help_advertises_validation_separately(self):
        response = invoke("--help")
        self.assertEqual(response.returncode, 0, response.stderr)
        self.assertIn("--validate", response.stdout)
        self.assertIn("--validation-profile", response.stdout)
        self.assertIn("--mode discovery", response.stdout)

    def test_quick_via_launcher_creates_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            response = invoke("--validate", "--validation-profile", "quick",
                              "--results-dir", directory)
            self.assertEqual(response.returncode, 0, response.stderr)
            sessions = list(Path(directory).glob("validation_*"))
            self.assertEqual(len(sessions), 1)
            target = sessions[0]
            expected = ("validation.json", "validation.csv",
                        "validation.md", "validation.html")
            self.assertTrue(all((target / name).is_file() for name in expected))
            record = json.loads((target / "validation.json").read_text())
            self.assertEqual(record["profile"], "QUICK")
            self.assertEqual(record["counts"]["PASS"], 4)
            before = (target / "validation.json").read_bytes()
            replay = invoke("--validation-report-only", str(target))
            self.assertEqual(replay.returncode, 0, replay.stderr)
            self.assertEqual(before, (target / "validation.json").read_bytes())

    def test_rejects_mode_conflicts_and_bad_profile(self):
        for arguments in (
            ("--validate", "--mode", "discovery"),
            ("--validation-profile", "full"),
            ("--validate", "--validation-profile", "invalid"),
            ("--validate", "--validation-report-only", "/tmp/missing"),
        ):
            with self.subTest(arguments=arguments):
                response = invoke(*arguments)
                self.assertEqual(response.returncode, 2,
                                 f"{arguments}: {response.stdout} {response.stderr}")

    def test_original_legacy_mode_remains_unsupported(self):
        response = invoke("--mode", "standard")
        self.assertEqual(response.returncode, 2)
        self.assertIn("not implemented", response.stderr)

    def test_packaging_configuration_contains_validation(self):
        script = (ROOT / "packaging/build.sh").read_text(encoding="utf-8")
        # Archive integrity and contents are exercised separately by the
        # original Phase 1 acceptance suite, avoiding a redundant build here.
        self.assertIn('"$ROOT/validation"', script)


if __name__ == "__main__":
    unittest.main()
