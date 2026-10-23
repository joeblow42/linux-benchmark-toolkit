"""End-to-end development CLI reporting and report-only regeneration tests."""
from pathlib import Path
import json
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ReportingCliTests(unittest.TestCase):
    def test_quick_output_and_report_only_preserve_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            session = Path(directory)
            command = [sys.executable, "-m", "validation.suites"]
            first = subprocess.run(command + ["quick", "--output", str(session)],
                                   cwd=ROOT, capture_output=True, text=True, timeout=45)
            self.assertEqual(first.returncode, 0, first.stderr)
            names = ("validation.json", "validation.csv", "validation.md", "validation.html")
            self.assertTrue(all((session / name).is_file() for name in names))
            record = json.loads((session / "validation.json").read_text())
            self.assertEqual(record["profile"], "QUICK")
            self.assertEqual(record["overall"], "PASS")
            self.assertEqual(record["counts"]["PASS"], 4)
            baseline = {name: (session / name).read_bytes() for name in names}
            report = subprocess.run(command + ["--report-only", str(session)],
                                    cwd=ROOT, capture_output=True, text=True, timeout=15)
            self.assertEqual(report.returncode, 0, report.stderr)
            self.assertEqual(baseline,
                             {name: (session / name).read_bytes() for name in names})

    def test_corrupted_canonical_rejected_by_development_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            session = Path(directory)
            session.joinpath("validation.json").write_text('{"schema_version":"wrong"}')
            report = subprocess.run(
                [sys.executable, "-m", "validation.suites", "--report-only", str(session)],
                cwd=ROOT, capture_output=True, text=True, timeout=15)
            self.assertEqual(report.returncode, 2)


if __name__ == "__main__":
    unittest.main()
