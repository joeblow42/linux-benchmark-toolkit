"""CP-02 expanded register source-preservation and fail-closed fixtures."""
import csv
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from verification.g5_04 import expand_traceability as generator

SOURCE_FIELDS = ["Requirement_ID"] + [f"Historical_{i:02}" for i in range(1, 20)]


class G504CP02ExpansionContracts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / "Requirements_Rev1_6.csv"
        self.trace = self.root / "trace.csv"
        self.output = self.root / "expanded.csv"
        with self.source.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=SOURCE_FIELDS)
            w.writeheader()
            for kind, maximum in (("FR", 209), ("NFR", 74)):
                for n in range(1, maximum + 1):
                    row = {k: f"verbatim:{k}:{kind}:{n}" for k in SOURCE_FIELDS}
                    row["Requirement_ID"] = f"LBT-{kind}-{n:03d}"
                    w.writerow(row)
        self.hash = hashlib.sha256(self.source.read_bytes()).hexdigest()
        with (generator.ROOT / "requirements_traceability_rev1_6.csv").open(
                newline="", encoding="utf-8") as f:
            fields = None
            source_rows = []
            reader = csv.DictReader(f)
            fields = reader.fieldnames
            for row in reader:
                row["Control_CSV_SHA256"] = self.hash
                source_rows.append(row)
        with self.trace.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            w.writerows(source_rows)

    def test_expanded_preserves_each_original_cell(self):
        before = self.source.read_bytes()
        with patch.object(generator, "EXPECTED_SHA", self.hash):
            self.assertEqual(generator.expand(self.source, self.output,
                                              self.trace), 283)
        self.assertEqual(self.source.read_bytes(), before)
        with self.source.open(newline="", encoding="utf-8") as f:
            originals = list(csv.DictReader(f))
        with self.output.open(newline="", encoding="utf-8") as f:
            expanded = list(csv.DictReader(f))
        self.assertEqual(len(expanded), 283)
        for src, out in zip(originals, expanded):
            self.assertEqual({key: out[key] for key in SOURCE_FIELDS}, src)
            self.assertEqual(out["Verification_State"], "NOT_VERIFIED")

    def test_rejects_wrong_unpinned_baseline(self):
        with self.assertRaises(ValueError):
            generator.expand(self.source, self.output, self.trace)
        self.assertFalse(self.output.exists())

    def test_does_not_overwrite_existing_expanded_output(self):
        self.output.write_bytes(b"old immutable export")
        with patch.object(generator, "EXPECTED_SHA", self.hash):
            with self.assertRaises(FileExistsError):
                generator.expand(self.source, self.output, self.trace)
        self.assertEqual(self.output.read_bytes(), b"old immutable export")

    def test_rejects_trace_that_omits_any_controlled_id(self):
        lines = self.trace.read_text().splitlines()
        self.trace.write_text("\n".join(lines[:-1]) + "\n")
        with patch.object(generator, "EXPECTED_SHA", self.hash):
            with self.assertRaises(ValueError):
                generator.expand(self.source, self.output, self.trace)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
