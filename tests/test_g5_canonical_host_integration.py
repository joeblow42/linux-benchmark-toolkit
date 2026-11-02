"""G5-04 Linux CI-host post-IC-02 manifest integration, no O1 operations."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lbt_g5.canonical_session import validate_canonical
from lbt_g5.host_smoke import main


class G504RealLocalCanonicalIntegration(unittest.TestCase):
    @unittest.skipIf(os.geteuid() == 0, "G4-07 prohibits running the engine as root")
    def test_real_memory_source_then_manifest_uses_single_engine(self):
        with tempfile.TemporaryDirectory() as root:
            with patch("lbt_g5.host_smoke.UnifiedCollectorEngine") as engine_spy:
                # Prevent mock substitution: use the original engine while
                # counting constructions, not another acquisition code path.
                from lbt_g5.engine import UnifiedCollectorEngine
                engine_spy.side_effect = UnifiedCollectorEngine
                exit_code = main(["--output-root", root, "--collectors",
                                  "COL-MEM", "--canonicalize"])
                self.assertEqual(engine_spy.call_count, 1)
            self.assertEqual(exit_code, 0)
            folders = list(Path(root).glob("run-*"))
            self.assertEqual(len(folders), 1)
            manifest = validate_canonical(folders[0])
            self.assertEqual(manifest["attempt_count"], 3)
            self.assertEqual(manifest["schema_version"], "1.0.0")
            self.assertGreaterEqual(manifest["observation_count"], 1)
            self.assertFalse((folders[0] / "public").exists())
            statuses = json.loads((folders[0] / "private/status_records.json").read_text())
            self.assertEqual(len(statuses["status_records"]), 4)


if __name__ == "__main__":
    unittest.main()
