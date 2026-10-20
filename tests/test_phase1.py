import json
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

class Phase1Test(unittest.TestCase):
    def test_cli_help(self):
        p = subprocess.run(['bash', str(ROOT / 'benchmark'), '--help'], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0)
        self.assertIn('--mode discovery', p.stdout)

    def test_unsupported_mode_is_explicit(self):
        p = subprocess.run(['bash', str(ROOT / 'benchmark'), '--mode', 'standard'],
                           capture_output=True, text=True)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('not implemented', p.stderr)

    def test_discovery_report_and_relocation(self):
        with tempfile.TemporaryDirectory() as temp:
            destination = pathlib.Path(temp) / 'benchmark-results'
            p = subprocess.run(['bash', str(ROOT / 'benchmark'), '--mode', 'discovery',
                                '--results-dir', str(destination)], capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            sessions = list(destination.iterdir())
            self.assertEqual(len(sessions), 1)
            session = sessions[0]
            self.assertTrue((session / 'report.html').exists())
            self.assertTrue((session / 'discovery.csv').exists())
            for name in ('system', 'benchmarks', 'assessments'):
                data = json.loads((session / (name + '.json')).read_text())
                self.assertEqual(data['schema_version'], '1.0.0')
                self.assertEqual(data['session_id'], session.name)
            report = (session / 'report.html').read_text()
            self.assertIn('NOT_TESTED', report)
            self.assertNotIn('https://', report)
            self.assertNotIn('http://', report)
            p = subprocess.run(['bash', str(ROOT / 'benchmark'), '--report-only', str(session)],
                               capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)

if __name__ == '__main__':
    unittest.main()
