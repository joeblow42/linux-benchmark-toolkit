#!/usr/bin/env python3
"""Offline, unprivileged Phase 1 acceptance suite. All test data is temporary."""
import argparse
import csv
import hashlib
import html
import json
import os
from pathlib import Path
import pty
import select
import shutil
import signal
import struct
import subprocess
import sys
import tarfile
import tempfile
import termios
import time
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
CHECKS = []


class SkipCheck(Exception):
    pass


def check(name):
    def decorator(fn):
        CHECKS.append((name, fn))
        return fn
    return decorator


def run(args, cwd=None, timeout=30):
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True,
                          timeout=timeout, check=False)


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def discover(root, where):
    p = run(['bash', str(root / 'benchmark'), '--mode', 'discovery',
             '--results-dir', str(where)], timeout=45)
    require(p.returncode == 0, 'discovery: ' + p.stderr.strip())
    sessions = list(where.glob('session_*'))
    require(len(sessions) == 1, 'discovery session count differs from one')
    session = sessions[0]
    for name in ['system.json', 'benchmarks.json', 'assessments.json',
                 'discovery.csv', 'report.html']:
        require((session / name).is_file(), 'missing ' + name)
    return session


def bundle(root, work):
    session = discover(root, work / 'results')
    data = {}
    for name in ('system', 'benchmarks', 'assessments'):
        data[name] = json.loads((session / (name + '.json')).read_text())
        require(data[name].get('schema_version') == '1.0.0', 'schema mismatch')
        require(data[name].get('session_id') == session.name, 'session mismatch')
    return session, data


@check('Bash syntax')
def bash_syntax(root, work):
    files = [root / 'benchmark']
    for folder in ('lib', 'tui', 'packaging', 'tests'):
        files += sorted((root / folder).glob('*.sh'))
    require(all(p.is_file() for p in files), 'required shell script missing')
    p = run(['bash', '-n', *map(str, files)])
    require(p.returncode == 0, p.stderr)


@check('Python unit tests')
def unit_tests(root, work):
    p = run([sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-v'], cwd=root, timeout=50)
    require(p.returncode == 0, p.stderr)


@check('CLI help, modes and dependencies')
def cli_checks(root, work):
    for args, expected in [(['--help'], '--mode discovery'),
                           (['--list-tests'], 'discovery'),
                           (['--check-deps'], 'python3')]:
        p = run(['bash', str(root / 'benchmark'), *args])
        require(p.returncode == 0 and expected in p.stdout, str(args) + ': ' + p.stderr)


@check('Invalid CLI options and missing values')
def invalid_cli(root, work):
    for args, expected in [(['--invalid-option'], 'Unknown argument'),
                           (['--mode'], 'Missing'),
                           (['--results-dir'], 'Missing'),
                           (['--report-only'], 'Missing')]:
        p = run(['bash', str(root / 'benchmark'), *args])
        require(p.returncode == 2 and expected.lower() in p.stderr.lower(),
                str(args) + ': unexpected error/exit code')


@check('Unavailable Standard and Extended modes')
def unavailable_modes(root, work):
    for mode in ('standard', 'extended'):
        p = run(['bash', str(root / 'benchmark'), '--mode', mode])
        require(p.returncode == 2 and 'not implemented' in p.stderr.lower(), mode + ': unexpected result')


@check('Unwritable results path')
def unwritable_results(root, work):
    if not Path('/proc').is_dir():
        raise SkipCheck('Linux /proc unavailable')
    dest = '/proc/lbt-phase1-test-' + str(os.getpid())
    p = run(['bash', str(root / 'benchmark'), '--mode', 'discovery', '--results-dir', dest])
    require(p.returncode != 0 and not Path(dest).exists(), 'wrote to /proc or failed to reject it')


@check('Missing report session')
def missing_report(root, work):
    p = run(['bash', str(root / 'benchmark'), '--report-only', str(work / 'missing')])
    require(p.returncode == 2 and 'Missing' in p.stderr, 'missing session accepted')


@check('JSON schema and workload status')
def json_check(root, work):
    session, data = bundle(root, work)
    require(data['host'] if 'host' in data else data['system']['host'], 'host details missing')
    require(data['benchmarks']['mode'] == 'discovery', 'incorrect mode')
    records = data['benchmarks']['tests']
    require({r['id'] for r in records} == {'CPU-INV', 'STORAGE-INV'}, 'unexpected inventory IDs')
    require(all(r['execution_status'] in ('COMPLETE', 'UNAVAILABLE', 'FAILED') for r in records), 'unknown status')
    require(all(x['classification'] == 'NOT_TESTED' for x in data['assessments']['workloads']), 'invented rating')
    require((session / 'logs').is_dir(), 'missing logs')


@check('CSV and JSON consistency')
def csv_check(root, work):
    session, data = bundle(root, work)
    with (session / 'discovery.csv').open(newline='', encoding='utf-8') as fh:
        reader = csv.DictReader(fh)
        require(reader.fieldnames == ['session_id', 'test_id', 'execution_status', 'description'],
                'CSV headers mismatch')
        rows = list(reader)
    records = {r['id']: r for r in data['benchmarks']['tests']}
    require(len(rows) == len(records), 'CSV count mismatch')
    for row in rows:
        require(row['session_id'] == session.name, 'CSV session mismatch')
        require(row['test_id'] in records, 'CSV ID mismatch')
        require(row['execution_status'] == records[row['test_id']]['execution_status'], 'CSV status mismatch')


@check('Offline HTML and report regeneration')
def html_check(root, work):
    session, data = bundle(root, work)
    report = session / 'report.html'
    original = report.read_bytes()
    require(original.startswith(b'<!DOCTYPE html>') and b'NOT_TESTED' in original, 'invalid HTML')
    require(b'https://' not in original and b'http://' not in original, 'external dependency in HTML')
    report.unlink()
    p = run(['bash', str(root / 'benchmark'), '--report-only', str(session)])
    require(p.returncode == 0 and report.read_bytes() == original, 'regeneration differs')


@check('Corrupted report data is rejected')
def corrupt_report(root, work):
    session, data = bundle(root, work)
    path = session / 'benchmarks.json'
    contents = json.loads(path.read_text())
    contents['session_id'] = 'mismatched-session'
    path.write_text(json.dumps(contents))
    p = run(['bash', str(root / 'benchmark'), '--report-only', str(session)])
    require(p.returncode != 0, 'accepted a mismatched session identifier')


@check('Archive contents and SHA-256')
def archive_check(root, work):
    if not shutil.which('tar') or not shutil.which('sha256sum'):
        raise SkipCheck('tar/sha256sum not installed')
    dest = work / 'dist'
    p = run(['bash', str(root / 'packaging/build.sh'), str(dest)], timeout=45)
    require(p.returncode == 0, p.stderr)
    archives = list(dest.glob('*.tar.gz'))
    require(len(archives) == 1, 'archive count mismatch')
    archive = archives[0]
    checksum = Path(str(archive) + '.sha256')
    require(checksum.is_file(), 'checksum manifest missing')
    digest, filename = checksum.read_text().split()[:2]
    require(filename == archive.name, 'checksum filename mismatch')
    require(hashlib.sha256(archive.read_bytes()).hexdigest() == digest, 'checksum mismatch')
    with tarfile.open(archive, 'r:gz') as fh:
        names = set(fh.getnames())
    for name in ('benchmark', 'reporting/generate.py', 'tests/acceptance-phase1.sh',
                 'tests/acceptance_phase1.py'):
        require('linux-benchmark-toolkit/' + name in names, 'archive missing ' + name)


def copy_toolkit(root, work):
    dest = work / 'relocated' / 'linux-benchmark-toolkit'
    shutil.copytree(root, dest, ignore=lambda directory, names:
        {name for name in names if name in ('results', 'dist', 'acceptance-results',
                                           '.git', '__pycache__', '.pytest_cache')})
    return dest


@check('Relocated directory execution')
def relocation(root, work):
    dest = copy_toolkit(root, work)
    session = discover(dest, work / 'outside-results')
    require((session / 'report.html').is_file(), 'relocated report missing')
    require(not (dest / 'results').exists(), 'unexpected in-tree results')


@check('Read-only source with external results')
def readonly(root, work):
    dest = copy_toolkit(root, work)
    for item in dest.rglob('*'):
        if item.is_file() or item.is_dir():
            item.chmod(item.stat().st_mode & ~0o222)
    dest.chmod(dest.stat().st_mode & ~0o222)
    session = discover(dest, work / 'outside-results')
    require((session / 'report.html').is_file(), 'read-only execution failed')
    require(not (dest / 'results').exists(), 'wrote results inside read-only source')


@check('Dialog pseudo-terminal Escape cancellation')
def dialog_cancel(root, work):
    if not shutil.which('dialog'):
        raise SkipCheck('dialog not installed; test on Bodhi or CI runner')
    master, slave = pty.openpty()
    proc = None
    try:
        import fcntl
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 28, 110, 0, 0))
        env = dict(os.environ, TERM='xterm', LBT_RESULTS_DIR=str(work / 'never-created'))
        proc = subprocess.Popen(['bash', str(root / 'benchmark')],
                                stdin=slave, stdout=slave, stderr=slave, env=env,
                                start_new_session=True)
        os.close(slave)
        slave = -1
        stream = b''
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline and proc.poll() is None:
            ready, _, _ = select.select([master], [], [], 0.2)
            if ready:
                try:
                    chunk = os.read(master, 8192)
                except OSError:
                    break
                if not chunk:
                    break
                stream += chunk
                if b'Discovery' in stream or b'Standard' in stream:
                    break
        require(proc.poll() is None, 'Dialog exited prematurely')
        require(b'Discovery' in stream or b'Standard' in stream, 'Dialog menu not observed')
        os.write(master, b'\x1b')
        try:
            rc = proc.wait(timeout=6)
        except subprocess.TimeoutExpired:
            raise AssertionError('Dialog did not exit on Escape')
        require(rc == 0, 'Dialog cancellation returned ' + str(rc))
        require(not (work / 'never-created').exists(), 'cancellation launched a benchmark')
    finally:
        if proc and proc.poll() is None:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait(timeout=3)
        os.close(master)
        if slave >= 0:
            os.close(slave)


def main():
    parser = argparse.ArgumentParser(description='Phase 1 offline acceptance')
    parser.add_argument('--output', type=Path, help='Report directory; default is acceptance-results/<UTC time>')
    options = parser.parse_args()
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    destination = (options.output or ROOT / 'acceptance-results' / stamp).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    results = []
    with tempfile.TemporaryDirectory(prefix='lbt-acceptance-') as temporary:
        for number, (name, test) in enumerate(CHECKS, 1):
            workspace = Path(temporary) / f'test-{number:02d}'
            workspace.mkdir()
            start = time.monotonic()
            try:
                test(ROOT, workspace)
                status, detail = 'PASS', ''
            except SkipCheck as error:
                status, detail = 'SKIP', str(error)
            except Exception as error:
                status, detail = 'FAIL', f'{type(error).__name__}: {error}'
            results.append({'test': name, 'status': status, 'detail': detail,
                            'seconds': round(time.monotonic() - start, 3)})
            print(f'[{status}] {name}' + (f' — {detail}' if detail else ''), flush=True)
    counts = {status: sum(x['status'] == status for x in results)
              for status in ('PASS', 'FAIL', 'SKIP')}
    overall = 'FAIL' if counts['FAIL'] else ('INCOMPLETE' if counts['SKIP'] else 'PASS')
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = {'suite': 'Phase 1 acceptance', 'schema_version': '1.0.0',
               'generated_utc': timestamp, 'overall': overall, 'counts': counts,
               'tests': results}
    (destination / 'acceptance.json').write_text(json.dumps(payload, indent=2) + '\n')
    with (destination / 'acceptance.csv').open('w', newline='', encoding='utf-8') as fh:
        writer = csv.DictWriter(fh, fieldnames=['test', 'status', 'detail', 'seconds'])
        writer.writeheader()
        writer.writerows(results)
    rows_md = ['# Phase 1 Acceptance', '', 'Overall: **' + overall + '**',
               '', f'PASS {counts["PASS"]} / FAIL {counts["FAIL"]} / SKIP {counts["SKIP"]}',
               '', '| Test | Status | Detail |', '|---|---|---|']
    for item in results:
        rows_md.append('| ' + item['test'] + ' | ' + item['status'] + ' | ' +
                       item['detail'].replace('|', '\\|').replace('\n', ' ') + ' |')
    rows_md.extend(['', 'SKIP is not PASS; interactive visual usability and physical-device workloads require separate evidence.'])
    (destination / 'acceptance.md').write_text('\n'.join(rows_md) + '\n')
    rows_html = ''.join('<tr><td>' + html.escape(x['test']) + '</td><td>' +
                        html.escape(x['status']) + '</td><td>' +
                        html.escape(x['detail']) + '</td><td>' + str(x['seconds']) +
                        '</td></tr>' for x in results)
    style = ('body{font:16px system-ui,sans-serif;max-width:1100px;margin:32px auto;padding:0 18px;'
             'background:#f5f7fa;color:#182235}header,section{background:white;border:1px solid #dae0e8;'
             'border-radius:9px;padding:20px;margin-bottom:18px}table{border-collapse:collapse;width:100%}'
             'th,td{border-bottom:1px solid #e4e9ef;text-align:left;padding:9px}th{background:#eef2f8}')
    page = ('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>Phase 1 Acceptance</title><style>' + style + '</style></head><body>'
            '<header><h1>Linux Benchmark Toolkit — Phase 1 Acceptance</h1><p>Overall: <strong>' +
            overall + '</strong> · PASS ' + str(counts['PASS']) + ' · FAIL ' +
            str(counts['FAIL']) + ' · SKIP ' + str(counts['SKIP']) + '</p><small>' +
            html.escape(timestamp) + '</small></header><section><table><thead><tr>'
            '<th>Test</th><th>Status</th><th>Detail</th><th>Seconds</th></tr></thead><tbody>' +
            rows_html + '</tbody></table></section><p>Skipped tests do not constitute acceptance. '
            'Hardware performance and visual usability need separate evidence.</p></body></html>')
    (destination / 'acceptance.html').write_text(page)
    print(f'\nOverall: {overall} — PASS={counts["PASS"]} FAIL={counts["FAIL"]} SKIP={counts["SKIP"]}')
    print(f'Reports: {destination}/acceptance.html, acceptance.md, acceptance.json, acceptance.csv')
    return 0 if overall == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
