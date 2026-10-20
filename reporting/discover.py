#!/usr/bin/env python3
"""Read-only, dependency-tolerant Phase 1 discovery; standard library only."""
import csv
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
from datetime import datetime, timezone

SCHEMA = '1.0.0'
TOOLS = ['bash', 'python3', 'dialog', 'lscpu', 'lsblk', 'lspci', 'smartctl',
         'ffmpeg', 'fio', 'iperf3', 'vainfo', 'sensors', 'ddrescue']

def probe(cmd, timeout=5):
    if not shutil.which(cmd[0]):
        return {'status': 'UNAVAILABLE', 'reason': 'command not installed'}
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
            timeout=timeout, check=False, env={**os.environ, 'LC_ALL': 'C'})
        return {'status': 'COMPLETE' if result.returncode == 0 else 'FAILED',
                'exit_code': result.returncode,
                'output': result.stdout[:32000], 'error': result.stderr[:2000]}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {'status': 'FAILED', 'reason': type(exc).__name__}

def save_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n', encoding='utf-8')

def main(session):
    machine = {
        'schema_version': SCHEMA,
        'session_id': session.name,
        'started_utc': datetime.now(timezone.utc).isoformat(),
        'host': {'architecture': platform.machine(),
                 'kernel': platform.release(), 'system': platform.system()},
        'tools': {tool: {'available': bool(shutil.which(tool))} for tool in TOOLS}
    }
    os_release = Path('/etc/os-release')
    if os_release.is_file():
        for line in os_release.read_text(errors='replace').splitlines():
            if line.startswith('PRETTY_NAME='):
                machine['host']['distribution'] = line.partition('=')[2].strip('"')
                break
    checks = [('CPU-INV', ['lscpu']), ('STORAGE-INV', ['lsblk', '-o', 'NAME,TYPE,SIZE,TRAN,ROTA', '-n'])]
    benchmarks = {'schema_version': SCHEMA, 'session_id': session.name, 'mode': 'discovery', 'tests': []}
    for test_id, command in checks:
        outcome = probe(command)
        benchmarks['tests'].append({
            'id': test_id, 'execution_status': outcome['status'], 'command': command,
            'reason': outcome.get('reason', ''), 'exit_code': outcome.get('exit_code'),
            'summary': 'Read-only discovery command executed' if outcome['status'] == 'COMPLETE'
                       else 'Discovery tool unavailable or failed'
        })
        (session / 'logs' / f'{test_id}.txt').write_text(
            outcome.get('output', '') + ('\nSTDERR:\n' + outcome['error'] if outcome.get('error') else ''),
            encoding='utf-8')
    assessments = {'schema_version': SCHEMA, 'session_id': session.name,
        'workloads': [{'name': name, 'classification': 'NOT_TESTED',
                       'confidence': 'INSUFFICIENT_DATA', 'reason': 'Phase 1 discovery only'}
                      for name in ['DVD archival', 'DVD conversion', 'Jellyfin Direct Play',
                                   'Jellyfin transcoding', 'Backup/Samba']]}
    save_json(session / 'system.json', machine)
    save_json(session / 'benchmarks.json', benchmarks)
    save_json(session / 'assessments.json', assessments)
    with (session / 'discovery.csv').open('w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(['session_id', 'test_id', 'execution_status', 'description'])
        for entry in benchmarks['tests']:
            writer.writerow([session.name, entry['id'], entry['execution_status'], entry['summary']])

if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit('usage: discover.py SESSION_DIR')
    directory = Path(sys.argv[1]).resolve()
    if not directory.is_dir():
        sys.exit('session directory does not exist')
    main(directory)
