#!/usr/bin/env python3
"""Create standalone offline HTML from versioned canonical session JSON."""
import html
import json
from pathlib import Path
import sys

def load(path, session_id):
    data = json.loads(path.read_text(encoding='utf-8'))
    if data.get('schema_version') != '1.0.0' or data.get('session_id') != session_id:
        raise ValueError(f'invalid schema/session in {path.name}')
    return data

def td(value):
    return '<td>' + html.escape(str(value)) + '</td>'

def render(session):
    identity = session.name
    system = load(session / 'system.json', identity)
    benchmarks = load(session / 'benchmarks.json', identity)
    assessments = load(session / 'assessments.json', identity)
    rows = ''.join('<tr>' + td(t['id']) + td(t['execution_status']) + td(t['summary']) + '</tr>'
                   for t in benchmarks['tests'])
    workloads = ''.join('<tr>' + td(x['name']) + td(x['classification']) +
                        td(x['confidence']) + td(x['reason']) + '</tr>' for x in assessments['workloads'])
    tools = ''.join('<tr>' + td(name) + td('available' if info['available'] else 'missing') + '</tr>'
                    for name, info in sorted(system['tools'].items()))
    host = ''.join('<tr>' + td(key) + td(value) + '</tr>' for key, value in sorted(system['host'].items()))
    style = 'body{font:16px system-ui,Arial,sans-serif;max-width:1050px;margin:32px auto;padding:0 18px;color:#172235;background:#f5f7fa}header,section{background:#fff;border:1px solid #dae0e8;border-radius:10px;padding:20px;margin-bottom:18px}h1{margin:0 0 6px}h2{font-size:1.2rem}table{border-collapse:collapse;width:100%}td,th{text-align:left;border-bottom:1px solid #e5eaf0;padding:9px}th{background:#eef2f8}small{color:#586575}.notice{border-left:4px solid #c78112;padding:12px;background:#fff7e8}'
    document = f'''<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Linux Benchmark — {html.escape(identity)}</title><style>{style}</style></head><body><header><h1>Linux Benchmark Toolkit</h1><small>Phase 1 — Discovery / initial report · Session {html.escape(identity)}</small><p class="notice">Performance benchmarks have not run. All workload suitability ratings remain NOT_TESTED.</p></header><section><h2>System</h2><table><tbody>{host}</tbody></table></section><section><h2>Discovery checks</h2><table><thead><tr><th>Test</th><th>Status</th><th>Summary</th></tr></thead><tbody>{rows}</tbody></table></section><section><h2>Workload suitability</h2><table><thead><tr><th>Workload</th><th>Classification</th><th>Confidence</th><th>Reason</th></tr></thead><tbody>{workloads}</tbody></table></section><section><h2>Dependency availability</h2><table><thead><tr><th>Tool</th><th>Status</th></tr></thead><tbody>{tools}</tbody></table></section><footer><small>Generated from system.json, benchmarks.json and assessments.json. No network or JavaScript required.</small></footer></body></html>'''
    (session / 'report.html').write_text(document, encoding='utf-8')

if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit('usage: generate.py SESSION_DIR')
    render(Path(sys.argv[1]).resolve())
