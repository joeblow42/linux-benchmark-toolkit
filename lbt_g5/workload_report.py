"""Generate a combined offline development report from a saved workload session."""
import argparse
import html
import json
import os
from pathlib import Path
import re
import tempfile

from .private_inventory import read_private_inventory
from .workload_assessment import assess

STYLE = """
body{font:16px system-ui,sans-serif;color:#172235;background:#f5f7fa;max-width:72rem;margin:2rem auto;padding:0 1rem}
section{background:#fff;border:1px solid #dbe2ea;padding:1rem;margin:1rem 0;overflow:auto}
table{border-collapse:collapse;width:100%}th,td{text-align:left;border-bottom:1px solid #dbe2ea;padding:.5rem;vertical-align:top}
td{overflow-wrap:anywhere}summary{cursor:pointer}pre{white-space:pre-wrap;overflow-wrap:anywhere}
"""


def table(headers, rows):
    def cells(tag, values):
        return "".join(f"<{tag}>{html.escape(str(value))}</{tag}>" for value in values)
    return ("<table><thead><tr>" + cells("th", headers) + "</tr></thead><tbody>"
            + "".join("<tr>" + cells("td", row) + "</tr>" for row in rows) + "</tbody></table>")


def render(workloads, inventory):
    assessment_rows = []
    measurements = []
    for row in workloads["results"]:
        assessment = assess(row)
        assessment_rows.append(tuple(assessment[key] or "—" for key in (
            "id", "capability", "performance", "reliability", "coverage", "reason", "performance_basis")))
        label = html.escape(row["id"])
        values = html.escape(json.dumps(row["measurements"], indent=2, ensure_ascii=False))
        measurements.append(f"<details><summary>{label}</summary><pre>{values}</pre></details>")
    sources = table(("Source", "Status", "Reason", "Facts"), (
        (item["source_id"], item["status"], item["reason_code"], item["semantic_fact_count"])
        for item in inventory["source_outcomes"]))
    facts = table(("Datum", "Value", "Unit"), (
        (fact["datum_path"], fact["normalized_value"], fact.get("unit") or "—")
        for fact in inventory["facts"]))
    for_action = ("Use demonstrated cases as evidence for keeping or repurposing the system. "
                  "A reproduced integrity failure can support repair. A measured performance shortfall "
                  "can support investigating an upgrade. Retirement needs broader evidence of condition "
                  "and workload suitability.")
    limitations = [*inventory["limitations"], "Assessments apply to the recorded workload and fixture."]
    notices = "".join(f"<li>{html.escape(str(item))}</li>" for item in limitations)
    status = html.escape(workloads["state"])
    inventory_status = html.escape(inventory["completion_state"])
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Linux Benchmark Toolkit report</title><style>{STYLE}</style></head>
<body><h1>Linux Benchmark Toolkit</h1><p>Workload session {status} · Inventory {inventory_status}</p>
<section><h2>Workload assessments</h2>{table(
    ("Workload", "Capability", "Performance", "Reliability", "Coverage", "Outcome", "Threshold"), assessment_rows)}
<p>{for_action}</p></section>
<section><h2>Recorded measurements</h2>{''.join(measurements)}</section>
<section><h2>System inventory</h2>{facts}<details><summary>Acquisition outcomes</summary>{sources}</details></section>
<section><h2>Limitations</h2><ul>{notices}</ul></section>
</body></html>"""


def saved_session(session):
    session = Path(session).resolve(strict=True)
    metadata = session.stat()
    if not session.is_dir() or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
        raise PermissionError("reporting requires an owner-only workload session")
    acquisitions = [item for item in session.iterdir() if re.fullmatch(r"run-\d{13}", item.name)
                    and item.is_dir() and not item.is_symlink()]
    if len(acquisitions) != 1:
        raise ValueError("expected one saved inventory acquisition")
    workloads = json.loads((session / "workloads.json").read_text(encoding="utf-8"))
    if workloads["state"] == "RUNNING":
        raise ValueError("wait for the workload session to finish")
    return session, workloads, read_private_inventory(acquisitions[0])


def publish(session):
    session, workloads, inventory = saved_session(session)
    document = render(workloads, inventory)
    directory = Path(tempfile.mkdtemp(prefix="report-", dir=session))
    pending = directory / ".report.tmp"
    try:
        with pending.open("x", encoding="utf-8") as stream:
            stream.write(document)
            stream.flush()
            os.fsync(stream.fileno())
        return pending.rename(directory / "report.html")
    finally:
        pending.unlink(missing_ok=True)
        if not any(directory.iterdir()):
            directory.rmdir()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("session", type=Path)
    args = parser.parse_args(argv)
    try:
        print(publish(args.session))
    except (OSError, KeyError, ValueError) as error:
        parser.exit(2, f"Workload report: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
