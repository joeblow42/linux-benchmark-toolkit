"""Generate a combined offline development report from a saved workload session."""
import argparse
import csv
import io
import html
import json
import os
from pathlib import Path
import re
import tempfile

from .private_inventory import read_private_inventory
from .publication_policy import load_policy, public_inventory, public_measurements
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


def render(workloads, inventory, *, private=False):
    assessment_rows = []
    measurements = []
    for row in workloads["results"]:
        assessment = assess(row)
        assessment_rows.append(tuple(assessment[key] or "—" for key in (
            "id", "capability", "performance", "reliability", "coverage", "reason", "performance_basis")))
        label = html.escape(row["id"])
        metrics = row["measurements"] if private else public_measurements(row["measurements"])
        values = html.escape(json.dumps(metrics, indent=2, ensure_ascii=False))
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
    heading = "Private local report" if private else "Publication report"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Linux Benchmark Toolkit report</title><style>{STYLE}</style></head>
<body><h1>Linux Benchmark Toolkit</h1><p>{heading} · Workload session {status} · Inventory {inventory_status}</p>
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


def publish(session, config, *, private=False):
    session, workloads, inventory = saved_session(session)
    policy = load_policy(config)
    if not private:
        inventory = public_inventory(inventory, policy)
    documents = {"report.html": render(workloads, inventory, private=private)}
    outcomes = {}
    assessments = [assess(row) for row in workloads["results"]]
    if not private:
        for output in sorted(policy.outputs):
            if not assessments and not inventory["facts"]:
                outcomes[output] = "NOT_APPLICABLE"
                continue
            if output == "json":
                results = [{"assessment": assessment,
                            "measurements": public_measurements(row["measurements"])}
                           for assessment, row in zip(assessments, workloads["results"])]
                documents["report.json"] = json.dumps(
                    {"version": 1, "inventory": inventory["facts"], "results": results},
                    indent=2, allow_nan=False) + "\n"
            elif assessments:
                stream = io.StringIO(newline="")
                writer = csv.DictWriter(stream, fieldnames=list(assessments[0]))
                writer.writeheader()
                writer.writerows(assessments)
                documents["assessments.csv"] = stream.getvalue()
            else:
                outcomes[output] = "NOT_APPLICABLE"
                continue
            outcomes[output] = "GENERATED"
    documents["publication.json"] = json.dumps({"version": 1, "outputs": outcomes}, indent=2) + "\n"
    directory = Path(tempfile.mkdtemp(prefix="report-", dir=session))
    pending = directory / ".report.tmp"
    try:
        for name, document in documents.items():
            with pending.open("x", encoding="utf-8") as stream:
                stream.write(document)
                stream.flush()
                os.fsync(stream.fileno())
            pending.rename(directory / name)
        return directory / "report.html"
    except BaseException:
        for item in directory.iterdir():
            item.unlink()
        directory.rmdir()
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("session", nargs="?", type=Path)
    parser.add_argument("--config", type=Path, default=Path(__file__).resolve().parents[1] / "config")
    parser.add_argument("--private", action="store_true", help="include private inventory for local use")
    parser.add_argument("--check-config", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.check_config:
            load_policy(args.config)
            print("Publication configuration valid")
        elif args.session:
            print(publish(args.session, args.config, private=args.private))
        else:
            parser.error("provide a saved session or --check-config")
    except (OSError, KeyError, ValueError) as error:
        parser.exit(2, f"Workload report: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
