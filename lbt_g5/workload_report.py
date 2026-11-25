"""Generate a combined offline development report from a saved workload session."""
import argparse
import csv
from datetime import datetime, timezone
import io
import html
import json
import os
from pathlib import Path
import re
import tempfile

from .private_inventory import read_private_inventory
from .publication_policy import OUTPUTS, load_policy, public_inventory, public_measurements
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
    inventory = read_private_inventory(acquisitions[0])
    if workloads["state"] in ("FAILED", "INTERRUPTED") or not inventory["minimum_usable"]:
        raise ValueError("saved session has no eligible completed or minimally usable inventory")
    return acquisitions[0], workloads, inventory


def csv_rows(columns, rows):
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(columns)
    for row in rows:
        writer.writerow([("'" + cell if isinstance(cell, str)
                          and (cell.startswith(("\t", "\r", "\n")) or cell.lstrip().startswith(("=", "+", "-", "@")))
                          else cell) for cell in row])
    return stream.getvalue()


def json_text(value):
    return json.dumps(value, indent=2, allow_nan=False) + "\n"


def validation_rows(path):
    from validation.reporting import validate_record

    record = json.loads(path.read_text(encoding="utf-8"))
    validate_record(record)
    columns = ("validation_id", "status", "duration_seconds")
    return columns, [tuple(item[key] for key in columns) for item in record["results"]]


def optional_output(output, workloads, inventory, acquisition):
    assessments = [assess(row) for row in workloads["results"]]
    results = [{"assessment": assessment, "measurements": public_measurements(row["measurements"])}
               for assessment, row in zip(assessments, workloads["results"])]
    if output == "PUB-02":
        return json_text({"schema_version": "1.0", "inventory": inventory["facts"],
                          "inventory_state": inventory["completion_state"], "results": results})
    if output == "PUB-03":
        rows = [(fact["datum_path"], fact["normalized_value"], fact["unit"],
                 fact["publication_state"]) for fact in inventory["facts"]]
        return csv_rows(("datum", "value", "unit", "publication_state"), rows) if rows else None
    if output == "PUB-04":
        rows = [(row["source_id"], row["status"], row["reason_code"], row["semantic_fact_count"])
                for row in inventory["source_outcomes"]]
        return csv_rows(("source", "status", "reason", "facts"), rows) if rows else None
    if output == "PUB-05":
        rows = [(row["id"], row["status"], json.dumps(result["measurements"], allow_nan=False))
                for row, result in zip(workloads["results"], results) if row["measurements"]]
        return csv_rows(("workload", "status", "measurements"), rows) if rows else None
    if output == "PUB-06":
        advice = {"VERIFIED_FOR_TEST_DATA": "Consider keeping or repurposing for the demonstrated case",
                  "INTEGRITY_FAILED": "Investigate the reproduced integrity failure"}
        rows = [(item["id"], advice[item["reliability"]], item["coverage"]) for item in assessments
                if item["reliability"] in advice]
        return csv_rows(("workload", "recommendation", "evidence_qualification"), rows) if rows else None
    validation = acquisition / "validation.json"
    if not validation.is_file() or validation.is_symlink():
        return None
    columns, rows = validation_rows(validation)
    if not rows:
        return None
    if output == "PUB-07":
        return json_text({"schema_version": "1.0", "results": [dict(zip(columns, row)) for row in rows]})
    if output == "PUB-08":
        return csv_rows(columns, rows)
    if output == "PUB-09":
        return '<!doctype html><html lang="en"><meta charset="utf-8"><title>Toolkit validation</title>' + table(columns, rows) + "</html>"
    return "# Toolkit validation\n\n" + "".join(
        f"- {case}: {status} ({duration} s)\n" for case, status, duration in rows)


def write_report(directory, name, contents):
    # Each output commits independently in this invocation's new directory.
    fd, name_pending = tempfile.mkstemp(prefix=".publication-", dir=directory)
    pending = Path(name_pending)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as stream:
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        pending.rename(directory / name)
    finally:
        pending.unlink(missing_ok=True)


def regeneration_directory(acquisition):
    prior = [item.name for item in acquisition.iterdir()
             if re.fullmatch(r"regeneration-\d{2}-\d{13}", item.name)]
    latest = max(prior, key=lambda name: (name[-13:], name[13:15]), default=None)
    sequence = int(latest[13:15]) % 99 + 1 if latest else 1
    stamp = datetime.now(timezone.utc).strftime("%Y%j%H%M%S")
    directory = acquisition / f"regeneration-{sequence:02d}-{stamp}"
    directory.mkdir(mode=0o700)
    return directory


def publish(session, config, *, private=False):
    acquisition, workloads, inventory = saved_session(session)
    policy = load_policy(config)
    if not private:
        inventory = public_inventory(inventory, policy)
    document = render(workloads, inventory, private=private)
    directory = regeneration_directory(acquisition)
    report_name = "private_report.html" if private else OUTPUTS["PUB-01"]
    write_report(directory, report_name, document)
    outcomes = {}
    for output in sorted(policy.outputs if not private else ()):
        try:
            contents = optional_output(output, workloads, inventory, acquisition)
            if contents is None:
                outcomes[output] = "NOT_APPLICABLE"
                continue
            write_report(directory, OUTPUTS[output], contents)
        except (OSError, KeyError, TypeError, ValueError):
            outcomes[output] = "FAILED"
        else:
            outcomes[output] = "GENERATED"
    write_report(directory, "publication.json", json_text({"schema_version": "1.0", "outputs": outcomes}))
    return directory / report_name


def latest_session(root):
    candidates = []
    for session in Path(root).glob("workload-*"):
        if session.is_symlink() or not session.is_dir():
            continue
        for run in session.glob("run-*"):
            if re.fullmatch(r"run-\d{13}", run.name) and run.is_dir() and not run.is_symlink():
                candidates.append((run.name, run.stat().st_mtime_ns, session))
    if not candidates:
        raise ValueError("no saved workload acquisition found")
    return max(candidates)[2]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("session", nargs="?", type=Path)
    selection.add_argument("--latest-under", type=Path, help="select the latest attempted acquisition")
    parser.add_argument("--config", type=Path, default=Path(__file__).resolve().parents[1] / "config")
    parser.add_argument("--private", action="store_true", help="include private inventory for local use")
    parser.add_argument("--check-config", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.check_config:
            load_policy(args.config)
            print("Publication configuration valid")
        elif args.session or args.latest_under:
            session = args.session if args.session else latest_session(args.latest_under)
            print(publish(session, args.config, private=args.private))
        else:
            parser.error("provide a saved session or --check-config")
    except (OSError, KeyError, ValueError) as error:
        parser.exit(2, f"Workload report: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
