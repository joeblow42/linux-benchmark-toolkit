"""Expand pinned CP-02 trace IDs with the untouched 20-column Rev 1.6 control.

Usage:
  python3 verification/g5_04/expand_traceability.py \
    --baseline /path/to/Requirements_Rev1_6.csv \
    --output /path/to/CP02_cumulative_expanded.csv

Requires the ORIGINAL approved CSV; does not alter it or infer any missing
authority. All original 20 source columns are written unchanged and in source
order, followed by the cumulative CP-02 verification columns. Refuses to
overwrite an existing destination.
"""
import argparse
import csv
import hashlib
import os
from pathlib import Path
import tempfile

EXPECTED_SHA = "04849cd13ecc75c803839ab7c59a1015c5b92d1f05bf31422b54406c188e2702"
ID = "Requirement_ID"
ROOT = Path(__file__).resolve().parent


def load_rows(path):
    with open(path, encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        fields = reader.fieldnames
        if not fields or len(fields) != len(set(fields)) or ID not in fields:
            raise ValueError("invalid source column contract")
        rows = list(reader)
        if any(None in row or None in row.values() for row in rows):
            raise ValueError("malformed CSV row")
        return fields, rows


def expand(baseline_path, output_path, trace_path=None):
    baseline_path = Path(baseline_path)
    output_path = Path(output_path)
    trace_path = Path(trace_path) if trace_path else ROOT / "requirements_traceability_rev1_6.csv"
    checksum = hashlib.sha256(baseline_path.read_bytes()).hexdigest()
    if checksum != EXPECTED_SHA:
        raise ValueError("Requirements Rev 1.6 source checksum differs from approved control")
    original_fields, originals = load_rows(baseline_path)
    if len(original_fields) != 20 or len(originals) != 283:
        raise ValueError("original 20-column / 283-row invariant violated")
    trace_fields, traces = load_rows(trace_path)
    if len(traces) != 283 or set(original_fields) & (set(trace_fields) - {ID}):
        raise ValueError("trace shape collides with approved baseline columns")
    lookup = {r[ID]: r for r in traces}
    if len(lookup) != 283 or {x[ID] for x in originals} != set(lookup):
        raise ValueError("trace/requirements ID mismatch")
    if any(t["Control_CSV_SHA256"] != EXPECTED_SHA for t in traces):
        raise ValueError("trace control checksum mismatch")
    if output_path.exists():
        raise FileExistsError("refusing overwrite of existing trace output")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fields = original_fields + [k for k in trace_fields if k != ID]
    # EXCL guards existing final artifact; no in-place mutation.
    fd = os.open(output_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as out:
            writer = csv.DictWriter(out, fieldnames=fields, lineterminator="\n")
            writer.writeheader()
            for row in originals:
                writer.writerow({**row, **{k: v for k, v in lookup[row[ID]].items()
                                           if k != ID}})
            out.flush()
            os.fsync(out.fileno())
    except BaseException:
        try:
            output_path.unlink()
        except FileNotFoundError:
            pass
        raise
    expanded_fields, expanded = load_rows(output_path)
    if len(expanded) != len(originals) or expanded_fields[:20] != original_fields:
        raise ValueError("expanded source columns/row count mismatch")
    for source, written in zip(originals, expanded):
        if any(source[col] != written[col] for col in original_fields):
            raise ValueError("original requirement content was changed")
    return len(expanded)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--baseline", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--trace", default=None)
    opts = p.parse_args()
    print("EXPANDED_TRACE_ROWS=" + str(expand(opts.baseline, opts.output, opts.trace)))
    print("SOURCE_SHA256=" + EXPECTED_SHA)


if __name__ == "__main__":
    main()
