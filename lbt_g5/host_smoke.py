"""G5-03 controlled Linux host verification of the unified IC-02 engine.

DEVELOPMENT TEST ONLY: not the production launcher, schema or public report.
O1 sources intentionally lack consent and must be DENIED without device access.
No sudo, no active benchmark, no package installation, no network probes.
This test creates private immutable original evidence and private receipts.
"""
import argparse
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from .catalog import initial_catalog
from .engine import UnifiedCollectorEngine


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output-root", default=None,
                        help="existing private directory, or new local directory")
    parser.add_argument("--collectors", default="all",
                        help="comma-separated approved owner IDs, or all")
    opts = parser.parse_args(argv)

    if os.geteuid() == 0:
        parser.error("the G4-07 main engine must not run as root")

    known = {x.collector_id for x in initial_catalog()[0]}
    if opts.collectors == "all":
        selected = None
    else:
        selected = tuple(part.strip() for part in opts.collectors.split(","))
        if not selected or any(s not in known for s in selected):
            parser.error("unknown collector ID")

    output = Path(opts.output_root or "/tmp/lbt-g5-03-host-evidence")
    if not output.is_absolute() or output.is_symlink():
        parser.error("output-root must be an absolute non-symlink path")
    if not output.exists():
        output.mkdir(mode=0o700, parents=False)
    if (not output.is_dir() or os.stat(output).st_uid != os.geteuid()
            or os.stat(output).st_mode & 0o077):
        parser.error("output-root must be owner-owned and mode 0700")

    run_id = datetime.now(timezone.utc).strftime("run-%Y%j%H%M%S")
    folder = output / run_id
    folder.mkdir(mode=0o700, exist_ok=False)
    engine = UnifiedCollectorEngine(str(folder), run_id)
    print("G5-03 IC-02 HOST SMOKE", flush=True)
    print("Run:", run_id, flush=True)
    print("Collector selection:", opts.collectors, flush=True)
    print("Privileged helper: DISABLED", flush=True)

    run = engine.run(selected)
    sources = {}
    items = 0
    byte_count = 0
    for collector in run.collectors:
        for attempt in collector.source_attempts:
            receipt_path = folder / attempt.receipt_private_path
            metadata = json.loads(receipt_path.read_text())
            if (metadata["run_id"] != run_id
                    or metadata["collector_id"] != collector.collector_id):
                raise RuntimeError("attempt owner or run identity mismatch")
            outcome = attempt.outcome
            if isinstance(outcome, dict):
                originals = tuple(outcome.get("receipts", ()))
                state = outcome["disposition"]
                reason = outcome["reason"]
            else:
                originals = tuple(getattr(outcome, "artifacts", ()) or ())
                if hasattr(outcome, "stdout"):
                    originals = tuple(v for v in (outcome.stdout, outcome.stderr)
                                      if v is not None)
                state, reason = outcome.disposition, outcome.reason
            if metadata["evidence_ids"] != [r.evidence_id for r in originals]:
                raise RuntimeError("attempt receipt/evidence mismatch")
            for item in originals:
                evidence_file = folder / item.private_relative_path
                with evidence_file.open("rb") as evidence:
                    original = evidence.read(item.byte_count + 1)
                if (len(original) != item.byte_count
                        or hashlib.sha256(original).hexdigest() != item.sha256):
                    raise RuntimeError("original-evidence digest/size mismatch")
                items += 1
                byte_count += len(original)
            sources.setdefault(metadata["source_id"], []).append(
                (state, reason, len(originals)))
            print("{} {} {} {} artifacts={}".format(
                collector.collector_id, metadata["source_id"],
                state, reason, len(originals)), flush=True)

    print("INTEGRITY: PASS", flush=True)
    print("Source families:", len(sources), flush=True)
    print("Attempt receipts:", run.source_attempt_count, flush=True)
    print("Verified artifacts:", items, flush=True)
    print("Verified original bytes:", byte_count, flush=True)
    print("Original evidence directory:", str(folder), flush=True)
    print("These are transport dispositions, not G5-04 canonical statuses.",
          flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
