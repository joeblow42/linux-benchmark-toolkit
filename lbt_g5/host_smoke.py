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
import time
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path

from .catalog import initial_catalog
from .engine import UnifiedCollectorEngine
from .safety import SourceConsent, SourceRequest
from .privileged_session import PrivilegedHealthSession


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output-root", default=None,
                        help="existing private directory, or new local directory")
    parser.add_argument("--collectors", default="all",
                        help="comma-separated approved owner IDs, or all")
    parser.add_argument("--sudo", action="store_true",
                        help="authenticate once via installed root-owned helper")
    parser.add_argument("--device-health", action="append", default=[],
                        metavar="/dev/sdX",
                        help="explicit SRC-13 SMART/NVMe health target (repeatable)")
    parser.add_argument("--acknowledge-drive-impact", action="store_true",
                        help="consent to queries which may wake selected drives")
    opts = parser.parse_args(argv)
    if opts.device_health and not opts.sudo:
        parser.error("--device-health requires --sudo")
    if opts.device_health and not opts.acknowledge_drive_impact:
        parser.error("--device-health requires --acknowledge-drive-impact")
    if opts.acknowledge_drive_impact and not opts.device_health:
        parser.error("drive-impact consent requires --device-health")
    if len(opts.device_health) != len(set(opts.device_health)):
        parser.error("duplicate drive-health target")
    if len(opts.device_health) > 32:
        parser.error("too many drive-health targets")

    if os.geteuid() == 0:
        parser.error("the G4-07 main engine must not run as root")

    known = {x.collector_id for x in initial_catalog()[0]}
    if opts.collectors == "all":
        selected = None
    else:
        selected = tuple(part.strip() for part in opts.collectors.split(","))
        if not selected or any(s not in known for s in selected):
            parser.error("unknown collector ID")

    if opts.device_health and selected is not None and "COL-BLOCK" not in selected:
        parser.error("--device-health requires COL-BLOCK in collector selection")
    if opts.sudo:
        print("Administrator authentication requested once for this LBT session.",
              flush=True)
    if opts.device_health:
        print("Drive-health consent: selected queries may wake or spin up devices.",
              flush=True)
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
    print("Privileged helper:", "REQUESTED" if opts.sudo else "DISABLED",
          flush=True)

    active = {}
    def show_progress(collector_id, source_id, event):
        key = (collector_id, source_id)
        if event == "START":
            active[key] = time.monotonic()
            print("BEGIN {} {}".format(collector_id, source_id), flush=True)
        else:
            start = active.pop(key, None)
            elapsed = max(0.0, time.monotonic() - start) if start is not None else 0.0
            print("{} {} {} elapsed={:.3f}s".format(
                event, collector_id, source_id, elapsed), flush=True)

    health_requests = ()
    if opts.device_health:
        issued = datetime.now(timezone.utc)
        health_requests = tuple(
            SourceRequest(run_id, "SRC-13", "DEVICE_HEALTH", target=target,
                          consent=SourceConsent(
                              run_id,"SRC-13","DEVICE_HEALTH",target,issued,True))
            for target in opts.device_health)
    with ExitStack() as stack:
        session = (stack.enter_context(PrivilegedHealthSession())
                   if opts.sudo else None)
        if session is not None:
            print("Privileged helper: AUTHENTICATED", flush=True)
        run = engine.run(selected, progress=show_progress,
                         o1_requests=({"SRC-13":health_requests}
                                      if health_requests else None),
                         privileged_session=session)
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
