"""Run the owner-authorized CT-11-P1 verification on Bodhi as an ordinary user.

Invoke with python3 -m scripts.rp04_ct11_p1_host_66. Retains private original
bytes, receipts, canonical files, and a verification summary in a 0700 workspace.
"""
import argparse
import hashlib
import json
import os
import platform
import sys
import tempfile
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

import lbt_g5.engine as engine
from lbt_g5.canonical_session import build_canonical, validate_canonical
from lbt_g5.private_inventory import read_private_inventory

SOURCES = ("SRC-08", "SRC-09", "SRC-10")
ATTEMPTS = tuple(f"{source}-01" for source in SOURCES)


def verify(workspace):
    check = TestCase()
    run_id = datetime.now(timezone.utc).strftime("run-%Y%j%H%M%S")
    folder = workspace / run_id
    folder.mkdir(mode=0o700)
    progress = []
    planned_sources = engine.UnifiedCollectorEngine._sources_by_collector()["COL-MEM"]
    check.assertEqual(tuple(source.source_id for source in planned_sources), SOURCES)
    check.assertTrue(all(source.authorization_class == "D0" for source in planned_sources))
    completed = engine.UnifiedCollectorEngine(str(folder), run_id).run(
        ("COL-MEM",), progress=lambda *event: progress.append(event))
    check.assertEqual(progress, [("COL-MEM", source, event) for source in SOURCES
                                 for event in ("START", "END")])
    check.assertEqual(completed.execution.terminal_state, "FINISHED")
    check.assertEqual(completed.execution.planned_attempt_ids, ATTEMPTS)
    check.assertEqual(tuple(c.collector_id for c in completed.collectors), ("COL-MEM",))
    check.assertEqual(completed.source_attempt_count, 3)
    originals = {}
    for source, recorded in zip(SOURCES, completed.collectors[0].source_attempts):
        receipt = recorded.receipt_private_path
        originals[receipt] = (folder / receipt).read_bytes()
        metadata = json.loads(originals[receipt])
        check.assertEqual((metadata["source_id"], metadata["authorization_class"]),
                          (source, "D0"))
        check.assertEqual(metadata["evidence_ids"],
                          [item.evidence_id for item in recorded.outcome.artifacts])
        for item in recorded.outcome.artifacts:
            raw = (folder / item.private_relative_path).read_bytes()
            check.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()),
                              (item.byte_count, item.sha256))
            originals[item.private_relative_path] = raw

    replay = False
    alarms = []

    def deny(label):
        alarms.append(label)
        raise AssertionError(f"Unexpected post-acquisition operation: {label}")

    def observe(event, args):
        if not replay:
            return
        if event == "open" and isinstance(args[0], (str, bytes)):
            path = os.path.abspath(os.fsdecode(args[0]))
            if path in ("/proc", "/sys") or path.startswith(("/proc/", "/sys/")):
                deny(event)
        if event in ("subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.fork"):
            deny(event)

    # The audit hook stays inert outside this replay window. Tests of the
    # prior increment separately exercise fault injection against the producer.
    sys.addaudithook(observe)
    with patch.object(engine.UnifiedCollectorEngine, "run",
                      side_effect=lambda *a, **k: deny("engine.run")), patch.object(
                          engine, "capture_and_record",
                          side_effect=lambda *a, **k: deny("capture_and_record")):
        replay = True
        try:
            manifest = build_canonical(folder, completed)
            check.assertEqual(validate_canonical(folder), manifest)
            inventory = read_private_inventory(folder)
        finally:
            replay = False

    check.assertEqual(alarms, [])
    check.assertTrue(manifest["integrity_verified"])
    check.assertEqual(manifest["source_attempt_ids"], list(ATTEMPTS))
    check.assertEqual(inventory["completion_state"], manifest["completion_state"])
    check.assertTrue(inventory["minimum_usable"])
    outcomes = inventory["source_outcomes"]
    check.assertEqual(tuple(row["source_id"] for row in outcomes), SOURCES)
    complete = all((row["status"], row["reason_code"]) == ("COMPLETE", "OK")
                   for row in outcomes)
    expected = (("COMPLETE", "COMMITTED", "COMPLETE", "ALL_REQUIRED_COMPLETE")
                if complete else ("PARTIAL", "INCOMPLETE", "PARTIAL", "MINIMUM_WITH_GAPS"))
    check.assertEqual(tuple(inventory[key] for key in ("completion_state", "lifecycle_state",
                                                       "orchestration_status", "orchestration_reason")),
                      expected)
    total = [row for row in inventory["facts"] if row["datum_path"] == "memory.meminfo.MemTotal"]
    check.assertEqual(len(total), 1)
    check.assertEqual((total[0]["source_id"], total[0]["unit"]), ("SRC-08", "bytes"))
    check.assertGreater(total[0]["normalized_value"], 0)
    for row in outcomes:
        facts = [fact for fact in inventory["facts"] if fact["source_id"] == row["source_id"]]
        check.assertEqual(len(facts), row["semantic_fact_count"])
        for fact in facts:
            check.assertEqual(set(fact), {"source_id", "supporting_source_ids", "datum_path",
                                          "ordinal", "observed_value", "normalized_value", "value_type",
                                          "unit", "acquisition_status", "acquisition_reason"})
    for path, raw in originals.items():
        check.assertEqual((folder / path).read_bytes(), raw)
    check.assertFalse((folder / "public").exists())
    check.assertEqual((folder / "private").stat().st_mode & 0o077, 0)
    return {
        "case": "CT-11-P1", "result": "PASS", "formal_cp02_execution": False,
        "host": platform.node(), "kernel": platform.release(),
        "architecture": platform.machine(), "python": platform.python_version(),
        "effective_uid": os.geteuid(), "run_id": run_id, "execution": asdict(completed.execution),
        "progress": progress, "completion_state": manifest["completion_state"],
        "manifest_counts": manifest["counts"], "outcomes": outcomes,
        "replay_alarms": alarms,
        "original_sha256": {path: hashlib.sha256(raw).hexdigest() for path, raw in originals.items()},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.parse_args()
    if os.getuid() == 0 or os.geteuid() == 0:
        parser.error("CT-11-P1 requires unprivileged execution")
    bodhi = Path("/etc/bodhi/info")
    if not bodhi.is_file() or 'DESCRIPTION="Bodhi Linux 7.0"' not in bodhi.read_text().splitlines():
        parser.error("CT-11-P1 requires the authorized Bodhi Linux 7 host")
    workspace = Path(tempfile.mkdtemp(prefix="lbt-ct11-p1-66-"))
    print(f"Private evidence workspace: {workspace}", flush=True)
    result = verify(workspace)
    (workspace / "verification.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"CT-11-P1 {result['result']} ({result['completion_state']})")


if __name__ == "__main__":
    main()
