"""Offline, independently regenerable reports for software validation.

validation.json is canonical. The other three formats are generated *only*
from validated canonical JSON, never from live test execution.
"""
import csv
import hashlib
from datetime import datetime, timezone
import html
import io
import json
import os
from pathlib import Path
import re
import tempfile
import uuid

from .requirements import APPROVED_IDS, coverage
from .registry import ValidationRegistry
from .runner import ValidationRun
from .results import ValidationStatus

SCHEMA_VERSION = "1.0.0"
FORMATS = ("validation.json", "validation.csv", "validation.md", "validation.html")
MANIFEST = "validation.manifest.json"
_ID = re.compile(r"^VAL-[A-Z0-9]+(?:-[A-Z0-9]+)*$")
_SAFE_REF = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
# Only these controller-originated messages are permitted in portable reports.
_SAFE_REASONS = (
    re.compile(r"^missing prerequisites: [A-Za-z0-9_,. +:-]+$"),
    re.compile(r"^required validation dependency did not pass$"),
    re.compile(r"^runner is not registered$"),
    re.compile(r"^controlled-impact test not authorized$"),
    re.compile(r"^not applicable in this environment$"),
    re.compile(r"^unit suite timed out \([0-9]+ seconds\)$"),
    re.compile(r"^unit suite exited unsuccessfully \(code -?[0-9]+\)$"),
    re.compile(r"^legacy acceptance check timed out \([0-9]+ seconds\)$"),
    re.compile(r"^legacy acceptance worker returned invalid results$"),
    re.compile(r"^legacy acceptance worker exit/status mismatch$"),
    re.compile(r"^legacy acceptance worker returned unsupported status$"),
    re.compile(r"^Legacy acceptance check failed; see protected diagnostic log$"),
)
_ALLOWED_OVERALL = frozenset(("PASS", "FAIL", "INCOMPLETE"))
_ALLOWED_PROFILES = frozenset(("QUICK", "STANDARD", "FULL"))

_PRIVATE_PATTERNS = (
    re.compile(r"(?i)(?:/home|/media|/mnt|/run/user)/[^\s<>\"']+"),
    re.compile(r"(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}"),
    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    re.compile(r"(?i)\b(?:password|passwd|token|secret|api_key)\s*[:=]\s*[^\s,;]+"),
)


def _safe_label(value: str, maximum: int = 200) -> str:
    if not isinstance(value, str):
        raise ValueError("invalid presentation metadata")
    if len(value) > maximum or any(pattern.search(value) for pattern in _PRIVATE_PATTERNS):
        return "[REDACTED]"
    if any(ord(ch) < 32 for ch in value):
        return "[REDACTED]"
    return value




def _safe_reason(reason: str) -> str:
    """Keep recognized controller diagnostics; never persist arbitrary host text."""
    if not reason:
        return ""
    if len(reason) <= 240 and any(pattern.fullmatch(reason) for pattern in _SAFE_REASONS):
        return reason
    return "Diagnostic detail withheld by default privacy policy"


def _safe_evidence(refs: tuple[str, ...]) -> list[str]:
    return [ref for ref in refs if _SAFE_REF.fullmatch(ref)]


def build_record(run: ValidationRun, registry: ValidationRegistry,
                 *, revision: str = "unrecorded",
                 timestamp: str | None = None, session_id: str | None = None) -> dict:
    """Freeze a redacted, versioned snapshot of one executed validation run."""
    known = {case.validation_id: case for case in registry.all_cases()}
    selected = registry.select(run.profile)
    expected = [case.validation_id for case in selected]
    actual = [result.validation_id for result in run.results]
    if actual != expected:
        raise ValueError("result set does not match selected registry cases")
    rows = []
    for result in run.results:
        case = known[result.validation_id]
        rows.append({
            "validation_id": result.validation_id,
            "title": _safe_label(case.title),
            "phase": case.phase,
            "category": _safe_label(case.category, 60),
            "status": result.status.value,
            "duration_seconds": round(result.duration_seconds, 3),
            "reason": _safe_reason(result.reason),
            "evidence": _safe_evidence(result.evidence),
            "requirement_ids": list(case.requirement_ids),
            "evidence_level": _safe_label(case.evidence_level, 60),
        })
    created = timestamp or datetime.now(timezone.utc).isoformat()
    record = {
        "schema_version": SCHEMA_VERSION,
        "session_id": session_id or ("validation_" + uuid.uuid4().hex),
        "generated_utc": created,
        "toolkit_revision": revision if re.fullmatch(r"[a-f0-9]{7,40}", revision) else "unrecorded",
        "profile": run.profile.name,
        "overall": run.overall,
        "counts": run.counts,
        "registered": len(known),
        "selected": len(rows),
        "out_of_scope": sorted(set(known) - set(actual)),
        "results": rows,
        "requirements_coverage": coverage(rows),
    }
    validate_record(record)
    return record


def validate_record(record: dict) -> None:
    """Reject inconsistent, incomplete, or unsupported canonical data."""
    if not isinstance(record, dict) or record.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported validation report schema")
    if record.get("profile") not in _ALLOWED_PROFILES or record.get("overall") not in _ALLOWED_OVERALL:
        raise ValueError("invalid profile or overall outcome")
    if not isinstance(record.get("session_id"), str) or not re.fullmatch(
            r"validation_[a-zA-Z0-9_-]{1,64}", record["session_id"]):
        raise ValueError("invalid validation session ID")
    if not isinstance(record.get("generated_utc"), str) or not record["generated_utc"]:
        raise ValueError("missing timestamp")
    try:
        parsed_time = datetime.fromisoformat(record["generated_utc"])
        if parsed_time.tzinfo is None:
            raise ValueError("timestamp lacks timezone")
    except (ValueError, TypeError) as error:
        raise ValueError("invalid timestamp") from error
    if not isinstance(record.get("toolkit_revision"), str) or not (
            record["toolkit_revision"] == "unrecorded" or
            re.fullmatch(r"[a-f0-9]{7,40}", record["toolkit_revision"])):
        raise ValueError("invalid toolkit revision")
    rows = record.get("results")
    if not isinstance(rows, list) or not rows:
        raise ValueError("missing validation results")
    counts = {status.value: 0 for status in ValidationStatus}
    seen = set()
    for row in rows:
        if not isinstance(row, dict) or not _ID.fullmatch(str(row.get("validation_id", ""))):
            raise ValueError("invalid validation result ID")
        cid = row["validation_id"]
        if cid in seen:
            raise ValueError("duplicate validation result")
        seen.add(cid)
        if row.get("status") not in counts:
            raise ValueError("invalid validation status")
        counts[row["status"]] += 1
        duration = row.get("duration_seconds")
        if type(duration) not in (int, float) or not 0 <= duration < float("inf"):
            raise ValueError("invalid validation duration")
        if not isinstance(row.get("reason"), str) or len(row["reason"]) > 300:
            raise ValueError("invalid diagnostic reason")
        if row["reason"] and row["reason"] != _safe_reason(row["reason"]) and (
                row["reason"] != "Diagnostic detail withheld by default privacy policy"):
            raise ValueError("unredacted diagnostic reason")
        if not isinstance(row.get("title"), str) or not isinstance(row.get("category"), str):
            raise ValueError("missing case metadata")
        if _safe_label(row["title"]) != row["title"] or (
                _safe_label(row["category"], 60) != row["category"]):
            raise ValueError("privacy-sensitive or oversized case metadata")
        if not isinstance(row.get("evidence_level"), str) or (
                _safe_label(row["evidence_level"], 60) != row["evidence_level"]):
            raise ValueError("invalid evidence level")
        if type(row.get("phase")) is not int or row["phase"] < 1:
            raise ValueError("invalid phase")
        if not isinstance(row.get("requirement_ids"), list) or not isinstance(row.get("evidence"), list):
            raise ValueError("invalid case evidence")
        if any(not isinstance(x, str) or not _SAFE_REF.fullmatch(x) for x in row["evidence"]):
            raise ValueError("invalid evidence reference")
        if len(set(row["evidence"])) != len(row["evidence"]):
            raise ValueError("duplicate evidence references")
        if any(not isinstance(x, str) or x not in APPROVED_IDS for x in row["requirement_ids"]):
            raise ValueError("unknown approved requirement ID")
        if len(set(row["requirement_ids"])) != len(row["requirement_ids"]):
            raise ValueError("duplicate requirement links")
    if record.get("requirements_coverage") != coverage(rows):
        raise ValueError("requirements coverage disagrees with results")
    if record.get("counts") != counts or record.get("selected") != len(rows):
        raise ValueError("validation counts do not match results")
    outside = record.get("out_of_scope")
    if not isinstance(outside, list) or any(
            not isinstance(item, str) or not _ID.fullmatch(item) for item in outside):
        raise ValueError("invalid out-of-scope records")
    if len(set(outside)) != len(outside) or seen.intersection(outside):
        raise ValueError("inconsistent case scope")
    if record.get("registered") != len(rows) + len(outside):
        raise ValueError("registered total does not match scope")
    calculated = ("FAIL" if counts["FAIL"] else
                  "INCOMPLETE" if counts["SKIP"] or counts["BLOCKED"] or
                  counts["NOT_APPLICABLE"] else "PASS")
    if calculated != record["overall"]:
        raise ValueError("overall outcome disagrees with results")


def _csv(record: dict) -> str:
    out = io.StringIO(newline="")
    columns = ("validation_id", "title", "phase", "category", "status",
               "duration_seconds", "reason", "requirement_ids", "evidence_level", "evidence")
    writer = csv.DictWriter(out, fieldnames=columns, lineterminator="\n")
    writer.writeheader()
    for item in record["results"]:
        writer.writerow({k: (";".join(item[k]) if k in ("requirement_ids", "evidence")
                             else item.get(k, "")) for k in columns})
    return out.getvalue()


def _markdown(record: dict) -> str:
    def cell(value: object) -> str:
        return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")
    rows = [
        "# Linux Benchmark Toolkit — Software Validation",
        "", f"Profile: **{record['profile']}**",
        f"Overall: **{record['overall']}**",
        f"Session: `{record['session_id']}`",
        f"Generated (UTC): {record['generated_utc']}",
        "", "## Counts", "",
    ]
    rows += [f"- {status.value}: {record['counts'][status.value]}" for status in ValidationStatus]
    rows += ["", f"Out of scope: {len(record['out_of_scope'])}",
             f"Linked approved requirement IDs: {record['requirements_coverage']['linked']} / 256",
             "Linked tests provide partial evidence, not requirement verification.", "",
             "| Validation ID | Check | Status | Seconds | Explanation |",
             "|---|---|---|---:|---|"]
    for item in record["results"]:
        rows.append("| " + " | ".join(cell(item[key]) for key in (
            "validation_id", "title", "status", "duration_seconds", "reason")) + " |")
    rows += ["", "Software validation is not physical hardware benchmark acceptance.",
             "Tests outside the selected profile are not counted as PASS.", ""]
    return "\n".join(rows)


def _html(record: dict) -> str:
    esc = lambda x: html.escape(str(x), quote=True)
    rows = "".join("<tr>" + "".join(f"<td>{esc(item[key])}</td>" for key in (
        "validation_id", "title", "status", "duration_seconds", "reason")) +
                   "</tr>" for item in record["results"])
    summary = " · ".join(f"{esc(status.value)}: {esc(record['counts'][status.value])}" for status in ValidationStatus)
    style = ("body{font:16px system-ui,sans-serif;max-width:1050px;margin:2rem auto;"
             "padding:0 1rem;color:#182235}table{border-collapse:collapse;width:100%}"
             "td,th{text-align:left;padding:.6rem;border-bottom:1px solid #ddd}"
             "th{background:#eee}caption{text-align:left;font-weight:bold;margin-bottom:1rem}")
    return ('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            '<title>Linux Benchmark Toolkit — Validation</title><style>' + style +
            '</style></head><body><h1>Toolkit Software Validation</h1>'
            f'<p>Session: {esc(record["session_id"])}</p>'
            f'<p>Profile: {esc(record["profile"])} · Overall: '
            f'<strong>{esc(record["overall"])}</strong></p>'
            f'<p>{summary} · Out of scope: {len(record["out_of_scope"])}</p>'
            '<table><caption>Validation checks</caption><thead><tr>'
            '<th>ID</th><th>Check</th><th>Status</th><th>Seconds</th>'
            '<th>Explanation</th></tr></thead><tbody>' + rows + '</tbody></table>'
            '<p>Software validation does not establish physical hardware performance.'
            ' Out-of-scope tests are not PASS.</p></body></html>')


def _atomic_text(path: Path, contents: str) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".validation-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as stream:
            stream.write(contents)
            os.fchmod(stream.fileno(), 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_reports(record: dict, destination: Path, *, regenerate: bool = False) -> tuple[Path, ...]:
    validate_record(record)
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination.chmod(0o700)
    payload = json.dumps(record, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    output = {
        "validation.json": payload,
        "validation.csv": _csv(record),
        "validation.md": _markdown(record),
        "validation.html": _html(record),
    }
    # Report-only must never modify canonical evidence.
    names = FORMATS[1:] if regenerate else FORMATS
    for name in names:
        _atomic_text(destination / name, output[name])
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "session_id": record["session_id"],
        "complete": True,
        "sha256": {
            name: hashlib.sha256((destination / name).read_bytes()).hexdigest()
            for name in FORMATS
        },
    }
    _atomic_text(destination / MANIFEST,
                 json.dumps(manifest, sort_keys=True, indent=2) + "\\n")
    return tuple(destination / name for name in names)


def regenerate_reports(destination: Path) -> tuple[Path, ...]:
    """Read canonical JSON, validate it, regenerate derived formats only."""
    path = Path(destination) / "validation.json"
    record = json.loads(path.read_text(encoding="utf-8"))
    manifest_path = Path(destination) / MANIFEST
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(manifest, dict) or manifest.get("complete") is not True:
            raise ValueError("incomplete validation session manifest")
        expected = manifest.get("sha256", {}).get("validation.json")
        if expected != hashlib.sha256(path.read_bytes()).hexdigest():
            raise ValueError("canonical validation data changed since completion")
        if manifest.get("session_id") != record.get("session_id"):
            raise ValueError("validation session manifest does not match canonical JSON")
    return write_reports(record, Path(destination), regenerate=True)
