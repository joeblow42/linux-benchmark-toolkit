"""Safe Quick readiness checks used by the unified CLI.

Run from the repository root with: python3 -m validation.quick
The standalone module is retained for compatibility.
"""
from pathlib import Path
import json
import subprocess
import sys
import tempfile

from .requirements import links_for
from .profiles import ValidationProfile
from .registry import ValidationCase, ValidationRegistry
from .runner import CheckOutcome, ValidationContext, run_validation
from .results import ValidationStatus


def _command(args: list[str], *, timeout: float = 10) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                          check=False)


def _launcher(context: ValidationContext) -> None:
    path = context.root / "benchmark"
    if not path.is_file():
        raise AssertionError("benchmark launcher missing")
    result = _command(["bash", "-n", str(path)])
    if result.returncode:
        raise AssertionError("launcher syntax rejected")


def _cli(context: ValidationContext) -> None:
    for args, expected in ((["--help"], "Usage:"), (["--list-tests"], "discovery")):
        result = _command(["bash", str(context.root / "benchmark"), *args])
        if result.returncode or expected not in result.stdout:
            raise AssertionError("CLI smoke check failed: " + " ".join(args))


def _writable(context: ValidationContext) -> None:
    root = context.results_dir
    root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="lbt-quick-", dir=root) as temporary:
        probe = Path(temporary) / "write-check"
        probe.write_text("ok", encoding="utf-8")
        if probe.read_text(encoding="utf-8") != "ok":
            raise AssertionError("results directory readback failed")


def _report_smoke(context: ValidationContext) -> None:
    """Exercise report generation on synthetic legacy schema, not real host data."""
    with tempfile.TemporaryDirectory(prefix="lbt-quick-report-") as td:
        session = Path(td) / "session_quick_fixture"
        session.mkdir()
        common = dict(schema_version="1.0.0", session_id=session.name)
        payloads = {
            "system": dict(common, host={"system": "Linux"}, tools={}),
            "benchmarks": dict(common, tests=[]),
            "assessments": dict(common, workloads=[]),
        }
        for name, value in payloads.items():
            (session / f"{name}.json").write_text(json.dumps(value), encoding="utf-8")
        result = _command([sys.executable, str(context.root / "reporting/generate.py"),
                           str(session)])
        if result.returncode or not (session / "report.html").is_file():
            raise AssertionError("synthetic report smoke test failed")
        if "session_quick_fixture" not in (session / "report.html").read_text():
            raise AssertionError("report missing synthetic session identity")


def quick_registry() -> ValidationRegistry:
    registry = ValidationRegistry()
    specs = (
        ("VAL-P1-LAUNCH-001", "Launcher syntax", "quick:launcher", ()),
        ("VAL-P1-CLI-001", "CLI help and listing", "quick:cli", ("VAL-P1-LAUNCH-001",)),
        ("VAL-P1-OUTPUT-001", "Writable results workspace", "quick:writable", ()),
        ("VAL-P1-REPORT-001", "Synthetic offline report generation",
         "quick:report", ("VAL-P1-LAUNCH-001",)),
    )
    for case_id, title, runner, dependencies in specs:
        registry.register(ValidationCase(
            validation_id=case_id, title=title, phase=1, category="readiness",
            minimum_profile=ValidationProfile.QUICK, runner=runner,
            dependencies=dependencies, requirement_ids=links_for(case_id),
            prerequisites=("bash", "python3") if runner != "quick:writable" else (),
            safety_class="temporary_write" if runner in ("quick:writable", "quick:report")
                         else "read_only",
        ))
    return registry


RUNNERS = {
    "quick:launcher": _launcher,
    "quick:cli": _cli,
    "quick:writable": _writable,
    "quick:report": _report_smoke,
}


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="lbt-quick-output-") as output:
        context = ValidationContext(root=root, results_dir=Path(output))
        run = run_validation(quick_registry(), ValidationProfile.QUICK, context, RUNNERS)
    for result in run.results:
        print(f"[{result.status.value}] {result.validation_id}"
              + (f" — {result.reason}" if result.reason else ""))
    print(f"Quick validation: {run.overall}")
    return {"PASS": 0, "FAIL": 1, "INCOMPLETE": 3}[run.overall]


if __name__ == "__main__":
    sys.exit(main())
