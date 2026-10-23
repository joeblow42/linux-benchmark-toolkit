"""Unified software validation, diagnostic evidence, and report regeneration."""
import argparse
from contextlib import nullcontext
from pathlib import Path
import subprocess
import sys
import tempfile

from .adapters import extend_registry
from .profiles import ValidationProfile
from .quick import RUNNERS, quick_registry
from .reporting import build_record, regenerate_reports, write_reports
from .runner import ValidationContext, run_validation


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Unified software validation")
    parser.add_argument("profile", nargs="?", choices=("quick", "standard", "full"))
    parser.add_argument("--output", type=Path, help="Directory for validation reports")
    parser.add_argument("--report-only", type=Path,
                        help="Regenerate derived reports from canonical validation.json")
    options = parser.parse_args(sys.argv[1:] if argv is None else argv)
    if options.report_only is not None:
        if options.profile or options.output:
            parser.error("--report-only cannot be combined with a profile or --output")
        try:
            paths = regenerate_reports(options.report_only)
        except (OSError, ValueError) as error:
            print(f"Validation report regeneration failed: {type(error).__name__}", file=sys.stderr)
            return 2
        print(f"Regenerated: {', '.join(str(p) for p in paths)}")
        return 0
    if not options.profile:
        parser.error("validation profile is required unless --report-only is specified")
    profile = ValidationProfile.parse(options.profile)
    root = Path(__file__).resolve().parents[1]
    registry = quick_registry()
    runners = dict(RUNNERS)
    runners.update(extend_registry(registry, root))
    workspace_manager = (
        tempfile.TemporaryDirectory(prefix="lbt-unified-results-")
        if options.output is None else nullcontext(str(options.output))
    )
    with workspace_manager as workspace:
        report_root = Path(workspace)
        report_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        run = run_validation(registry, profile,
                             ValidationContext(root, report_root), runners)
    for result in run.results:
        print(f"[{result.status.value}] {result.validation_id}"
              + (f" — {result.reason}" if result.reason else ""))
    print(f"Validation {profile.name}: {run.overall} ({run.counts})")
    if options.output is not None:
        try:
            revision = subprocess.run(
                ["git", "rev-parse", "--short=12", "HEAD"], cwd=root,
                capture_output=True, text=True, timeout=3, check=False)
            identifier = revision.stdout.strip() if revision.returncode == 0 else "unrecorded"
            record = build_record(run, registry, revision=identifier)
            paths = write_reports(record, options.output)
        except (OSError, ValueError) as error:
            print(f"Validation report generation failed: {type(error).__name__}",
                  file=sys.stderr)
            return 2
        print(f"Reports: {', '.join(str(p) for p in paths)}")
    return {"PASS": 0, "FAIL": 1, "INCOMPLETE": 3}[run.overall]


if __name__ == "__main__":
    sys.exit(main())
