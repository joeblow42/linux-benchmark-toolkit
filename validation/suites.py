"""Development entry point for legacy suites under the unified controller.

Not the final --validate CLI or the full structured reporting integration.
"""
from pathlib import Path
import sys
import tempfile

from .adapters import extend_registry
from .profiles import ValidationProfile
from .quick import RUNNERS, quick_registry
from .runner import ValidationContext, run_validation


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1 or args[0].lower() not in ("quick", "standard", "full"):
        print("usage: python3 -m validation.suites quick|standard|full", file=sys.stderr)
        return 2
    profile = ValidationProfile.parse(args[0])
    root = Path(__file__).resolve().parents[1]
    registry = quick_registry()
    runners = dict(RUNNERS)
    runners.update(extend_registry(registry, root))
    with tempfile.TemporaryDirectory(prefix="lbt-unified-results-") as workspace:
        run = run_validation(registry, profile,
                             ValidationContext(root, Path(workspace)), runners)
    for result in run.results:
        print(f"[{result.status.value}] {result.validation_id}"
              + (f" — {result.reason}" if result.reason else ""))
    print(f"Validation {profile.name}: {run.overall} ({run.counts})")
    return {"PASS": 0, "FAIL": 1, "INCOMPLETE": 3}[run.overall]


if __name__ == "__main__":
    sys.exit(main())
