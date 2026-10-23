"""Reuse existing unittest and Phase 1 acceptance checks without changing criteria.

The unified adapter invokes unittest once per validation session. The legacy
Phase 1 "Python unit tests" check becomes an explicit dependency/alias, not a
second invocation. The legacy acceptance script and its CLI remain unchanged.
"""
import importlib.util
from pathlib import Path
import signal
import subprocess
import sys
import tempfile

from .profiles import ValidationProfile
from .registry import ValidationCase, ValidationRegistry
from .runner import CheckOutcome, ValidationContext
from .results import ValidationStatus

UNIT_ID = "VAL-P1-UNIT-001"
ACCEPTANCE_IDS = tuple(f"VAL-P1-ACCEPT-{index:03d}" for index in range(1, 17))
# Check positions match the existing @check registration order. Do not reorder.
STANDARD_INDICES = frozenset(range(1, 12))
FULL_INDICES = frozenset(range(12, 17))


def load_acceptance(root: Path):
    path = root / "tests" / "acceptance_phase1.py"
    spec = importlib.util.spec_from_file_location("_lbt_phase1_acceptance", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Phase 1 acceptance source unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if len(module.CHECKS) != 16:
        raise RuntimeError(f"expected 16 original Phase 1 checks; found {len(module.CHECKS)}")
    return module


def _unittest(context: ValidationContext) -> CheckOutcome:
    """Single bounded subprocess: group-level result, not 59 independent claims."""
    args = [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"]
    # The existing legacy check has a 50-second subprocess deadline.
    try:
        proc = subprocess.Popen(
            args, cwd=context.root, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, start_new_session=True,
        )
        try:
            stdout, stderr = proc.communicate(timeout=50)
        except subprocess.TimeoutExpired:
            import os
            os.killpg(proc.pid, signal.SIGKILL)
            proc.communicate()
            return CheckOutcome(ValidationStatus.FAIL, "unit suite timed out (50 seconds)")
    except OSError as error:
        return CheckOutcome(ValidationStatus.FAIL, f"unittest unavailable: {type(error).__name__}")
    if proc.returncode:
        # Detailed raw output is intentionally not persisted at this stage.
        tail = stderr.strip().splitlines()[-1:] or stdout.strip().splitlines()[-1:]
        return CheckOutcome(ValidationStatus.FAIL,
                            "unit suite failed: " + (tail[0][:180] if tail else "no summary"))
    # The suite is a group-level result; individual requirements are not approved.
    return CheckOutcome(ValidationStatus.PASS, evidence=("unit-suite:unittest-discover",))


def _acceptance(case_index: int):
    def execute(context: ValidationContext) -> CheckOutcome | None:
        if case_index == 2:
            # The controller executes the UNIT_ID dependency first, once.
            return CheckOutcome(ValidationStatus.PASS,
                                evidence=(f"delegated-to:{UNIT_ID}",))
        module = load_acceptance(context.root)
        _, fn = module.CHECKS[case_index - 1]
        with tempfile.TemporaryDirectory(prefix="lbt-unified-accept-") as temp:
            try:
                fn(context.root, Path(temp))
            except module.SkipCheck as error:
                return CheckOutcome(ValidationStatus.SKIP, str(error))
        return None
    return execute


def extend_registry(registry: ValidationRegistry, root: Path) -> dict:
    """Attach the original 16 acceptance checks in their original order."""
    module = load_acceptance(root)
    registry.register(ValidationCase(
        validation_id=UNIT_ID, title="Existing Python unittest discovery suite",
        phase=1, category="unit", minimum_profile=ValidationProfile.STANDARD,
        runner="legacy:unittest", prerequisites=("python3",),
        evidence_level="unit",
    ))
    runners = {"legacy:unittest": _unittest}
    for index, (title, _) in enumerate(module.CHECKS, 1):
        profile = (ValidationProfile.STANDARD if index in STANDARD_INDICES
                   else ValidationProfile.FULL)
        runner_name = f"legacy:acceptance:{index:02d}"
        # The second original acceptance check calls unittest; represent that
        # check as a dependent alias, never invoke its subprocess again.
        dependencies = (UNIT_ID,) if index == 2 else ()
        registry.register(ValidationCase(
            validation_id=ACCEPTANCE_IDS[index - 1], title=title,
            phase=1, category="acceptance", minimum_profile=profile,
            runner=runner_name, dependencies=dependencies,
            prerequisites=("python3",),
            safety_class=("temporary_write" if index > 5 else "read_only"),
            evidence_level="integration",
        ))
        runners[runner_name] = _acceptance(index)
    return runners
