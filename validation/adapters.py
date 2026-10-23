"""Reuse existing unittest and Phase 1 acceptance checks without changing criteria.

The unified adapter invokes unittest once per validation session. The legacy
Phase 1 "Python unit tests" check becomes an explicit dependency/alias, not a
second invocation. The legacy acceptance script and its CLI remain unchanged.
"""
import importlib.util
import json
from pathlib import Path
import sys

from .evidence import private_diagnostic
from .processes import run_bounded
from .profiles import ValidationProfile
from .registry import ValidationCase, ValidationRegistry
from .runner import CheckOutcome, ValidationContext
from .results import ValidationStatus

UNIT_ID = "VAL-P1-UNIT-001"
ACCEPTANCE_IDS = tuple(f"VAL-P1-ACCEPT-{index:03d}" for index in range(1, 17))
# Check positions match the existing @check registration order. Do not reorder.
STANDARD_INDICES = frozenset(range(1, 12))
FULL_INDICES = frozenset(range(12, 17))


def acceptance_timeout(index: int) -> int:
    return 120 if index in (12, 13, 14, 15) else 35


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
    result = run_bounded(args, str(context.root), 50)
    evidence = ()
    if result.timed_out or result.returncode:
        ref = private_diagnostic(context.results_dir, UNIT_ID,
                                 result.stdout + "\\n" + result.stderr)
        evidence = (ref,) if ref else ()
    if result.timed_out:
        return CheckOutcome(ValidationStatus.FAIL, "unit suite timed out (50 seconds)",
                            evidence=evidence)
    if result.returncode:
        # Do not expose raw subprocess output in operator-facing reasons.
        return CheckOutcome(ValidationStatus.FAIL,
                            f"unit suite exited unsuccessfully (code {result.returncode})",
                            evidence=evidence)
    return CheckOutcome(ValidationStatus.PASS, evidence=("unit-suite:unittest-discover",))


def _acceptance(case_index: int):
    def execute(context: ValidationContext) -> CheckOutcome | None:
        if case_index == 2:
            # The controller executes the UNIT_ID dependency first, once.
            return CheckOutcome(ValidationStatus.PASS,
                                evidence=(f"delegated-to:{UNIT_ID}",))
        # Isolate the original check in its own bounded process. Each check
        # receives its own temporary workspace, created by the worker.
        # Packaging and relocation cases may run longer than CLI checks.
        timeout = acceptance_timeout(case_index)
        cmd = [sys.executable, "-m", "validation.acceptance_worker",
               str(context.root), str(case_index)]
        result = run_bounded(cmd, str(context.root), timeout)
        evidence = ()
        if result.timed_out or result.returncode:
            ref = private_diagnostic(context.results_dir, ACCEPTANCE_IDS[case_index - 1],
                                     result.stdout + "\\n" + result.stderr)
            evidence = (ref,) if ref else ()
        if result.timed_out:
            return CheckOutcome(ValidationStatus.FAIL,
                                f"legacy acceptance check timed out ({timeout} seconds)", evidence=evidence)
        try:
            response = json.loads(result.stdout)
            status = ValidationStatus(response["status"])
            reason = response.get("reason", "")
        except (ValueError, KeyError, TypeError):
            return CheckOutcome(ValidationStatus.FAIL,
                                "legacy acceptance worker returned invalid results", evidence=evidence)
        if (result.returncode == 0) != (status in (
                ValidationStatus.PASS, ValidationStatus.SKIP)):
            return CheckOutcome(ValidationStatus.FAIL,
                                "legacy acceptance worker exit/status mismatch", evidence=evidence)
        if status not in (ValidationStatus.PASS, ValidationStatus.SKIP, ValidationStatus.FAIL):
            return CheckOutcome(ValidationStatus.FAIL,
                                "legacy acceptance worker returned unsupported status", evidence=evidence)
        if status == ValidationStatus.FAIL:
            return CheckOutcome(status, "Legacy acceptance check failed; see protected diagnostic log",
                                evidence=evidence)
        return CheckOutcome(status, reason, evidence=evidence)

    return execute


def extend_registry(registry: ValidationRegistry, root: Path) -> dict:
    """Attach the original 16 acceptance checks in their original order."""
    module = load_acceptance(root)
    registry.register(ValidationCase(
        validation_id=UNIT_ID, title="Existing Python unittest discovery suite",
        phase=1, category="unit", minimum_profile=ValidationProfile.STANDARD,
        runner="legacy:unittest", prerequisites=("python3",),
        evidence_level="unit", timeout_seconds=50,
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
            evidence_level="integration", timeout_seconds=acceptance_timeout(index),
        ))
        runners[runner_name] = _acceptance(index)
    return runners
