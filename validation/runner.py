"""Deterministic software-validation execution, with no hardware benchmark side effects.

Runner callables receive a ValidationContext and return None for PASS, or a
ValidationStatus with a reason via CheckOutcome. External command timeouts must
be enforced in the callable; this controller does not claim hard timeouts for
in-process Python functions.
"""
from dataclasses import dataclass
from pathlib import Path
import shutil
import time
import traceback
from typing import Callable

from .evidence import private_diagnostic
from .profiles import ValidationProfile
from .registry import ValidationCase, ValidationRegistry
from .results import ValidationResult, ValidationStatus


@dataclass(frozen=True)
class ValidationContext:
    root: Path
    results_dir: Path
    allow_controlled_impact: bool = False


@dataclass(frozen=True)
class CheckOutcome:
    status: ValidationStatus
    reason: str = ""
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True)
class ValidationRun:
    profile: ValidationProfile
    results: tuple[ValidationResult, ...]
    overall: str

    @property
    def counts(self) -> dict[str, int]:
        return {s.value: sum(r.status == s for r in self.results)
                for s in ValidationStatus}


Runner = Callable[[ValidationContext], CheckOutcome | None]
Prerequisite = Callable[[str], bool]


def default_prerequisite(name: str) -> bool:
    """Only executable names are allowed as command prerequisites."""
    return bool(name) and "/" not in name and shutil.which(name) is not None


def run_validation(
    registry: ValidationRegistry,
    profile: ValidationProfile,
    context: ValidationContext,
    runners: dict[str, Runner],
    prerequisite_available: Prerequisite = default_prerequisite,
    applicable: Callable[[ValidationCase], bool] | None = None,
) -> ValidationRun:
    """Execute each selected case once; record failures without aborting the run.

    Runner registration is explicit. Unknown runners are BLOCKED; unrelated
    checks continue. Dependencies require PASS, not merely completion.
    """
    selected = registry.select(profile)
    results: list[ValidationResult] = []
    by_id: dict[str, ValidationResult] = {}
    for case in selected:
        started = time.monotonic()
        status = ValidationStatus.PASS
        reason = ""
        evidence: tuple[str, ...] = ()
        if case.safety_class == "controlled_impact" and not context.allow_controlled_impact:
            status, reason = ValidationStatus.SKIP, "controlled-impact test not authorized"
        elif (applicable is not None and not applicable(case)) or (
            applicable is None and case.applicability == "never"
        ):
            status, reason = ValidationStatus.NOT_APPLICABLE, "not applicable in this environment"
        elif any(by_id[dep].status != ValidationStatus.PASS for dep in case.dependencies):
            status, reason = ValidationStatus.BLOCKED, "required validation dependency did not pass"
        else:
            missing = [p for p in case.prerequisites if not prerequisite_available(p)]
            if missing:
                status, reason = ValidationStatus.BLOCKED, "missing prerequisites: " + ", ".join(missing)
            elif case.runner not in runners:
                status, reason = ValidationStatus.BLOCKED, "runner is not registered"
            else:
                try:
                    outcome = runners[case.runner](context)
                    if outcome is not None:
                        if not isinstance(outcome, CheckOutcome):
                            raise TypeError("runner must return CheckOutcome or None")
                        status, reason, evidence = outcome.status, outcome.reason, outcome.evidence
                    if status != ValidationStatus.PASS and not reason.strip():
                        raise ValueError("non-PASS outcome requires a reason")
                    # In-process Python checks cannot be forcibly terminated.
                    # Apply advisory elapsed-time enforcement after they return.
                    if (case.timeout_seconds is not None and
                            time.monotonic() - started > case.timeout_seconds and
                            status == ValidationStatus.PASS):
                        status = ValidationStatus.FAIL
                        reason = "validation check exceeded advisory timeout"
                except Exception as error:
                    status = ValidationStatus.FAIL
                    reason = f"{type(error).__name__}: validation check raised an exception"
                    ref = private_diagnostic(context.results_dir, case.validation_id,
                                             traceback.format_exc())
                    evidence = (ref,) if ref else ()
        result = ValidationResult(
            case.validation_id, status, time.monotonic() - started,
            reason=reason, evidence=evidence,
        )
        results.append(result)
        by_id[case.validation_id] = result
    overall = ("FAIL" if any(r.status == ValidationStatus.FAIL for r in results)
               else "INCOMPLETE" if any(r.status in (
                   ValidationStatus.SKIP, ValidationStatus.BLOCKED,
                   ValidationStatus.NOT_APPLICABLE) for r in results)
               else "PASS")
    return ValidationRun(profile, tuple(results), overall)
