"""Result data for software validation, not collector or benchmark execution."""

from dataclasses import dataclass
from enum import Enum


class ValidationStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"
    BLOCKED = "BLOCKED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass(frozen=True)
class ValidationResult:
    validation_id: str
    status: ValidationStatus
    duration_seconds: float
    reason: str = ""
    evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.validation_id:
            raise ValueError("validation_id is required")
        if not isinstance(self.status, ValidationStatus):
            raise ValueError("status must be a ValidationStatus")
        if self.duration_seconds < 0:
            raise ValueError("duration cannot be negative")
        if self.status in (ValidationStatus.FAIL, ValidationStatus.SKIP,
                           ValidationStatus.BLOCKED, ValidationStatus.NOT_APPLICABLE):
            if not self.reason.strip():
                raise ValueError(f"{self.status.value} requires a reason")
