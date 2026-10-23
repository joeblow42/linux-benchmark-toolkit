"""Explicit metadata registry. Registration never imports or invokes a runner."""

from dataclasses import dataclass
import re

from .profiles import ValidationProfile

_ID = re.compile(r"^VAL-[A-Z0-9]+(?:-[A-Z0-9]+)*$")
_REQ_ID = re.compile(r"^LBT-(?:FR|NFR)-[0-9]{3}$")
_SAFETY = frozenset(("read_only", "temporary_write", "controlled_impact"))


class RegistryError(ValueError):
    """Invalid validation case or registry."""


@dataclass(frozen=True)
class ValidationCase:
    validation_id: str
    title: str
    phase: int
    category: str
    minimum_profile: ValidationProfile
    runner: str
    requirement_ids: tuple[str, ...] = ()
    prerequisites: tuple[str, ...] = ()
    dependencies: tuple[str, ...] = ()
    applicability: str = "linux"
    timeout_seconds: float | None = None
    safety_class: str = "read_only"
    hardware_dependency: bool = False
    evidence_level: str = "infrastructure"

    def __post_init__(self) -> None:
        if not _ID.fullmatch(self.validation_id):
            raise RegistryError(f"invalid validation ID: {self.validation_id!r}")
        if not self.title.strip() or not self.category.strip() or not self.runner.strip():
            raise RegistryError(f"{self.validation_id}: missing title/category/runner")
        if type(self.phase) is not int or self.phase < 1:
            raise RegistryError(f"{self.validation_id}: invalid phase")
        if not isinstance(self.minimum_profile, ValidationProfile):
            raise RegistryError(f"{self.validation_id}: invalid minimum profile")
        if self.safety_class not in _SAFETY:
            raise RegistryError(f"{self.validation_id}: invalid safety class")
        if self.timeout_seconds is not None and (
            isinstance(self.timeout_seconds, bool) or self.timeout_seconds <= 0
        ):
            raise RegistryError(f"{self.validation_id}: invalid timeout")
        if not self.applicability.strip() or not self.evidence_level.strip():
            raise RegistryError(f"{self.validation_id}: missing applicability/evidence level")
        for req in self.requirement_ids:
            if not _REQ_ID.fullmatch(req):
                raise RegistryError(f"{self.validation_id}: invalid requirement ID {req!r}")
        if len(set(self.requirement_ids)) != len(self.requirement_ids):
            raise RegistryError(f"{self.validation_id}: duplicate requirement link")
        if len(set(self.dependencies)) != len(self.dependencies):
            raise RegistryError(f"{self.validation_id}: duplicate dependency")
        if self.validation_id in self.dependencies:
            raise RegistryError(f"{self.validation_id}: self-dependency")
        if any(not _ID.fullmatch(dep) for dep in self.dependencies):
            raise RegistryError(f"{self.validation_id}: invalid dependency ID")


class ValidationRegistry:
    def __init__(self) -> None:
        self._entries: dict[str, ValidationCase] = {}

    def register(self, case: ValidationCase) -> None:
        if not isinstance(case, ValidationCase):
            raise RegistryError("registered object must be a ValidationCase")
        if case.validation_id in self._entries:
            raise RegistryError(f"duplicate validation ID: {case.validation_id}")
        self._entries[case.validation_id] = case

    def validate(self) -> None:
        for case in self._entries.values():
            for dependency in case.dependencies:
                if dependency not in self._entries:
                    raise RegistryError(
                        f"{case.validation_id}: unknown dependency {dependency}"
                    )
                prerequisite = self._entries[dependency]
                if prerequisite.minimum_profile > case.minimum_profile:
                    raise RegistryError(
                        f"{case.validation_id}: dependency {dependency} is excluded "
                        "at the case's minimum profile"
                    )
        visited: set[str] = set()
        active: set[str] = set()

        def visit(case_id: str) -> None:
            if case_id in active:
                raise RegistryError(f"cyclic dependency involving {case_id}")
            if case_id in visited:
                return
            active.add(case_id)
            for dep in self._entries[case_id].dependencies:
                visit(dep)
            active.remove(case_id)
            visited.add(case_id)

        for case_id in sorted(self._entries):
            visit(case_id)

    def select(self, profile: ValidationProfile) -> tuple[ValidationCase, ...]:
        if not isinstance(profile, ValidationProfile):
            raise RegistryError("invalid selection profile")
        self.validate()
        selected = {
            cid for cid, case in self._entries.items()
            if profile.includes(case.minimum_profile)
        }
        ordered: list[ValidationCase] = []
        visited: set[str] = set()

        def add(case_id: str) -> None:
            if case_id in visited:
                return
            for dep in sorted(self._entries[case_id].dependencies):
                add(dep)
            visited.add(case_id)
            ordered.append(self._entries[case_id])

        for case_id in sorted(selected):
            add(case_id)
        return tuple(ordered)

    def all_cases(self) -> tuple[ValidationCase, ...]:
        return tuple(self._entries[cid] for cid in sorted(self._entries))
