"""IC-01: declarative Phase 2 HARDWARE collector registration.

Metadata lookup and module import do not collect hardware. The future IC-02
orchestrator owns selection, ordering, invocation, and result aggregation.
This registry is intentionally independent of validation/registry.py.
"""

from dataclasses import dataclass
from importlib import import_module
from inspect import Parameter, signature
import re
from typing import Callable

from .core import CollectorResult, DiscoveryContext


class CollectorRegistryError(ValueError):
    """Invalid collector registration, ID, or callable interface."""


@dataclass(frozen=True)
class CollectorSpec:
    collector_id: str
    module: str
    entrypoint: str
    phase: int
    category: str
    read_only: bool
    requires_privilege: bool
    optional_tools: tuple[str, ...]
    applicability: str
    related_requirements: tuple[str, ...]


# The sequence and identifiers are explicit IC-01 API commitments.
EXPECTED_COLLECTOR_IDS = (
    "system", "cpu", "memory", "storage", "optical",
    "gpu", "vaapi", "network", "thermal", "power",
)

COLLECTORS: tuple[CollectorSpec, ...] = (
    CollectorSpec(
        collector_id="system", module="discovery.system", entrypoint="collect",
        phase=2, category="OS and firmware", read_only=True,
        requires_privilege=False, optional_tools=(),
        applicability="linux", related_requirements=("LBT-FR-031", "LBT-FR-140"),
    ),
    CollectorSpec(
        collector_id="cpu", module="discovery.cpu", entrypoint="collect",
        phase=2, category="CPU inventory", read_only=True,
        requires_privilege=False, optional_tools=(),
        applicability="linux", related_requirements=("LBT-FR-024", "LBT-FR-025"),
    ),
    CollectorSpec(
        collector_id="memory", module="discovery.memory", entrypoint="collect",
        phase=2, category="Memory and swap", read_only=True,
        requires_privilege=False, optional_tools=(),
        applicability="linux", related_requirements=("LBT-FR-026",),
    ),
    CollectorSpec(
        collector_id="storage", module="discovery.storage", entrypoint="collect",
        phase=2, category="Storage topology", read_only=True,
        requires_privilege=False, optional_tools=(),
        applicability="linux", related_requirements=("LBT-FR-028", "LBT-FR-048", "LBT-FR-049"),
    ),
    CollectorSpec(
        collector_id="optical", module="discovery.optical", entrypoint="collect",
        phase=2, category="Optical hardware", read_only=True,
        requires_privilege=False, optional_tools=(),
        applicability="linux", related_requirements=("LBT-FR-029",),
    ),
    CollectorSpec(
        collector_id="gpu", module="discovery.gpu", entrypoint="collect",
        phase=2, category="Graphics hardware", read_only=True,
        requires_privilege=False, optional_tools=(),
        applicability="linux", related_requirements=("LBT-FR-027",),
    ),
    CollectorSpec(
        collector_id="vaapi", module="discovery.vaapi", entrypoint="collect",
        phase=2, category="Video acceleration capabilities", read_only=True,
        requires_privilege=False, optional_tools=("vainfo",),
        applicability="linux", related_requirements=("LBT-FR-079",),
    ),
    CollectorSpec(
        collector_id="network", module="discovery.network", entrypoint="collect",
        phase=2, category="Network interfaces", read_only=True,
        requires_privilege=False, optional_tools=(),
        applicability="linux", related_requirements=("LBT-FR-030", "LBT-FR-050", "LBT-FR-051"),
    ),
    CollectorSpec(
        collector_id="thermal", module="discovery.thermal", entrypoint="collect",
        phase=2, category="Sensors and temperatures", read_only=True,
        requires_privilege=False, optional_tools=(),
        applicability="linux", related_requirements=("LBT-FR-013",),
    ),
    CollectorSpec(
        collector_id="power", module="discovery.power", entrypoint="collect",
        phase=2, category="Battery and power supplies", read_only=True,
        requires_privilege=False, optional_tools=(),
        applicability="linux", related_requirements=("LBT-FR-032",),
    ),
)

_BY_ID = {spec.collector_id: spec for spec in COLLECTORS}
_ID = re.compile(r"[a-z][a-z0-9_]*\Z")
_MODULE = re.compile(r"discovery\.[a-z][a-z0-9_]*\Z")
_TOOL = re.compile(r"[a-zA-Z0-9_.+-]+\Z")
_REQUIREMENT = re.compile(r"LBT-(?:FR|NFR)-[0-9]{3}\Z")


def all_collectors() -> tuple[CollectorSpec, ...]:
    """Return immutable, ordered metadata; never import collector modules."""
    return COLLECTORS


def get_collector(collector_id: str) -> CollectorSpec:
    """Look up one canonical ID without importing or executing its module."""
    if not isinstance(collector_id, str):
        raise CollectorRegistryError("collector ID must be a string")
    try:
        return _BY_ID[collector_id]
    except KeyError as exc:
        raise CollectorRegistryError(f"unknown collector ID: {collector_id!r}") from exc


def validate_registry(entries: tuple[CollectorSpec, ...] | None = None) -> None:
    """Check IC-01 metadata, ordering and coverage without hardware access.

    The optional entries argument permits malformed-registry tests. It is not a
    registration/plugin mechanism; COLLECTORS remains the authoritative set.
    """
    specs = COLLECTORS if entries is None else tuple(entries)
    seen: set[str] = set()
    for spec in specs:
        if not isinstance(spec, CollectorSpec):
            raise CollectorRegistryError("registry entry must be a CollectorSpec")
        cid = spec.collector_id
        if not isinstance(cid, str) or not _ID.fullmatch(cid):
            raise CollectorRegistryError("invalid collector ID")
        if cid in seen:
            raise CollectorRegistryError(f"duplicate collector ID: {cid}")
        seen.add(cid)
        if not isinstance(spec.module, str) or not _MODULE.fullmatch(spec.module):
            raise CollectorRegistryError(f"{cid}: invalid module")
        if spec.module != f"discovery.{cid}":
            raise CollectorRegistryError(f"{cid}: module does not match collector ID")
        if spec.entrypoint != "collect":
            raise CollectorRegistryError(f"{cid}: entrypoint must be collect")
        if type(spec.phase) is not int or spec.phase != 2:
            raise CollectorRegistryError(f"{cid}: invalid development phase")
        if not isinstance(spec.category, str) or not spec.category.strip():
            raise CollectorRegistryError(f"{cid}: missing category")
        if type(spec.read_only) is not bool or not spec.read_only:
            raise CollectorRegistryError(f"{cid}: collector must be read-only")
        if type(spec.requires_privilege) is not bool or spec.requires_privilege:
            raise CollectorRegistryError(f"{cid}: unexpected privilege requirement")
        if not isinstance(spec.optional_tools, tuple) or any(
            not isinstance(tool, str) or not _TOOL.fullmatch(tool)
            for tool in spec.optional_tools
        ) or len(set(spec.optional_tools)) != len(spec.optional_tools):
            raise CollectorRegistryError(f"{cid}: invalid optional tools")
        if spec.applicability != "linux":
            raise CollectorRegistryError(f"{cid}: invalid applicability")
        refs = spec.related_requirements
        if not isinstance(refs, tuple) or not refs or any(
            not isinstance(ref, str) or not _REQUIREMENT.fullmatch(ref)
            for ref in refs
        ) or len(set(refs)) != len(refs):
            raise CollectorRegistryError(f"{cid}: invalid requirement links")
    if tuple(spec.collector_id for spec in specs) != EXPECTED_COLLECTOR_IDS:
        raise CollectorRegistryError("collector coverage or order differs from IC-01")


def resolve_collector(collector_id: str) -> Callable[..., CollectorResult]:
    """Resolve a collector, but DO NOT execute it.

    Require the existing collect(context, *, optional_fixture_parameters)
    interface. Runtime exceptions remain the responsibility of run_collector()
    when IC-02 (or a controlled test) explicitly invokes the callable.
    """
    spec = get_collector(collector_id)
    try:
        module = import_module(spec.module)
    except ImportError as exc:
        raise CollectorRegistryError(f"{collector_id}: module unavailable") from exc
    collect = getattr(module, spec.entrypoint, None)
    if not callable(collect):
        raise CollectorRegistryError(f"{collector_id}: entrypoint unavailable")
    try:
        parameters = tuple(signature(collect).parameters.values())
    except (TypeError, ValueError) as exc:
        raise CollectorRegistryError(f"{collector_id}: signature unavailable") from exc
    if not parameters or parameters[0].name != "context" or (
        parameters[0].kind not in (Parameter.POSITIONAL_ONLY, Parameter.POSITIONAL_OR_KEYWORD)
    ) or any(
        parameter.kind != Parameter.KEYWORD_ONLY
        or parameter.default is Parameter.empty
        for parameter in parameters[1:]
    ):
        raise CollectorRegistryError(f"{collector_id}: incompatible callable signature")
    return collect
