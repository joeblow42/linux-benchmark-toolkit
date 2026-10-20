"""Shared hardware collector interface and data provenance.

This module neither escalates privileges nor invokes collectors automatically.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Optional


class CollectionStatus(str, Enum):
    COMPLETE = "COMPLETE"
    UNAVAILABLE = "UNAVAILABLE"
    UNSUPPORTED = "UNSUPPORTED"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    TOOL_MISSING = "TOOL_MISSING"
    FAILED = "FAILED"


@dataclass(frozen=True)
class DiscoveryContext:
    """Policies supplied explicitly by a future CLI integration.

    Default discovery redacts identifying fields. Detailed output requires an
    explicit request. Privilege-assisted mode never means automatic sudo.
    """
    include_identifiers: bool = False
    allow_privileged: bool = False


@dataclass
class CollectorResult:
    collector_id: str
    status: CollectionStatus
    data: Dict[str, Any] = field(default_factory=dict)
    sources: list = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "collector_id": self.collector_id,
            "status": self.status.value,
            "data": self.data,
            "sources": self.sources,
            "reason": self.reason,
        }


def run_collector(collector_id: str, collect: Callable[[DiscoveryContext], CollectorResult],
                  context: Optional[DiscoveryContext] = None) -> CollectorResult:
    """Isolate collector failures, preserving missing-device semantics."""
    if not collector_id or not callable(collect):
        raise ValueError("collector_id and callable collect required")
    context = context if context is not None else DiscoveryContext()
    try:
        result = collect(context)
        if not isinstance(result, CollectorResult) or result.collector_id != collector_id:
            raise ValueError("collector returned an invalid result")
        return result
    except Exception as exc:
        return CollectorResult(
            collector_id=collector_id, status=CollectionStatus.FAILED,
            reason=f"collector error: {type(exc).__name__}",
        )
