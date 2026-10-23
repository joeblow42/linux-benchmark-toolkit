"""IC-02: Phase 2 read-only hardware discovery orchestration.

No collection occurs at import. The caller explicitly invokes collect_inventory.
This module does not implement session persistence, benchmarking or reporting.
"""

from datetime import datetime, timezone
import platform
import time
from typing import Callable

from .core import CollectionStatus, CollectorResult, DiscoveryContext, run_collector
from .registry import all_collectors, get_collector, resolve_collector, validate_registry


CONTRACT_VERSION = "1.0"
_BENIGN = frozenset((
    CollectionStatus.COMPLETE,
    CollectionStatus.UNAVAILABLE,
    CollectionStatus.UNSUPPORTED,
    CollectionStatus.TOOL_MISSING,
))
_PROBLEM = frozenset((CollectionStatus.FAILED, CollectionStatus.PERMISSION_DENIED))
_BASELINE = frozenset(("cpu", "memory", "storage"))


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_stamp(value: datetime) -> str:
    """Normalize clock input to an unambiguous UTC timestamp."""
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("UTC clock must return an aware datetime")
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _select_ids(collector_ids: list[str] | None) -> tuple[list[str], list[str], str]:
    """Validate all IDs before attempting any collector; execute in registry order."""
    ordered_ids = [spec.collector_id for spec in all_collectors()]
    if collector_ids is None:
        return list(ordered_ids), list(ordered_ids), "full"
    if not isinstance(collector_ids, list) or not collector_ids:
        raise ValueError("collector_ids must be a nonempty list")
    seen: set[str] = set()
    for cid in collector_ids:
        # get_collector performs exact, type-safe lookup; no unknown IDs allowed.
        get_collector(cid)
        if cid in seen:
            raise ValueError(f"duplicate collector ID: {cid}")
        seen.add(cid)
    execution_order = [cid for cid in ordered_ids if cid in seen]
    return list(collector_ids), execution_order, "selected"


def _valid_result(result: object, collector_id: str) -> bool:
    """Guard aggregation from malformed collector payloads without rewriting evidence."""
    return (
        isinstance(result, CollectorResult)
        and result.collector_id == collector_id
        and isinstance(result.status, CollectionStatus)
        and isinstance(result.data, dict)
        and isinstance(result.sources, list)
        and isinstance(result.reason, str)
    )


def _minimum_inventory_met(scope: str, results: dict) -> bool:
    if scope == "full":
        return (
            results.get("system", {}).get("status") == CollectionStatus.COMPLETE.value
            and any(
                results.get(cid, {}).get("status") == CollectionStatus.COMPLETE.value
                for cid in _BASELINE
            )
        )
    # Selected scopes cannot claim a full host baseline. A valid absence
    # observation is useful when the user explicitly selects optional hardware.
    return any(entry["status"] in {s.value for s in _BENIGN}
               for entry in results.values())


def _collect_inventory(
    context: DiscoveryContext,
    collector_ids: list[str] | None = None,
    *,
    resolver: Callable = resolve_collector,
    monotonic: Callable[[], float] = time.monotonic,
    utc_now: Callable[[], datetime] = _utc_now,
    platform_name: Callable[[], str] = platform.system,
) -> dict:
    """Private injection seam for deterministic, hardware-free unit tests."""
    if not isinstance(context, DiscoveryContext):
        raise TypeError("context must be a DiscoveryContext")
    validate_registry()
    requested, ordered, scope = _select_ids(collector_ids)
    started_utc = _utc_stamp(utc_now())
    platform_supported = platform_name() == "Linux"
    results: dict[str, dict] = {}
    timings: dict[str, dict] = {}
    errors: list[dict[str, str]] = []
    attempted = 0
    interrupted = False

    for collector_id in ordered:
        start = monotonic()
        attempted += 1
        category = None
        try:
            if not platform_supported:
                result = CollectorResult(
                    collector_id, CollectionStatus.UNSUPPORTED,
                    reason="collector applicable only to Linux",
                )
            else:
                try:
                    callable_collector = resolver(collector_id)
                    result = run_collector(collector_id, callable_collector, context)
                except Exception as exc:
                    # Module resolution failures must not stop later collectors.
                    result = CollectorResult(
                        collector_id, CollectionStatus.FAILED,
                        reason=f"collector dispatch error: {type(exc).__name__}",
                    )
                    category = "DISPATCH_FAILURE"
            if not _valid_result(result, collector_id):
                result = CollectorResult(
                    collector_id, CollectionStatus.FAILED,
                    reason="collector error: invalid result structure",
                )
                category = "INVALID_RESULT"
            results[collector_id] = result.to_dict()
            if result.status in _PROBLEM:
                errors.append({
                    "collector_id": collector_id,
                    "kind": category or (
                        "ACCESS_DENIED" if result.status == CollectionStatus.PERMISSION_DENIED
                        else "COLLECTOR_FAILURE"
                    ),
                })
        except KeyboardInterrupt:
            interrupted = True
            errors.append({"collector_id": collector_id, "kind": "INTERRUPTED"})
            break
        finally:
            # Monotonic durations remain separate from original CollectorResult.
            elapsed_ms = max(0.0, (monotonic() - start) * 1000)
            timings[collector_id] = {"elapsed_ms": round(elapsed_ms, 3)}

    minimum_met = _minimum_inventory_met(scope, results)
    if interrupted:
        outcome = "INTERRUPTED"
    elif not minimum_met:
        outcome = "FAILED"
    elif any(entry["status"] in {status.value for status in _PROBLEM}
             for entry in results.values()):
        outcome = "PARTIAL"
    else:
        outcome = "COMPLETE"
    counts = {status.value: 0 for status in CollectionStatus}
    for entry in results.values():
        counts[entry["status"]] += 1
    return {
        "contract_version": CONTRACT_VERSION,
        "scope": scope,
        "started_utc": started_utc,
        "completed_utc": _utc_stamp(utc_now()),
        "requested_collector_ids": requested,
        "execution_order": ordered,
        "results": results,
        "timings": timings,
        "summary": {
            "outcome": outcome,
            "minimum_inventory_met": minimum_met,
            "selected": len(ordered),
            "attempted": attempted,
            "executed": len(results),
            "status_counts": counts,
        },
        "errors": errors,
    }


def collect_inventory(
    context: DiscoveryContext,
    collector_ids: list[str] | None = None,
) -> dict:
    """Collect selected hardware inventory without writing files or reports.

    None requests the full ten-collector Linux inventory. A nonempty list
    requests a scoped inventory with deterministic canonical execution order.
    Each collector executes through the established run_collector() wrapper.
    """
    return _collect_inventory(context, collector_ids)
