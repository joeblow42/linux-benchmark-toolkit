# IC-02 — Phase 2 discovery orchestration

**Implementation:** `discovery/orchestrator.py`. This document implements
approved IC-02 and decisions IC02-D1 through IC02-D3. The authoritative
IC-01 registry is `discovery/registry.py`; the separate
`validation/registry.py` registers software validation checks.

## Interface

```python
from discovery.core import DiscoveryContext
from discovery.orchestrator import collect_inventory

inventory = collect_inventory(DiscoveryContext())
selected = collect_inventory(DiscoveryContext(), ["system", "cpu"])
```

The caller must opt in by calling this function. Importing the module
does **not** collect hardware. `None` requests all ten registry entries;
a nonempty list requests an explicit scoped inventory. IDs are validated
before any collector executes; unknown or repeated IDs raise an exception.
Callers retain the requested list order for traceability, but execution
follows the IC-01 canonical registry order.

On Linux, the controller resolves registered callables lazily, invokes
each via the existing `run_collector()` wrapper, records duration with a
monotonic clock, and isolates failures. It never calls sudo, installs
packages, starts benchmarks, writes output artifacts, or renders HTML.
The registry metadata marks these collectors read-only with no mandatory
privilege; collectors retain existing `collect(context, *, ...)` signatures.

The `_collect_inventory` helper accepts injected resolver and clock
functions for deterministic, hardware-free unit testing. It is **not**
a separate production API.

## Returned in-memory contract, version 1.0

```json
{
  "contract_version": "1.0",
  "scope": "selected",
  "started_utc": "2026-10-23T18:00:00.000Z",
  "completed_utc": "2026-10-23T18:00:01.000Z",
  "requested_collector_ids": ["cpu", "system"],
  "execution_order": ["system", "cpu"],
  "results": {
    "system": {
      "collector_id": "system",
      "status": "COMPLETE",
      "data": {},
      "sources": [],
      "reason": ""
    }
  },
  "timings": {
    "system": {"elapsed_ms": 12.4}
  },
  "summary": {
    "outcome": "COMPLETE",
    "minimum_inventory_met": true,
    "selected": 2,
    "attempted": 2,
    "executed": 2,
    "status_counts": {
      "COMPLETE": 2,
      "UNAVAILABLE": 0,
      "UNSUPPORTED": 0,
      "PERMISSION_DENIED": 0,
      "TOOL_MISSING": 0,
      "FAILED": 0
    }
  },
  "errors": []
}
```

*Illustrative subset of `results` for readability; not a literal complete
output. The selected count, attempted count and status counts show the
shape of a valid two-result return.*

- `results`: keyed by collector ID; each original
  `CollectorResult.to_dict()` is retained unmodified when structurally
  valid and JSON serializable.
- `timings`: each attempted collector gets `elapsed_ms`, including
  one interrupted mid-invocation.
- `summary.status_counts`: six **collector** statuses, never software
  validation statuses. `executed` counts completed result records;
  `attempted` includes an interrupted last attempt.
- `errors`: non-sensitive collector ID + category only, e.g.
  `COLLECTOR_FAILURE`, `DISPATCH_FAILURE`, `INVALID_RESULT`,
  `ACCESS_DENIED`, or `INTERRUPTED`. The original collector
  `reason` and `sources` are preserved inside `results`; no raw
  exception detail is introduced by the orchestrator.

## Full and selected minimum inventory

**Full scope (IC02-D1):** `system` must report `COMPLETE` and at least one
of `cpu`, `memory`, or `storage` must report `COMPLETE`.

**Selected scope:** it cannot claim full-host discovery. A selected run has
a minimum useful observation when at least one selected collector reports
`COMPLETE` or a non-error capability-absence status
(`UNAVAILABLE`, `UNSUPPORTED`, `TOOL_MISSING`). The caller can
therefore intentionally check for absent optional hardware. A selected
request consisting only of failed or permission-denied records is `FAILED`.

On non-Linux hosts, collectors are not invoked; results report
`UNSUPPORTED`, and the discovery outcome is `FAILED` because the
hardware inventory contract is Linux-only.

## Session outcomes (IC02-D3)

| Outcome | Meaning |
| --- | --- |
| COMPLETE | Minimum observation obtained, with no FAILED/PERMISSION_DENIED collector statuses |
| PARTIAL | Minimum obtained, but a collector failed or access was denied |
| FAILED | Minimum not obtained, regardless of other status counts |
| INTERRUPTED | `KeyboardInterrupt` during a collector; preceding results returned in memory |

The controller treats absent optical devices, unsupported acceleration,
missing optional `vainfo`, and missing sensors as normal inventory
observations, not host malfunctions. One collector's exception does not
erase subsequent independent collectors. Failed result structure or
unserializable payloads are replaced with a safe `FAILED` result;
serializable valid evidence is never rewritten.

The `KeyboardInterrupt` behavior captures completed in-memory evidence
only. A process kill, power failure, and arbitrary termination are not
recoverable in IC-02; persistent interruption support belongs to IC-03
and later integration. Existing bounded subprocess probes remain bounded,
but the orchestrator does **not** enforce hard deadlines for in-process
Python collectors.

## Integration boundary

IC-02 does **not** activate this implementation from the Phase 1
`benchmark --mode discovery` path, write `system.json`, add or rerun
benchmarks, alter the existing report schema, or introduce a new
software-validation controller. IC-03/05/06 will define session storage,
privacy review, and reports. Requirement links in the approved IC-02
design document indicate relevant evidence only, not complete requirement
verification.

## Verification

```sh
python3 -m unittest discover -s tests -p 'test_phase2_orchestrator.py' -v
./benchmark --validate --validation-profile full
```

The new fixture-based unittest cases automatically participate in the
existing Standard/Full validation adapter. On-target Bodhi/Linux execution
and independent hardware comparisons remain separate acceptance evidence.

No existing collector, launcher, reporting, or validation module was
changed for this IC-02 implementation. The IC-02 branch requires owner
review and explicit authorization before merging into `main`.
