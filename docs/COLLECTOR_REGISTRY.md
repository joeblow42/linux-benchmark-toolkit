# IC-01 — Phase 2 hardware collector registry

**Status:** implementation branch; subject to review and acceptance.
**Approved contract:** IC-01 of the Integration Interface Contract Specification.
**Approved requirements baseline:** Revision 1.2 (256 requirements).
**Boundary:** this file describes the *hardware collector* registry, not
`validation/registry.py`, which registers *software validation tests*.

## Public interface

`discovery/registry.py` defines:

- `CollectorSpec`: immutable declarative record containing
  `collector_id`, `module`, `entrypoint`, `phase`, `category`,
  `read_only`, `requires_privilege`, `optional_tools`,
  `applicability`, and `related_requirements`.
- `all_collectors()`: inspect an immutable ordered tuple of ten records.
- `get_collector(id)`: look up metadata by exact ID.
- `validate_registry()`: verify metadata integrity, unique IDs, accepted
  IDs/order, read-only/no-privilege policy and syntactically valid requirement
  links. Optional entries are accepted solely for negative-fixture testing.
- `resolve_collector(id)`: import and return the existing `collect`
  function, after checking its `collect(context, *, ...)` signature.
  **Resolution does not call the collector.**

Unknown IDs, invalid registration metadata, missing modules/entrypoints,
and incompatible signatures raise `CollectorRegistryError`. The registry
never suppresses a hardware collector result or produces a discovery session.

## Stable order, modules and related requirements

| ID | Module | Related approved requirement IDs |
| --- | --- | --- |
| system | discovery.system | LBT-FR-031, LBT-FR-140 |
| cpu | discovery.cpu | LBT-FR-024, LBT-FR-025 |
| memory | discovery.memory | LBT-FR-026 |
| storage | discovery.storage | LBT-FR-028, LBT-FR-048, LBT-FR-049 |
| optical | discovery.optical | LBT-FR-029 |
| gpu | discovery.gpu | LBT-FR-027 |
| vaapi | discovery.vaapi | LBT-FR-079 |
| network | discovery.network | LBT-FR-030, LBT-FR-050, LBT-FR-051 |
| thermal | discovery.thermal | LBT-FR-013 |
| power | discovery.power | LBT-FR-032 |

All records have `phase=2`, `read_only=True`,
`requires_privilege=False`, and `applicability="linux"`.
Only `vaapi` declares an optional external tool (`vainfo`).

**Traceability rule:** these entries are *relevance links*, not a declaration
that each requirement is implemented or verified. Examples: CPU scaling
governor details, SMART/NVMe health, complete GPU model identification,
functional video acceleration, and sustained fan behavior remain separate
scope/evidence questions. Approval of registry links must not be counted as
requirement-level acceptance.

## Responsibilities and non-responsibilities

Registry metadata inspection imports no hardware collector modules and
runs no probes. Callables are loaded only through explicit resolution;
normal discovery execution is a separate later integration activity.

The existing `DiscoveryContext`, `CollectorResult`, `CollectionStatus`,
and `run_collector()` in `discovery/core.py` remain authoritative. No
collector signature or fixture keyword parameter changes are required.

The future IC-02 orchestrator owns selecting applicable collectors,
invoking them with an explicit context through `run_collector()`, ordering,
per-collector failure isolation, timing, and orchestration outcomes.
The registry does **not** implement IC-02, change `--mode discovery`,
write `system.json`, or generate HTML/CSV. IC-03/05/06 govern subsequent
persistence, privacy review, and reporting integration. Existing
`run_probe()` command timeouts are not universal Python execution timeouts.

The registry does not automatically elevate privileges, install packages,
access external networks, perform benchmarks, or inspect physical hardware
on metadata import. An absent optional device or tool is not automatically
a software-validation failure.

## Acceptance verification

Run the isolated tests:

```sh
python3 -m unittest tests.test_phase2_registry -v
```

Run the established complete software validation:

```sh
./benchmark --validate --validation-profile full
```

The new test module is discovered by the existing unittest adapter.
Its tests cover unique IDs and order, immutable metadata, import safety,
unknown IDs, callable resolution, synthetic fixture invocation, malformed
registrations, missing modules, invalid signatures, existing
`run_collector()` exception isolation, and exact approved requirement IDs.

**Acceptance boundary:** IC-01 registry acceptance does not imply that a
future orchestrator has invoked all ten collectors, preserved results across
failures, or integrated collector output into canonical session reports.
Those are IC-02 and subsequent acceptance gates. Review the branch and its
CI/host evidence before authorizing merge to `main`.
