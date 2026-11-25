# Operator-controlled thresholds: change plan

## Purpose

This plan describes the work to make the LBT's numeric workload thresholds, safety cutoffs, and resource ceilings editable by the operator in a separate configuration file. It is a planning document only. No threshold behavior is changed by this file.

The intended outcome is one operator-edited file that supplies the effective values for every workload and acquisition bound. The program reads and validates it once at run start, applies that snapshot consistently, and records the exact effective configuration with the run. Missing, malformed, internally inconsistent, or unsupported configuration must stop the run with a clear error. Numeric defaults must live in the file, rather than be silently repeated as fallback values in Python.

## Current state

[`LBT_THRESHOLDS.md`](LBT_THRESHOLDS.md) is a human-readable reference, not an executable configuration file. Runtime values are currently distributed among Python constants, dataclass defaults and validation ranges, CLI defaults, worker command limits, source authorization policy, privileged helper contracts, and report validators. Some values are also repeated in documentation and tests.

Changing only `LBT_THRESHOLDS.md` would therefore not change test behavior. A complete migration must make the file the runtime source of truth and update each consumer that currently embeds or verifies the numeric values.

## Threshold and bound inventory

| Area | Current values and examples | Main code locations to migrate |
|---|---|---|
| Host I/O safeguards | Notify above 50%; stop at 75%; telemetry missing/lost behavior; normal sampling interval | `lbt_g5/core_workloads.py` (`IO_NOTIFY_PERCENT`, `IO_STOP_PERCENT`, `IOPressureGuard`), `lbt_g5/video_workload.py`, `lbt_g5/sustained_workloads.py`, DVD decode check |
| CPU and memory pressure preflight | CPU pressure 25% for short CPU, 15% for sustained CPU/video; memory pressure 10% for memory and concurrent video | `lbt_g5/core_workloads.py`, `lbt_g5/sustained_workloads.py`, `lbt_g5/video_workload.py`, `lbt_g5/jellyfin_workloads.py`, `scripts/rp08_dvd_decode_check.py` |
| Thermal and headroom cutoffs | 80°C default and the currently accepted 45–90°C input range; 16× available-memory factor for memory-copy test; 768 MiB per concurrent stream; telemetry-validity rules | `lbt_g5/sustained_workloads.py`, `lbt_g5/video_workload.py`, `lbt_g5/core_workloads.py`, `lbt_g5/jellyfin_workloads.py`, `lbt_g5/workload_cli.py` |
| Workload size and duration bounds | CPU/memory sample durations and workers; storage payload and operation count; sustained duration, scratch size and target rate; video media/wall durations, thread count, fixture size and dimensions; network peer duration, rate, streams and timeout | `lbt_g5/core_workloads.py`, `lbt_g5/sustained_workloads.py`, `lbt_g5/video_workload.py`, `lbt_g5/peer_workload.py`, `lbt_g5/jellyfin_workloads.py`, `lbt_g5/workload_cli.py` |
| Runtime resource ceilings | Maximum CPU workers, memory and disk reservations; free-space reserve; concurrency reservations | `lbt_g5/workload_runtime.py`, `lbt_g5/workload_cli.py`, workload registration functions |
| External command bounds | Per-command wall deadline and combined stdout/stderr cap; FFmpeg probe/encode limits; DVD imaging worker deadline and output cap; DVD decode/extraction/verification deadlines and diagnostic cap | `lbt_g5/workload_process.py`, `lbt_g5/video_workload.py`, `lbt_g5/optical_workload.py`, `lbt_g5/peer_workload.py`, `scripts/rp08_dvd_decode_check.py` |
| Optical-media bounds | DVD maximum capacity, sector/chunk size, retry count, read deadline, private output reserve, title and media-duration bounds, fixture byte cap | `lbt_g5/optical_workload.py`, `lbt_g5/optical_worker.py`, `scripts/rp08_dvd_decode_check.py` |
| Evidence and run budgets | G4-07 run ceiling of 180 seconds and 512 MiB; per-source byte, entry/call and time limits for SRC-01 through SRC-28; per-target limits; evidence stream caps and parser/receipt input caps | `lbt_g5/safety.py`, `lbt_g5/evidence.py`, `lbt_g5/passive_worker.py`, `lbt_g5/runtime.py`, `lbt_g5/additional.py`, `lbt_g5/records.py`, `lbt_g5/canonical_session.py`, normalizer modules |
| Privileged health-query bounds | 4 KiB request frame; 12 MiB response frame; 8 MiB health output; 12-second query; 32 requests per run | `lbt_g5/privilege_contract.py`, `lbt_g5/privileged_session.py`, installed helper implementation and helper installer |
| Result classifications | Proposed video 1.5× and DVD 2.0×/0.75× realtime boundaries; sustained CPU 90%/70%; backup throughput 80/30 MiB/s; integrity and thermal overrides | `docs/LBT_THRESHOLDS.md`, `docs/TEST_SPECIFICATION.md`, and any assessment/reporting code that turns these criteria into ratings |

The inventory also includes fixed bounds in normalization code that limit accepted input sizes (often 1 MiB), report/receipt parsers, and individual worker arguments. These are not performance thresholds, but they constrain test execution or evidence handling and must be classified explicitly. They should not be left behind just because they do not appear in the threshold reference.

## Proposed configuration behavior

1. Add a documented, operator-editable configuration file with a schema version, named sections, explicit units, and the values currently described by this inventory. A format supported by the shipped Python runtime should be selected before implementation; the test laptop currently uses Python 3.10, so choosing TOML would require either a dependency or a compatible parser.
2. Add one loader that reads the file once, validates required keys, types, units, and cross-field relationships, and returns an immutable run configuration. Do not allow individual workloads to reread the file or resolve different values during one run.
3. Make the operator-supplied numbers authoritative. Do not silently clamp them to a second set of numeric constants or fall back to hardcoded defaults. Invalid or absent values fail before any workload starts. Structural checks remain necessary (for example, positive durations and a stop threshold not below a notification threshold), but must not reintroduce hidden operator-inaccessible numeric cutoffs.
4. Thread the immutable configuration through the CLI, runtime, workload constructors, worker requests, source policies, and privileged health session. Replace dataclass defaults, literals, validation maxima, and helper-side numeric checks with values from this snapshot wherever they represent a tunable test bound.
5. Include the effective configuration values, schema version, source path, and a digest of the exact file in private run evidence and result metadata. Reports should state which limits were active, including when a native-speed DVD mode intentionally reports I/O pressure without enforcing the ordinary I/O stop.
6. Keep executable path allowlists, exact command templates, target validation, consent checks, ordinary-user requirements, and private-file handling distinct from numeric thresholds. A text file should control the numeric budget; it should not become a mechanism for supplying shell commands, arbitrary paths, or bypassing consent.

## Policy and compatibility work

The acquisition ceilings in `safety.py` are tied to the accepted G4-07 source policy. `records.py` and `canonical_session.py` currently validate captured evidence against those fixed values. Making these operator-controlled means the run's policy snapshot must be carried into acquisition and validation so the validator can prove that each observed limit matched the exact policy used for that run.

This changes the meaning of the current fixed G4-07 limits. Before implementation, the project owner must decide whether an edited file may raise each existing ceiling without a second numeric maximum, and whether the controlled requirements/policy revision and serialized evidence schema need a revision. If operator control is intended to include raising every listed ceiling, the implementation and its documentation must say so directly; it must not advertise full operator control while retaining undocumented code caps.

The privileged health helper is separately installed and independently validates requests. It must receive the run's approved numeric policy through a trusted, versioned protocol or a securely selected matching policy snapshot. Changing only the unprivileged Python caller would leave the helper's limits hardcoded and would not complete this work.

## Test and documentation work

Update focused tests for each migrated consumer and add shared configuration-loader coverage for:

- shipped values matching the current documented behavior;
- valid operator edits changing effective behavior for each threshold category;
- missing keys, unknown keys, wrong types/units, invalid relationships, unreadable files, and unsupported schema versions failing before workload execution;
- loading once per run and recording a stable effective snapshot/digest;
- propagation of custom run/source limits through workers, evidence writing, privilege protocol, and canonical validation;
- helper and caller disagreement being rejected;
- native-speed DVD pressure reporting continuing across the ordinary I/O stop while its separate deadline and thermal behavior remain intact;
- every report showing the actual configured values rather than the old defaults.

Update `LBT_THRESHOLDS.md`, `TEST_SPECIFICATION.md`, development usage, operator configuration examples, packaging/install locations, and the controlled G4-07 or requirements records affected by changing source budgets. The markdown reference should be generated from, or checked against, the same configuration schema to avoid another source of truth.

There are 111 test files in the repository. The directly relevant focused suites include core, sustained, video, Jellyfin, optical, workload runtime, subprocess runner, source safety/evidence, privilege contract/session, and canonical-session tests. A complete change needs focused coverage for each affected group plus the full established regression suite because acquisition limits and evidence validation are cross-cutting.

## Estimated size and sequence

This is a **large, cross-cutting change**, rather than a small edit to one threshold table. A reasonable breakdown is five to seven reviewable increments:

1. Inventory and version the schema; add the loader and validation rules; add an operator example and fail-closed startup behavior.
2. Migrate B/C workload thresholds, thermal limits, resource reservations, and their CLI/default wiring.
3. Migrate DVD, video, Jellyfin, storage, and peer workload bounds and subprocess limits.
4. Migrate G5 acquisition/source budgets and evidence writer policy propagation.
5. Migrate privileged helper budgets and its versioned policy exchange.
6. Update canonical evidence/report validation to validate against the recorded per-run policy snapshot; update schemas and controlled policy documentation.
7. Complete cross-cutting regression coverage, packaging/docs, and verify a changed configuration end to end on disposable fixtures.

The exact increment count depends mainly on whether increasing the G4-07 and privileged-helper ceilings requires a separate requirements/policy approval and serialized schema revision. The workload-only portion is moderate; including every acquisition, evidence, and helper cap makes the overall work large.

## Completion criteria

- Every numeric workload, safety, resource, time, byte, retry, parser, and evidence bound in the inventory has an explicit configuration key or a documented reason it is a fixed structural invariant.
- No runtime consumer silently uses an old numeric fallback when an operator file is selected.
- The exact active policy is immutable for a run and is recorded so outputs remain interpretable and verifiable later.
- The helper, acquisition engine, evidence writer, and validators agree on the same policy snapshot.
- An operator can edit the file, rerun a fixture workload, and see the changed value enforced and reported without editing Python source.
