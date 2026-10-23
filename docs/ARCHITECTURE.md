# Architecture — Linux Benchmark Toolkit

Status: initial design baseline (2026-10-20).

## Scope
Portable, offline-capable Linux x86_64 toolkit runnable from a persistent Bodhi USB and movable to a future SSD toolkit. Other Linux architectures are future extensions, not implied support.

- **TUI:** Dialog, keyboard-driven; headless CLI also supported.
- **Engine:** modular Bash, with safe external benchmark utilities.
- **Reporting:** self-contained HTML as primary output, versioned canonical JSON, and CSV metric exports.
- **Modes:** discovery, standard, extended.
- **Workloads:** DVD imaging and video conversion, Jellyfin Direct Play and transcoding, backup and Samba; CPU/RAM/storage/network/thermal/reliability baseline.
- **Offline:** operation and reporting do not require Internet access.

## Layers
1. `benchmark` launcher resolves its own directory, checks host compatibility and privileges, and dispatches CLI or Dialog.
2. `tui/` owns input, confirmations, selection, status and report navigation. No benchmark or assessment logic in the TUI.
3. `lib/` provides configuration, inventory, dependency resolution, session management, monitoring, validation, cleanup and logging.
4. `tests/` modules implement standardized test interfaces and return structured measurements.
5. `reporting/` calculates assessments and produces HTML/JSON/CSV output without needing to rerun a benchmark.
6. `packaging/` inventories/bundles permitted dependencies, captures licenses and versions, and produces a checksummed release archive.

## Data contract
One results directory per host/session:
`results/<sanitized-hostname>_<UTC-date>_<unique-id>/`

- `system.json`: host/OS/hardware metadata, privacy-redacted by default.
- `benchmarks.json`: tests, settings, measurements, units, status, tool versions and evidence.
- `assessments.json`: workload ratings, thresholds, evidence references, confidence, exclusions.
- `*.csv`: tabular and time-series numeric measurements.
- `logs/`: stdout/stderr and diagnostics with sensitive-data review.
- `report.html`: self-contained HTML with inline styling/charts/data, works from a `file://` URL.

Schema version starts at `1.0.0`. CSV is a derived export; JSON is canonical. Preserve raw values, units, fixture IDs and sampling interval.

## Test states and outcomes
Execution status: COMPLETE, SKIPPED, UNAVAILABLE, FAILED, INTERRUPTED.
Suitability: GOOD, MARGINAL, POOR, NOT_TESTED.
Confidence: HIGH, MEDIUM, LOW, INSUFFICIENT_DATA.
Do not equate missing data with a failed benchmark. Capability, actual performance and reliability are separately reported; critical gates determine the workload classification.

## Safety and integrity
- No raw-block-device writes, repartitioning or formatting.
- Storage writes only within isolated paths explicitly validated against reserved free space, with uniquely named files and controlled cleanup.
- Explicit opt-in for sustained stress, live optical imaging, remote network throughput tests, and integration tests that affect services.
- Unprivileged default; targeted elevated actions only after permission and explanation.
- Monitor throttling, thermal state, disk errors, capacity and preexisting workload; enforce cancellation and bounded timeouts.
- No automatic package installation or unexpected external downloads.
- Record fixture provenance and checksums. Do not include copyrighted commercial DVD content as test fixtures.
- Default report redacts usernames, hardware serial numbers, IPs and other identifying details; optional opt-in detailed diagnostics.
- Preserve valid completed outputs from interrupted operations when available; never delete files that were not created by the toolkit. Under owner-approved IC-REC-01, no automatic or manual checkpoint resumption is supported: a subsequent run starts from the beginning. An abrupt kill or power loss does not guarantee that new final files are written. Single-file atomic replacement does not make a whole session transactionally complete.

## Portability contract
Package carries scripts, configuration, licensed distributable binaries where feasible, fixtures, Python runtime/libraries if needed, manifests and checksums. This does **not** make the toolkit independent of the host kernel, GPU driver stack, architecture, libc, permissions, or optical hardware. Detect incompatibilities and explain host-side requirements. Prefer ext4 for execution; an archive may be transported on exFAT and extracted to ext4. Relative paths only.

## Test-interface proposal
Each module exposes metadata (ID, dependencies, applicable modes, safety class, fixture requirements), preflight, execute, parse, and cleanup operations. Keep transient and final status separate. Inputs and outputs validated against a versioned schema.

## Minimum acceptance
Discovery runs without privileged destructive operations; Dialog menu and CLI select the same functions; JSON and CSV accompany every completed session; HTML opens offline; absent GPU, optical drive or network do not crash; no invented test results or unsupported workload ratings.
