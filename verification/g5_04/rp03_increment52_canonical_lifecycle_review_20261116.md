# G5-04 / RP-03.3 Increment 52 — witnessed canonical lifecycle reconciliation

**Approved authority:** RP-03.3 Alternative A explicitly approved by owner on 2026-11-16, under AI-Assisted Software Engineering Governance Standard v1.0 and Alternative B FAT Readiness Roadmap Rev 0.2. This increment is a development candidate, not formal acceptance.

## Purpose

Eliminate the previous indefinite INCOMPLETE lifecycle for a **witnessed, actually completed selected acquisition** without pretending that a finished source traversal proves each source successful or that any benchmark/reporting ran. Produce no new command or acquisition path. Preserve CP-01 D-02 schema 1.0.0, approved 14-field status envelope and 41 status pairs.

## Implemented

- New pure `lbt_g5/session_lifecycle.py` reconciles the actual immutable `SessionExecution` witness from Increment 51 with the ordered sealed source attempts/receipts and their existing D-02 acquisition outcomes. It verifies selected catalog ownership/order, fixed SRC-23 dual calls, bounded O1 multi-target ordinals, complete intended plan for `FINISHED`, and an actually incomplete planned prefix for deliberate `INTERRUPTED`. It does not run source code.
- The existing `build_canonical()` now sets only already-approved fields: `system.header.started_utc/completed_utc/lifecycle_state/collector_ids`, the orchestration `StatusRecord` status/reason/timing/detail/source_attempt_ids, `session_manifest.completion_state/finalized_utc`. The source plan and terminal event are recorded compactly as source attempt *identifiers* (not evidence or raw paths) within the existing private 1024-character status-detail field. No new D-02 field or sidecar schema.
- Factual conditions: `COMPLETE/ALL_REQUIRED_COMPLETE` and manifest `COMPLETE` only for witnessed FINISHED traversal where **every exact selected source attempt has a validated COMPLETE/OK acquisition status**; FINISHED with a denied, absent, malformed or incomplete source remains `PARTIAL/MINIMUM_WITH_GAPS` and manifest `PARTIAL`; deliberate cancellation returns `INTERRUPTED/RUN_INTERRUPTED` and manifest `INTERRUPTED`. Legacy/manual `EngineRun.execution=None` retains conservative `INCOMPLETE`, nullable whole-run clocks, and `PARTIAL/MINIMUM_WITH_GAPS`. Zero-observation minimum usable remains allowed but never alone establishes COMPLETE.
- The read-only `validate_canonical()` now independently checks persisted plan/actual attempt prefix, source status reconciliation, status/manifest/header states, actual UTC timing and finalized clock. The existing private consumer receives these approved semantic fields unchanged and remains unmasked, not a public report.
- Eight functional, source-first tests in `tests/test_g5_cp03_rp03_lifecycle_reconciliation_52.py` use actual `EvidenceWriter` sealed test bytes, existing G5-03 operational receipt builder, real single engine selection under a mocked fixed source-dispatch call, canonical producer/validator/private consumer. Cases: all-selected complete; missing D0 source partial; cancellation after one source; zero-attempt cancellation; missing and out-of-order selected receipts; legacy no-witness INCOMPLETE; pure persisted result contradiction. All existing CI steps retained.

## Limitations and gate

A `FINISHED` runtime witness is a successful *traversal of this selected source scope*, not completion of unselected hardware inventory, full first article, benchmarks, privacy-publication, RP-06 runtime mode or formal host FAT. `cancel_requested` is a cooperative between-attempt cancellation; a sudden process crash or OS signal is not yet a witnessed interrupted run. The formal CP-02 original 39 cases remain 0 accepted and physical Bodhi Linux 7 AMD64 FAT is not executed. CP-07 and release remain unapproved.

**Verification:** explicit GitHub CI step plus full Toolkit validation; publish implementation SHA and exact-head PR/push CI only after successful completion. Keep PR draft/unmerged.
