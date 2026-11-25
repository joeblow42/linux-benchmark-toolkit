# G5-04 / RP-04 Increment 58 — CT-04 source-outcome evidence review

Date: 2026-11-18. Governed by AI-Assisted Software Engineering Governance Standard v1.0 and owner-approved Alternative B FAT Readiness Roadmap Rev 0.2. Draft PR stacked on Increment 57 PR #83. No merge or physical host authorization.

## Exact controlled case conditions

- CT-04-P1: a G5-02 `SRC-13` O1 attempt with absent consent, DENY/DENIED/OPERATOR_AUTH_REQUIRED, must produce private `UNAUTHORIZED/OPERATOR_AUTH_REQUIRED` with actual attempt ID, no original artifact and no fake privileged invocation.
- CT-04-P2: offline already-sealed `SRC-27` tool resolver observation for `lscpu` with null resolved path; separately persisted `SRC-05` UNAVAILABLE/EXECUTABLE_NOT_FOUND receipt yields `TOOL_MISSING/EXECUTABLE_NOT_FOUND`. **This fixture is not proof that lscpu is absent on a real computer or CI.** Exact live per-tool source-to-attempt correlation remains subject to independent acceptance assessment.
- CT-04-N1: unrecognized transport reason from ordinary unknown worker result must fail closed with no completed session or coerced FAILED/ACQUISITION_ERROR status.
- CT-04-N2: source absence must produce UNAVAILABLE/SOURCE_ABSENT, never COMPLETE/OK; capture with zero originals is also rejected.

All cases use isolated offline G5-02 operational receipts, the existing G5-04 canonical producer and validator; no sources are acquired, benchmarks run, or raw original files changed. Per-case CI artifacts record test facts without promoting them to formal CP-02 acceptance.

**Boundaries:** Frozen 41 status combinations, D-02 schema v1.0.0, source/privilege/consent/limit policy and raw evidence remain intact. Original 39 CP-02 cases formally NOT_EXECUTED/0 accepted, no independent reviewer, CP-07, Bodhi 7 host or FAT.
