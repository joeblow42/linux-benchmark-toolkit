# LBT RP-04 Increment 60 — exact CT-06 source timing handoff

**Date 2026-11-19, America/Denver** · AI-Assisted Software Engineering Governance Standard v1.0 · owner-approved Alternative B FAT Rev 0.2.

## Recovery

- Repository: https://github.com/joeblow42/linux-benchmark-toolkit
- Branch: `g5/rp04-ct06-measured-timing-60`; **draft PR #86** stacked on draft #85 → #84 → #83 → #82 and prior. DO NOT MERGE.
- Implementation head `6e7fe5ec430ea158e727facc39029160907f2fdc`.
- Exact implementation-head [PR CI 44670066694](https://github.com/joeblow42/linux-benchmark-toolkit/actions/runs/44670066694) SUCCESS, [push CI 44670060354](https://github.com/joeblow42/linux-benchmark-toolkit/actions/runs/44670060354) SUCCESS. Job logs show all four CT-06 development checks run and pass, zero skip, and unified full validation SUCCESS.
- Generated case artifact `rp04-ct06-candidate-60`, push artifact ID 14600120051; includes SRC-08 UTC/monotonic timing only, no raw memory data. Artifact retention is finite.
- Final checkpoint/docs HEAD will follow. Verify exact final-head PR/push CI separately before final checkpoint claim and annotate PR #86.

## Implementation and verification

CT-06-P1: genuine unprivileged CI Linux G5-03 source-first D0 memory acquisition of SRC-08, source receipt with measured UTC and monotonic elapsed_ms, exact binding to D-02 status/attempt and verified private manifest. CT-06-P2: O1 DENIED before execution leaves all source timing null. CT-06-N1: simulated ordinary producer data loss (removal of a clock from in-memory receipt view only) is rejected; original immutable receipt remains unchanged and valid after restoring reader. CT-06-N2: reversed UTC timestamps rejected in G5-02 and status validators. These are **development candidate** validations, NOT formal CP-02 acceptance.

Test-harness issue: initial `RUN=run-2026320206000` encoded minute 60; G5-02 correctly rejected invalid run ID (initial PR CI 44669911769 failed). Corrected to valid `run-2026320205900` without any production-code alteration. Re-run both workflows and full validation SUCCESS.

**Authority/protected controls**: 41 status combinations, D-02 schema 1.0.0, source/privilege/consent/limits, raw evidence, single engine and draft/unmerged PR stack unchanged. Original 39 CP-02 cases remain formally **NOT_EXECUTED, 0 accepted**; no physical Bodhi 7, CP-07, FAT, release or merge authorization.

## Next incremental review

Increment 61 CT-07 cases P1/P2/N1/N2. Respect owner threat-model correction: ordinary wrong-run, stale attempt, missing evidence and accidental byte corruption. Do not introduce adversarial forged-record/rehashed-digest campaigns. Use real G5-02 sealed fixture data, same-run multi-original support, distinct IDs for repeated identical bytes and read-only simulated missing/corruption via patched reads that never edits raw originals. Independently check technical feasibility before implementation. All formal acceptance remains owner gated.

## Conversation safety

Development authority coherent. Proceed only after final documentation-head PR/push CI both SUCCESS. Stop for substantive verification failure, changing protected contracts, physical host or CP-07/FAT decisions.
