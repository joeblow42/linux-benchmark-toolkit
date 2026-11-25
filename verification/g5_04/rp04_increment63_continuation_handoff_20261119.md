# LBT RP-04 Increment 63 — typed/lossless CT-09 candidate continuation

**2026-11-19 local** · AI-Assisted Software Engineering Governance Standard v1.0 · owner-approved Alternative B FAT Rev 0.2.

## Recover from GitHub

- Repository https://github.com/joeblow42/linux-benchmark-toolkit
- Development branch `g5/rp04-ct09-lossless-data-63`, **draft PR #89** stacked on draft #88 → #87 → #86 and all predecessors. DO NOT MERGE.
- Verified implementation HEAD: `c3cb73d2df2ec712f284573472ad3a155e2c222c`; [PR CI 44672121753](https://github.com/joeblow42/linux-benchmark-toolkit/actions/runs/44672121753) SUCCESS and [push CI 44672094308](https://github.com/joeblow42/linux-benchmark-toolkit/actions/runs/44672094308) SUCCESS. GitHub job logs show **4 of 4 CT-09 candidate checks actually executed and passed**, full validation SUCCESS.
- Machine per-case JSON artifact `rp04-ct09-candidate-63`, push artifact ID 14600876845. GitHub artifact retention applies.
- Recovery checkpoint/docs commit follows; verify exact final-head PR CI and push CI separately, then comment on draft PR #89.

## Scope and protected contracts

`tests/test_g5_cp03_rp04_ct09_63.py` with `scripts/rp04_ct09_case_runner_63.py` verifies original CT-09-P1/P2/N1/N2 through actual G5-02 EvidenceWriter sealed offline fixture bytes and actual G5-04 canonical producer/validator.

- P1 previously unrecognized SRC-02 attribute receives typed semantic observation with correct evidence/attempt; nonUTF8 retains byte-exact sealed BYTES_REF fallback and an attributable parser error, not fabricated normalized value.
- P2 recognized SRC-08 MemTotal `1024 kB` normalizes to `1048576` INTEGER bytes with correct parser findings and source provenance.
- N1 undeclared D-02 top-level/object keys are rejected as before.
- N2 ordinary regression simulated by dropping unknown semantic row **in memory only**; independent G5-04 source reparse/manifest identity detects the omission. No original or canonical file overwritten or rehashed.

No new source, privilege, consent, time/byte limit, schema v1.0.0, 41 status keys, acquisition path, host probe, public output or benchmark. Original **39 CP-02 cases formally NOT_EXECUTED / 0 accepted**, 283 requirements not formally verified. Previously deferred CT-08-N2 remains downstream G5-06 NOT_EXECUTED.

## Next bounded work

**Increment 64 / CT-10 P1/N1/N2/N3** are OFFLINE_FIXTURE under the approved case plan: manifest published last with real checks, missing/incomplete manifest rejected, ordinary corrupted-read/incorrect count detected without touching immutable raw originals, and duplicate run attempts refuse exclusive overwrite. Avoid hostile-person or rehashed-manifest tampering campaigns. Preserve source/privilege/schema/status and draft PR stack. Require exact-head CI and checkpoint.

## Conversation safety / next owner gate

No substantive failure or owner action through Increment 63 implementation. The subsequent **CT-11-P1** is physical Bodhi 7 read-only host and explicitly separately owner-gated; do not execute it without a constrained approved plan. CT-11-N2 needs G5-06 and CT-11-N3 TUI downstream. Stop for these decisions/limitations after safe offline increments.
