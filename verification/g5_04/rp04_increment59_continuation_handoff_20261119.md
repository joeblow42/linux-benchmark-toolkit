# LBT G5-04 / RP-04 — Increment 59 measured-source limit handoff

**2026-11-19 local**. Governed by AI-Assisted Software Engineering Governance Standard v1.0 and approved Alternative B FAT Readiness Roadmap Rev 0.2.

## Restore authority

- Repository https://github.com/joeblow42/linux-benchmark-toolkit
- Current development branch `g5/rp04-ct05-measured-limits-59`, **draft PR #85**, stacked on **draft PR #84** → #83 → #82 → #81 and earlier. DO NOT MERGE.
- Verified implementation head `0fde92dbd0a6b3759d780a05784d7d927263b0ea`, exact-head [PR CI 44669323852](https://github.com/joeblow42/linux-benchmark-toolkit/actions/runs/44669323852) SUCCESS and [push CI 44669297804](https://github.com/joeblow42/linux-benchmark-toolkit/actions/runs/44669297804) SUCCESS. Job logs confirm 3/3 bounded CT-05 candidate checks executed PASS, zero skip, and unified full validation PASS.
- Per-case GitHub Actions artifact `rp04-ct05-candidate-59` in push run, artifact ID 14599377688 (subject to artifact retention).
- Final checkpoint/docs commit will follow. Independently verify final exact-head PR/push runs before claiming documentation-head completion and record the numbers on PR #85.

## CT-05 candidate facts

- **P1** SRC-15 source-wrapper monotonic elapsed reached its real **15-second source wall ceiling** under a bounded Linux CI test. The worker transport and FS_STAT payload were **synthetic**. Real monotonic time elapsed and the G5-03 wrapper measured it; receipts `source_timing` and `limit_witnesses` and G5-04 D-02 CaptureLimit must agree in **seconds**, without any guessed omitted byte count. No actual mounted filesystem was queried.
- **P2** The actual G5-02 writer kept 2 MiB temporary synthetic source bytes and observed 8 omitted bytes on the next attempted item; D-02 CaptureLimit reports approved threshold/retained bytes and known omitted-at-least. No raw evidence modified.
- **N1** Time event reclassified as byte quota or as omitted bytes rejected before receipt commit.
- These are source-first **development candidate** checks only. **All 39 original CP-02 cases remain formally NOT_EXECUTED, 0 accepted**; 283 requirements remain formally unverified. No physical Bodhi 7 testing, independent CP-07, FAT entry or release.
- Protected: source commands, privileges, consent, collection limits, 41-pair status register, canonical schema v1.0.0, single engine and evidence preservation. No production code change.

## Next bounded increment

**Increment 60 / RP-04 CT-06** original cases P1/P2/N1/N2: measured source start/end UTC + monotonic elapsed; denied-before-execution retains nulls; completed source with a measured clock cannot drop all timing fields; reject completed-before-start timestamps. Prefer actual unprivileged Linux CI selected source *if no physical host or elevated controls are involved*, and exact offline negative conditions. Maintain separate CI candidate evidence and exact-head checkpoints.

## Conversation safety

No owner decision needed for offline/unprivileged CI continuation. Review exact-head CI and any substantive failures before advancing. Stop before physical Bodhi 7, CP-07, FAT or changes to frozen contracts.
