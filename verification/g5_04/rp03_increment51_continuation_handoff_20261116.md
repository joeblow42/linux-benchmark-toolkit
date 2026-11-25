# LBT — Increment 51 owner-approved session-witness continuation

**G5-04 / RP-03.3** · Alternative A approved 2026-11-16 · Governing AI-Assisted Software Engineering Governance Standard v1.0 · FAT Roadmap Rev 0.2.

## Authority and recovery

- Repo: https://github.com/joeblow42/linux-benchmark-toolkit
- Planning authority: `verification/fat/altb_owner_approval_rev02_20261116.json`.
- Draft PR #77 stacked on #76; **keep draft/unmerged**. Verified Increment 51 implementation commit `156122e0f3aa58f2894f627ded46fd4df45f5baf` with PR CI `44028793468` SUCCESS and push CI `44028787123` SUCCESS. Verify *documentation-head* CI after this checkpoint/handoff commit.
- Owner's explicit RP-03.3 decision was Alternative A: minimum factual runtime selected-source/terminal witness, actual clock, interruption, reconcile planned vs performed; do not relax D-02 v1.0.0/status/privilege contracts.

## What Increment 51 did

`lbt_g5/engine.py` now returns `EngineRun.execution: SessionExecution | None`, carrying ordered selected collector/source IDs, exact planned source attempt IDs (including multiple O1 target attempts and SRC-23 two calls), witnessed UTC start/end, monotonic elapsed milliseconds, and terminal `FINISHED` or `INTERRUPTED`. Optional callback cancellation checks between attempts and returns only actually completed source receipts. Unexpected exceptions and KeyboardInterrupt are not silently converted to success.

Eight source-plan and cancellation tests in `tests/test_g5_cp03_rp03_lifecycle_witness_51.py` passed in explicit CI. First attempted CI failed solely from the test fixture passing an invalid run-directory name; corrected at `156122e0...` and verified by both workflows. No new source command, privilege, budget, schema, report, public view or status pair.

**Not yet durable:** canonical producer still conservatively labels every old D-02 session INCOMPLETE. Witness is in-memory until the next bounded producer/validator increment; do not declare successful acquisition from `FINISHED` alone. Original 39 CP-02 cases remain 0 formally accepted; no Bodhi Linux 7 physical FAT.

## Next bounded Increment 52

Reconcile `SessionExecution` against actual G5-03 sealed attempt receipts **before** any canonical success:
- Same run and selected collector/source ordering, exact intended attempt IDs and actual receipt attempt IDs; FINISHED must have every intended attempt; INTERRUPTED only a properly ordered prefix.
- Each acquisition result already validated via approved D-02 producer/status registry; COMPLETE only if every *selected* acquisition status is COMPLETE/OK, no missing source attempts and a witnessed FINISHED terminal event.
- A FINISHED session with denied/unavailable/partial source remains PARTIAL; witnessed cancellation produces INTERRUPTED. No witness (legacy/manual fixture) remains INCOMPLETE. Zero observations permitted as minimum-usable but cannot alone prove completeness.
- Set only **already approved** `SessionHeader` clocks/lifecycle, `StatusRecord` orchestration status/timing, `session_manifest.json` completion and finalization fields. Keep D-02 schema v1.0.0 and 41 status pairs; ensure `validate_canonical` checks status/manifest/lifecycle consistency. Never infer benchmark or hardware suitability.
- Use deterministic sealed original and cancelled-run scenarios plus explicit CI. Fail the increment if a missing attempt or non-OK source is promoted to COMPLETE. No hostile-actor scenarios, publication, new command, privilege or merge.

**Conversation integrity:** current repository/approval and CI consistent; safe to proceed with Increment 52 after exact final-head PR/push CI check; reassess after increment.
