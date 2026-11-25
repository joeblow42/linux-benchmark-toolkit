# G5-04 / RP-03.3 Increment 51 — witnessed source selection and termination

**Owner authority:** Alternative A explicitly approved 2026-11-16 in LBT engineering conversation. Continues owner-approved Alternative B FAT Roadmap Rev 0.2. **Implementation candidate only**; schema v1.0.0 and the existing 41 status pairs remain frozen.

## Scope

`UnifiedCollectorEngine.run()` now returns an immutable `SessionExecution` when it returns normally or is deliberately cancelled *between* source attempts. The in-memory witness records the ordered selected collector IDs, selected source IDs, exact planned per-source attempt IDs (including two SRC-23 calls and multiple requested O1 devices), actual UTC session start/end and measured monotonic elapsed milliseconds, and terminal `FINISHED` or `INTERRUPTED`.

`FINISHED` means only that the engine traversed its selected source plan, **not** that any acquisition succeeded or that benchmarks/reporting ran. A caller-provided optional `cancel_requested()` boolean callback permits safe cancellation between attempts; completed actual receipts survive, unattempted calls get no synthetic receipt. The feature does not catch/swallow unexpected adapter exceptions or KeyboardInterrupt, never bypasses consent and never adds source invocations. No separate collector engine, extra worker or privileged operation is introduced.

`EngineRun.execution` is optional/default None to preserve legacy synthetic/manual test fixtures, where lack of a witness is never interpreted as completion. The witness is **in-memory only in this increment**. Increment 52 may translate verified execution scope into approved D-02 session header/status/manifest fields with a new independent reconciliation and validator; do not claim durable or fully complete session state from this Increment 51 alone.

## Verification

Eight independent `tests/test_g5_cp03_rp03_lifecycle_witness_51.py` cases check normal selected scope, UTC/monotonic timing, SRC-23 planned two calls, O1 multiple target attempts, cancellation before first and after one actual source attempt, normal traversal of denied O1, invalid cancellation API and ordinary source-adapter exception propagation. Dedicated workflow step plus full regression. These are mock dispatcher tests, not physical Bodhi Linux 7 host FAT, CP-02 acceptance or actual interruption of a blocking command.

## Protected boundaries

No changed D-02 schema/status pair, privacy/report output, TUI viewer, source command, privilege, consent, capture ceiling, evidence preservation, or host benchmark. No PR merge, release or FAT entry authorized. Original 39 CP-02 formal acceptances remain zero.

**Increment 52 gate:** reconcile the witnessed planned-vs-actual attempt list with receipt and acquisition status evidence; only a truly finished and all-OK selected acquisition may be declared COMPLETE. Record actual timing in approved nullable fields, and mark interrupted/partial/zero-observation honestly. Revalidate without trusting a simple finished flag alone.
