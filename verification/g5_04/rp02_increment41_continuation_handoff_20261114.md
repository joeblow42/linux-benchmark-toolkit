# Linux Benchmark Toolkit — G5-04 / RP-02 / CP-03 Increment 41 engineering continuation

Date: 2026-11-14. **Governing authority:** AI-Assisted Software Engineering Governance Standard v1.0; owner-approved First Article Test (FAT) Readiness Roadmap; Requirements Rev 1.6 (283 controlled, of which 210 FAT mandatory, 65 conditional, 8 deferred). Preserve all RP-01 scope dispositions and the owner-approved RP-02 private operational receipt v0.6 Choice A.

## Authoritative exact recovery

- Repository: https://github.com/joeblow42/linux-benchmark-toolkit
- Known-good starting baseline: Increment 39 verified `b7797b80188f228b4a7d15f5cc8ba28e9d71062f`, PR #64, exact-head CI `43630844392` SUCCESS.
- Increment 40: branch `g5/cp03-rp02-o1-transport-40`, draft PR #65 stacked on #64. Implementation `4166c2bcd08450f6246f9df42f27bee3811c647d` CI `43632760912` SUCCESS; checkpoint head `6020bdb64b61f23d5ae6ab8cd42dc96aa1d08728`, exact-head CI `43632910220` SUCCESS.
- Increment 41: branch `g5/cp03-rp02-o1-aggregate-41`, draft PR #66 stacked on #65. Implementation `8351e0f4b149f7a94cd6e7a9bf9aaa8904371382` CI `43633380973` SUCCESS; checkpoint head `f21c29983cd602db424e5845467704fdccf4293a`, exact-head CI `43633514052` SUCCESS.
- **Important:** This detailed handoff itself is committed after the checkpoint CI. The next session MUST verify the final handoff-commit branch head and its exact-head SUCCESS workflow before continuing.
- Source-first tests and oracles were committed BEFORE production modifications. Preimplementation failure at the new intended test step was observed, followed by successful implementation-head and checkpoint-head CI. Earlier failing runs are not acceptance evidence.

## Increment 40 — Transport applied limit, narrow candidate

Source-first oracle `verification/g5_04/cp03_rp02_o1_transport_oracle_40.json`, test `tests/test_g5_cp03_rp02_o1_transport_40.py` (eight methods).

- **SRC-18** direct `sg_get_config`: unambiguous combined-byte overflow at exactly approved 4MiB, only when stdout and stderr are both nonempty and each individually below its cap, total sealed original exactly 4MiB, positive known original omission, no timeout or competing writer clipping.
- **SRC-21** direct `vainfo`: same narrow mechanism at exactly approved 8MiB.
- **SRC-13** existing privileged helper: a returned full sealed 8MiB combined original with a positive exceeded-limit omission proves the actual effective cap was the entire 8MiB per-request cap; a helper internal lower cumulative remaining cap could not return that much original. No helper changes or introspection used.
- **Must not infer** a shorter helper-effective byte ceiling, stream-versus-combined tied direct event, timeout-plus-overflow, missing extent or earlier unsealed bytes. Source receipt v0.6 only when corroborated; unsupported limit events fail closed at canonical.
- Existing same-run sealed D0 inventory, exact operator consent, target, registered argv, actual in-memory transport and original artifacts are required independently of receipt claim.

## Increment 41 — SRC-18 cumulative source-writer limit, narrow candidate

Source-first oracle `verification/g5_04/cp03_rp02_o1_aggregate_oracle_41.json`, test `tests/test_g5_cp03_rp02_o1_aggregate_41.py` (seven methods).

- Two authorized 4MiB SRC-18 calls can fill its existing 8MiB source EvidenceWriter allowance *without clipping*. A third separately authorized call with positive raw input may be clipped entirely by the existing writer-source meter.
- New private v0.6 source-writer fact is **only** `SRC-18:callNNNN:source:writer`, threshold/observed exactly 8MiB with positive omitted extent and no transport timeout/overflow.
- Canonical independently totals the exact same-run sealed SRC-18 original artifacts, requires 8MiB and unique evidence identifiers, matches the current original clip and O1 consent/inventory/approved argv. It refuses omitted previous originals, unsealed source reservations, forged dimensions, absent extent.
- SRC-21 has a one-call ceiling and an 8MiB per-call/source byte cap: no later executed positive source-writer event is evidenced. Do not invent one.
- SRC-13 helper internally enforces 32MiB, 60s cumulative per-run caps, and can lower an individual request. Its currently approved response lacks exact effective reduced caps; refuse such claims. No privileged helper or wire protocol was modified.

## Engineering boundaries — unchanged

- Fixed `SRC-13` SMART/NVMe, `SRC-18` optical and `SRC-21` VA-API tool argv and device allowlist.
- Operator per-run/target/operation consent, root-helper permissions and installed helper protocol.
- G4-07 ceiling registry (source bytes, per-call/per-target/run bytes/seconds, slots and count).
- Canonical schema 1.0.0, exact approved D-02 CaptureLimit entity/field contract, status schema 1.0 and 41 approved status/reason pairs.
- Original sealed raw evidence and public privacy restrictions; no public serialization contract changes.
- Source catalog, `lbt_g5/safety.py`, `lbt_g5/o1.py`, `lbt_g5/privilege_contract.py`, `lbt_g5/privileged_session.py`, `packaging/lbt_root_helper.py`, `lbt_g5/evidence.py`, `lbt_g5/canonical_contract.py` unchanged since Increment 39.

The only production files changed since Increment 39 are `lbt_g5/o1_execution.py`, `lbt_g5/records.py` and `lbt_g5/canonical_session.py`. Test workflow, two new fixture modules, two new source-first oracles, and two checkpoint records were added or changed. GitHub compare from `b7797b8` to `f21c299` was ahead-only, 15 commits, with zero protected paths changed.

## Remaining work and order

1. **Increment 42 / complete RP-02.3 assurance:** source-first explicit positive/negative/boundary feasibility for O1 direct per-target deadlines and cumulative source seconds/call count; isolate source wall timing from transport-process deadline and time spent after capture in evidence sealing. Inspect `SourceCallBudget`, `_capture_child`, `execute_optional`, `PrivilegedSession.capture`, and `_limit_run_request` directly. Prove actual applied threshold and reached event; never infer an omitted operation from elapsed time or deny. Refuse promotion of SRC-13 internally reduced helper byte/time events lacking effective-cap attestation.
2. For any necessary change in **protected** helper protocol/privilege/consent or approved ceiling, **STOP** and present explicit alternatives for owner authority; none is preapproved. Conservative non-promotion is permitted without new authorization; document any resulting coverage gaps honestly.
3. After RP-02 evidence and gap disposition, continue **RP-03 F-06 / D-02 exact production canonical producer-validator contract conformance**. Source-first cross-check 1.0.0 schema, D-02 multi-limit references, 41 status pairs and unclassified-public-field behavior.
4. Continue **RP-04** independent original 39 CP-02 case assurance, all 283 Rev 1.6 requirements verification, real Bodhi Linux 7 AMD64 original acquisition, consent and helper behavior and FAT evidence. CI mock success is **not** CP-02 acceptance or real host verification.
5. Continue later owner-approved FAT readiness roadmap increments, raising only actual material owner decisions.

## Current gate status

G5-04 **OPEN**; RP-02 **PARTIAL**; RP-03 and RP-04 **OPEN**; all 283 controlled requirements **NOT_VERIFIED**; original 39 CP-02 cases **NOT_ACCEPTED**; independent assurance **OPEN**; Bodhi 7 AMD64 host proof **NOT_EXECUTED**; FAT readiness and release **NOT AUTHORIZED**. PRs #55–66 remain draft/unmerged at last inspection.

## Conversation integrity and next-session instruction

A new conversation is recommended now because two source-first implementation increments, multiple private contract reviews, substantial GitHub Actions CI and 15 dependent new commits have accumulated. This is a context-integrity precaution, not a project defect. No routine owner decision was needed for Increment 40/41.

**Next conversation opening:** Continue LBT from the authoritative Increment 41 GitHub checkpoint and this handoff. Read both files directly from PR #66 head; verify exact-head CI for the final handoff commit, repo identity, PR #66 → #65 → #64 ancestry and protected boundaries. Then begin Increment 42 source-first O1 remaining time/call-count/helper cumulative-limit assurance without changing any protected authority. Continue autonomously until an actual owner decision or conversation-integrity checkpoint is needed. Keep every PR draft/unmerged.
