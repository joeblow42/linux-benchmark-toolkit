# LBT — G5-04 / RP-03 / CP-03 Increment 45 verified engineering handoff

**Date:** 2026-11-14. **Governance:** AI-Assisted Software Engineering Governance Standard v1.0, approved FAT Readiness Roadmap, Requirements Rev 1.6. The following is **candidate engineering evidence only**; no formal owner CP-02 acceptance, CP-07 gate, FAT, merge or release is authorized.

## 1. Authoritative recovery and exact implementation CI

Repository: https://github.com/joeblow42/linux-benchmark-toolkit

- Previous verified Increment 44 branch `g5/cp03-rp03-d02-validator-44`, exact head `c2003906c10e9351b49814869e55a97c545c60db`, draft PR #69.
- **Increment 45 branch** `g5/cp03-rp03-d02-producer-45`, **draft PR #70**, base is Increment 44 PR #69, stacked #70 → #69 → #68 → #67 → #66 and earlier drafts. Do **not merge**.
- **Verified implementation commit** `fe208c1abb9ab441c332b1187ad9373b17561c00`. GitHub Actions **PR run 43655270253 SUCCESS** and **push run 43655266526 SUCCESS** at precisely this SHA.
- The JSON checkpoint and this handoff are committed *after* implementation-head CI, so the next agent **must** check PR #70's final current head SHA and its exact-head CI; the final checkpoint-head CI and SHA will be recorded on PR #70 as a durable comment after that CI completes. Do not confuse the implementation SHA with a subsequent checkpoint commit.

## 2. Governing frozen authority

The controlling, byte-verified CP-01 §6 D-02 approval ODT had SHA-256 `6d836d28af086a0fec7df2ca0949faf9447f9cee29cfabb8751344bd5104c98b`. Its frozen source-backed ledger is `verification/g5_04/rp03_cp01_d02_approved_contract_43.json`; original source retention ZIP and historical audit verified in Increment 43. Never rebuild D-02 from provisional code or change field names to accommodate it.

Production canonical schema **1.0.0**; status schema **1.0**, **exactly 14 status fields** and **41 approved status domain/status/reason combinations**. Preserve CP-01 D-01–D-05 and RP-02 private receipt v0.6 Choice A. Requirements Rev 1.6 has **283** controlled requirements.

## 3. Increment 45 source-first RED → GREEN audit

New `tests/test_g5_cp03_rp03_producer_45.py` contains **13** producer/validator source-first positive/negative cases; workflow `.github/workflows/test.yml` invokes this as its own gate. All 13 and the complete applicable unified suite passed at `fe208c1abb9ab441c332b1187ad9373b17561c00` in both PR/push exact-head runs.

- Initial test-only `cb8d31041c20336606b7b71d5e4ee98ace18706f`: PR CI **43653874608** expected RED; the eight initial tests exposed provisional `system.json` and `session_manifest.json` fields, missing SourceAttempt fields and rehashed unknown-key acceptance.
- Follow-on test-only `0f4b3b591d5c6085b143b14b50f02e7111334f44`: push CI **43654885809** expected RED; independently demonstrated three rehashed contradictions accepted before repairs: observation linked to session orchestration rather than its single-source status, evidence representation inconsistent with original discriminator, and original receipt byte aggregate exceeding sealed evidence.
- Orphan source-first `432c7d5464ef0e5002884cee6640172cf6184e6a`: PR CI **43655175070** expected RED; a type/enum-correct extra acquisition status was accepted even though no observation or source attempt referenced it.
- Green repairs culminated at `fe208c1abb9ab441c332b1187ad9373b17561c00`: CI **43655270253** PR and **43655266526** push SUCCESS. The additional source-first actual D0 `SRC-12` file-limit fixture verified one approved `CaptureLimit` entity, precise limit ID in attempt/status/manifest, and original byte integrity.

Candidate existing tests were changed only to reconcile provisional **flat** count references with approved D-02 **nested `counts`**. CP-02 review guard F-06 no longer marks a valid candidate production shape as expected failure. F-02 and F-04 review guards are still recorded separately and original CP-02 cases remain **0 formally accepted**.

## 4. Implementation and protected engineering boundaries

Changed production `lbt_g5/canonical_session.py` only for the approved D-02 producer/validator migration; `lbt_g5/host_smoke.py` only to display `manifest["counts"]["observations"]`. Canonical output preserves separate restricted `system.json`, `source_attempts.json`, `status_records.json`, `session_manifest.json`; the original G5-02 source-attempt receipts and original G5-03 sealed evidence bytes remain untouched.

The producer now emits exact D-02-required session header, 24-field SourceAttempt entity, approved EvidenceArtifact representation and restricted path, nested seven-field `Counts`, receipt digest maps and full ID lists. No fictitious whole-run clocks, tool versions, errno or seals; unknowns remain nullable; zero-observation denial is valid but does **not** establish completeness. The D-02 pure shape validator gates every private file before publication. Read-only validation rechecks file digests and D-02 shapes, same-run attempt/collector/source/authorization relationships, original sealed evidence SHA/size and representation, receipt SHA/size/content/byte aggregate, status/provenance relationships, real source-limit owners, manifest counts/IDs, and rejects orphan acquisition statuses and rehashed tampering.

Actual source limits are still determined by existing G4-07 and independently witnessed RP-02 rules, **not reconstructed from status or schema**. Per-artifact `EvidenceArtifact.limit_record_ids` remain empty unless individually proved; capture-limit records are correctly linked at source attempt, status and manifest levels; source-to-artifact attribution must be further examined in RP-03.2. Existing file no-replace/atomic finalization remains unchanged.

No changes to `lbt_g5/safety.py`, `lbt_g5/o1.py`, `lbt_g5/privilege_contract.py`, `lbt_g5/privileged_session.py`, `packaging/lbt_root_helper.py`, `lbt_g5/evidence.py`, `lbt_g5/canonical_contract.py`, `lbt_g5/o1_execution.py`, `lbt_g5/records.py`, `lbt_g5/engine.py`, `lbt_g5/d02_schema.py`. Do not change source argv, allowlists, consent, sudo/helper protocol, source count/time/byte ceilings, raw evidence, production schema 1.0.0, status 1.0/41, unified IC-02 architecture, FR-121 public evidence exclusion, or add a TUI report viewer. All candidate PRs must remain draft/unmerged.

## 5. Remaining work and exact starting increment

**Begin Increment 46 / RP-03.2** only after reading/validating this checkpoint, PR #70 final head, and exact-head CI, followed by the controlling D-02 ledger and source files. First assess all registered source-family typed/lossless normalization and provenance contract coverage; develop independent source-first positive/negative/boundary/adversarial tests for a **real two-original contributor datum**, multiple artifacts with same-source attribution, and same-bytes/different-attempt IDs. Require evidence refs and status relationships to point to original actually sealed contributors, not invented paths; keep unparsed source data lossless and private. Split RP-03.2 into bounded independently verified increments with draft stacked PRs as needed.

Continue afterwards RP-03.3 approved D-05 lifecycle validity vs completeness, zero-observation sessions, interruption and truthful limitations; RP-04.1 independent original **39** CP-02 cases; RP-04.2 CP-04 persistence/tamper/atomicity; RP-04.3 CP-05 cumulative RTM and real CP-06 **Bodhi Linux 7 AMD64** host/consent/device proof; RP-04.4 CP-07 explicit owner review. No formal acceptance can be inferred solely from candidate workflow green.

## 6. Acceptance gates and conversation safety

RP-03.1 **candidate implementation verified**, RP-03 **OPEN**, RP-04 **OPEN**, G5-04 **OPEN**. Original CP-02 **0/39 formally accepted**, Rev 1.6 **283 NOT_VERIFIED**, Bodhi 7 physical FAT **NOT_EXECUTED**, FAT readiness **NOT ESTABLISHED**, release **NOT AUTHORIZED**. No material owner decision presently pending.

**Conversation handoff recommended after 45** to preserve accuracy after extensive source recovery, multiple RED→GREEN iterations and CI evidence. This is not a product failure. Review and validate PR #70 and GitHub CI before starting new changes.

Suggested next-conversation opening:

> Continue Linux Benchmark Toolkit from the verified G5-04 / RP-03 / CP-03 Increment 45 checkpoint under Engineering Governance Standard v1.0 and the owner-approved FAT Readiness Roadmap. Repository `joeblow42/linux-benchmark-toolkit`, draft PR #70 on draft PR #69, current verified implementation `fe208c1abb9ab441c332b1187ad9373b17561c00`, CI PR 43655270253 and push 43655266526 SUCCESS. Fetch `verification/g5_04/rp03_increment45_verified_checkpoint_20261114.json`, `verification/g5_04/rp03_increment45_continuation_handoff_20261114.md`, and the frozen D-02 ledger directly from GitHub at PR #70's latest head. Check any later checkpoint commit and exact-head CI, re-verify draft PR ancestry and protected boundaries, then begin Increment 46 / RP-03.2 typed/lossless multi-original provenance source-first. Preserve all owner approvals, never modify source commands/consent/helper/limits, canonical 1.0.0/status 1.0/41, or sealed evidence; no PR merges or formal FAT acceptance without owner authority.
