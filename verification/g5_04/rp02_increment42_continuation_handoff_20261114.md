# Linux Benchmark Toolkit — G5-04 / RP-02 Increment 42 verified continuation and RP-03 source-authority hold

Date: 2026-11-14. Governing authority: **AI-Assisted Software Engineering Governance Standard v1.0**, owner-approved **First Article Test (FAT) Readiness Roadmap** (RP-02 and RP-03), owner-approved CP-01 D-01–D-05, controlled Requirements Rev 1.6 (283 requirements, including 210 FAT mandatory, 65 conditional and 8 later release). Preserve all prior owner decisions, including the RP-01 applicability/disposition approval and RP-02 private operational receipt v0.6 Choice A.

## 1. Exact recovery and GitHub stack

Repository: https://github.com/joeblow42/linux-benchmark-toolkit (authenticated login joeblow42, owner with push access).

- Increment 39 accepted starting candidate: `b7797b80188f228b4a7d15f5cc8ba28e9d71062f`, draft PR #64, exact-head CI `43630844392` SUCCESS.
- Increment 40: draft PR #65 stacked on #64; checkpoint `6020bdb64b61f23d5ae6ab8cd42dc96aa1d08728`; CI `43632910220` SUCCESS.
- Increment 41: draft PR #66 stacked on #65; verified handoff head `fef623af250edd37552ca985b81fd4275ab3f388`; CI `43633763967` SUCCESS. This head and CI were independently checked before Increment 42.
- **Increment 42:** draft PR **#67**, branch `g5/cp03-rp02-o1-limits-42`, stacked on #66. Its focused test/CI implementation commit `4d94b03de99a3f879dcaf91ac4666cbb185b0c7b` passed exact-head PR CI **`43643119681` SUCCESS**.
- The Increment 42 checkpoint commit `86a60481b50bd4265f953596c4f65dd9f1c126ac` was verified by exact-head PR CI **`43643242099` SUCCESS** and push CI SUCCESS. This review-only handoff and RP-03 blocker record are committed *after* that checkpoint. **Verify the final handoff-commit HEAD and its exact-head GitHub Actions SUCCESS before implementation in a subsequent conversation.**
- No PR was merged or marked ready for review. Continue keeping all PRs draft/unmerged; do not rebase the stack without independently verifying ancestry.

## 2. Increment 42: source-first O1 time/count/helper cumulative-limit assurance

Committed source-first oracle `verification/g5_04/cp03_rp02_o1_limits_oracle_42.json`, nine synthetic tests `tests/test_g5_cp03_rp02_o1_limits_42.py`, and a standalone CI workflow test step. **No production implementation files changed in Increment 42.** All nine new tests passed in exact-head CI, as did the existing unified workflow. An initial CI run **`43643045357` FAILED** because a synthetic helper-usage fixture keyed an earlier run ID while the request came from `test_g5_root_helper`; the test-only fixture was corrected and rechecked in green CI. The initial failure is not an accepted product defect or acceptance evidence.

The independently inspected boundaries are:

- `SourceCallBudget.begin` reserves run/source subcalls and rejects already-exhausted count, duplicate subcall, or source cumulative elapsed seconds. The attempted next call returns `DENIED/SOURCE_CALL_LIMIT` **before** any O1 device command. Do not claim a CaptureLimit corresponding to an operation that never ran.
- `execute_optional` supplies its transport timeout as `min(plan.max_seconds, calls.remaining(...), writer.meter.time_remaining())`. An actual child `timed_out` is recorded truthfully, but the selected *effective* threshold is not independently attested by the current receipt. Source wall clock includes pre/post capture and sealing; it cannot be substituted for child timeout. Canonical correctly refuses unsupported D-02 time-limit promotion.
- The installed root helper `_limit_run_request` independently enforces SRC-13 **32 MiB / 60 seconds** cumulative limits, potentially reducing the individual request's effective bytes/seconds. On exhausted helper quota it refuses without executing. The installed response has no `applied_max_bytes` or `applied_max_seconds` fields; `TransportCapture` has no such fields either. Do not promote reduced effective helper quota events by guessing threshold, including when reported `timed_out` or `exceeded_limit`.
- Actual proven O1 original-byte limit events from Increments 39–41 remain valid only with the exact prior provenance conditions. Increment 42 did not alter them.
- The RP-02 roadmap requires supported events to be witnessed **or explicitly nonpromotable**. This increment documents the unsupported time/count/helper dimensions rather than changing protected authority. RP-02 candidate assurance is partially closed with explicit gaps; independent CP-02 acceptance remains OPEN.

`verification/g5_04/rp02_increment42_verified_checkpoint_20261114.json` is the committed receipt of this result.

## 3. RP-03.1 entry audit: material source-authority blocker

**Stop implementation before editing the producer, validator or frozen schema.** The known F-06 discrepancy is real and not fixed by passing candidate CI:

- `verification/g5_04/cp03_adversarial_findings_review_25.json`, finding **R25-03**, identifies missing approved `system.json.header`, unsupported candidate top-level `platform_scope` and `normalization_state`, and multiple missing manifest fields. It classifies the mismatch a **BLOCKER**.
- The current `lbt_g5/canonical_session.py` emits `schema_version`, `run_id`, `platform_scope`, `normalization_state`, `observations`, `capture_limits`, `limitations` in `system.json`; `session_manifest.json` is not the approved complete D-02 manifestation. Its `validate_canonical` checks selected identity/digest/references, but not the frozen closed-world field/type/nullability contract.
- `tests/test_g5_cp02_reconciliation_review_25.py` contains a **known expected failure** for exact D-02. It is not proof that the hypothetical replacement field set in the test equals the full approved §6 contract.
- The approved FAT roadmap RP-03.1 explicitly requires exact fields/types/nulls for `system.json`, `source_attempts.json`, `status_records.json`, `session_manifest.json` and the header/attempt/artifact/observation/limit/count/digest entities, with mandatory comparison against **approved CP-01 §6**. Owner instructions forbid altering the frozen schema without explicit authorization.

The controlling exact document is identified by retained recovery audit entry **76**:

- **Name:** `LBT_G5_04_CP01_Contract_Reconciliation_Approval_Review_2026-11-02.odt`
- **Archive:** `LBT_G5_04_CP02_Traceability_and_Test_Specification_Recovery_2026-11-02.zip`
- **Internal path:** `03_DECISION_AUTHORITY/LBT_G5_04_CP01_Contract_Reconciliation_Approval_Review_2026-11-02.odt`
- **SHA-256 recorded in audit:** `6d836d28af086a0fec7df2ca0949faf9447f9cee29cfabb8751344bd5104c98b`
- Retention-audit reference: `LBT_Archive_Unique_Content_Retention_Audit_2026-11-04.csv`.
- **Availability finding:** handoff/audit materials identify the controlling ODT and its accepted role, but its complete §6 entity/field/type/nullability text was not in the current GitHub tree or currently accessible project-file results. Hence no authoritative field-by-field implementation can be responsibly completed now.

The durable blocker record is `verification/g5_04/rp03_d02_source_authority_blocker_20261114.json`. The recommendation is **recovery, not schema redesign**: obtain the exact archived ODT (or entire stated ZIP), independently check its SHA-256, read §6 verbatim, and pin its complete authoritative contract in a durable verification artifact before designing RP-03 oracle/tests or altering `canonical_session.py`. If the recovered ODT conflicts with an owner approval or digest, surface specific alternatives as a **material owner decision**. Do not assume a partial handoff, historical G4 design, or current candidate implementation is sufficient.

## 4. Protected engineering boundaries

Throughout Increment 42, unchanged:

- `lbt_g5/safety.py`, `lbt_g5/o1.py`, `lbt_g5/privilege_contract.py`, `lbt_g5/privileged_session.py`, `packaging/lbt_root_helper.py`, `lbt_g5/evidence.py`, `lbt_g5/canonical_contract.py`.
- The production files modified by Increments 39–41 (`lbt_g5/o1_execution.py`, `lbt_g5/records.py`, `lbt_g5/canonical_session.py`) were **not modified by Increment 42**.
- Preserve the fixed SRC-13/18/21 argv and device allowlist, exact O1 run/operation/target consent, privileged helper invocation, installed helper protocol, G4-07 source/run/target/call ceilings, sealed raw originals, D-02 production canonical 1.0.0, separate 14-field status 1.0 and 41 approved domain/status/reason pairs.
- Preserve original CP-02 independent 39-case specification without promoting expected-failure or proxy tests to acceptance.
- Do not add public evidence paths, references or pointers. No TUI report viewer or second acquisition engine.

## 5. Gates and immediate next work

G5-04 OPEN. RP-02 candidate assurance has explicit documented nonpromotion limits; **not** independent complete acceptance. RP-03 OPEN/BLOCKED_ON_SOURCE_AUTHORITY. RP-04 OPEN. Original 39 independent CP-02 acceptance cases **0 accepted**. All 283 Requirements Rev 1.6 remain **NOT_VERIFIED**. Genuine Bodhi Linux 7 AMD64 host acquisition/privilege FAT **NOT_EXECUTED**. FAT readiness and release **NOT AUTHORIZED**.

Once exact CP-01 §6 is byte-verified and available, continue sequentially:

1. RP-03.1 source-first strict **approved** D-02 closed-world producer/validator oracles for all four private files. Red test(s) before permitted candidate implementation; no change to approved contract. Maintain precise evidence/receipt identity and manifest integrity.
2. RP-03.2 all 28 registered sources' typed/lossless fallback, multi-original attribution and reason distinctions.
3. RP-03.3 D-05 truthful integrity/minimum-usable/completeness lifecycle and zero-observation semantics.
4. RP-04.1 the **original** 39 CP-02 cases, with independently reviewed case-by-case evidence (not proxy substitution).
5. RP-04.2 CP-04 integrity/adversarial tests; RP-04.3 CP-05 integrated tests and genuine Bodhi 7 host proof; RP-04.4 CP-07 owner dossier/decision. Then resume remaining owner-approved FAT roadmap, preserving gates.

At each completed increment assess conversation safety, source authority, PR ancestry and exact-head CI. Create a verified GitHub checkpoint and handoff if context integrity warrants it. Never promote candidate mock CI to first-article acceptance.

## 6. Next-conversation opening, after recovery of controlling ODT

> Continue Linux Benchmark Toolkit development under Governance Standard v1.0 and approved FAT Roadmap from the verified Increment 42 PR #67 GitHub handoff. Read `verification/g5_04/rp02_increment42_verified_checkpoint_20261114.json`, `verification/g5_04/rp03_d02_source_authority_blocker_20261114.json`, and `verification/g5_04/rp02_increment42_continuation_handoff_20261114.md` at PR #67 head. Verify exact HEAD/CI and draft/unmerged PR #67 → #66 → #65 → #64 stack. Recover the exact CP-01 approved D-02 §6 contract from the named 2026-11-02 archive, verify its recorded SHA-256, then perform RP-03.1 source-first producer-validator conformance without changing frozen schemas or other protected boundaries. Continue sequentially unless material owner action, source conflict, or conversation-integrity concerns require stopping.

**Conversation safety assessment:** A new conversation is appropriate only *after the controlling CP-01 ODT is recovered*, because the present checkpoint is complete and the next engineering change depends on absent controlling source text. This is an authority/integrity stop, not a false CI failure or a suggestion to bypass safeguards.
