# LBT — G5-04 / RP-03 / CP-03 Increment 44 continuation handoff

Date: 2026-11-14. Governance: **AI-Assisted Software Engineering Governance Standard v1.0**, owner-approved **First Article Test (FAT) Readiness Roadmap**, Requirements Rev 1.6 (283 controlled: 210 FAT mandatory, 65 conditional, 8 explicit later release), approved CP-01 decisions D-01 through D-05 and RP-02 private operational receipt v0.6 Choice A.

**Disposition:** RP-03 governing contract source recovered and byte verified; Increment 43 static authority freeze and Increment 44 pure strict D-02 shape validator implemented source-first and exact-head CI verified at their respective implementation heads. This is **NOT** a complete RP-03.1 producer/validator migration, independent CP-02 acceptance, CP-07, first article, merge or release authorization.

## 1. Exact GitHub recovery and PR stack

Repository: https://github.com/joeblow42/linux-benchmark-toolkit (authenticated owner account joeblow42).

- Increment 39: PR #64, verified `b7797b80188f228b4a7d15f5cc8ba28e9d71062f`, CI `43630844392` SUCCESS.
- Increment 40: PR #65 on #64, checkpoint `6020bdb64b61f23d5ae6ab8cd42dc96aa1d08728`, CI `43632910220` SUCCESS.
- Increment 41: PR #66 on #65, verified head `fef623af250edd37552ca985b81fd4275ab3f388`, CI `43633763967` SUCCESS.
- Increment 42: PR #67 on #66, verified final handoff head `74f9873dbacde10fd45a1c9e6268a223533cecf8`, exact-head CI PR `43643623019` and push `43643616037` SUCCESS.
- **Increment 43:** PR **#68**, branch `g5/cp03-rp03-d02-contract-43`, stacked on #67, checkpoint head `4116302831cb5ecd3df48fcbb7d6f8de27c9685f`, exact-head PR `43651534050` and push `43651529930` SUCCESS.
- **Increment 44:** PR **#69**, branch `g5/cp03-rp03-d02-validator-44`, stacked on #68. Pure shape validator implementation head `0ff94ee3365b643424d0d82e703a3a14d005d542`, exact-head PR `43651921510` and push `43651917072` SUCCESS.
- **Important:** This checkpoint and handoff are committed *after* implementation-head CI. The next conversation MUST read the latest head of PR #69 and verify **exact-head SUCCESS** of GitHub Actions for the final handoff commit before proceeding.
- All PRs #67–69 were independently verified OPEN, DRAFT and UNMERGED immediately before the checkpoint. No merge/ready-for-review or production launcher cutover is authorized.

## 2. Owner-approved CP-01 source §6 recovered with exact hash

At the prior Increment 42 stop, RP-03 was blocked because the exact CP-01 §6 D-02 annex was unavailable in the GitHub tree. The owner then uploaded the original archive `LBT_G5_04_CP02_Traceability_and_Test_Specification_Recovery_2026-11-02(1).zip`.

- ZIP SHA-256 **`75bd8d7f4ad5167449cc63974fdc85650dc364cce0b037d9633a9794c2b157a2`**.
- ZIP CRC **PASS**; all seven files in `SHA256SUMS.txt` **PASS**.
- Controlling ODT: `03_DECISION_AUTHORITY/LBT_G5_04_CP01_Contract_Reconciliation_Approval_Review_2026-11-02.odt`.
- Controlling ODT SHA-256 **`6d836d28af086a0fec7df2ca0949faf9447f9cee29cfabb8751344bd5104c98b`**, exact match to historical retention audit entry #76.
- The CP-01 ODT itself was originally a *proposal* (§5–§6), subsequently owner-approved as D-01 through D-05 on 2026-11-02. Do not treat the ODT's obsolete 'hold pending approval' footer as a new unresolved owner decision.
- The exact §6 field/type/nullability and enum contract was transcribed into durable `verification/g5_04/rp03_cp01_d02_approved_contract_43.json`. No fields were reconstructed from provisional code; the tests compare explicitly against that source-backed ledger. The older RP-03 blocker record is retained historically; its **source availability blocker is now resolved**.

§6 rules: four exact private files; nine exact entity definitions `SessionHeader`, `SourceAttempt`, `EvidenceArtifact`, `CanonicalObservation`, `CaptureLimit`, `StatusRecord`, `Counts`, `FileDigest`, `ReceiptDigest`. Every named field required, '?' means required but nullable, unknown production keys forbidden, unknown **acquired source data** retained in typed/lossless fallback. Canonical schema **1.0.0**, distinct status envelope **1.0**, exactly **41** approved domain/status/reason triples. Read the committed ledger, not a generalized template, before editing the producer.

## 3. Increment 43 — verified authority mapping, NOT producer conformance

- Draft PR #68, seven static source-first checks `tests/test_g5_cp03_rp03_authority_43.py`.
- Verifies original ODT digest, exact file shapes (6/3/3/16 top-level fields), nine entity definitions (7/24/12/17/9/14/7/2/4 fields), required nullability, enum restrictions and the 41-pair status authority.
- New source control ledger: `verification/g5_04/rp03_cp01_d02_approved_contract_43.json`.
- Changed only the ledger, static tests, and test workflow. No approved schema or existing production code changed. CI at final checkpoint head SUCCESS.
- The RP-03.1 F-06 gap remained intentionally OPEN after this increment.

## 4. Increment 44 — source-first pure strict-shape validator

- Draft PR #69 on #68; source-first oracle: `verification/g5_04/rp03_d02_shape_oracle_44.json`.
- Nine positive/negative fixtures: `tests/test_g5_cp03_rp03_d02_shape_44.py`.
- First test-only CI `43651771114` failed deliberately at the new gate, `ModuleNotFoundError: No module named lbt_g5.d02_schema`, before any implementation. This is the witnessed RED test-first evidence, **not a passing acceptance run**.
- New implementation: `lbt_g5/d02_schema.py` with `D02_FILES`, `D02_ENTITIES`, `validate_d02_file` and `validate_d02_entity`. It compares exactly to the separately pinned §6 JSON ledger in tests, rejects absent and unknown fields, invalid types/nulls/UTC/non-finite JSON, negative lengths/counts, unapproved enums or invalid status pairs. It retains arbitrary JSON-typed **observed_value** content to avoid discarding unclassified acquired source facts.
- The strict-shape tests passed in PR CI `43651921510` and push CI `43651917072`, along with the existing unified suite. **No existing canonical producer/reader was changed in 44**; no claim that emitted production records are already conformant.
- Increment 44's protection diff relative to Increment 43 consists solely of `.github/workflows/test.yml`, `lbt_g5/d02_schema.py`, the nine-test fixture, and the source-first oracle. The subsequent checkpoint/handoff records only document assurance.
- Limitation: this pure validator checks field/type/enum shape only. Its caller must still independently establish exact run/attempt/evidence ownership, digest/counts/receipt integrity and operational lifecycle; the frozen D-02 schemas cannot be weakened to make provisional output pass.

## 5. Mandatory next engineering order

**Increment 45 — RP-03.1 producer/validator integration, bounded source-first.** Start from exact PR #69 head and inspect the actual current `lbt_g5/canonical_session.py` and existing tests. Before production changes, write independent RED oracles for all four private output shapes, including zero observations, an authorized sealed original, an exact CaptureLimit and a manifest with digest/count maps. Assert `validate_d02_file` over produced system/source-attempt/status/manifest records; assert `validate_d02_entity` for all nested entities. Compare every field against approved ledger. Run and observe first failing CI. Then in one or more limited draft stacked PRs correct the producer, import and enforce the strict validator, and update legacy *candidate tests* only where the approved D-02 behavior supersedes their expected provisional fields. Keep exact-head CI green before a checkpoint.

Known exact candidate discrepancies needing a permitted producer **migration, not schema redesign**:

- `private/system.json` currently emits unapproved top-level `platform_scope` and `normalization_state`, and omits required `header:SessionHeader`.
- `private/source_attempts.json.attempts[*]` currently contains unapproved `source_disposition`, `source_reason`, `capture_limited` and omits D-02's 24-field SourceAttempt shape (operation, authorization decision, consent, invocation, safety bounds, time, tool/errno, limit IDs). Do not invent command/consent facts; the existing verified private receipt is the trusted source.
- `private/session_manifest.json` currently uses provisional top-level counts `observation_count`, `attempt_count`, `source_count`, `original_byte_count`; approved D-02 requires nested `counts:Counts` with seven keys plus `manifest_version`, `minimum_usable`, `finalized_utc`, `source_receipts`, and the required ID lists.
- `evidence` map currently carries provisional `complete` and `private_relative_path`; approved `EvidenceArtifact` uses `completeness`, `restricted_relative_path` and the additional exact required fields. The sealed raw file bytes and actual receipt paths **must remain unmodified**.
- `CanonicalObservation` fields mostly resemble the approved form; validate each literal type, required contributor references and honest nullable timestamps rather than assuming compliance.
- `CaptureLimit` shapes already resemble the accepted D-02 form, but preserve the rigorous RP-02 event attribution and non-promotion constraints, especially for SRC-13 helper shortened caps.
- `lbt_g5/canonical_contract.py` is protected: status schema version 1.0 and all 41 domain/status/reason triples remain EXACTLY as accepted.

**After completed 45 stages:** RP-03.2 provenance and typed/lossless parser coverage for all registered source families, including a true two-original semantic datum and same-bytes-different-attempt proof; RP-03.3 D-05 validity/completeness/empty/interrupted outcomes; RP-04 original 39 independently specified CP-02 cases and CP-04 integrity; CP-05 G5-03→G5-04 integration and cumulative RTM; CP-06 genuine Bodhi Linux 7 AMD64 original host/device/consent/helper proof; CP-07 explicit owner gate review. Resume downstream FAT stages as approved.

## 6. Protected boundaries and gates

- Preserve fixed source command argv, D0/D1/O1 source policy, registered devices, O1 operator per-run/target/operation consent, helper protocol, privilege/sudo boundary and G4-07 byte/time/call/slot ceilings.
- Preserve original sealed raw artifacts byte-for-byte, separate private receipts and ownership; reject public raw pointers under FR-121; keep source acquisition inside the one IC-02 engine. Do not introduce parallel source execution or a TUI report viewer.
- Do not change production canonical schema **1.0.0**, its owner-approved D-02 **exact field/type/nullability** contract, status envelope **1.0** or 41 registered triples without explicit owner approval.
- Original 39 CP-02 cases **0 independently accepted**. Requirements Rev 1.6 **283 NOT_VERIFIED**. Bodhi Linux 7 AMD64 physical FAT **NOT_EXECUTED**. G5-04, RP-03, RP-04, FAT readiness and release remain OPEN / NOT AUTHORIZED. A passing candidate workflow is not FAT.
- All PRs remain draft/unmerged. Do not merge, modify protected authority, or falsely report gate acceptance.

## 7. Conversation-safety and next opening

A new conversation is recommended now after recovery/cryptographic review of the authoritative ZIP, two new stacked source-first development increments, deliberate CI RED and subsequent exact-head green workflow, and full frozen schema review. The context-integrity concern is process risk, not a product defect. No material owner decision is currently required.

Recommended next-conversation opening:

> Continue LBT under AI-Assisted Software Engineering Governance Standard v1.0 and the approved FAT Readiness Roadmap from G5-04 / RP-03 / CP-03 Increment 44. Repository `joeblow42/linux-benchmark-toolkit`, draft PR #69 stacked on #68 → #67 → #66. Read `verification/g5_04/rp03_cp01_d02_approved_contract_43.json`, `verification/g5_04/rp03_increment44_verified_checkpoint_20261114.json` and `verification/g5_04/rp03_increment44_continuation_handoff_20261114.md` directly from PR #69 head. Verify final exact-head CI and protected ancestry. The original CP-01 §6 ODT was byte-verified (SHA256 `6d836d28af086a0fec7df2ca0949faf9447f9cee29cfabb8751344bd5104c98b`), and a pure strict-shape validator passed source-first RED→GREEN candidate tests. Begin Increment 45 with independent source-first exact D-02 production producer/validator conformance for all four private files. Do not modify source commands, consent/privilege/helper protocol, G4-07 ceilings, canonical 1.0.0, status 1.0/41 pairs, or original evidence. Continue in sequence, keep all PRs draft/unmerged, stop only for a material owner decision or context-integrity concern.
