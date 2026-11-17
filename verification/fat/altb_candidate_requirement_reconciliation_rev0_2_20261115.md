# LBT — FAT Requirements and CP-02 Method Reconciliation Rev 0.2 (CANDIDATE)
**Status:** owner approval pending; planning-only; no Increment 48, merge or FAT acceptance. **Dated:** 2026-11-16.

## 1. Recovered authority and validity
The protected source files are `authority/Requirements_Rev1_6.csv` (283×20; SHA-256 `04849cd13ecc75c803839ab7c59a1015c5b92d1f05bf31422b54406c188e2702`) and `authority/LBT_RP01_283_Requirement_FAT_Applicability_Approved_20261113.csv` (283×17; SHA-256 `deb4ea158491d980e7ff57d6ac9bc58560316edf3adfb8d3e9c37c59f9266092`). Their original bytes remain unchanged. The exact hashes are checked by the GitHub recovery workflow. Seven overlapping approved attributes × 283 IDs = **1,981 exact matches, zero mismatches**.

All **283 ID classifications are recovered and owner-approved** (`OWNER_APPROVED_2026-11-13`): **210 FAT_MANDATORY, 65 CONDITIONALLY_APPLICABLE, 8 EXPLICIT_LATER_RELEASE**. All 283 remain `NOT_VERIFIED`. The matrix's historical narrative `Trace_Gap_or_Decision_Need` still contains some pre-approval wording; it is original protected data, not a current owner decision request.

## 2. 283-ID derived crosswalk and join defect avoided
`altb_candidate_requirement_reconciliation_283_20261115.csv` now contains **53 columns**: all 20 original requirement cells unchanged, 16 approved RP-01 additional columns (`RP01_` prefix; shared `Requirement_ID` once), 11 unchanged CP-02 trace columns (`CP02_` prefix), and six proposed review-only columns. No per-ID disposition, source text, original release target, platform scope or verification evidence is rewritten.

**Critical:** original Rev 1.6 and approved RP-01 matrix have the same ID sequence, but the 12-column CP-02 trace has a **different row order for 141 positions**. All three contain the same 283 unique IDs. Joining by row position would misattribute trace evidence; the crosswalk instead joins strictly by `Requirement_ID`. The CI verifier enforces exact per-ID cell preservation and checks every original CP-02 case linkage. Neither CP-02 `Trace_Scope` nor its old 'unassessed' values determine approved FAT applicability.

## 3. Exact requirement impact and later release
**No controlled requirement-text change, per-ID applicability change, or production-contract change is proposed.** Alternative B retains core CPU/memory/storage/thermal/network, optical/DVD, FFmpeg/Jellyfin and backup/rsync/SMB workloads. The eight approved later-release requirements are **LBT-FR-001, -002, -003, -004** (host security posture), **-008, -009** (cluster), **-010** (local AI inference), **-134** (TUI viewing of prior reports). FR-177/FR-186 stay FAT mandatory for operator execution and test selection; FR-208 forbids a TUI report viewer.

Exact source text supports normal operational controls under **FR-121** (withhold raw-source pointers from public outputs), **FR-168** (do not equate presence with execution), **FR-191** (truthful authorized collection), **FR-192** (bounded original observations), **NFR-068** (lossless provenance), **NFR-070** (correct status domain), **NFR-018** (preserve completed data after interruption without session resume), **NFR-071** (single current session format), and **NFR-074** (earlier-run preservation). These functions are not evidence of a hostile local operator.

## 4. Exact original 39-case CP-02 method review
The original input/expected-result/trace fields remain unchanged in `verification/g5_04/cp02_39case_coverage_review_25.csv`. A separate additive case-by-case overlay `altb_cp02_39case_method_review_20261116.csv` classifies:

| Proposed treatment | Count | Case detail |
|---|---:|---|
| KEEP_FUNCTIONAL | 35 | Ordinary parser, missing-tool, status, measurement, canonical-schema, corruption, interrupted-write and safe-UI checks retained; no attack permutations |
| REPLACE_WITH_ORDINARY_FAILURE | 1 | CT-07-N1 input narrative: accidental stale/wrong-run or missing provenance instead of forged identity; **owner approval required before rewording**; reject outcome unchanged |
| DOWNSTREAM_NOT_EXECUTED | 3 | CT-08-N2 report regeneration; CT-11-N2 public raw-pointer suppression; CT-11-N3 prohibited TUI report/diagnostics viewer |
| PROPOSE_REMOVAL_ATTACK_ONLY | 0 | No originally approved test recommended for removal |

**All 39 cases remain formally unaccepted.** A malformed input, unexpected D-02 key, broken digest, missing original or wrong run ID can result from ordinary faults. It is legitimate to reject such faults without inventing an attacker. Do not extend Increment 47's rehashed-manifest, forged-record, replay or tampering campaigns; conduct a bounded independent impact review before removing any existing dual-purpose test in draft PR #72.

## 5. Protected boundaries and required owner gates
Preserve G5-03 source/consent/privilege/capture policy, canonical D-02 1.0.0, status schema 1.0 and 41 approved status/reason pairs, privacy.yaml/outputs.yaml, 1 combined HTML report plus nine approved conditional outputs, original evidence retention, and approved TUI boundaries. Actual physical-host FAT has not occurred; GitHub CI is not a substitute.

Owner review requested only for **(1) the detailed Rev 0.2 six-slice roadmap and Alternative B practical test-method rationale**, and **(2) the optional CT-07-N1 ordinary-fault wording change**. No silent change to any requirement, test expected result, schema, source command, status pair or publication contract is authorized. Remain draft/unmerged; **Increment 48 paused** until approval.
