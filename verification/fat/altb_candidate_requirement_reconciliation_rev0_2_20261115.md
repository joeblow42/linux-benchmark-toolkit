# LBT — FAT Requirements and Verification-Method Reconciliation Rev 0.2 (CANDIDATE)
**Date:** 2026-11-15 | **Authority:** Alternative B approved; *only the intended operating model and inclusion of specialized workloads have been approved*. This reconciliation does not revise the controlled 283 requirements, the per-ID FAT classifications, D-02/consent/limits, or original acceptance evidence.

## 1. Recoverable authority
| Item | Recovered fact |
|---|---|
| Baseline | Requirements Rev 1.6; 283 IDs = 209 FR + 74 NFR |
| Approved original 20-column CSV SHA256 | `04849cd13ecc75c803839ab7c59a1015c5b92d1f05bf31422b54406c188e2702` |
| Approved RP-01 scope count | 210 FAT mandatory; 65 conditionally applicable; 8 explicit later release; 0 pending |
| Approved per-ID scope matrix SHA256 | `deb4ea158491d980e7ff57d6ac9bc58560316edf3adfb8d3e9c37c59f9266092` |
| Verified per-ID exceptions | FR-134 later TUI report viewing; FR-177 FAT mandatory TUI execution selection; FR-186 FAT mandatory individual/group selection where practical |
| CP-02 current source | `verification/g5_04/requirements_traceability_rev1_6.csv` |
| G5-04 CP-02 trace classes | 33 DIRECT; 11 BOUNDARY; 6 DOWNSTREAM; 233 UNASSESSED_FOR_G5_04 |
| Formal CP-02 acceptance evidence | Original 39 cases NOT formally accepted (0/39); no actual host FAT |
| Requirement state | 283 NOT_VERIFIED, including apparently implemented candidates |

**Critical limitation:** Current GitHub revision contains the **283-ID 12-column CP-02 overlay**, not the original 20-column requirement text or the approved per-ID RP-01 classification worksheet. Therefore the companion full-row CSV **does not claim new per-ID FAT dispositions**. It faithfully carries the 12 known CP-02 fields and appends explicitly marked review columns. Do not conflate G5-04 Trace_Scope with FAT applicability.

## 2. Corrected operating assumption
A **single trusted operator** runs LBT from a **live Linux USB**, normally offline/isolated, on hardware being inspected. There is no assumed malicious second operator, record forger, co-tenant, or hostile administrator. DVD/Jellyfin and backup test profiles remain first-article objectives under Alternative B. Explicit peer-connected SMB/Jellyfin/network paths require operator choice and do not convert default offline discovery into an online service.

Residual risks are real: failing hardware producing malformed/partial data, run interruption, wrong path/drive selection, insufficient disk space, overheating, uncontrolled writes, missing dependencies, incorrect units/results, inaccurate suitability judgments and report disclosure **when copied elsewhere**.

## 3. Reconciliation rules (separate product obligation from test technique)
**KEEP IN SCOPE:** All currently approved FAT-mandatory or conditional functional obligations until an authorized requirement change; core + specialized benchmarks; true fault handling; unprivileged default; non-destructive temporary data; bounded thermal/disk tests; truthful report statuses; approved schema; operational consent; privacy controls appropriate to exporting reports; real host FAT.

**REMOVE AS A DEVELOPMENT OBJECTIVE:** Further invented-attacker rehashed-manifest, substituted-original, malicious-field, spoofed status, forged parser ID or similar hostile-record campaigns. This is a **test-method proposal** and shall not unilaterally erase an approved requirement or a check that also catches ordinary file corruption.

**RETAIN/STREAMLINE:** Format and schema validation, counts, file incompleteness, safe atomic writes and recovery after power loss or interruption, parser correctness, checksums for the operator's own backup/media *test fixtures*, and cross-file links necessary to avoid wrong measurements. Prefer representative normal/error cases over exhaustive adversarial combinations.

**NOT AN AUTOMATIC DEFERRAL:** Security-posture assessment of the computer (e.g., firewall/update-readiness) may be a genuine *measured system fact*, distinct from hostile-actor defense of LBT. Evaluate it against the actual 20-column requirement wording before disposition. Likewise, no unilateral removal of the approved nine conditional publication outputs.

## 4. Requirement impact groups for exact-text review
| Group | Candidate impact | Required review |
|---|---|---|
| Existing FR-134 / FR-177 / FR-186 decisions | No change | Preserve exactly |
| FR-020 / FR-121 / FR-127 / FR-208 and NFR-016 / NFR-031 | Functional single-engine, evidence/publication/TUI boundary (CT-11) | Preserve genuine operation and sharing constraints; review attack-language separately |
| FR-168 / FR-191 and NFR-070 | Honest parser/absence/error status (CT-01..04) | Retain truthful failures and normal functional error tests |
| FR-192 and NFR-068 | Acquisition limits and source attribution (CT-05/07/09) | Retain correctness if needed for measured results; drop only adversary-only extensions on owner approval |
| NFR-018 / NFR-071 / NFR-074 | Commit, counts, interruption and lifecycle (CT-08/10) | Keep ordinary crash/incomplete-output consistency; review hostile tamper scenarios |
| All other requirement IDs | Exact statement unavailable in current recovered source | No speculative per-ID disposition; recover 20-column control first |

The above identifiers are **candidate triage references**, not judgments that the individual requirement text is security-related. The attached CSV is the authoritative 283-ID inventory.

## 5. Original CP-02 verification-method review
| CT family | Recommended handling |
|---|---|
| CT-01: allowed status vocabulary | Retain standard status correctness; no combinatorial attack rationale |
| CT-02/03/04: parser absent/failed/permission/missing tool | Retain normal error cases |
| CT-05/06: actual limits and time | Retain practical safety/correctness checks, no speculative limit hierarchy |
| CT-07: contributing-original record relationships | Retain sufficient association to correct data; no attacker-led substitution campaign |
| CT-08: zero-observation and incomplete runs | Retain |
| CT-09: unknown data and schema keys | Retain malformed-input/unknown-data fallback; avoid invented hostile field forging |
| CT-10: atomic commit, counts, interrupted run | Retain crash/incomplete-output checks; review tamper-only negative methods |
| CT-11: single path/privacy/TUI | Retain actual operation and approved UI/output behavior; avoid hostile-party construction |

Original 39 cases must be individually classified against the recovered test specification: **KEEP_FUNCTIONAL**, **REPLACE_WITH_ORDINARY_FAILURE**, **PROPOSE_REMOVAL_ATTACK_ONLY**, or **DOWNSTREAM_NOT_EXECUTED**. Until accepted, 0/39 formal acceptances remain unchanged. No blanket deletion or acceptance is claimed.

## 6. Working 283-ID reconciliation CSV
File: `verification/fat/altb_candidate_requirement_reconciliation_283_20261115.csv`.
- Exactly one row for every ID from the current CP-02 trace, in source order.
- Carries all current 12 trace fields unchanged.
- Appended candidate columns explicitly distinguish current approved information, missing owner-approved per-ID scope, proposed test-scope review, and owner-action status.
- Source truth not recovered is `NOT_RECOVERED_PER_ID`, not guessed.
- All current requirement Verification_State remain `NOT_VERIFIED` and no original baseline cells are edited.

## 7. Exit criteria before implementation
1. Recover and checksum-verify the 20-column Requirements Rev 1.6 source and per-ID RP-01 scope matrix; reconcile by ID and preserve control cells.
2. Review the functional impact of each proposed change: user-visible benefit, measurement integrity, safety, approved interface and test method. Neither "security" nor "hash" alone is grounds for removal.
3. Owner approve revised roadmap and any actual changes to mandatory/conditional requirements or original CP-02 acceptance methods.
4. Keep draft PR #72 unmerged, resume with a useful source-to-consumer integration increment rather than an adversary-based test.
