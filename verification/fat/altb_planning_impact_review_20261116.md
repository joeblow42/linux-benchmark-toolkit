# LBT Alternative B — Source-to-Requirement Impact Review (CANDIDATE)
**Date:** 2026-11-16 | **Implementation authority:** NONE | **Owner FAT Rev 0.2 approval:** PENDING

## Verified sources
- Rev 1.6 original: 283 × 20, byte-exact SHA-256 `04849cd13ecc75c803839ab7c59a1015c5b92d1f05bf31422b54406c188e2702`.
- Owner-approved RP-01 per-ID matrix: 283 × 17, byte-exact SHA-256 `deb4ea158491d980e7ff57d6ac9bc58560316edf3adfb8d3e9c37c59f9266092`.
- All 1,981 controlled overlaps agree; 210 mandatory, 65 conditional, eight later-release.
- Source and RP-01 rows align. CP-02 trace row order differs in **141 positions**; exact `Requirement_ID` join prevents false traceability.
- 283 requirement verification states NOT_VERIFIED; 39 original CP-02 acceptance cases formally accepted: zero.

## Required handling and bounded engineering impact
| Authority/concern | Disposition | Rationale |
|---|---|---|
| Original Rev 1.6 texts and RP-01 per-ID decisions | PRESERVE | Zero controlled-cell and per-ID changes |
| FR-001…004, FR-008…010, FR-134 | PRESERVE LATER RELEASE | Explicitly approved exclusion; host-security posture is not LBT attacker defense |
| FR-177, FR-186, FR-208 | PRESERVE FAT TUI CONTRACT | Execution and selection required; report viewer prohibited |
| FR-121, FR-168, FR-191, FR-192, NFR-068, NFR-070/071/074, NFR-018 | KEEP OPERATIONAL VERIFICATION | Protect correctness, provenance, source error truth and report sharing |
| Existing CP-02 cases | 35 KEEP, 1 PROPOSED REPHRASE, 3 DOWNSTREAM | No acceptance deletion, no formal case passed |
| CT-07-N1 | OWNER REVIEW | Reword forged-attempt input as accidental wrong-run/stale/missing evidence; preserve the same rejection condition |
| Draft PR #72 Increment 47 | NO AUTOMATIC DELETION | Later independently review dual-purpose integrity tests vs adversary-only expansions |
| G5-03 commands, consent, privileges, capture policy | NO CHANGE | Approved source-first operating limits preserved |
| D-02 schema 1.0.0 and 41 status/reason pairs | NO CHANGE | Approved consumer contract protected |
| Privacy/output contract | NO CHANGE | Reports may be shared; combined offline HTML plus nine conditional outputs preserved |

## Functional safety and ordinary faults to retain
Non-destructive user-drive handling and correct destination selection; safe temporary test files, free-space reserves and cleanup; bounded CPU/storage/thermal load; honest units and sample limitations; incomplete and failed source capture; interruption with no false completion; unknown source datum lossless fallback; permitted privileged reads; explicit peer-network consent; independent integrity of generated backup/DVD test fixtures; physical-host evidence for FAT.

## Owner decisions before further implementation
**Decision 1:** Approve/amend revised Rev 0.2 six-slice roadmap and corrected single-operator threat boundary. **Decision 2:** Approve/reject CT-07-N1 proposed input-wording clarification without changing rejection criteria. Everything else is unchanged. Keep PR #73 draft/unmerged and Increment 48 blocked until the decisions are recorded.
