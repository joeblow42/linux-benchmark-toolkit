# LINUX BENCHMARK TOOLKIT — ENGINEERING CONTINUATION HANDOFF

**Version:** 2026-11-16 / Alternative B authoritative source recovery  
**Status:** PLANNING AND REQUIREMENTS RECONCILIATION ONLY — NOT APPROVED FAT REV 0.2 IMPLEMENTATION BASELINE  
**Governing standard:** AI-Assisted Software Engineering Governance Standard v1.0  
**Application:** Trusted single operator / isolated Bodhi Linux live USB / hardware suitability assessment

## 1. Immediate direction and stop conditions

- The owner approved **Alternative B**: retain core hardware inventory and CPU/memory/storage/thermal/network benchmarks plus **optical/DVD, FFmpeg/Jellyfin and backup/rsync/SMB** specialist workloads for First Article Test (FAT).
- The owner explicitly **rejected any assumed malicious second operator**, forged-record attacker or hostile local administrator. Stop building further rehashed-manifest, synthetic-forgery, malicious-parser-identity and similar threat-driven verification work. Do not extend Increment 47's adversarial approach into Increment 48.
- Continue to protect against **real accidental damage and ordinary faults**: destructive writes to existing disks, wrong drive/path selection, overheating, unchecked load, insufficient free space, incomplete/corrupt source data, interrupted sessions, mistaken units, false benchmark results, and reports that may later be shared.
- Operating default is offline and isolated. Operator-selected, explicitly authorized external peer testing (e.g., SMB or real Jellyfin sessions) is optional; never imply that a network benchmark ran offline.
- **Do not begin Increment 48 or merge draft pull requests** until the owner has reviewed and approved the candidate Rev 0.2 roadmap and requirements-methodology reconciliation. Do not silently modify approved Rev 1.6 requirement text, the CP-01 D-02 schema, approved source/privilege policy, or status vocabulary.

## 2. Authoritative GitHub recovery point

- Repository: https://github.com/joeblow42/linux-benchmark-toolkit
- Planning branch: `planning/fat-rebaseline-altb-20261115`.
- Planning draft PR #73: https://github.com/joeblow42/linux-benchmark-toolkit/pull/73. Open, draft, unmerged, stacked on draft PR #72.
- PR #73 last verified head: `5d4dceec64b858c60136bb4514778dc0a17273dc`. Base: `16a50ba2dbe570f4790ac7d0cfcd8d63601d6b49` (Increment 47 / draft PR #72). No code changes in PR #73; only three candidate planning/reconciliation files at this checkpoint.
- Exact-head PR CI `43776736223`: SUCCESS. Exact-head push CI `43776730165`: SUCCESS. GitHub PR comment records final-head verification.
- Prior Increment 47 test/implementation: draft PR #72; final head `16a50ba2dbe570f4790ac7d0cfcd8d63601d6b49`. Its tests addressed an invalid hostile-record assumption; this code has **not** been removed or merged merely because its threat rationale was rejected. A separate bounded impact review is required before deleting existing tests.
- GitHub candidate documents: `verification/fat/altb_candidate_fat_roadmap_rev0_2_20261115.md`, `verification/fat/altb_candidate_requirement_reconciliation_rev0_2_20261115.md`, `verification/fat/altb_candidate_requirement_reconciliation_283_20261115.csv`.
- Current candidate GitHub 283-row CSV is **provisional**: it marked 280 per-ID applicability entries as not recovered, because the two authoritative CSVs were not yet available. This is now **outdated** and MUST be corrected through an additive, authority-preserving reconciliation. Do not use its unresolved labels as the actual approved scope.

## 3. Newly recovered owner-authoritative requirements sources

- **Requirements Rev 1.6 (283 rows / 20 columns):** `Requirements_Rev1_6.csv`. SHA-256: `04849cd13ecc75c803839ab7c59a1015c5b92d1f05bf31422b54406c188e2702`. **PASS.**
- **RP-01 approved FAT applicability (283 rows / 17 columns):** `LBT_RP01_283_Requirement_FAT_Applicability_Approved_20261113.csv`. SHA-256: `deb4ea158491d980e7ff57d6ac9bc58560316edf3adfb8d3e9c37c59f9266092`. **PASS.**

- Both original file bytes are preserved **unchanged** inside this recovery ZIP under `authority/`.
- Both sources contain the same 283 unique requirement IDs in the same order: 209 functional, 74 nonfunctional.
- Seven corresponding approved attributes match for all 283 rows: type, category, exact requirement text, criticality, controlled disposition, original release target, and platform applicability. **0 mismatches** across all 1,981 comparisons.
- All 283 applicability entries say `OWNER_APPROVED_2026-11-13`. Exact approved counts: **210 FAT_MANDATORY; 65 CONDITIONALLY_APPLICABLE; 8 EXPLICIT_LATER_RELEASE**.
- All 283 entries retain `NOT_VERIFIED`. Approved classification is not evidence that a capability has been implemented or tested.
- FR-134: later-release prior-results TUI viewing; no TUI report viewer. FR-177 and FR-186: FAT-mandatory TUI assessment execution and group/individual test selection (not TUI report viewing).
- Approved per-ID matrix is now found; **its exact hash matches the prior RP-01 GitHub approval record** at `verification/fat/rp01_owner_scope_approval_20261113.json`. Its previously unrecovered 280 individual dispositions must be restored in the GitHub reconciliation.

## 4. What remains controlled, and what is merely proposed

**Preserved baseline:** Original Rev 1.6 283-row/20-column requirements; owner-approved 283-row/17-column FAT applicability matrix; no source wording or approved applicability rewrite; G5-03 accepted single acquisition engine and its command/consent/privilege/capture limitations; CP-01 D-02 production canonical schema 1.0.0; status schema 1.0 with 14 fields and 41 approved status/reason pairs; approved private receipt model; separate combined HTML report and configured conditional outputs; no TUI report viewer.

**Approved Alternative B:** Same core and specialist workload scope, corrected one-trusted-operator offline USB model, no more unjustified hostile-actor defenses. Engineering safety against accidental or operational damage remains essential.

**Candidate / still requiring owner approval:** Detailed Rev 0.2 revised roadmap sequencing, specific adjustments to CP-02 verification methods or acceptance tests, any modification to a controlled requirement or approved contract, and any changes to approved nine conditional outputs.

**Current verification truth:** Formal original 39 CP-02 cases: 0 formally accepted; 283 requirement verification rows not verified; actual Bodhi 7 AMD64 integrated FAT has not been executed; release not authorized. Passing GitHub CI does not equal physical-host acceptance.

## 5. Proposed practical roadmap (retain original RP package numbers)

1. **Slice A (RP-03/RP-04):** Validate the real acquisition-to-inventory/report-consumer path, honest incomplete/failed states, zero-observation behavior, and Bodhi host collection. Retain routine malformed/partial input and interruption tests. Stop adversarial rehash/forgery tests. Reconcile original 39 CP-02 cases individually; escalate only proposed changes to accepted test-method authority.
2. **Slice B (RP-06/RP-07):** Finish single-engine Discovery/Standard/Extended/Interactive dispatch and **real** CPU, memory, storage and thermal benchmarks, with safe temporary data, timeouts, cleanup, and optionally consented network tests.
3. **Slice C (RP-08):** Optical detection, known-good DVD read/imaging/verification, FFmpeg DVD encoding/deinterlace, and Jellyfin JF-01..JF-10 representative codec/concurrency scenarios. Distinguish actual Jellyfin server evidence from FFmpeg-only throughput and missing test hardware.
4. **Slice D (RP-09):** Generated test-file backup/rsync large/small/incremental transfer benchmarks; optional operator-authorized USB/SMB endpoints; data integrity verification of test fixtures, error/retry and safe cleanup.
5. **Slice E (RP-05/RP-10/RP-11):** Practical explainable suitability judgments with declared thresholds, confidence and NOT_TESTED outcomes; one combined self-contained offline HTML report, practical sharing privacy, configured conditional outputs and report-only regeneration.
6. **Slice F (RP-12/RP-13):** Unified CLI/Dialog TUI cutover (explicit authorization gate), portable offline AMD64 package, then actual first-article testing on live-USB Bodhi and representative hardware, followed by owner FAT-entry gate.

These six slices group the remaining thirteen approved RP identifiers; they are **not** six commits or an automatic relaxation of requirements.

## 6. Immediate next-conversation workflow — in order

1. Read this handoff and `README_RECOVERY.md` from the ZIP, verify `SHA256SUMS.txt`, and inspect both authoritative CSVs directly. Confirm the SHA256 values and 283/20, 283/17 structures. Preserve originals without modifying them.
2. Read the three candidate planning files directly from PR #73 at its verified exact head. Confirm current branch/PR state before writing.
3. Rebuild the GitHub 283-ID reconciliation **using the recovered authoritative per-ID FAT matrix**, joined to the original 20-column source by exact Requirement_ID, carrying all 20 controlled cells unchanged and all owner-approved 17 matrix cells unchanged. The existing 12-column CP-02 overlay is separate and must not be mistaken for original source requirements. Keep traceability to the 39 original CP-02 cases.
4. Review each candidate scope/method alteration against **actual requirement text**. Differentiate user-visible security-posture assessment (if genuinely required by Rev 1.6) from LBT attacker defenses unsupported by the operating model. Do not automatically delete legitimate fault tests for malformed data or interrupted runs.
5. Update the candidate Rev 0.2 roadmap and draft PR #73 with the real per-ID reconciled output and a written impact assessment. Keep it planning-only, draft and unmerged. Run exact-head CI and document verified results.
6. Ask the owner for approval of the revised planning baseline and any material controlled requirement/test-method changes. Do not begin Increment 48 until this decision is received.
7. Once approved, resume a **functional, source-to-consumer integration** increment, rather than speculative hostile-data tests. Maintain independent checks for values and physical safety proportional to the stated purpose.

## 7. Package inventory and integrity

- `authority/Requirements_Rev1_6.csv` — exact source bytes, owner baseline.
- `authority/LBT_RP01_283_Requirement_FAT_Applicability_Approved_20261113.csv` — exact source bytes, owner-approved per-ID matrix.
- `handoff/LBT_FAT_Alternative_B_Updated_Engineering_Handoff_20261116.odt` — this complete handoff, LibreOffice ODT.
- `handoff/LBT_FAT_Alternative_B_Updated_Engineering_Handoff_20261116.md` — editable text equivalent of handoff and GitHub-friendly recovery content.
- `planning/LBT_FAT_Roadmap_Rev0_2_Alternative_B_Candidate_20261115.odt` and `planning/LBT_FAT_Requirements_Reconciliation_Rev0_2_Alternative_B_Candidate_20261115.odt` — prior **candidate** planning review copies; GitHub PR #73 Markdown is the latest exact-head source for candidate content.
- `validation/source_recovery_verification_20261116.json` — source ID/hash/cell overlap verification report.
- `README_RECOVERY.md`, `SHA256SUMS.txt`, `scripts/verify_recovery.sh` — operator instructions and archive checksum check.

All package content is for preservation and engineering recovery. Nothing here constitutes a release, completed FAT, merged PR, updated implementation authorization, or owner approval of the candidate Rev 0.2 roadmap.