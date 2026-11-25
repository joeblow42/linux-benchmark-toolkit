# LINUX BENCHMARK TOOLKIT — ALTERNATIVE B PLANNING RECOVERY HANDOFF
**Date:** 2026-11-16 | **Status:** RECONCILIATION PREPARED — OWNER REVIEW REQUIRED, NO IMPLEMENTATION AUTHORIZATION
**Governing method:** AI-Assisted Software Engineering Governance Standard v1.0. **Operator model:** one trusted operator, normally offline on a Bodhi Linux live USB.

## 1. Scope and immediate stop
The owner approved Alternative B: retain core CPU/memory/storage/thermal/network benchmarks, hardware inventory, optical/DVD, FFmpeg/Jellyfin and backup/rsync/SMB specialist workloads. Do **not** presume a malicious second operator, hostile local administrator, forged canonical editor or other fabricated attacker. Do **retain** non-destructive storage writes, bounded thermal/load tests, safe paths, authorized source privileges and peer tests, correct provenance, useful fault handling and honest reporting. Never claim physical FAT from CI alone.

**Increment 48 is BLOCKED** until the owner reviews and approves the revised Rev 0.2 planning baseline and the CT-07-N1 test-input rephrasing proposal. Do not merge any draft PR. Do not change Rev 1.6 text, RP-01 applicability, G5-03 source/consent/privilege/capture policy, D-02 production canonical schema 1.0.0, status vocabulary (41 pairs), privacy/output contracts, or the original CP-02 acceptance criteria without express owner authority.

## 2. GitHub authority and state
- Repository: https://github.com/joeblow42/linux-benchmark-toolkit
- Draft planning PR #73: https://github.com/joeblow42/linux-benchmark-toolkit/pull/73
- Branch: `planning/fat-rebaseline-altb-20261115`; stacked on Increment 47 draft PR #72, baseline `16a50ba2dbe570f4790ac7d0cfcd8d63601d6b49`.
- Per-ID reconciliation commit: `7d76f05f1ea17afe68f955953f5ea2a12d49a993`. **This handoff may be newer than that commit: use GitHub PR #73's current exact head as the authoritative recovery SHA and recheck status/CI.**
- Planning files under `verification/fat/`; originals under `verification/fat/authority/`.
- Current CI truth: independently verify exact-head workflow runs after every subsequent planning commit. Historical success on a prior head is not current-head acceptance.

## 3. Byte-exact source authority recovered
- `authority/Requirements_Rev1_6.csv`: 283 requirements (209 FR, 74 NFR), 20 columns, SHA-256 `04849cd13ecc75c803839ab7c59a1015c5b92d1f05bf31422b54406c188e2702`.
- `authority/LBT_RP01_283_Requirement_FAT_Applicability_Approved_20261113.csv`: 283 IDs / 17 columns, SHA-256 `deb4ea158491d980e7ff57d6ac9bc58560316edf3adfb8d3e9c37c59f9266092`.
- Both original source bytes remain unchanged. They share 283 unique IDs in the same order, with seven matching controlled attributes for every ID (1,981 exact comparisons, zero mismatch).
- All approval states `OWNER_APPROVED_2026-11-13`: **210 FAT_MANDATORY, 65 CONDITIONALLY_APPLICABLE, 8 EXPLICIT_LATER_RELEASE**, no pending classifications. All 283 verification states `NOT_VERIFIED`.
- The eight explicit deferrals are FR-001, FR-002, FR-003, FR-004 (host security-posture assessment), FR-008, FR-009 (cluster), FR-010 (local AI inference), FR-134 (TUI prior-results viewing). FR-177/FR-186 execution and selection remain FAT mandatory; FR-208 prohibits TUI report viewer.

## 4. Corrected 283-ID reconciliation — ordering trap
- The existing CP-02 12-column trace file `verification/g5_04/requirements_traceability_rev1_6.csv` uses a **different ID row order in 141 positions**, although it contains the same 283 unique IDs. Joining by line number would corrupt traceability.
- `altb_candidate_requirement_reconciliation_283_20261115.csv` is a **53-column derived planning sheet**, joined by exact `Requirement_ID`. It carries all 20 unchanged original cells, 16 additional approved RP-01 cells, 11 additional CP-02 trace cells and six expressly candidate-only review fields. The shared ID is represented once.
- `scripts/verify_altb_reconciliation.py` independently checks original byte hashes, 283-ID join and controlled cells, 1,981 overlap matches, approved disposition totals, trace links and the 39-case overlay. The dedicated `.github/workflows/altb-fat-recovery.yml` must pass at exact PR head before claiming recovery ready.
- The old provisional `NOT_RECOVERED_PER_ID` dispositions have been replaced with actual owner-approved per-ID scope. CP-02 Trace_Scope is never substituted for RP-01 FAT applicability.

## 5. Original CP-02 verification cases and practical fault coverage
- Original 39-case review source: `verification/g5_04/cp02_39case_coverage_review_25.csv`. All 39 remain **formally unaccepted**; no physical-host FAT has been executed.
- Additive overlay: `altb_cp02_39case_method_review_20261116.csv` retains the original 12 case fields unchanged and proposes **35 KEEP_FUNCTIONAL; 1 REPLACE_WITH_ORDINARY_FAILURE; 3 DOWNSTREAM_NOT_EXECUTED; 0 PROPOSE_REMOVAL_ATTACK_ONLY**.
- CT-07-N1 is the only proposed input-method clarification: replace 'forged attempt' narrative with an accidental wrong-run/stale-attempt/missing-original reference, **keeping the same rejection**. Do not amend its original case without owner approval.
- Downstream cases: CT-08-N2 (regeneration), CT-11-N2 (public evidence-pointer withholding), CT-11-N3 (no TUI report/diagnostics viewer). Retain and execute at their proper stages.
- Ordinary corruption, malformed source input, wrong IDs, missing evidence, hash/count/size mismatches, unexpected schema keys, interrupted writes, false success and wrong units remain essential correctness checks. Avoid rehashed-manifest attacker/replay and hostile-parser campaigns.
- Increment 47 tests in PR #72 have **not** been deleted or merged. Prior to any future removal perform a bounded test-by-test impact check for legitimate ordinary-fault coverage.

## 6. Candidate six-slice FAT roadmap, not yet owner-approved
1. Slice A — RP-03/RP-04: actual acquisition → typed/lossless record → truthful consumer; zero-observation, interruption, real Bodhi source acquisition; independent CP-02 39-case review.
2. Slice B — RP-06/RP-07: unified Discovery/Standard/Extended/Interactive mode orchestration; safe real CPU, memory, storage, thermal; optional consented peer network tests.
3. Slice C — RP-08: optical/DVD read and verification, FFmpeg encode/deinterlace, representative Jellyfin JF-01…10 scenarios with explicit local/remote hardware limitations.
4. Slice D — RP-09: generated-test-content backup and rsync, optional USB/SMB selected peer paths, integrity, interruption and cleanup.
5. Slice E — RP-05/RP-10/RP-11: practical explained suitability outcomes, privacy.yaml/outputs.yaml, one combined self-contained offline HTML report and nine approved conditional outputs, no report-source reacquisition.
6. Slice F — RP-12/RP-13: unified CLI/Dialog TUI and portable offline AMD64 package; physical-host readiness; **owner FAT-entry gate before formal FAT execution**; independent FAT evidence.

## 7. Latest candidate documents
- `altb_candidate_fat_roadmap_rev0_2_20261115.md` — corrected Rev 0.2 roadmap candidate, six slices.
- `altb_candidate_requirement_reconciliation_rev0_2_20261115.md` — narrative, exact-text impact and owner gates.
- `altb_candidate_requirement_reconciliation_283_20261115.csv` — complete 53-column derived 283-ID crosswalk.
- `altb_cp02_39case_method_review_20261116.csv` — original-case-preserving method overlay.
- `altb_planning_impact_review_20261116.md` — requirement/test/safety impact and decisions.
- `altb_source_authority_crosscheck_20261116.json` — reconciliation checks and recorded evidence.
- `scripts/verify_altb_reconciliation.py` — independent gate; `scripts/build_altb_recovery.py` — ODT and ZIP recovery artifacts from GitHub sources.

## 8. Next authorized workflow
1. Verify draft PR #73 exact current HEAD, base PR #72, unchanged controlled authority and fresh exact-head CI including the recovery-package job.
2. Execute or examine the independent verification output; confirm both source hashes, 283/20 and 283/17, 1,981 matches, 283×53 crosswalk, 39-case overlay and 210/65/8 classifications.
3. Present the candidate roadmap and CP-02 impact decisions to the owner. **Do not begin Increment 48** pending a documented owner approval.
4. After owner approval only, resume first functional source-to-consumer integration and ordinary-fault checks. Preserve independent measurement correctness and physical safety.

**This handoff documents planning and source recovery, not release authorization, merged acceptance or completed FAT.**
