# LBT G5-04 / RP-04 Increment 54 — original CP-02 case evidence preparation

**Status: CANDIDATE PLAN ONLY.** Owner-approved Alternative B FAT Rev 0.2 and governance v1.0; exact parent is draft PR #79 at `2690e3ae22c7fe129bbf3ac756bdfe07ba495c64`. No product code, G5-03 commands, privileges, limits, D-02 1.0.0, 41 status pairs, public report, source evidence or original 39 CP-02 criteria changed. Draft/unmerged.

## Result and limitations

- 39 original CP-02 cases preserved (input/expected result and requirement associations). All **39 remain formally NOT_EXECUTED**, **zero accepted**; no physical Bodhi Linux 7 tests authorized or performed.
- The owner-approved CT-07-N1 Alternative B ordinary stale/wrong-run/missing-reference scenario is a separate *execution-input overlay*; original source specification remains intact and rejection expectation is unchanged.
- Existing Increment 44–53 and earlier tests are labeled **supporting candidate proxy evidence**, not an executed case. CI success of this matrix verifier is not CP-02 acceptance.
- Three downstream cases (CT-08-N2, CT-11-N2, CT-11-N3) remain explicitly unexecuted pending G5-06 reporting/regeneration or TUI functionality. No guess about their success.
- CT-11-P1 has a candidate physical read-only Bodhi 7 pre-FAT context, **requiring a separate owner-approved safe host test plan**. It is not an instruction to run on the owner's laptop.
- Candidate statuses are deliberately conservative: F-02/F-04 issues called out in the historical 25 review must be independently reassessed against newer implementation (27–53), not assumed unresolved or accepted from the old review.

## Acceptance preparation and next gate

The JSON plan provides for every case: source and approved input condition, unchanged expected result, requirements, proposed fixture/CI/host/downstream context, existing related test files, additional exact-case evidence, independent-review status, owner gate, and formal zero-acceptance state. `tests/test_g5_cp03_rp04_case_plan_54.py` audits 39-case completeness, bounded CT-07 input change, all candidate pointers, downstream/host gates and preservation of formal status. CI adds one dedicated read-only audit step.

**Before executing the actual 39 CP-02 acceptance cases:** owner/reviewer must approve a bounded formal case execution protocol, independent result recording and the proposed context assignments. Physical Bodhi 7 host read-only pre-FAT requires separate explicit owner approval. CP-07 and formal FAT remain separately gated. Do not merge candidate stacked draft PRs.
