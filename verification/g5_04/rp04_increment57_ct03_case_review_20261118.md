# LBT G5-04 RP-04 Increment 57 — original CT-03 parser evidence candidate execution

Date: 2026-11-18. Authority: AI-Assisted Software Engineering Governance Standard v1.0, owner-approved Alternative B FAT Readiness Roadmap Rev 0.2, exact original controlled CP-02 test specification and approved RP-04 method classification. Branch follows Increment 56 PR #82 as stacked draft. **No merge or formal acceptance authorized.**

## Scope

Three exact-source original cases: CT-03-P1, CT-03-N1, CT-03-N2. Tests seal real fixture bytes via G5-02 EvidenceWriter and append-only receipts in an isolated temporary run. Actual canonical producer and validator are exercised. The SRC-02 OS-release parser error is intentionally ordinary malformed input, not a simulated hostile actor; source acquisition, privilege, benchmark, network and physical host are not invoked.

- CT-03-P1: a genuinely invoked parser raises OS_RELEASE_MALFORMED_ASSIGNMENT on sealed bytes; producer preserves raw text, parser finding, source references and bounded detail, and emits PARTIAL/PARSE_FAILED. Verified canonical manifest and files.
- CT-03-N1: same sealed bytes, parser deliberately unavailable *inside the test fixture only*, never invoked. Producer fails closed with NORMALIZATION_PENDING, does not publish a PARSE_FAILED status or final canonical manifest, and preserves originals and receipt.
- CT-03-N2: producer's genuine PARTIAL/PARSE_FAILED status requires a resolvable original evidence reference; independent status validator rejects an absent reference. Also simulate an ordinary read-unavailable original only within a patched validator read, no modification or deletion of raw evidence. Validation refuses the previously produced canonical session, and passes again on a normal read.

## Evidence and interpretation

`scripts/rp04_ct03_case_runner_57.py` emits per-case machine-readable JSON retained in GitHub Actions artifact `rp04-ct03-candidate-57`. Original CP-02 source case data unchanged. Test result reflects *development candidate verification only*; 39 original formal cases remain NOT_EXECUTED / 0 accepted until approved independent protocol and review. Physical Bodhi 7, CP-07 and FAT are separately owner gated.

No source commands, capture bounds, consent or privileges, production schema v1.0.0, status-pair vocabulary (41), immutable original evidence, parser or report consumer code changed. Proposed scope is tests, CI wiring and checkpoint only.
