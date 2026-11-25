# LBT RP-04 Increment 61 — CT-07 verified candidate handoff

**Date:** 2026-11-19 local · AI-Assisted Software Engineering Governance Standard v1.0 · owner-approved Alternative B FAT Readiness Roadmap Rev 0.2.

## GitHub recovery

- Repository: https://github.com/joeblow42/linux-benchmark-toolkit
- Current branch `g5/rp04-ct07-provenance-61`, **draft PR #87** stacked on #86 → #85 → #84 → #83 and earlier DRAFT PRs; NEVER MERGE without owner approval.
- Verified implementation head `ec8ea174da67f9c6777cb50057d47c0db7532359`, exact-head [PR CI 44670849200](https://github.com/joeblow42/linux-benchmark-toolkit/actions/runs/44670849200) SUCCESS and [push CI 44670824967](https://github.com/joeblow42/linux-benchmark-toolkit/actions/runs/44670824967) SUCCESS.
- GitHub Actions logs attest all four original CT-07 *candidate development* methods ran PASS, zero skip, and unified full validation passed. Retained per-case evidence artifact `rp04-ct07-candidate-61`, push run artifact ID 14600730168 (expires per Actions retention).
- Final recovery documentation commit follows; independently check final-head PR and push CI, and annotate draft PR #87 with exact runs.

## CT-07 source-first evidence

`tests/test_g5_cp03_rp04_ct07_61.py` reuses verified Increment 46 bounded fixtures (no collection of host source). P1 tests actual D-02 two-original SRC-15 FS_STAT semantic value with independently sealed SRC-14 MOUNTINFO contributor; verifies both IDs, attempts, lengths, SHA-256. P2 repeats identical SRC-08 bytes in attempts 01 and 02 and verifies distinct run/attempt-qualified IDs, equal hashes and correct records.

N1 uses approved **ordinary wrong-run/stale attempt/missing original** interpretation (no forged attempt campaign). It tests invalid attempt/evidence universes and in-memory mismatched observation ID as an ordinary consumer regression; no files or digests rewritten. N2 simulates a temporary bit-corrupt original read through test-only read interception; refuses the corrupted byte digest, then original bytes are confirmed unchanged and valid. Original controlled CP-02 expected outcomes unchanged.

No production code/source/privilege/consent/limits/status-pair/D-02 schema change, no actual host, benchmark or report. **Original 39 CP-02 cases still formally NOT_EXECUTED, zero accepted**, 283 requirements not formally verified. Separate owner decisions required for physical Bodhi 7, CP-07 formal acceptance, FAT entry and PR merges.

## Next bounded review

**Increment 62 / CT-08:** original P1 zero-observation denial/unavailable session and N1 preventing false complete classification are eligible as OFFLINE_FIXTURE. **CT-08-N2 is expressly G5_06_DOWNSTREAM** (most recent run invalid during regeneration); do not fabricate a report/regeneration consumer or count it as accepted. Record it explicitly as deferred and review next test groups for other offline-reachable cases. Stop for change to original method, unapproved source/host work, or production contract change.

## Conversation safety

Authority through Increment 61 implementation coherent; verify final docs CI and keep bounded sequential steps. No hostile-actor threat engineering.
