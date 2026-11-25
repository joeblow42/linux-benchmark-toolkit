# G5-04 / RP-04 Increment 55 — CT-01 exact candidate execution

**Authority:** Owner-approved Alternative A 2026-11-17; Alternative B FAT Rev 0.2; AI-Assisted Software Engineering Governance Standard v1.0. Draft, stacked on draft PR #80. No merge authorized.

## Scope and method

Three original CP-02 CT-01 cases only (P1, N1, N2), all offline and unprivileged. Use separately controlled `verification/g5_04/status_pair_keys_rev0_2.csv` pinned to Git blob `500a189c150beacd80d73f9bffaf82900e2a1965`; no status vocabulary copied from production for expected results. Exercise both production 14-field status validator and D-02 StatusRecord entity validator; also D-02 status-records file shape on all 41 approved records.

- **CT-01-P1:** independently pinned 40 historical keys plus single approved forward 41st; validate each approved combination and total 41.
- **CT-01-N1:** controlled cross-domain acquisition/BLOCKED/UNCLASSIFIED_PUBLIC_FIELD must reject.
- **CT-01-N2:** controlled publication/BLOCKED/POLICY_CHANGED_DURING_BATCH must reject and must leave 41-key authority unchanged.

The runner `scripts/rp04_ct01_case_runner_55.py` runs exactly three unittest methods and emits machine-readable JSON per-case outcome into a CI artifact. GitHub Actions runs it explicitly and retains evidence; unified validation also discovers the test module. No bench, source acquisition, real host, raw-file mutation, O1 privileges, public report, schema/status modification, or network.

## Review and acceptance boundaries

A successful **candidate development execution is not the formal independent CP-02 acceptance** of any case; all 39 original cases remain formally NOT_EXECUTED and zero accepted, and 283 requirements remain formally unverified. CI results must include actual execution (no skip) and exact HEAD checks. Case evidence/acceptance requires independent reviewer and owner CP-07 dispositions; physical Bodhi 7 and formal FAT remain separately gated.

**Implementation CI:** pending exact-head PR/push verification before Increment 55 is considered implementation verified.
