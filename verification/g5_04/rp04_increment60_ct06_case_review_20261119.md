# RP-04 Increment 60 — CT-06 actual source timing and negative case candidate checks

2026-11-19. Owner-approved Alternative B FAT Readiness Roadmap Rev 0.2 and AI-Assisted Software Engineering Governance Standard v1.0. Draft PR stacked on Increment 59 PR #85, no merge.

**CT-06-P1:** One real selected D0 memory-source acquisition on the unprivileged Linux CI host through G5-03's single engine, sealed source original and private receipt; compare its actual started/completed UTC and measured monotonic elapsed_ms with independently loaded D-02 source-attempt and status records. No sudo/O1/network/benchmark. CI host not Bodhi 7 first article. If CI is root or non-Linux, a skip must **fail candidate verification**, never count as pass.

**CT-06-P2:** Actual DENY/DENIED O1 receipt, no source execution, no invented source clock; D-02 source attempt and acquisition status retain allowed null timestamps and elapsed.

**CT-06-N1:** Simulated ordinary production reader regression that drops a previously measured source_timing in its *in-memory receipt view*; original append-only receipt remains byte-identical and the canonicalizer must reject missing versioned timing before creating a final manifest. Restoring normal processing must succeed. No fake hostile editor or rehashed-record campaign.

**CT-06-N2:** Reject completion time before start in actual G5-02 attempt contract and the existing 14-field status contract.

Tests record per-case candidate results and limited actual CI-host timestamps, no raw source data in public artifacts. Original CP-02 all 39 cases remain formally NOT_EXECUTED and zero accepted. Owner physical host, CP-07, FAT, release and merge gates unchanged. No production/schema/source/privilege/limits change.
