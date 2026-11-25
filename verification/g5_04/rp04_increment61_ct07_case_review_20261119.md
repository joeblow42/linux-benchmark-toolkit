# RP-04 Increment 61 — CT-07 exact evidence/attempt provenance case review

2026-11-19. Owner-approved Alternative B FAT Rev 0.2; AI-Assisted Software Engineering Governance Standard v1.0. Original CT-07-N1 wording superseded **only in test input** by approved ordinary wrong-run/stale/missing scenario; expected rejection unchanged. No speculative hostile attacker.

- **CT-07-P1:** Original SRC-14 sealed mountinfo and SRC-15 sealed FS_STAT stdout (2 independently sealed bytes/attempts) support a semantic observation. Both IDs, attempt IDs, SHA256 and exact bytes checked against actual G5-04 manifest.
- **CT-07-P2:** Actual G5-02 EvidenceWriter seals identical source bytes twice on two distinct source attempts; distinct run/attempt-qualified IDs, matching SHA-256, and distinct D-02 original attribution verified end to end. No duplicate/acquisition path introduced.
- **CT-07-N1:** Missing original or stale/wrong attempt universe is rejected by independent status validation; a simulated ordinary in-memory observation-link regression is rejected by G5-04 validation. No raw/canonical files rewritten.
- **CT-07-N2:** Ordinary transient corrupt-byte read simulated via test-only read interception; canonical validation refuses original SHA mismatch, then original bytes and normal validation are confirmed unchanged. No raw evidence editing or hostile edit simulation.

The reused Increment 46 fixture uses controlled synthetic originals, not live host actions, O1 privileges, commands, benchmarks or public output. Results are CI **candidate development checks** only, not formal original CP-02 execution, CP-07 acceptance or FAT. All 39 original controlled cases remain NOT_EXECUTED / 0 accepted. D-02 schema v1.0.0, 41 status pairs, source commands/consent/limits and immutable originals unchanged.
