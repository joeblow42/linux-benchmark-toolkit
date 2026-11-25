# RP-04 Increment 63 — CT-09 typed/lossless acquired data and closed-world schema

2026-11-19 · AI-Assisted Software Engineering Governance Standard v1.0 · owner-approved Alternative B FAT Rev 0.2 · original CP-02 controlled cases. Draft PR stacked on #88; no merge.

- **CT-09-P1:** A source-reported previously unknown `EXPERIMENTAL_FIELD` from sealed SRC-02 bytes is retained as a typed semantic `os.release.EXPERIMENTAL_FIELD` observation with exact original evidence ID, attempt and parser finding. A second non-UTF8 fixture preserves byte-exact original and emits `BYTES_REF` lossless raw fallback rather than fabricating a typed value. No new static canonical schema field is added.
- **CT-09-P2:** Known SRC-08 MemTotal value `1024 kB` becomes exact INTEGER `1048576` bytes with source-specific datum path, reference, parser transformation ID and finding.
- **CT-09-N1:** The production D-02 closed-world type/field validators reject undeclared top-level or observation member in memory (no canonical file changes).
- **CT-09-N2:** An ordinary consumer regression in the *in-memory* observation view silently drops the unrecognized source's semantic record. The independent canonical validation refuses missing output, and the original sealed bytes and persisted private records remain unchanged. No forged-manifest or attacker narrative.

Dedicated runner reports four per-case candidate checks and unified validation in GitHub CI. Formal original CP-02 execution remains **0/39, 0 accepted**; no physical Bodhi 7, CP-07, FAT, source/privilege/consent/limit/schema/status code modifications or release.
