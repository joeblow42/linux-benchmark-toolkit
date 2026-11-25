# RP-04 Increment 59 — CT-05 controlled measured-limit candidate verification

Date: 2026-11-19. Governed by AI-Assisted Software Engineering Governance Standard v1.0, owner-approved Alternative B FAT Readiness Roadmap Rev 0.2, controlled CP-02 CT-05 original cases.

## Real measurements and scope qualification

**P1**: In a controlled unprivileged Linux CI fixture, G5-03 SRC-15 source acquisition route uses the *real* monotonic clock and real idle time (approximately the approved 15-second source ceiling). Returned FS_STAT stdout is **synthetic** and child process is mocked, so this is measured **source-wrapper elapsed** in CI, *not* actual filesystem-stat process time or a physical Bodhi 7 case. The actual G5-02 source receipt has measured source_timing elapsed_ms, source elapsed_seconds, and a v0.6 source:time fact. Validate seconds threshold/observed seconds and null omitted bytes against G5-04 D-02 CaptureLimit.

**P2**: Existing G5-02 EvidenceWriter actually seals two MiB of temporary synthetic stdout bytes under approved 2-MiB SRC-15 source-writer ceiling. A third 8-byte fixture payload exceeds writer quota; retained extent 2 MiB and omitted-at-least 8 are observed at the writer, rather than invented. G5-04 produces exact byte unit and measured limit metadata. No original evidence altered.

**N1**: An explicitly invalid negative input re-labels a time event as byte quota, mislabels reason/units or invents omitted bytes. Existing G5-02 receipt guard must reject it before canonical production.

A dedicated CI runner writes per-case test result and measured source/time/byte witness JSON. All original 39 CP-02 cases remain NOT_EXECUTED and 0 formally accepted; independent FAT, physical host and CP-07 remain separately gated. No source commands, privilege/consent/safety thresholds, D-02 schema v1.0.0, 41-pair registry, or production implementation changed.
