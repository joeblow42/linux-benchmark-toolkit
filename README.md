# Linux Benchmark Toolkit

Portable, offline-capable Linux hardware benchmarking and workload suitability assessment toolkit.

> **Status:** design baseline established; benchmark executable and packaged dependencies are not implemented yet. See [Phase 1](https://github.com/joeblow42/linux-benchmark-toolkit/issues/1).

## Purpose
Evaluate older and modern Linux desktops and laptops for DVD imaging and conversion, Jellyfin Direct Play/transcoding, backups/Samba, and general performance. Keep capability, real measurements and reliability separate. Ratings: GOOD, MARGINAL, POOR or NOT_TESTED, with confidence and supporting evidence.

## Agreed design
- **UI:** Dialog ncurses terminal menus; independent command-line operation.
- **Modes:** discovery, standard and extended.
- **Engine:** modular Bash; Python report generator.
- **Report:** self-contained offline `report.html` backed by canonical JSON and CSV exports.
- **Deployment:** portable archive runnable from persistent Bodhi Live USB or copied/extracted on the planned SSD toolkit.
- **Scope:** Linux x86_64 initially; host kernel/GPU drivers and ABI constraints detected explicitly; no Internet needed for normal use.
- **Safety:** no raw device writes, no automatic package installation, validated isolated test files and bounded stress activity.

## Project documents
- [Architecture](docs/ARCHITECTURE.md)
- [Development roadmap](docs/ROADMAP.md)
- [Test definitions and thresholds](docs/TEST_SPECIFICATION.md)
- [Report data contract](docs/REPORT_SCHEMA.md)
- [Portable packaging requirements](docs/PACKAGING.md)
- [Development standards](docs/CONTRIBUTING.md)

## Development tracker
- [Phase 1 — Foundation and Dialog](../../issues/1)
- [Phase 2 — Hardware discovery](../../issues/2)
- [Phase 3 — General benchmarks](../../issues/3)
- [Phase 4 — DVD, Jellyfin and backups](../../issues/4)
- [Phase 5 — Assessments and reporting](../../issues/5)
- [Phase 6 — Release and physical-host validation](../../issues/6)
- [Cross-cutting quality and safety](../../issues/7)

## Validation
Automated tests verify code logic and packaging, but thermal, optical, VA-API, sustained I/O and actual Jellyfin playback results require running on the target host. Benchmark scores and hardware suitability are not reported until supporting measurements exist.
