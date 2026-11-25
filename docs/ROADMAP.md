# Development roadmap

The toolkit uses one evolving repository; each phase has executable acceptance tests and updates the complete release package.

## Phase 1 — Portable foundation, Dialog, baseline reporting
- Portable relative-path launcher, Bash conventions, config loading, log/session handling.
- Dialog main menu, CLI equivalents, cancellation and error handling.
- Minimal versioned JSON data contract, CSV export, offline HTML report generation.
- Host capability/dependency inspection, no automatic installers.
- Package layout, licenses/dependency manifest, SHA256 verification.
**Exit criteria:** Bodhi Live USB launches offline; relocating extracted directory does not change behavior; report opens locally; missing Dialog is handled clearly.

## Phase 2 — Hardware discovery
- CPU, RAM, GPU/VA-API, OS/kernel, storage, optical, network, thermal/power inventory.
- Redaction, inaccessible device handling, tool-version provenance.
- Structured inventory and hardware-focused HTML report.
**Exit criteria:** verify on Bodhi and Basement against independent OS commands; missing devices represented as unavailable.

## Integration-contract status (2026-10-23)
IC-01 registry, IC-02 in-memory orchestration, IC-03 opt-in session-v2 persistence, and IC-04 typed status contracts were merged through PRs #14–17. IC-05 provenance/privacy/error lifecycle, IC-06 v2 reporting, and IC-07 extended validation/requirements-traceability integration remain outstanding. The Phase 2 end-to-end CLI-to-v2-report path is not complete; integrated contracts do not represent a percentage of overall phase delivery. IC-REC-01 intentionally excludes checkpoint resumption after interruption; a new attempt begins from the beginning.

## Phase 3 — General performance
- Repeatable CPU and RAM workloads, file-backed fio, optional iperf3 peer, monitoring and thermal/reliability metrics.
- Disk-capacity reserve, timeouts, stop conditions, non-root default, CSV series.
**Exit criteria:** standard mode completes; user files untouched; results and units reproducible, degraded/missing dependencies explicit.

## Phase 4 — Specialized workloads
- DVD read reliability / image and verification using approved media; bounded retries.
- FFmpeg fixture matrix for MPEG-2, MPEG-4 Part 2, WMV3, H.264, HEVC where supported, optional VA-API hardware paths.
- Jellyfin Direct Play and optional actual server integration tests separated from stand-alone FFmpeg.
- Backup/rsync and SMB throughput using dedicated test data.
**Exit criteria:** fixture provenance and measured ratios; no claims about unexecuted hardware or codecs.

## Phase 5 — Workload assessments and detailed reporting
- Per-workload capability/performance/reliability gates and configurable thresholds.
- Confidence levels and test coverage, bottleneck analysis, HTML charts/tables.
- Comparison across sessions, JSON/CSV export and report-only regeneration.
**Exit criteria:** every judgment links to evidence; offline HTML portable; CSV compatible with LibreOffice Calc.

## Phase 6 — Portable offline release and hardware validation
- x86_64 bundled executable/library dependency review; host compatibility checks and fallbacks.
- Reproducible archive, SHA-256, third-party license notices, release notes and user guide.
- Validate on Bodhi USB, Basement Ubuntu, then any additional older laptops available.
**Exit criteria:** transfer by archive to different media, extract, launch and obtain valid results without Internet; known host-side dependencies documented.

## Working method
Each phase: design -> implement -> static/unit checks -> physical-host validation -> fix -> tagged acceptance. Avoid declaring physical-host validation completed based only on CI. Track each phase in GitHub Issues.
