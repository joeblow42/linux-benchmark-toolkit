# Benchmark test definitions — initial specification

Values below are **proposed configurable operational thresholds**, not universal industry standards. Hardware readiness, measured throughput and stability are separate gates.

| Group | Test | Measurement | Mode |
|---|---|---|---|
| Hardware | CPU/OS/memory/GPU/disk/optical/network | capabilities and versions | discovery |
| CPU | single-thread, all-thread | operations/s, scale factor | standard |
| CPU | sustained stress | throughput retention, temp/throttling | extended |
| Memory | bandwidth and pressure | MiB/s, swap/PSI | standard |
| Storage | isolated sequential read/write, random 4KiB | MiB/s, IOPS, latency | standard |
| Storage | sustained write, SMART/NVMe health | throughput curve, health flags | extended/discovery |
| Network | interface inventory and optional iperf3 | link speed, measured Mbps, loss | discovery/standard |
| Thermal | sensors under load | C, frequency, throttle events | standard/extended |
| DVD | drive/media detection | drive, media type | discovery |
| DVD | read and full ISO imaging | MiB/s, elapsed, unreadable sectors | extended |
| DVD | verify against readable source | integrity/copy completeness | extended |
| Video | MPEG-2 480p -> H.264 480p | relative real-time speed, errors | extended |
| Video | MPEG-2 480p -> HEVC / deinterlace | relative speed, errors | extended |
| Jellyfin | H.264 1080p -> H.264 720/1080p | real-time factor | extended |
| Jellyfin | MPEG-4 Part 2, WMV3, HEVC -> H.264 | real-time factor/errors | extended |
| Jellyfin | concurrency 1/2/4 | per-stream factor, stability | extended |
| Jellyfin | real server sessions (optional) | direct play/transcode evidence | extended |
| Backup | large and many small files, rsync delta | MiB/s, files/s, integrity | extended |
| Backup | SMB and external drive test | effective link use and errors | extended |

## Initial suitability rules
- Video real-time factor: GOOD >= 1.5; MARGINAL >=1.0 and <1.5; POOR <1.0 or conversion fails. DVD offline conversion uses a distinct speed target: GOOD >=2.0, MARGINAL >=0.75 and <2.0, POOR <0.75.
- DVD imaging: COMPLETE without unreadable data GOOD; COMPLETE with retries MARGINAL if verified; unrecovered required sectors POOR. Disc health must not be confused with host CPU suitability.
- Backup integrity mismatch or critical I/O errors is POOR regardless of transfer speed. Starting large-file reference rates: GOOD >=80 MiB/s; MARGINAL >=30 and <80; POOR <30, **only** after normalizing for link and media constraints.
- Sustained CPU throughput retention: GOOD >=90%; MARGINAL >=70% and <90%; POOR <70%; thermal evidence may override.
- Healthy Direct Play requires actual sustained read+network throughput and representative client compatibility; never infer from FFmpeg-only tests.
- Unknown/unmeasured capability: NOT_TESTED with explicit confidence and reason.
- Reliability-critical failures override average performance.

## Measurement rules
Record start/end UTC, test ID/version, host, parameters, fixture hash, tool/driver version, core/thread count, units, pass/fail reasons, samples and summary. Standardize MiB (2^20 bytes) vs MB (10^6 bytes). Preserve raw logs. Retry only when safe and bounded.

## Safeguards
Read-only discovery; temp-file-only write tests; explicit path validation and space reserve; no raw write to drives; optional confirmation for optical/network/integration operations; avoid automatic permission escalation. Use synthetic/owned media fixtures and do not bundle copyrighted DVD titles.

## Calibration
Collect a minimum of one baseline and one repeat on both older and newer test hosts before stabilizing performance thresholds. Compare like-for-like codec profiles, encoding settings and fixture hashes. These thresholds are never presented as hardware certification.
