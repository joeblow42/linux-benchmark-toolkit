# LBT thresholds and limits

This reference covers the active B/C development workloads, their supporting acquisition and validation limits, and the proposed assessment thresholds. Percentages from Linux PSI refer to host-wide stall time, independent of the filesystem selected for the workload.

## Workload safeguards

| Check | Threshold | Effect |
|---|---|---|
| Host I/O pressure notification | Above 50% on `/proc/pressure/io` `some avg10` | Emits a notification when the 10-second average first crosses the threshold during a guard instance. Work can continue below the stop threshold. |
| Host I/O pressure stop | At or above 75% on the same 10-second average | Storage, optical, and video workloads return `PREEXISTING_IO_PRESSURE` before starting payload I/O, or `IO_PRESSURE_STOP` during a run. Samples are taken at most four times per second during normal polling. The guard also samples at start and at completion. |
| I/O pressure telemetry | A valid sample is required | Missing telemetry blocks startup. Loss of telemetry during a guarded run stops it. |
| CPU pressure before short CPU test | 25% `some avg10` | At or above the threshold, report unavailable. |
| CPU pressure before sustained CPU and video tests | 15% `some avg10` | At or above the threshold, report unavailable. |
| Memory pressure before memory and concurrent encoder tests | 10% `some avg10` | At or above the threshold, report unavailable. |
| Available RAM for memory-copy test | At least 16 times the configured single buffer size | With the 8 MiB default, require 128 MiB available before allocating the two buffers. |
| Available RAM for concurrent video | 768 MiB per stream | Require the measured headroom before spawning the encoders. The runtime also reserves 512 MiB per stream. |
| CPU temperature | Stop at 80°C by default. Configurable from 45°C to 90°C for sustained and fixture video workloads. | Sustained CPU and storage and video require valid CPU temperatures. The owned-disc decode check uses 80°C. A missing starting temperature blocks the run. Loss of readings during testing stops it. |
| Filesystem free-space reserve | 1,024 MiB by default | Before a disk workload, require the declared payload reservation plus this reserve on the filesystem. The development CLI exposes `--disk-reserve-mib`. |
| Resource reservations | Requested worker count, memory, and disk must fit the run limits | A workload over any limit returns `RESOURCE_LIMIT`. |
| External command output | 1 MiB combined by default | The bounded command runner stops children on deadline, cancellation, or excess output. Video operations use reduced limits where specified below. |

## B workload sizes

| Workload | Defaults and allowed values | Summary |
|---|---|---|
| Short CPU | 1 second each for single and parallel samples. 0.05–3 seconds allowed. Up to 4 workers by default, configurable from 1–64 and capped by CPU affinity. | Counts fixed 64 KiB SHA-256 operations. |
| Short memory | 1 second and two 8 MiB buffers. 0.05–3 seconds, 1–64 MiB per buffer. | Measures copied bytes and records host pressure and swap deltas. |
| Short storage | 16 MiB scratch, 64 operations per random direction, 4 KiB blocks. Scratch range 4 KiB–128 MiB in 4 KiB increments. Operation count 1–1,024. | Uses a newly created local scratch file. Sequential writes include a flush. Buffered read and random I/O results may include cache effects. |
| Sustained CPU | 30 seconds and up to 2 workers by default. 1–300 seconds and 1–16 workers at the API. | Records hash throughput in windows up to 5 seconds and samples thermal telemetry. |
| Sustained storage | 30 seconds, a 16 MiB rotating file, and a 4 MiB/s target. 1–300 seconds, 1–64 MiB scratch in MiB increments, and 1–16 MiB/s at the API. | Writes only the fixed-footprint scratch file and flushes sampled writes. Reported throughput includes pacing. |
| Optional network peer | 30 seconds per direction, 25 Mb/s target, one stream, TCP port 5201. 1–30 seconds, 1–100 Mb/s, ports 1–65535. | Requires explicit authorization for a literal unicast peer. The command deadline is the selected duration plus 12 seconds per direction. |

## C workload sizes

| Workload | Defaults and allowed values | Summary |
|---|---|---|
| Raw DVD imaging | 64 KiB–8,600,000,000 bytes in 2,048-byte sectors. 1 MiB chunks. One retry by default, 0–2 allowed. Deadline 1,800 seconds, 1–3,600 allowed. | Known-good unencrypted media. Exact-capacity confirmation, raw readback verification, and an additional 4 MiB disk reservation for supporting evidence. |
| Owned DVD short decode | 5 seconds by default. 1–15 seconds, title 1–99, 90-second command deadline. | Explicitly authorized disc input and a null output. Retains private diagnostics. |
| Owned DVD encoding fixture | Up to 120 seconds and 256 MiB. Read at 1× real time. 180-second extraction deadline, 120-second verification deadline, 512 KiB combined tool-output cap each. Disk reservation includes 4 MiB for supporting evidence. | Retain the video stream after a complete decode and SHA-256 check. Require at least 30 seconds when the requested sample is 30 seconds or longer. |
| File-based video | Short default 120 seconds of media and 180 seconds wall time. Extended default 300 and 600 seconds. Range 1–600 seconds of media, 1–900 wall seconds, 1–4 threads. | Probe deadline 15 seconds, tool inventory deadline 10 seconds each, 512 KiB encode output cap. Input file cap 2 GiB, dimensions up to 4096×2160, FFmpeg allocation cap 256 MiB per allocation, and 512 MiB runtime reservation per encoder. |
| Jellyfin concurrent fixture count | 1, 2, or 4 encoders. Default 2. | Run separate FFmpeg processes and require a positive overlap. Synchronization waits up to 20 seconds or the video deadline if shorter. |
| Jellyfin Direct Play | 1–64 profile streams, default 1. Profile JSON up to 16,384 characters. | Compare aggregate input bitrate with supplied positive storage and network throughput evidence. |
| Jellyfin exported session evidence | Up to 2 MiB each for session JSON and transcode log. | Import owner-supplied evidence for separate live-session review. |

## Inventory acquisition and software verification

The G5 inventory acquisition run is limited to 180 seconds and 512 MiB with up to two ordinary probes or one O1 probe. These are acquisition limits, separate from B/C workload pressure thresholds. See [the executable source policy](../lbt_g5/safety.py) for per-source ceilings and [the command runner](../lbt_g5/runtime.py) for output stream limits.

| Source | Max captured data | Entry or call cap | Source deadline | Additional target or call limit |
|---|---:|---:|---:|---|
| SRC-01 | 1 MiB | 8 | 2s | — |
| SRC-02 | 1 MiB | 1 | 2s | — |
| SRC-03 | 512 KiB | 128 | 2s | — |
| SRC-04 | 4 MiB | 64 | 3s | — |
| SRC-05 | 16 MiB | 1 | 6s | — |
| SRC-06 | 32 MiB | 1 | 4s | — |
| SRC-07 | 32 MiB | 4096 | 5s | — |
| SRC-08 | 2 MiB | 1 | 2s | — |
| SRC-09 | 2 MiB | 1 | 2s | — |
| SRC-10 | 2 MiB | 1 | 2s | — |
| SRC-11 | 16 MiB | 1 | 6s | — |
| SRC-12 | 32 MiB | 4096 | 5s | — |
| SRC-13 | 32 MiB | 32 | 60s | 8 MiB / 12s |
| SRC-14 | 16 MiB | 1 | 3s | — |
| SRC-15 | 2 MiB | 128 | 15s | 2 MiB / 2s |
| SRC-16 | 1 MiB | 1 | 2s | — |
| SRC-17 | 8 MiB | 128 | 3s | — |
| SRC-18 | 8 MiB | 4 | 20s | 4 MiB / 8s |
| SRC-19 | 16 MiB | 2048 | 4s | — |
| SRC-20 | 16 MiB | 1 | 6s | — |
| SRC-21 | 8 MiB | 1 | 10s | — |
| SRC-22 | 16 MiB | 2048 | 4s | — |
| SRC-23 | 16 MiB | 2 | 10s | 8 MiB / 5s |
| SRC-24 | 8 MiB | 2048 | 4s | — |
| SRC-25 | 16 MiB | 4096 | 5s | — |
| SRC-26 | 16 MiB | 2048 | 4s | — |
| SRC-27 | 2 MiB | 128 | 3s | — |
| SRC-28 | 32 MiB | 4 | 20s | 8 MiB / 8s |

Unified Full gives unittest discovery 50 seconds. Legacy acceptance workers have a 35-second deadline, with 120 seconds for cases 12–15. See [validation adapters](../validation/adapters.py).

## Proposed assessment values

| Measure | Proposed values |
|---|---|
| Video speed | Good at 1.5× real time or more. Marginal from 1.0× to below 1.5×. Poor below 1.0× or on conversion failure. |
| DVD conversion speed | Good at 2.0× or more. Marginal from 0.75× to below 2.0×. Poor below 0.75×. |
| DVD imaging | Good if complete without unreadable data. Marginal if complete and verified after retries. Poor for unrecovered required sectors. |
| Sustained CPU retention | Good at 90% or more. Marginal from 70% to below 90%. Poor below 70%. Thermal evidence can override the rating. |
| Later backup assessment | Good at 80 MiB/s or more. Marginal from 30 to below 80 MiB/s. Poor below 30 MiB/s after normalizing for link and media. Integrity failure overrides speed. |

See [the benchmark test specification](TEST_SPECIFICATION.md) for applicability and interpretation.
