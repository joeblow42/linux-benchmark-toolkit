# Increment 69 sustained workload handoff

Extended mode registers sustained CPU and buffered storage workloads. CPU reports per-window hash throughput, retention after multiple windows, and host-wide utilization. The temperature limit, missing telemetry guard, frequency samples and available core throttle counters support the safety decision. Storage rotates writes inside one bounded scratch file, rate-limits writes, checks host I/O pressure, and records flushed sample throughput. The default engineering bounds are 30 seconds, two CPU workers, 80 C thermal stop, and 4 MiB/s storage pacing. The preview CLI accepts a configurable duration and temperature ceiling.

An optional iperf3 workload requires an authorized literal address and explicit selection. It caps duration, stream count, and offered bitrate. Fixture tests exercised both direction plans without network traffic. The subprocess wrapper bounds capture and kills its process group on cancellation or deadline.

Four targeted checks and Unified Full 21/21 passed. The physical Bodhi smoke exercised real temperature sensors for a two-second single-worker run. Sustained storage was fixture-only, and full-duration hardware and peer measurements remain open. Implementation push and PR CI passed for draft #95. Verify the documentation commit separately.

Next is RP-08 C1. DVD workloads require known-good unencrypted media, ordinary-user device read permissions, and an owner-chosen output directory with sufficient reserve. The owner authorized Slice C engineering. Physical media choices remain separate. Formal CP-02 remains 0/39.
