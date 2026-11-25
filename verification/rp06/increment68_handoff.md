# Increment 68 short workload handoff

RP-07 B2 registers CPU SHA-256 single and bounded parallel throughput, memory buffer-copy bandwidth with host-wide pressure and swap observations, and buffered local scratch storage tests. The CPU result identifies whether the worker cap covers all affinity CPUs. Storage measures sequential MiB/s and random 4 KiB IOPS/latency. The sequential write includes an fsync. Reads can include page-cache effects and the reported random-write latency excludes flush. These measurements describe the stated workload and method.

Use `python3 -m lbt_g5.workload_cli --help` for the development entry point. It requires an existing owner-only root. The Phase 1 production launcher and protected inventory formats remain unchanged.

Four targeted checks and Unified Full 21/21 passed. A bounded Bodhi smoke yielded complete CPU and memory measurements. The filesystem test declined to write because pre-existing I/O pressure exceeded the guard. The positive storage test used a private isolated fixture. The implementation passed both exact-commit Actions events on draft #94. Verify the documentation commit independently. Formal CP-02 remains 0/39.

Next is RP-07 B3 sustained CPU and file-backed storage, thermal observations and stops, and optional explicitly authorized peer testing. Retain the storage-pressure guard until the host can safely measure storage.
