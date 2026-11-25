# Increment 70 optical imaging handoff

RP-08 C1 adds an explicitly selected DVD imaging workload. The operator supplies an optical device and expected media capacity and confirms permitted unencrypted media. The worker opens only an optical block device read-only and checks its measured capacity before imaging. The runtime reserves space in the private destination. The worker bounds retries, keeps a read-error map, and preserves an incomplete image as a partial file. It publishes a private ISO only after the copy, a second source read, and the on-disk image agree. Average copy rate includes reads and writes. Peak read rate is measured per chunk and destination write rate includes flush time.

The confirmed media type is operator-supplied and the kernel verifies the capacity. Independent hardware media/profile verification and ddrescue recovery-map execution remain open. The native reader writes its own byte-range retry log.

Four targeted tests, a generated synthetic ISO image and verification, and Unified Full 21/21 passed. No physical disc was read. The ordinary account cannot read the optical device on the current Bodhi setup, and a known-good permitted DVD has not been confirmed. The host still showed heavy pre-existing I/O pressure. To verify on hardware, arrange read access and select the media and an owner-only destination with space and reserve. A second local USB volume can provide the destination when explicitly designated. All physical safeguards still apply.

Draft #96 is stacked on draft #95. Both implementation Actions events passed. Verify the documentation head independently. Formal CP-02 remains 0/39. Continue with C2 local MPEG-2 to H.264 and HEVC fixture work.
