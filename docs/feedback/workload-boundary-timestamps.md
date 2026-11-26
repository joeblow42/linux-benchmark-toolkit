# Record workload start and stop timestamps

Capture a start and stop timestamp in memory at each workload boundary and save them after the timed portion. Use the same time basis as temperature samples. For any workload that is skipped without starting, represent that fact without inventing timestamps.

## Review check

Verify that boundaries can be compared with temperature samples and add no per-iteration logging in the benchmark loop.

