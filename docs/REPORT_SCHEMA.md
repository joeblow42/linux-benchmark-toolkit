# Report contract — Version 1.0.0 (proposal)

Every session emits:
- `system.json`: schema_version, session_id, UTC timestamp, anonymized host identity, OS/kernel/architecture, hardware components and capability evidence.
- `benchmarks.json`: ordered test records with id, execution status, configuration, sample/summary metrics (unit included), tool/driver versions, sources, diagnostic log references.
- `assessments.json`: per-workload classification, capability/performance/reliability gates, confidence, threshold IDs and evidence IDs.
- `<metric>.csv`: time-series or tabular exports with header, stable units and test/session identity.
- `report.html`: fully inlined CSS/JS (if used), embedded summary and charts; usable offline with JavaScript disabled for essential content.
- `logs/`: detailed test outputs; avoid copying private file names unless deliberately requested.

## Status enumerations
Execution: COMPLETE, SKIPPED, UNAVAILABLE, FAILED, INTERRUPTED.
Suitability: GOOD, MARGINAL, POOR, NOT_TESTED.
Confidence: HIGH, MEDIUM, LOW, INSUFFICIENT_DATA.

## Example record
```json
{
  "schema_version": "1.0.0",
  "test_id": "JF-02",
  "execution_status": "COMPLETE",
  "parameters": {"input_codec": "h264", "output_codec": "h264", "width": 1920, "height": 1080, "acceleration": "vaapi"},
  "metrics": {"elapsed_seconds": {"value": 73, "unit": "s"}, "realtime_ratio": {"value": 1.64, "unit": "x"}},
  "fixture_id": "h264_1080p_reference_v1",
  "tool": {"name": "ffmpeg", "version": "record-during-execution"},
  "errors": [],
  "log_ref": "logs/JF-02.log"
}
```

No fabricated values in production reports. `NOT_TESTED` remains distinct from performance failure. Schema migrations and backward compatibility must be tested before release.
