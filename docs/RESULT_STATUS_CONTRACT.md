# IC-04 — Result-status and assessment-domain contract

**Implementation baseline:** approved IC-04 Detailed Design Draft 1.1 (23 October 2026).
**Status (2026-10-23):** Owner-accepted and merged via PR #17 (`669e55886321f3d6f7374f2f7338ac9247898321`); typed contract only, not a benchmark execution engine.

## Separate status domains

| Domain | Canonical Python type | Values |
| --- | --- | --- |
| Hardware collector | `discovery.core.CollectionStatus` | COMPLETE, UNAVAILABLE, UNSUPPORTED, PERMISSION_DENIED, TOOL_MISSING, FAILED |
| Overall discovery | IC-02 orchestrator `summary.outcome` | COMPLETE, PARTIAL, FAILED, INTERRUPTED |
| Benchmark execution | `reporting.status_contract.BenchmarkExecutionStatus` | COMPLETE, SKIPPED, UNAVAILABLE, FAILED, INTERRUPTED |
| Software verification | `validation.results.ValidationStatus` | PASS, FAIL, SKIP, BLOCKED, NOT_APPLICABLE |
| Workload suitability | `reporting.status_contract.WorkloadSuitability` | GOOD, MARGINAL, POOR, NOT_TESTED |
| Assessment confidence | `reporting.status_contract.AssessmentConfidence` | HIGH, MEDIUM, LOW, INSUFFICIENT_DATA |

Application failures, including IC-03 `SessionPersistenceError.category`,
form a separate diagnostic domain and must not overwrite collector results.

Do **not** convert statuses by matching their text. In particular, an
optical collector returning UNAVAILABLE or VA-API collector returning
TOOL_MISSING is not an automatic failure in software validation.
A fixture-based unit test can PASS by verifying correct missing-device
handling while the workload remains NOT_TESTED.

## Pure benchmark-result interface

```python
from reporting.status_contract import (
    BenchmarkExecutionStatus,
    normalize_benchmark_result,
    validate_benchmark_record,
)

result = normalize_benchmark_result(
    "JF-02",
    BenchmarkExecutionStatus.COMPLETE,
    parameters={"codec": "h264", "width": 1920, "height": 1080},
    metrics={"realtime_ratio": {"value": 1.64, "unit": "x"}},
    evidence=["measurement:observed01"],
    tool={"name": "ffmpeg", "version": "7.0"},
    fixture_id="reference_h264_v1",
    log_ref="logs/JF-02.log",
)
validate_benchmark_record(result)
```

The returned mapping is a strict JSON defensive copy with required keys
`test_id`, `execution_status`, `parameters`, `metrics`, `reason`,
and `evidence`. Optional fields are `tool`, `fixture_id` and
`log_ref`. The factory requires a typed `BenchmarkExecutionStatus`;
it rejects `CollectionStatus`, `ValidationStatus`, untyped labels and
invalid or unsafe fields. The validator is specifically for a record
already known to belong to the benchmark domain and permits a string
status in serialized JSON.

A COMPLETE record requires a nonempty validated metric set with finite
numeric values and explicit units, nonempty execution configuration,
at least one structured evidence identifier, and tool name/version
provenance. It cannot independently verify that a future runner actually
measured the declared value; the runner remains responsible for truthful
evidence capture. This contract must not be used to fabricate results.

Other benchmark statuses require an explicit safe reason and no
**final-performance metrics**. Preflight observations and diagnostics can
appear as structured evidence IDs and safe relative `logs/` references;
raw tool output and private paths must not be included.

Measured numbers are not ratings. Suitability GOOD/MARGINAL/POOR and
confidence HIGH/MEDIUM/LOW cannot be assigned from hardware presence,
advertised GPU codecs, a successful collector, or benchmark COMPLETE
alone. When testing is not performed, the honest state is
NOT_TESTED / INSUFFICIENT_DATA.

## Example missing-device scenario

A system without an optical drive may yield:
- Hardware collector: `UNAVAILABLE` (the device was not detected)
- Discovery session: `COMPLETE` if the IC-02 minimum inventory exists
- Selected DVD benchmark: `UNAVAILABLE` (missing prerequisite)
- Software validation of correct no-drive handling: `PASS`
- DVD suitability: `NOT_TESTED` / `INSUFFICIENT_DATA`

A missing `vainfo` may similarly produce TOOL_MISSING for the
collector and UNAVAILABLE for a selected dependent benchmark. This
is not proof that the physical GPU or Linux software is defective.

A schema/privacy/persistence error must remain an application-level
error, distinct from the hardware statuses collected before it.

## IC-REC-01 — Interruption and restart policy

The approved policy **does not support resuming an interrupted
benchmark or Discovery execution**, neither automatically nor manually.
There is no checkpoint cursor, saved execution position, resumed-state
flag, recovery supervisor, or continuation interface.

A handled interruption can be marked `INTERRUPTED`, and the system can
retain already-valid evidence. The operator may initiate a **fresh,
separate execution from the beginning**; the previous attempt remains
interrupted. Abrupt process termination may prevent a final record
from being written, and no cross-crash recovery is promised.

IC-REC-01 retains collector failure isolation, atomic file replacement
and accurate interruption classification. Bounded optical retries and
operator-selected ddrescue mapfiles are separate features.

**Requirements history (2026-10-23):** The preserved Revision 1.2 wording of `LBT-NFR-018` required resumption and conflicted with IC-REC-01. The owner has explicitly approved the targeted Revision 1.3 replacement: valid completed evidence is retained when available, checkpoint recovery and automatic/manual resumption are excluded, and subsequent executions start from the beginning. This approved wording does not establish requirement verification; Rev 1.2 remains historical evidence.

## Scope boundary

The IC-04 module contains only contracts and validation. It does not
execute benchmarks, change collectors, perform I/O, write
`benchmarks.json`/`assessments.json`, change either schema version,
run `benchmark --mode discovery`, or trigger software validation.

A future, separately reviewed benchmark runner will supply measured
performance, actual attempt identities, applicable scoring thresholds
and persistent benchmark records. The live Phase 1 paths remain in
place, and IC-05/06 will handle broader privacy/reporting integration.

## Verification

```sh
python3 -m unittest discover -s tests -p 'test_status_contract.py' -v
./benchmark --validate --validation-profile full
```

`tests/test_status_contract.py` addresses IC04-T01–T19 and
IC04-T21–T22 plus additional strict-contract, copy, and resume-guard
cases. IC04-T20 is the existing Full suite, including Python tests and
Phase 1 acceptance. All tests are synthetic; they are not physical benchmark evidence. Historical acceptance (2026-10-23): 25/25 dedicated Bodhi status-contract tests PASS, 21/21 Full top-level checks PASS, PR #17 merged following owner authorization, and main CI run 40015791627 succeeded.
