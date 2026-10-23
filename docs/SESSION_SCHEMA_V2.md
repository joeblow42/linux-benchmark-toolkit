# Canonical session data — system.json schema 2.0.0 (IC-03)

**Status (2026-10-23):** IC-03 owner-accepted and merged via PR #16 (`5e00cc14f17b4289b584abaf181367530265df92`). The v2 writer remains opt-in and is not activated from the Phase 1 CLI.
**Authority:** approved IC03-D1 through IC03-D4, IC-03 integration contract,
and the IC-03 Detailed Design Draft 1.0 approved October 23, 2026.

## Canonical ownership and backwards compatibility

Existing Phase 1 session artifacts and their filenames remain authoritative:

```text
session_<UTC>_<token>/
  system.json
  benchmarks.json
  assessments.json
  discovery.csv
  report.html
  logs/
```

`system.json` owns discovered hardware evidence. `benchmarks.json` owns
**executed** benchmark measurements, not claims inferred from hardware.
`assessments.json` owns evidence-based suitability decisions, which remain
`NOT_TESTED` and `INSUFFICIENT_DATA` until measured evidence exists.
The remaining CSV/HTML/log files remain unchanged.

The existing Phase 1 reader and generator handle **only version 1.0.0**.
The new writer handles **only version 2.0.0**. Neither auto-converts a
session to the other version. The v2 writer is intentionally not invoked
by `benchmark --mode discovery`, so Phase 1 CLI and byte-identical
HTML regeneration continue to use the existing implementation.

## Pure schema/mapping API

```python
from reporting.session_schema import (
    build_system_document, validate_system_document,
)
from reporting.session_store import write_system_document

doc = build_system_document(
    "session_20261023T180000Z_1234567890",
    inventory,  # explicit IC-02 collect_inventory() result
    host={"system": "Linux", "architecture": "x86_64", "kernel": "observed"},
    session_started_utc="2026-10-23T18:00:00Z",
)
validate_system_document(doc)
write_system_document(existing_session_directory, doc)
```

The explicit caller must already own and choose an existing
`session_...` directory. No collectors, reporting, privilege
escalation, or package installs occur in these functions. The writer
does not create the directory or any missing Phase 1 artifacts.

`system.json` v2 has exactly five required top-level fields:
`schema_version` (`2.0.0`), `session_id`, `started_utc`,
`host`, and `discovery`.

`discovery` contains `contract_version` (`1.0`),
`scope`, `started_utc`, `completed_utc`,
`requested_collector_ids`, `execution_order`, `collectors`,
`timings`, `summary`, and `errors`. The `collectors` mapping
is taken from IC-02 `results`. Each entry retains exactly:
`collector_id`, `status`, `data`, `sources`, `reason`.

The validator enforces exact IC-01 IDs, six hardware statuses,
canonical order, full versus selected scope, no fabricated minimum
inventory, consistent attempted/executed/status counts, finite
nonnegative elapsed milliseconds and UTC timestamps. It rejects
unsupported disk versions, mismatched directory IDs, cyclic/untyped
objects, NaN, Infinity, and evidence fields not yet reviewed.

## Default privacy boundary (IC03-D4)

Persist a **defensive copy**, never mutate IC-02 in-memory evidence.
Host fields are limited to nonidentifying `system`,
`architecture`, `kernel` and optional `distribution`.

The ten hardware modules have explicit top-level payload field
allowlists matching the existing collectors. Nested fields exclude
identity fields (including serial numbers, MAC/IP addresses, UUIDs,
hostnames, usernames and private mountpoints); private strings are
redacted rather than published. Unknown top-level payload fields are
**rejected**, pending a documented schema review.

Only known `/sys/`, `/proc/` and `/etc/` provenance roots
are converted to nonidentifying labels (`sysfs:...`, `procfs:...`,
`etc:...`). Absolute fixture/user paths become `[REDACTED]`;
normalized provenance is idempotently accepted. `vainfo` is the
sole approved external tool in the current collector set. Collector
status and numerical observations are never changed to fabricate
success. Raw opt-in private diagnostic export is an IC-05 concern.

The allowlist is a conservative default protection—not a claim that
all unconstrained hardware strings can be classified with perfect
semantic accuracy. New fields require explicit review.

## Atomic single-document writer (IC03-D3)

`write_system_document(dir, document)` validates the v2 contract and
privacy before writing. It refuses existing v1 targets and symlink
targets. It serializes sorted UTF-8 JSON with a trailing newline,
writes a same-directory unique `0600` temporary file, flushes and
`fsync`s it, then performs `os.replace` into the fixed filename.
Directory metadata sync is best effort. Validation, privacy,
permissions, and I/O failures raise structured
`SessionPersistenceError.category`; the writer does not claim
multi-file transactionality.

The optional `build_session_manifest(dir, state=...)` function
**only constructs** a checksum-bearing manifest model; it does not
write a manifest. `COMPLETE` requires all five canonical artifact
files, a `logs/` directory and a valid v2 `system.json`.
`INCOMPLETE`, `FAILED` and `INTERRUPTED` record only observed
artifacts. `read_session_manifest` returns `None` for absent
manifests, which remains legitimate for **legacy** Phase 1 sessions.
An absent manifest must never be interpreted as a complete v2
multi-file session. Production publication of completion markers is
reserved for later IC-05/06 pipeline integration.

## Remaining work and limits

- The new v2 writer is **inactive** in the normal CLI pending
  version-aware reporting and IC-05/06 integration.
- Single-file atomicity does not guarantee multi-file consistency.
- Interrupted in-memory inventory can be persisted if explicitly
  supplied; no checkpoint recovery or automatic/manual resumption is supported
  under owner-approved IC-REC-01. Any new run starts from the beginning.
- Version 1 reports remain generated by their original reader. The v2
  HTML/CSV renderer, capability claims and Phase 2 physical-hardware
  acceptance will be separately approved.
- New package artifacts are discoverable by existing recursive
  `reporting/` and `tests/` packaging rules. No build-script change
  is required.

## Verification commands

```sh
python3 -m unittest discover -s tests -p 'test_session_schema.py' -v
python3 -m unittest discover -s tests -p 'test_session_store.py' -v
./benchmark --validate --validation-profile full
```

These unit cases provide controlled synthetic fixture evidence; they
do not certify Bodhi hardware values. The existing Phase 1 acceptance
suite remains active and unchanged. Historical acceptance (2026-10-23): PR #16 merged after owner acceptance, Bodhi tests (37/37 dedicated IC-03 tests and 21/21 Full top-level checks), and successful GitHub CI. These results do not establish physical-host hardware accuracy or live v2 CLI/report integration. Single-file atomic replacement and optional manifest inspection are not multi-file transactions or restart/recovery mechanisms.
