# LBT G5-04 / RP-03.3 Increment 53 — real CI-host lifecycle check

**Authority:** Owner-approved Alternative A session witness and lifecycle reconciliation; AI-Assisted Software Engineering Governance Standard v1.0; Alternative B FAT Roadmap Rev 0.2. Development/CI-host evidence only, not physical Bodhi Linux 7 FAT.

## Bounded engineering scope

The new `tests/test_g5_cp03_rp03_host_lifecycle_53.py` exercises actual unprivileged G5-03 `UnifiedCollectorEngine` D0 `COL-MEM` source acquisition (`SRC-08` meminfo, `SRC-09` swaps, `SRC-10` memory pressure) against the Linux CI runner. It uses real original bytes, real persisted G5-03 receipts, current D-02 producer+validator and read-only private consumer. No mocks of the acquisition path in the normal case, no sudo, O1, disk write to existing user data, network command or workload benchmark.

Three tests verify:

1. A normal selected-source traversal returns exact 3-attempt plan and matching receipts; the **real acquisition status rows**, rather than a fixed assumption about CI-host capabilities, independently determine whether acquisition scope is COMPLETE or PARTIAL. Typed memory total is reported in bytes, preserved original digests checked, and no benchmark/public result exists.
2. Cooperative cancellation immediately after the first actually acquired D0 source returns a proper INTERRUPTED session with one original and no invented SRC-09/SRC-10 receipts.
3. Cancellation before any source creates a valid zero-observation interrupted D-02 session, owner-only empty private directories, no evidence/public artifacts, and cleans up the disposable test directory.

These are safe host-context regressions that provide operational confidence in the new RP-03.3 lifecycle witness without asserting that any physical FAT host, optional privileged device, or benchmark passed.

## Unchanged controls

Approved D-02 v1.0.0 closed-world schema; 41 status pairs; G5-03 command/privilege/consent/byte/time/count limits; single engine; original evidence preservation; one HTML+conditional outputs policy; no TUI report viewer. Original 39 CP-02 cases remain 0 formally accepted. RP-03.2 remaining source-family coverage, RP-04 formal cases and real Bodhi 7 FAT still open. Draft PRs stay unmerged.

**Verification:** Run the new dedicated test step and unified Toolkit validation in both exact-head PR and push CI; record final head and runs before calling the increment verified.
