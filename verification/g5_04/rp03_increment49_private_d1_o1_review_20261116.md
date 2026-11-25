# LBT G5-04 / RP-03.2 — Increment 49 D1 and applicable O1 integration

**Authority:** owner-approved Alternative B FAT Readiness Roadmap Rev 0.2 and CT-07-N1 ordinary-fault wording, recorded in `verification/fat/altb_owner_approval_rev02_20261116.json`. Predecessor: Increment 48, draft PR #74 at `d71507f62a58b5906856d406a68e84712f4980fb` (exact-head PR CI 44025874432 and push CI 44025868758 SUCCESS).

## Purpose and boundaries

Extend the actual sealed G5-03 receipt → approved D-02 v1.0.0 private canonical producer → existing validator → internal read-only inventory consumer to representative D1 command output and O1 consented device evidence. No new collection calls, probes, shell execution, privileges, acquisition policy, status combination, field in D-02 files, benchmark claim or public report. The consumer is **private/unmasked** and never substitutes for approved privacy.yaml/outputs.yaml. Do not treat fixtures as physical Bodhi Linux FAT or formal CP-02 acceptance.

## Bounded implementation

- `lbt_g5/private_inventory.py` now passes through **existing approved** D-02 `authorization_class`, `authorization_decision`, `exit_code`, and `unavailable_fields` alongside the source outcome. This prevents a tool-missing event and D1/O1 nonzero partial outcome from losing existing factual availability/exit context at the consumer boundary.
- `tests/test_g5_cp03_rp03_d1_o1_consumer_49.py` uses deterministic `EvidenceWriter` sealed original bytes and actual `build_attempt`/persisted receipts, not bare mock normalized data. Eight cases exercise: D1 lsblk stdout+stderr; nonzero D1 with preserved factual data and PARTIAL/SOURCE_INCOMPLETE; D1 stderr-only no hardware fact; malformed D1; absent D1 tool; O1 SRC-13 SMART with same-run sealed SRC-12 inventory and recorded consent/approved fixed command; O1 nonzero output with partial status; O1 consent denial without hardware claims.
- All paths are the same existing source and canonical pipeline. The D1 model/serial and O1 SMART text are **reported source values, not a suitability verdict**. A partially acquired source can contribute qualified observed values but cannot be declared complete.
- The suite asserts no subprocess probe and checks that the consumed internal representation does not expose original evidence or invocation paths. This check does **not** imply that unmasked observed values are suitable for publication.
- `.github/workflows/test.yml` adds an explicit Increment 49 step while retaining all pre-existing validation.

## Acceptance discipline

Development CI verifies deterministic fixture integration only. Existing canonical file contracts and original 39 CP-02 acceptance expectations remain unchanged and **0 cases are formally accepted**. RP-03.2 remains OPEN pending broader representative family integration and a verified host exercise. RP-03.3 lifecycle/interruption and RP-04 CP-02 acceptance remain open. No merge or FAT entry authorized.

## Verification evidence

Exact-head PR and push CI identifiers and final branch SHA will be recorded in a subsequent checked checkpoint only after GitHub Actions completes successfully. Stop and correct any substantive test failure; do not infer success from a prior head.
