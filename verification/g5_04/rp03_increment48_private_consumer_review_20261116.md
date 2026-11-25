# LBT G5-04 / RP-03.2 — Increment 48 private source-to-consumer integration

**Scope:** authorized by Alternative B Rev 0.2 and CT-07-N1 owner approvals at `verification/fat/altb_owner_approval_rev02_20261116.json`. **Development candidate only**; not formal CP-02 acceptance or FAT.

## Objective

Prove that realistic, deterministic sealed G5-03 acquisition evidence and source receipts can be built into an approved D-02 v1.0.0 private canonical session, validated, then consumed through a **read-only, internal, factual inventory view**, with honest partial/missing/parse-failure states. This is **not a public report** and contains potentially sensitive observed hardware values. The approved privacy.yaml/outputs.yaml publication boundary is reserved for RP-05/RP-11.

## Implementation

- New `lbt_g5/private_inventory.py` calls `validate_canonical` first and reads only private same-run canonical files (no new acquisition). Each file is checked against the already validated manifest digest and size.
- Reads exactly the D-02 canonical observation/status/attempt fields. Returns semantic facts with original observed and normalized values, units, primary source ID and **actual acquisition outcome**, plus explicit lifecycle/completion/orchestration statuses, limitations and counts.
- Raw observation bytes, evidence references, receipt paths, source invocation commands and original file paths are not copied into the internal consumer structure. Values themselves are **not masked** and must not be published without the approved publication policy.
- A minimum-usable session is not relabeled COMPLETE, and no benchmark execution or suitability result is invented.

## Independent seeded source tests

`tests/test_g5_cp03_rp03_private_consumer_48.py` checks:

1. Two distinct actually sealed D0 source originals (SRC-02 os-release and SRC-08 meminfo) flow through receipts → canonical producer → existing validator → consumer; independent expected OS and byte-converted memory values and truthful INCOMPLETE orchestration.
2. DENIED SRC-13 consent gives zero observations and UNAUTHORIZED/OPERATOR_AUTH_REQUIRED, not success.
3. Malformed OS assignment yields PARTIAL/PARSE_FAILED with retained original and no typed factual claim.
4. Ordinary missing `status_records.json` fails session consumption before returning results.
5. Consumer representation does not contain private evidence/receipt/command paths; it is **not** declared publicly safe.
6. Missing committed manifest fails consumption.

No source commands, privilege, capture budgets, D-02 schema, status vocabulary, preservation logic or publication outputs changed. Draft PR stacked on Rev 0.2 approved planning branch; no merges.

## Remaining

RP-03.2 remains open beyond this incremental private-consumer proof. RP-03.3 session lifecycle finalization and RP-04 original 39 CP-02 acceptance cases remain unaccepted, and real Bodhi host FAT has not been performed. CI completion must be recorded at the exact increment head.
