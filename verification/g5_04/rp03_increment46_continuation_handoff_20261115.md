# LBT G5-04 / RP-03.2 / CP-03 — Increment 46 engineering continuation

Date: 2026-11-15. **Candidate engineering verification only.** Governing authority: AI-Assisted Software Engineering Governance Standard v1.0; approved First Article Test Readiness Roadmap; Requirements Rev 1.6 (283 requirements); frozen CP-01 D-02 §6 contract.

## Authority and repository

- Repository: https://github.com/joeblow42/linux-benchmark-toolkit
- Increment 45 recovery parent: commit `b9187732b414c6cfcbec77e07fa677cabe758685`, draft PR #70.
- Increment 46 branch: `g5/cp03-rp03-multioriginal-46`, draft PR #71 stacked on PR #70. **Do not merge**.
- Implementation/test correction verified head: `b515e66585c4bb1b8a1e5b75ec53afc78f6da20a`; exact-head PR CI **43751900734 SUCCESS**, push CI **43751895329 SUCCESS**.
- The registry-parity test and this verification/checkpoint documentation were committed **after** that implementation-head. Verify PR #71's final current head and its exact-head CI. Once verified, record final SHA, run numbers, and conclusion as a durable comment on #71.
- Frozen D-02 ledger: `verification/g5_04/rp03_cp01_d02_approved_contract_43.json`; owner approval ODT SHA256 `6d836d28af086a0fec7df2ca0949faf9447f9cee29cfabb8751344bd5104c98b`. Canonical 1.0.0; status 1.0 exact 14 fields/41 combinations; RP-02 receipt v0.6 Choice A retained.

## Increment 46 scope and source-first audit

New `tests/test_g5_cp03_rp03_multioriginal_46.py` asserts seven cases (initial six plus explicit 28-family registry parity). Initial source-first PR/push at `ec25de8a56f8daacfb847b82ab23e79f9c18167d` exposed four relevant expected RED failures in **push CI 43751645202**: missing SRC-14 contributor in SRC-15 semantic row; rehashed sibling SRC-15 original substitution accepted; rehashed normalized statvfs value accepted; rehashed literal original accepted. Two controls (identical bytes under different attempt IDs; non-UTF8 lossless fallback) passed. Source-first cases were not an attempt to approve CP-02.

Production repair in `lbt_g5/canonical_session.py` only: SRC-15 typed observations now refer to the actual sealed SRC-14 mountinfo selection original *and* the SRC-15 sealed worker stdout with their distinct attempt IDs. Primary acquisition status stays tied to SRC-15 (no invented multi-source status). Read-only validator independently reconstructs eligible mounts from sealed SRC-14 and parses SRC-15 statvfs bytes, validates each worker artifact/label, exact typed observation value and single-primary source acquisition status. Raw observations for all source families must match sealed UTF-8 or lossless sealed-byte reference; artifact identity and status remain checked even under rehashed manifests. Historical `tests/test_g5_cp03_fs_stat_19.py` single-original assertion updated to reflect actual two-original dependence, without reducing other checks.

Implementation GREEN: PR 43751900734 / push 43751895329 both SUCCESS at `b515e66585c4bb1b8a1e5b75ec53afc78f6da20a`. Subsequent addition test #46_07 checks registry and PARSERS both enumerate 28 source families (19 D0 / 6 D1 / 3 O1). Final exact-head CI still needs confirming.

Audit ledger: `verification/g5_04/rp03_increment46_source_family_coverage_audit_20261115.json`.
Checkpoint: `verification/g5_04/rp03_increment46_verified_checkpoint_20261115.json`.

## Protected boundaries

No changes to approved source argv, allowlists, permissions, sudo/helper, consent, source byte/time/count limits, G5-03 sealed original bytes, private operational receipts, production schema version, status vocabulary, unified IC-02 engine, public evidence exclusion, or publication/TUI design. Protected files (`lbt_g5/safety.py`, `lbt_g5/o1.py`, `lbt_g5/privilege_contract.py`, `lbt_g5/privileged_session.py`, `packaging/lbt_root_helper.py`, `lbt_g5/evidence.py`, `lbt_g5/canonical_contract.py`, `lbt_g5/o1_execution.py`, `lbt_g5/records.py`, `lbt_g5/engine.py`, `lbt_g5/d02_schema.py`) unchanged relative to Increment 45.

## Known limits and next work

Registry parity and the existing 28 parser-family source-first tests do **not** independently prove postcommit typed-value reparse for the other 27 source families. RP-03.2 remains OPEN. Starting **Increment 47**, build source-first adversarial tests with actually sealed originals from remaining D0 families and independently verify the exact per-original parser values; expand source-family groups without guessing provenance, then cover D1 streams, optional O1 consent and original bindings. Keep small independent increments and draft stacked PRs.

After RP-03.2: RP-03.3 owner-approved D-05 validity versus completeness, zero-observation sessions, interruptions and limitations; RP-04.1 independent original 39 CP-02 cases; RP-04.2 CP-04 persistence, tamper and atomicity; RP-04.3 CP-05 RTM and real CP-06 Bodhi Linux 7 AMD64 host/device/consent; RP-04.4 explicit owner CP-07 review gate.

No original CP-02 cases formally accepted (0/39), 283 Rev 1.6 requirements NOT_VERIFIED, Bodhi host FAT NOT_EXECUTED, FAT readiness NOT ESTABLISHED, release NOT AUTHORIZED. No owner decision pending. Review conversation context integrity; if at risk, use this handoff in a new chat.

## Recovery instruction

Fetch the checkpoint, this handoff, 28-source coverage ledger and frozen D-02 contract directly at PR #71's final verified head. Recheck PR #71 base #70 remains draft/unmerged, protected diff boundaries and exact-head PR/push CI. Start Increment 47 source-first D0 independent typed-value/bytes attribution in a fresh draft stacked PR. Never merge or infer acceptance from CI.
