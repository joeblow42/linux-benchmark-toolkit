# Linux Benchmark Toolkit — G5-04 / RP-02 / CP-03 Increment 39 engineering continuation

Date: 2026-11-14. Governing methodology: **AI-Assisted Software Engineering Governance Standard v1.0**. Owner-approved FAT Readiness Roadmap; requirements Rev 1.6 (283 total: 210 FAT mandatory, 65 conditional, 8 deferred); FR-134, FR-177, FR-186 FAT dispositions and RP-02 private operational receipt v0.6 **Choice A** approved.

## Repository and exact recovery reference

- Repository: https://github.com/joeblow42/linux-benchmark-toolkit
- Prior verified checkpoint: `bd8e1bd36bcc42a0941070dce7a391e47d3f89f3`, PR #63, run `43628829976` SUCCESS.
- Increment 39 branch: `g5/cp03-rp02-o1-writer-39`, draft PR #64 stacked on PR #63; do not merge.
- Increment 39 implementation verified at commit `587f658a32f7330a116ee315588a69b0e65efa91`: GitHub Actions run `43630599504` SUCCESS, exact `head_sha`. Additional durable checkpoint commit may follow; verify its exact head and CI before claiming *final* checkpoint verified.
- Source-first oracle: `verification/g5_04/cp03_rp02_o1_writer_oracle_39.json`.
- Executable fixtures: `tests/test_g5_cp03_rp02_o1_writer_39.py`, seven test methods, all PASS at implementation head. Source-first oracle and tests were committed **before** production source changes.
- Changed vs previous checkpoint: `.github/workflows/test.yml`, `lbt_g5/o1_execution.py`, `lbt_g5/records.py`, `lbt_g5/canonical_session.py`, new test and oracle. No changes to protected helper, safety, root policy, source catalog, raw evidence writer, production canonical/status contracts.

## Increment 39 scope and evidence

This is a **narrow candidate O1 writer-run implementation**, not complete RP-02.3 assurance.

- Optional source families: SRC-13 SMART/NVMe, SRC-18 optical, SRC-21 VA-API.
- Existing sealed same-run D0 inventory respectively SRC-12, SRC-17, SRC-19 must bind exact approved target to run-specific operator consent and command identity.
- After the existing bounded O1 capture, the unchanged EvidenceWriter may report an **actual** `writer_run_bytes` clipping event with positive omitted suffix. The private v0.6 source receipt records `SRC-xx:callNNNN:run:writer` **only** when there is exactly one such event and no competing transport timeout/overflow/unknown omitted extent.
- Canonical independently requires the matching in-memory execution record, approved operator/target/argv and original D0 evidence chain, same-run sealed aggregate equal to the actual applied run meter threshold, positive original omission and matching private extent. The existing D-02 CaptureLimit entity and 41 status combinations are unchanged.
- A zero-omission exact boundary is **not** a capture-limit event. An unsealed meter reservation, absent inventory, conflicting or unknown limit, or unauthenticated O1 witness must fail closed.
- Seven source-first test methods covered all three positive O1 variants, exact boundary, inventory/provenance absence, invalid fabricated scopes/thresholds, simultaneous transport/writer timeout and overflow, unsealed reservation, and helper internal unknown effective transport ceiling. All existing CI test steps and unified validation passed at verified implementation commit.
- During development, earlier CI found a missing `RUN_BYTES` import and a negative-test error-message mismatch; both were corrected before the successful run. Never cite prior failed runs as successful evidence.

## Protected authority

No change authorized to:
- Fixed source command argv, tool paths, device target classes, authorization or consent.
- SRC-13 installed root-helper behavior, privilege scope, protocol, transport limits, or sudo authentication.
- G4-07 per-call/per-target/source/run ceilings, slots, execution controls, or source count.
- Production canonical schema v1.0.0 and exact D-02 entity/field contract; status schema 1.0 and 41 approved pairs.
- Original sealed acquired bytes, private provenance/integrity, approved requirements wording, or release gates.

## Open engineering work

1. **Next Increment 40 / remaining RP-02.3:** independently derive O1 per-target transport stdout/stderr/combined byte and time events; distinguish SRC-13 helper-run cumulative effective caps from requested caps, ensure multiple competing dimensions cannot be guessed; verify direct O1 captured transport and preserved originals. Design positive, negative, exact-boundary and simultaneous evidence **before** production changes. If an exact helper-effective threshold requires altering the installed helper protocol or privilege/consent behavior, stop and present alternatives for owner approval instead of expanding authority.
2. Remaining RP-02 source-total budgets, source-call count and source-wall timing for SRC-13 (60s, 32 calls, 32 MiB), SRC-18 (20s, 4 calls, 8 MiB), SRC-21 (10s, 1 call, 8 MiB), including proof of unreachable dimensions. Do not infer an omitted operation merely from elapsed time.
3. RP-03 F-06/D-02 **exact** canonical producer/validator contract conformance.
4. RP-04 independent original 39 CP-02 case assurance, 283 Rev 1.6 requirement verification, Bodhi Linux 7 AMD64 real-host source/privilege/consent validation.
5. Subsequent owner-approved FAT readiness roadmap packages, with owner gate review when actually needed.

**Unresolved privilege evidence caveat:** The installed SRC-13 root helper independently enforces 32 MiB and 60s cumulative per-run limits and may lower an individual request before capture. Its currently approved response reports captured original bytes and exceeded/timed-out flags, not the helper's exact applied, potentially reduced per-request threshold. Thus such helper internal events **must not** be promoted to an exact D-02 CaptureLimit without independently sufficient evidence. This increment does **not** change the helper; no helper interface changes are preauthorized.

## Gates and safety

G5-04 OPEN; RP-02 PARTIALLY COMPLETE; all 283 requirements NOT_VERIFIED; original 39 CP-02 cases NOT_ACCEPTED; independent human/source-first assurance OPEN; Bodhi 7 AMD64 host proof OPEN; RP-03 D-02/F-06 OPEN; FAT/release authorization NOT ESTABLISHED. All PRs remain draft/unmerged.

Reassess conversation integrity after every increment. This handoff is produced because the current session accumulated extensive GitHub file and CI review; start a fresh conversation with this exact recovery record to avoid cross-increment context ambiguity. Continue through successive increments without routine owner confirmation, stopping only for an owner authority decision, a protected-boundary conflict or material context risk. The next assistant should **read the recovery checkpoint directly from GitHub, verify PR stack and exact-head CI, then proceed**. Never ask the owner to repeat approved decisions.
