# LBT G5-04 / RP-03.2 / CP-03 — Increment 47 engineering continuation

**Date:** 2026-11-15. **Candidate verification only.** AI-Assisted Software Engineering Governance Standard v1.0, approved FAT Readiness Roadmap, Requirements Rev 1.6 (283 requirements), and frozen CP-01 D-02 §6 remain authoritative.

## Authoritative recovery

- Repository: https://github.com/joeblow42/linux-benchmark-toolkit
- Increment 46 parent: `391ba75a28b1f396ad28f89e951b135d01edeb02`, draft PR #71, stacked on #70. Exact-head PR CI **43752194895 SUCCESS**, push **43752190351 SUCCESS**; durable reconciliation comment recorded on #71.
- Increment 47 branch: `g5/cp03-rp03-d0-semantic-47`; draft PR **#72** stacked directly on #71; **do not merge**.
- Increment 47 implementation verified head: `b0d012a57b496d8dd36a35a701fe5c91a24022ad`; exact-head PR CI **43763957465 SUCCESS**, push **43763953297 SUCCESS**.
- This audit/checkpoint/handoff documentation was committed **after the verified implementation head**. Verify the final current PR #72 head and exact-head PR and push workflow conclusions before using this as a verified recovery anchor. Record final SHA and run IDs on PR #72 as a durable comment.
- Read directly from GitHub at the final PR head: `verification/g5_04/rp03_increment47_verified_checkpoint_20261115.json`, `verification/g5_04/rp03_increment47_source_first_audit_20261115.json`, this handoff, and `verification/g5_04/rp03_cp01_d02_approved_contract_43.json`.
- Frozen D-02 canonical 1.0.0, status schema 1.0 exact 14 fields/41 combinations, approved RP-02 receipt v0.6 Choice A and Requirements Rev 1.6.

## Increment 47 source-first results

Bounded D0 families: **SRC-02 OS_RELEASE, SRC-08 MEMINFO, SRC-09 SWAPS, SRC-10 MEM_PRESSURE**. All source data were independently specified synthetic originals sealed using the same G5-03 EvidenceWriter and normal source receipt path; no host probing, live commands, changed source policy or fabricated timestamps.

`tests/test_g5_cp03_rp03_d0_semantics_47.py` contains eight cases. Explicit independent expected field paths, raw/normalized typed values, unit conversion, parser identity, ordinal, original evidence and source attempt were checked. Two controls passed (four-family positive semantic oracles and non-UTF8 lossless fallback). Initial source-first head `302eaeea77aa9f8d0e7b37f3611df38829b6578b`: push CI **43763828270** and PR CI **43763844953** intentionally RED with six observed false-acceptances: rehashed forged OS/memory/swap/PSI typed values, rehashed omission of a semantic row with matching manifest identity/counts, and parser-ID substitution. This was not an authorized acceptance or a regression to merge.

The only production repair is in `lbt_g5/canonical_session.py`'s **read-only validator**: independently reparse each eligible actual sealed original for the four D0 families, reconstruct the entire exact semantic row using the sealed evidence/attempt identity, and require a complete contiguous set of observed parser rows plus one raw original row. On parse failure, retain lossless fallback; never infer a semantic value. The post-repair implementation-head PR and push workflows were both SUCCESS, including unified validation.

The producer, parser behavior, source commands, helper, authorization, consent, applied capture ceilings, original evidence and receipts, status vocabulary, and production schema were not changed. Draft PR #72 changed only `.github/workflows/test.yml`, `lbt_g5/canonical_session.py`, and new `tests/test_g5_cp03_rp03_d0_semantics_47.py` before recovery documentation.

## Bounds and remaining work

The validator and producer share the pure normalization parser implementation, while the test cases supply independently hand-computed sealed-byte semantic oracles. This is meaningful adversarial verification but **not** a separate independent parser implementation or CP-02 acceptance. Other 15 D0 family-specific semantic oracles remain to be assessed; SRC-14 was previously checked as an actual FS_STAT contributor but has not received this independent per-family completeness test. SRC-15 D1 multi-original postcommit verification was addressed in Increment 46; remaining D1 and optional O1 original/consent bindings still need source-first work. RP-03.2 stays OPEN.

No original CP-02 acceptance case formally accepted (**0/39**); 283 Rev 1.6 requirements NOT_VERIFIED; Bodhi Linux 7 AMD64 host FAT NOT_EXECUTED; FAT readiness NOT_ESTABLISHED; release NOT_AUTHORIZED. No owner decision pending. All existing draft PRs stay unmerged.

## Next increment

Begin **Increment 48 / RP-03.2** with a small, source-first D0 group from the remaining families. Explicitly verify actual sealed file/stream identity, path-sensitive sysfs provenance where relevant, exact typed values and lossless fallback; try rehashed contradictions before production repairs. Avoid treating adjacent source families as presumed semantic contributors. Later increments address D1 and optional O1, then RP-03.3 validity-versus-completeness and RP-04 verification gates. Reassess context integrity at the next increment and hand off if it is compromised.
