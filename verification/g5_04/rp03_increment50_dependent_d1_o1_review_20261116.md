# LBT G5-04 / RP-03.2 — Increment 50 dependent D1/O1 consumer review

**Authority:** AI-Assisted Software Engineering Governance Standard v1.0; owner-approved Alternative B FAT Roadmap Rev 0.2. **Predecessor:** Increment 49, PR #75 final head `b4830a7dea10ff77e96c5256b0a438fafab5acff`, exact-head PR run 44027384543 SUCCESS, push run 44027378149 SUCCESS.

## Bounded source-to-consumer behavior

- Real `EvidenceWriter` sealed test bytes for **D0 SRC-14** mountinfo and **D1 SRC-15** FS_STAT are passed through committed G5-03 receipts, the approved D-02 canonical producer, its validator, and the existing private read-only consumer. The FS_STAT snapshot reports actual statvfs fields in bytes/counts and explicitly identifies SRC-14 as its verified supporting source, without disclosing raw evidence IDs, attempt IDs or paths.
- Real sealed test bytes for **D0 SRC-19** GPU inventory and **O1 SRC-21** VAINFO are passed through the same pipeline. O1 source claims require approved fixed command, same-run validated GPU evidence, recorded operator consent and operational witness. Return only reported VA-API driver/profile/entrypoint capabilities, **never inferred encode/transcode or benchmark performance**.
- `lbt_g5/private_inventory.py` adds `supporting_source_ids` to each private fact using existing validated D-02 observation source-attempt links. This is private transient consumer metadata and **not a change** to the production canonical schema 1.0.0 or public outputs.
- Eight deterministic cases cover captured/valid dependencies; ordinary missing SRC-14 contributor; malformed FS_STAT; valid and nonzero O1 VA-API; no relevant VA-API device; malformed VAINFO; and no restricted evidence/command pointer leakage. All fixture operations are sealed-byte only: no actual host commands, helper, devices or driver initialization.
- Maintain truthful INCOMPLETE session lifecycle and PARTIAL/SOURCE_INCOMPLETE, PARSE_FAILED, NOT_APPLICABLE where evidenced; never infer source success from a usable reported value.

## Protected boundaries and unfinished acceptance

No new command, privilege, source authorization or capture ceilings; no changed 41 status combinations, published mask, benchmark result, HTML report, CLI/TUI, or original evidence mutation. Internal values remain **unmasked** and unsuitable for public sharing without the approved publication policy. CP-02 original 39 cases: **zero formally accepted**; physical Bodhi Linux 7 FAT not executed. RP-03.2 remains OPEN until representative acquisition/consumer completeness and real host readiness are evidenced. RP-03.3 and RP-04 still open.

**Evidence gate:** exact-head GitHub Actions success for push and pull_request is required. No merge or FAT entry authorized.
