# LBT G5-04 RP-04 Increment 56 — narrowed Alternative A / CT-02

Owner expressly approved narrowed Alternative A 2026-11-17. This increment **first freezes source-first failing tests** to ensure the provisional state label is actually absent before repair. Three exact case IDs CT-02-P1/N1/N2; persisted source receipt and original bytes come from existing G5-02. A registered D0 SRC-02 parser is disabled **only within the offline test fixture** to model unavailable parser; acquisition is not repeated, and no new production source or command is introduced.

## Factual finding and minimal proposal

The existing append-only G5-02 receipt has `status_record_pending: true`, independently sealed original bytes, receipt/evidence IDs, and factual CAPTURED/BYTES_PRESERVED. The canonicalizer refuses to finalize with parser NOT_RUN, so no false PARSE_FAILED or COMPLETE record is emitted. Its exception currently does not explicitly label normalization pending. Propose a narrow change to that fail-closed exception message only: include `NORMALIZATION_PENDING` when a captured original exists but parsing was not run. Retain existing persisted receipt; **no new file or schema field**. Do not label absent originals as normalization pending.

The exception provides the immediate explanation; the source receipt provides the durable pending fact. No claim is made that the exact error string itself persists after a process exits. If independently reviewed CT-02-P1 requires *separate durable reason detail*, that is a later owner method decision, not an automatic new artifact.

## No acceptance

Passing these checks means development candidate evidence only. Original 39 CP-02 cases remain formally NOT_EXECUTED, zero accepted. No physical Bodhi 7, CP-07, FAT, public report, schema/status/privilege/consent/limit change or PR merge/release authorized.
