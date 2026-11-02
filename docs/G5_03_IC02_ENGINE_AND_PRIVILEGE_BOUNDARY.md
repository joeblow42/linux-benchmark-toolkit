# G5-03 — IC-02 single engine and once-per-session sudo design boundary

Status: implementation increment in progress; not a release, gate acceptance or active privileged-helper authorization.
Authority: Owner directed G5-03 after G5-02 technical closeout and selected **one sudo/administrator password prompt per LBT application session**.

## Single acquisition architecture

The run-scoped entry point is lbt_g5.engine.UnifiedCollectorEngine.run.
It owns the current thirteen G4-01 collector responsibilities and their 28
registered G4-07 source families. capture_and_record remains the ONLY source
invocation/evidence path. ProbeSlots, SourceCallBudget, EvidenceWriter,
source policies and SourceRequest are shared within a run. SRC-23 has two
registered subcalls with separate immutable attempt receipts. SRC-15 must consume
the SHA-256-verified sealed SRC-14 mountinfo artifact, not re-read mountinfo as
an unrelated acquisition. O1 targets are restricted to verified current-run D0
inventory and still require one-run, source/target/operation-specific consent;
a caller-supplied trusted_targets set cannot bypass D0 evidence. Unknown
collectors, non-O1 override requests and unselected sources fail before dispatch.
Imports do not probe host devices.

This API is NOT the current production CLI. The Phase 1 legacy discovery path
must not be retired or routed to this API until equivalence/coverage, canonical
persistence and TUI/CLI integration are demonstrated. **Do not ship two
operational acquisition engines**. The existing legacy entry point remains a
historical compatibility/testing dependency during this isolated development
increment, not the target architecture. G5-04 owns canonical session schema,
validated status envelopes and manifests; operational G5-02 source receipts must
not be misrepresented as public/canonical results.

## Once-per-session sudo: required implementation contract

1. Main LBT executable and collector orchestration remain unprivileged.
2. On first approved privileged need, suspend or temporarily leave the TUI
   to give sudo control of the terminal for **one administrator-password
   prompt**, with a clear operation/target-impact summary. LBT must not read,
   handle, persist or log the password. Failed/cancelled authentication
   preserves a truthful denial/permission outcome; unrelated D0/D1 continue.
3. An independently installed, root-owned, non-user-modifiable narrowly scoped
   helper must be started by that successful sudo invocation and remain alive
   for precisely this LBT application session. Subsequent approved privileged
   requests reuse the helper, not another sudo invocation or sudo timestamp.
4. The privileged helper must accept a **versioned structured allowlist
   protocol**, not shell snippets, arbitrary executables, unverified paths or
   user-provided arguments. Initially eligible: SRC-13 non-destructive SMART
   health requests against individually verified local block/NVMe devices.
   New privileged source operations require explicit contract revision.
5. Authenticated session IPC must be private to the LBT process/helper pair:
   no permissive filesystem socket, world-accessible daemon or shared token.
   Validate message sizes, IDs, request type, target type/identity, source,
   operator authorization, run identity and consent before device access.
   Mitigate FD/path races and ensure the helper cannot follow attacker-controlled
   symlinks or run arbitrary commands.
6. Root must never own or rewrite unprivileged session canonical/evidence
   directories. Transfer bounded, unmodified result streams to the unprivileged
   G5-02 evidence writer, including stderr, real return code and truncation
   records. All G4-07 per-source and whole-run budget ceilings still apply.
7. Exiting LBT closes the IPC channel and terminates the helper/process group.
   Unexpected helper death returns explicit failure; never silently re-prompt,
   fall back to unsafe commands or continue with stale privileged authority.
8. Do not request credentials if only D0/D1 work is selected, if O1 consent is
   absent, or if the operator declines the operation. A successful sudo login
   is NOT blanket consent to O1 device activity. Explicit target/impact consent
   remains a separate required input, but does not require another password.
9. No helper is enabled by the present G5-03 engine module. The existing G5-02
   policy forbidding root execution remains active until an approved, reviewed
   privilege boundary is implemented and verified.

## Required security and host proof before enabling privileged acquisition

- Negative: sudo absent/cancelled/wrong password; helper exits; no TTY;
  unauthorized caller; multiple concurrent sessions; stale/replayed request;
  O1 consent mismatch; unknown device; missing/bad device node; symlink race;
  unknown or manipulated arguments; PATH/environment tricks; non-root
  execute refusal; injected IPC bytes; budget/timeout and huge output.
- Positive: one sudo authentication, multiple individually authorized SRC-13
  queries without another prompt, no automatic privilege on D0/D1, correct
  user-owned immutable evidence and private receipts, helper exit on session
  termination, SMART health read on applicable Bodhi hardware where permitted.
- Regression: existing G5-01/02 contract tests, full legacy validation while
  integration is underway, fixture coverage of all 13 owners/28 sources and
  eventual complete Bodhi 7 AMD64 production-entry smoke tests.
- Formal gate continuation: review controlled G4-07/G4-09/IC contract changes
  required by this privileged-helper extension before operational activation.

**Open work:** real sudo helper/process lifecycle, collector result envelope,
benchmark launcher cutover, canonical status/schema, full hardware authorization
tests, verified package distribution and owner gate acceptance.
