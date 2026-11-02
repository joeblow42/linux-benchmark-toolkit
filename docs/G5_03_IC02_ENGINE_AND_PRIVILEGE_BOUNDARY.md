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
an unrelated acquisition. O1 requests may contain multiple distinct devices only up to each registered
source limit (e.g., multiple SRC-13 disks; SRC-21 remains one GPU per run).
O1 targets are restricted to verified current-run D0 inventory and still require
one-run, source/target/operation-specific consent;
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

## Developer-only Bodhi live verification

After checkout of this G5-03 branch at the intended verified commit,
from repository root, run:

    python3 -m lbt_g5.host_smoke --output-root /tmp/lbt-g5-03-host-evidence

This starts one unprivileged run and attempts the registered collectors using
G5-02 safety ceilings. No O1 consent is provided, so SRC-13, SRC-18 and SRC-21
are denied and receive private refusal receipts; no privileged device query is
executed. D0/D1 collectors attempt their approved bounded passive/local probes.
The script verifies SHA-256 for all actually captured original artifacts and
prints transport dispositions and counts, not collected private data.
One local test is NOT whole-project release/host acceptance; inspect partial,
unavailable and denied outcomes before asserting source coverage.

## Bodhi host anomaly investigation (2026-11-02)

The initial full IC-02 Bodhi smoke run 2026306040218 captured 28 source
families, 29 attempts, 307 immutable artifacts and 99,503 original bytes,
all SHA-256 PASS. Its temporary-directory evidence was later unavailable.

A second targeted persistent-storage run 2026306162501 reported no per-source
progress after startup because the old harness displayed results only at the
end. The preserved private receipts show SRC-14 CAPTURED (0.033 s), SRC-15
PARTIAL/CAPTURE_LIMIT (19.515 s, error INVOCATION_LIMIT, the receipt-specific
artifact count was not included in the diagnostic extract), and SRC-16 CAPTURED (0.032 s). No SRC-17
receipt was committed before the run stopped. SRC-17's cause is **unknown**:
absence of its receipt proves no committed outcome, not that the optical device
was absent. /sys/class/block/sr0 and /dev/sr0 were visible at a later check.

The SRC-15 adapter previously enforced its 15-second source budget by
accounting for completed subcalls; it could exceed that ceiling and conflate
exhausted time with invocation-count limits. Corrected in G5-03 by applying a
source-level monotonic wall-clock deadline to each future worker and by
recording TIME_BUDGET_EXCEEDED instead of INVOCATION_LIMIT/CAPTURE_LIMIT when
the cumulative time is exhausted. The host smoke harness now announces each
BEGIN and END/ERROR immediately with elapsed timing. This does not increase
any approved G4-07 source limit. Negative fixture and CI evidence must precede
another targeted Bodhi host run.

SRC-26 requires examination of the private attempt errors/unavailable-field
records from a new completed run. Source status cannot be determined solely
from the earlier PARTIAL summary.

## Privileged helper wire contract prototype — 2026-11-02

The isolated pure-validation module `lbt_g5/privilege_contract.py` now
defines `lbt-root-helper-1` request envelopes for SRC-13 DEVICE_HEALTH only:
session identifier, monotonic request sequence, verified UTC run identity,
selected disk/NVMe node, and strict <=8-MiB / <=12-second limits.
It rejects unknown keys/operations, arbitrary argv, path traversal,
duplicate or malformed JSON keys, stale or replayed sequence numbers and
more than 32 drive-health requests per acquisition run. Contract fixtures
exercise valid SATA/NVMe and denial/replay/limit/format cases.

**This module is not the privileged helper.** It does not invoke sudo, run
as root, open devices, or confer authority. The separately installed, root-owned
helper, IPC/authenticated parent process association, device identity recheck,
bounded process/stream capture, graceful session teardown and actual
G5-02 evidence integration remain engineering tasks. The model's
per-run O1 consent and host D0 discovery requirements remain mandatory.
Do not claim sudo access or install a helper based only on a passing
wire-format test.


## G5-03 restricted privileged helper test readiness (not final package)

The G5-03 development-only CLI entry point supports:
- 'python3 -m lbt_g5.host_smoke --sudo' — request **one sudo/administrator
  authentication at application initiation** and hold a session-scoped helper
  for that run, even if no drive-health target is specified.
- '--device-health /dev/sdX' (repeatable for different approved devices) and
  '--acknowledge-drive-impact' — explicitly authorize SRC-13 drive-health
  operations with the standard IC-02 D0 inventory check and O1 exact-target
  consent. A sudo login is NOT itself consent. Without these options,
  SRC-13 continues to record DENIED/OPERATOR_AUTH_REQUIRED.
- The main LBT process and original-evidence writer remain the invoking user;
  the installed helper returns bounded original bytes over private stdin/stdout
  pipes and accepts only fixed smartctl -i -H /dev/sdX or nvme smart-log
  /dev/nvmeX operations.

There is no permission to launch an arbitrary program with root privileges
through these options. No password is read or retained by LBT. The helper
is bootstrapped only once by sudo -k; its session ends when the CLI exits.
The existing generic G4-07 primary-app euid==0 prohibition remains active.

### Controlled standalone helper installation

From the verified branch, review 'packaging/lbt_root_helper.py' before
installation. An interactive administrator must install this *standalone*
script into a root-owned, non-group/world-writable directory; **never** run
the user-writable checkout source directly under sudo. The following is
a **manual, privileged host setup** and is not performed by the CLI:

    sudo install -d -o root -g root -m 0755 /usr/local/libexec/lbt
    sudo install -o root -g root -m 0644 \
       packaging/lbt_root_helper.py /usr/local/libexec/lbt/lbt-root-helper.py
    stat -c '%U:%G %a %n' /usr/local/libexec/lbt /usr/local/libexec/lbt/lbt-root-helper.py

The installed file and every parent must be root-owned and not writable
by ordinary users. The helper independently checks its installation path
and access mode when invoked under sudo. There are no permissions grants
to raw disk devices, no new sudoers rules, no setuid executables and no
password storage.

### Recommended two-stage host readiness tests

From repository root on Bodhi Linux 7 AMD64, with persistent
owner-restricted evidence:

    python3 -m lbt_g5.host_smoke --sudo \
       --output-root "$HOME/lbt-g5-03-verify/evidence" \
       --collectors COL-OS

Expected: sudo prompts at most once, helper reports AUTHENTICATED,
collector D0 passes, no drive query is performed; inspect the exit status.
Next, only for individually selected locally discovered devices
after approving the may-wake-drive impact:

    python3 -m lbt_g5.host_smoke --sudo \
       --output-root "$HOME/lbt-g5-03-verify/evidence" \
       --collectors COL-BLOCK \
       --device-health /dev/sda --acknowledge-drive-impact

Never substitute another machine's device ID without verifying its own
host inventory. The result must retain original output and exit code in
user-owned private evidence. A permission denial, missing tool, missing
installed helper, user cancellation or helper failure must remain explicit.

**Limits / outstanding acceptance:** CLI proof remains pending on Bodhi.
The privilege protocol has non-root regression coverage, but no actual sudo
or SMART host result has been verified in this increment. Restrict this
helper to local development pending independent security review and packaging
hardening. No production launcher cutover or G5 gate closure implied.
