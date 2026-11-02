# G5-03 — TUI Privilege Lifecycle and Single-Launcher Cutover Readiness

Status: development-only candidate, draft PR #21. Not production launcher, G5-03 gate acceptance or G5 closeout.

## Verified design boundary

1. The development TUI can start the privileged helper at launch using --sudo, or through an explicit "Enable privileged helper" menu action. It permits at most one administrator authentication attempt while the menu remains open. A successful helper persists across any number of independently authorized acquisition runs. An unsuccessful authentication is not retried in that open TUI.
2. CLI invocations with --sudo each start their own session-scoped helper. With an effective NOPASSWD sudo rule, no password is requested; LBT does not store passwords or override host sudo policy. The owner's temporary password-required sudo test demonstrated exactly one prompt.
3. Each TUI acquisition creates a fresh UTC run directory, one UnifiedCollectorEngine instance, and a private evidence writer. All sources use the same G5-02 capture_and_record dispatch. The TUI never replaces this with a separate acquisition path.
4. SRC-13 device-health work is opt-in and requires explicit consent per exact source/target/run, plus fresh same-run D0 device inventory. The command may wake/spin up storage; typed device names are untrusted until validated. Consent is separate from administrator authentication, not another password.
5. Main TUI and evidence writer remain unprivileged. Only the independently installed root-owned fixed-command helper can run bounded SMART/NVMe commands. Terminating the TUI closes the helper.
6. The development TUI exposes operational completion messages only. No report-opening/viewing/navigation, diagnostic controls or pre-run privacy-mask preview are included.

## Development entry point

Run as an ordinary user with Dialog installed:

    python3 -m lbt_g5.tui_dev --output-root "$HOME/lbt-g5-03-tui-evidence"

To request administrator authentication immediately when the TUI opens:

    python3 -m lbt_g5.tui_dev --sudo --output-root "$HOME/lbt-g5-03-tui-evidence"

The ordinary menu offers OS, memory, block-device or all registered collectors; and an individually consented drive-health acquisition. Each operation gets a separate private session. Displayed status is not a published report.

## Evidence and remaining verification

- Bodhi 7: full 28-source acquisition exercised; authorized SRC-13 acquisition produced original evidence and succeeded; one administrator password prompt demonstrated with a temporary PASSWD sudoers override; original sudo policy subsequently restored.
- Mocked CI: one TUI helper across two independently consented acquisitions, no re-prompt after denied authentication, no privilege on ordinary collection or declined health, same-run consent binding, and no TUI viewer/diagnostic items.
- Actual interactive Bodhi Dialog/TUI lifecycle proof is still needed. A CI fixture is not a substitute for a real TTY/sudo test.
- Owner disposition: abnormal live USB overlay filesystem timing is non-blocking for development host acceptance, not authorization to weaken original evidence durability or G4-07 ceilings.

## Release launcher cutover — blocking prerequisites

The existing benchmark Bash launcher and historical tui/menu.sh still use separate historical discovery and diagnostics. They are not the intended final TUI. DO NOT route production invocation to the development engine yet: the current output comprises private G5-02 attempt receipts, not the approved canonical or publication artifacts. Shipping two competing operational collection engines is disallowed; the old path is a transitional test dependency only in this isolated draft branch.

Production cutover prerequisites:

1. G5-04 unified canonical schema 1.0.0, validated status envelope and provenance, responsibility-specific files, manifests, and truthful zero-observation handling.
2. One mandatory combined offline HTML report, privacy masking via owner-only config/privacy.yaml, outputs selection via config/outputs.yaml, optional public JSON/CSV and other nine conditional exports; generated public output must not expose raw evidence pointers. Unclassified public fields are withheld with the approved BLOCKED / UNCLASSIFIED_PUBLIC_FIELD marker.
3. Accepted UTC acquisition and regeneration directory lifecycle; diagnostics CLI only; no TUI report navigation or diagnostics controls.
4. TUI and CLI release paths using one IC-02 dispatcher, full consent and sudo-session lifecycle tests, source/evidence/result parity, and correct behavior on cancellation and missing tools.
5. Independent helper-security/package review, root-owned update/install/remove path and Linux AMD64/Bodhi host verification.
6. Owner review and explicit authorization before merging PR #21, switching benchmark default entry points and retiring old acquisition operations.

Next G5-03 checkpoint: real Bodhi TUI test of two acquisition operations under one privileged helper session; then G5-04 canonical/publication implementation before default launcher cutover.
