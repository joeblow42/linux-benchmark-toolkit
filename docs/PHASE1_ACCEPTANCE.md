# Phase 1 automated acceptance

Run from the repository or extracted archive:

```bash
bash tests/acceptance-phase1.sh
```

To select a report directory, especially when the package resides on read-only media:

```bash
bash tests/acceptance-phase1.sh --output "$HOME/lbt-acceptance"
```

**Outputs:** `acceptance.html` (offline standalone HTML), `acceptance.md` (text summary), `acceptance.json` (structured results) and `acceptance.csv` (tabular results).

The runner is offline and unprivileged. It creates temporary isolated sessions and relocatable copies, then cleans up its own temporary data. It never deletes its requested output directory or existing user benchmark sessions.

**Acceptance rule:** Every check must PASS for overall PASS (exit code 0). Any FAIL yields FAIL; any SKIP without failures yields INCOMPLETE. Both return exit code 1. Missing Dialog is SKIP, **not** a false PASS.

## Tests
1. Bash syntax, Python unit tests.
2. CLI help, available modes, dependency inventory.
3. Unknown options, missing required parameters, Standard/Extended unavailable errors.
4. Rejection of output directories under Linux `/proc`.
5. Rejection of missing report session.
6. Versioned JSON and accurate NOT_TESTED workload state; discovery logs.
7. CSV schema and consistency with canonical JSON.
8. Offline HTML creation, report-only byte-for-byte regeneration.
9. Corrupted session metadata rejection.
10. Archive contents and SHA-256 verification.
11. Relocated execution from a private directory and independently executing a newly extracted archive.
12. Execution from a read-only source tree, using an external results directory.
13. Pseudo-terminal Dialog Escape cancellation, if Dialog is installed.

## CI and physical validation
GitHub Actions installs Dialog **in its own CI runner** and runs the acceptance suite, then uploads the HTML/JSON/CSV/Markdown reports as an artifact named `phase1-acceptance-report`. The application itself never installs software automatically.

The pseudo-terminal test covers Escape-driven cancellation, not graphical presentation or the Cancel-button UX. Bodhi already underwent a manual Dialog test. CI does not replace target-machine acceptance.

Run the script on the Bodhi USB and capture its result in [Issue #1](https://github.com/joeblow42/linux-benchmark-toolkit/issues/1) before considering Phase 1 accepted. Full benchmark workload testing belongs to later phases.
