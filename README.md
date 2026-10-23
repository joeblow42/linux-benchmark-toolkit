# Linux Benchmark Toolkit

**Phase 1 discovery with integrated software validation.** Portable Linux terminal toolkit with read-only discovery, Dialog menu, canonical JSON data, CSV exports and a self-contained offline HTML report.

## Quick start

```bash
bash benchmark --check-deps
bash benchmark --mode discovery
# In an interactive terminal with Dialog installed:
bash benchmark
```

A completed Discovery run creates `results/session_<UTC>_<random>/` with `report.html`, `system.json`, `benchmarks.json`, `assessments.json`, `discovery.csv` and logs.

```bash
bash benchmark --list-tests
bash benchmark --results-dir /path/to/results --mode discovery
bash benchmark --report-only /path/to/existing/session
python3 -m unittest discover -s tests -v
bash -n benchmark lib/*.sh tui/*.sh packaging/*.sh
bash packaging/build.sh
```

The generated archive and SHA-256 manifest live in `dist/` (ignored by Git). The package can be extracted to another path; the launcher finds files relative to its own directory. The HTML report works offline.

## Automated Phase 1 acceptance

Run the full offline acceptance suite on Bodhi or another Linux host:

```bash
bash tests/acceptance-phase1.sh
# Or place reports outside the installation (e.g. read-only toolkit media):
bash tests/acceptance-phase1.sh --output "$HOME/lbt-acceptance"
```

It generates standalone `acceptance.html`, `acceptance.md`, `acceptance.json`, and `acceptance.csv`. Every check must PASS for overall PASS; SKIP produces INCOMPLETE, never a false success. See [acceptance test documentation](docs/PHASE1_ACCEPTANCE.md). The legacy acceptance entry point remains available. CI uses one unified Full validation run and uploads `toolkit-validation-report`.

## Dependencies and limitations

The toolkit uses host Bash and Python 3. Dialog is required only for TUI mode. `lscpu` and `lsblk` are optional discovery tools; the system identifies missing utilities. **No automatic package installation.** The `0.2.0-validation` archive includes the unified software validation modules but does not bundle third-party executables, and it is not the final fully self-contained release.

**Not implemented yet:** detailed hardware inventory, actual CPU/memory/storage benchmarks, thermal load tests, DVD imaging, transcoding, Jellyfin playback and Samba tests. Workload ratings correctly remain NOT_TESTED.

## Architecture and tracker

- [Architecture](docs/ARCHITECTURE.md)
- [Roadmap](docs/ROADMAP.md)
- [Test specification](docs/TEST_SPECIFICATION.md)
- [Report contract](docs/REPORT_SCHEMA.md)
- [Portability and packaging](docs/PACKAGING.md)
- [Contributing](docs/CONTRIBUTING.md)
- [Phase 1 tracker](../../issues/1), [all issues](../../issues)

This repository does not include test results or any private hardware identifiers.

## Unified software validation

Software-validation profiles are distinct from hardware benchmark modes. The
cumulative profiles are Quick (readiness), Standard (unit and safe integration),
and Full (additional acceptance, relocation, packaging and Dialog checks).

```bash
./benchmark --validate --validation-profile quick
./benchmark --validate --validation-profile standard
./benchmark --validate --validation-profile full
./benchmark --validation-report-only /path/to/validation-session
```

A software-validation run stores canonical `validation.json`, derived CSV,
Markdown and offline HTML, a completion/hash manifest, and private diagnostics
under `logs/` when a runner fails. Do not publish raw `logs/` files: they
may contain sensitive host details. The portable reports withhold arbitrary
diagnostic contents and reference logs by stable validation IDs. Files are
created with owner-only permissions. Report-only regeneration does not execute
validation cases. New canonical records use validation schema 1.1.0; older
1.0.0 records regenerate through an in-memory compatibility view without
rewriting their canonical JSON.

The approved Requirements Baseline Rev 1.2 has 256 IDs. Reports show linked
tests and all uncovered IDs; a link or a successful check is **partial evidence**,
not automatic verification that a requirement is satisfied. The seven explicit
later-release deferrals remain in the baseline.

The release archive name is `linux-benchmark-toolkit-0.2.0-validation.tar.gz`
with a corresponding SHA-256 file. The legacy Phase 1 acceptance CLI and
hardware `--mode discovery` functionality are retained. Collector integration,
hardware benchmarking and benchmark session schema modernization remain separate
future work.

Overall validation is PASS only if all selected cases PASS, or if there are
only PASS results plus no non-PASS results. FAIL dominates; SKIP, BLOCKED, and
NOT_APPLICABLE produce INCOMPLETE when no failure occurred.
