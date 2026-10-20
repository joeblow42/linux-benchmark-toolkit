# Linux Benchmark Toolkit

**Phase 1 prototype — validation pending on Bodhi.** Portable Linux terminal toolkit with read-only discovery, Dialog menu, canonical JSON data, CSV exports and a self-contained offline HTML report.

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

It generates standalone `acceptance.html`, `acceptance.md`, `acceptance.json`, and `acceptance.csv`. Every check must PASS for overall PASS; SKIP produces INCOMPLETE, never a false success. See [acceptance test documentation](docs/PHASE1_ACCEPTANCE.md). GitHub Actions uploads test reports as `phase1-acceptance-report`.

## Dependencies and limitations

Phase 1 uses host Bash and Python 3. Dialog is required only for TUI mode. `lscpu` and `lsblk` are optional discovery tools; the system identifies missing utilities. **No automatic package installation.** The Phase 1 archive does not yet bundle third-party executables, and it is not the final fully self-contained release.

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
