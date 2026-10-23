# Portable offline packaging requirements

Deliverable: one versioned archive containing a relocatable directory and a sibling SHA-256 checksum manifest. Intended starting host: Bodhi Linux Live USB. Destination: future SSD utilities collection or another extracted ext4 volume.

## Layout
```
linux-benchmark-toolkit/
  benchmark
  bin/linux-x86_64/
  tui/
  lib/
  tests/
  reporting/
  validation/       # software-validation framework and reporters
  config/
  fixtures/
  manifests/
  packaging/
  docs/
  results/          # generated at runtime, not checked in
```

## Definition of self-contained
Bundle scripts, configs, report templates, freely redistributable utilities and fixtures to the extent compatible with licenses and target hosts. Also record binary architecture, checksums, dynamic linker/ABI requirements, runtime library dependencies, third-party licenses and tools that require host kernel/device support. Portable does not mean independently bootable or distribution agnostic.

Do not ship copied host GPU drivers as a blanket compatibility shortcut. Probe host VA-API, optical support, USB, permissions and kernel capabilities on each target machine.

## Acceptance
1. Archive extracts and launcher finds all paths based on its own location.
2. Works offline and does not install packages without express user action.
3. Reports missing/unsupported host facilities clearly.
4. A complete session keeps HTML, JSON, CSV and logs together.
5. Packaging includes third-party license notices and SHA-256 checksums.
6. Results from one computer do not overwrite those from another.
7. No automatic upload of hardware identifiers or benchmark data.

## Current validation-enabled package

The versioned software-validation archive is
`linux-benchmark-toolkit-0.2.0-validation.tar.gz`, accompanied by a SHA-256
manifest. The full external executable bundle described above remains a future
release target. The current archive contains Bash and Python sources, unit and
acceptance tests, independent validation reports, and no bundled proprietary
drivers or performance-test utilities.

Portable validation creates owner-only session/report files, `logs/` diagnostics,
and `validation.manifest.json`, recording SHA-256 hashes and successful report
publication. Raw diagnostics are local-only and may include sensitive host details.
