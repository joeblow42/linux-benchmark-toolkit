#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
VERSION="0.1.0-phase1"
DEST="${1:-$ROOT/dist}"
mkdir -p -- "$DEST"
DEST="$(cd -- "$DEST" && pwd -P)"
STAGE=$(mktemp -d)
trap 'rm -rf -- "$STAGE"' EXIT
mkdir -p "$STAGE/linux-benchmark-toolkit"
cp -R "$ROOT/benchmark" "$ROOT/lib" "$ROOT/tui" "$ROOT/discovery" "$ROOT/reporting" "$ROOT/tests" "$ROOT/config" "$ROOT/docs" "$ROOT/packaging" "$ROOT/validation" "$STAGE/linux-benchmark-toolkit/"
cp "$ROOT/README.md" "$STAGE/linux-benchmark-toolkit/"
chmod 755 "$STAGE/linux-benchmark-toolkit/benchmark" "$STAGE/linux-benchmark-toolkit/packaging/build.sh"
ARCHIVE="$DEST/linux-benchmark-toolkit-$VERSION.tar.gz"
tar -C "$STAGE" -czf "$ARCHIVE" linux-benchmark-toolkit
(cd "$DEST" && sha256sum "$(basename "$ARCHIVE")" > "$(basename "$ARCHIVE").sha256")
printf 'Archive: %s\nSHA256: %s.sha256\n' "$ARCHIVE" "$ARCHIVE"
