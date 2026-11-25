#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
VERSION="0.2.0-validation"
DEST="${1:-$ROOT/dist}"
mkdir -p -- "$DEST"
DEST="$(cd -- "$DEST" && pwd -P)"
STAGE=$(mktemp -d)
trap 'rm -rf -- "$STAGE"' EXIT
mkdir -p "$STAGE/linux-benchmark-toolkit/config"
cp -R "$ROOT/benchmark" "$ROOT/lib" "$ROOT/tui" "$ROOT/discovery" "$ROOT/reporting" "$ROOT/tests" "$ROOT/docs" "$ROOT/packaging" "$ROOT/validation" "$ROOT/lbt_g5" "$STAGE/linux-benchmark-toolkit/"
cp "$ROOT/README.md" "$ROOT/LICENSE" "$STAGE/linux-benchmark-toolkit/"
cp "$ROOT/config/README.md" "$STAGE/linux-benchmark-toolkit/config/"
find "$STAGE/linux-benchmark-toolkit" -type f -name '*.pyc' -delete
find "$STAGE/linux-benchmark-toolkit" -type d -name '__pycache__' -empty -delete
chmod 755 "$STAGE/linux-benchmark-toolkit/benchmark" "$STAGE/linux-benchmark-toolkit/packaging/build.sh"
ARCHIVE="$DEST/linux-benchmark-toolkit-$VERSION.tar.gz"
tar -C "$STAGE" -czf "$ARCHIVE" linux-benchmark-toolkit
(cd "$DEST" && sha256sum "$(basename "$ARCHIVE")" > "$(basename "$ARCHIVE").sha256")
printf 'Archive: %s\nSHA256: %s.sha256\n' "$ARCHIVE" "$ARCHIVE"
