#!/usr/bin/env bash
# Build a compressed, read-only DMG containing the app and an /Applications
# symlink (drag-to-install layout). No external dependencies beyond hdiutil.
#
# Usage: scripts/make-dmg.sh <path/to/App.app> <version> <out.dmg>
set -euo pipefail

usage() {
  echo "usage: $0 <path/to/App.app> <version> <out.dmg>" >&2
  exit 64
}

[ "$#" -eq 3 ] || usage

app="${1%/}"
version="$2"
out="$3"

case "$app" in
  *.app) ;;
  *) echo "error: '$app' is not an .app bundle" >&2; exit 65 ;;
esac
if [ ! -d "$app" ]; then
  echo "error: '$app' does not exist or is not a directory" >&2
  exit 65
fi
if ! [[ "$version" =~ ^[0-9A-Za-z][0-9A-Za-z.+-]*$ ]]; then
  echo "error: invalid version '$version'" >&2
  exit 65
fi
case "$out" in
  *.dmg) ;;
  *) echo "error: output '$out' must end in .dmg" >&2; exit 65 ;;
esac
out_dir="$(dirname "$out")"
if [ ! -d "$out_dir" ]; then
  echo "error: output directory '$out_dir' does not exist" >&2
  exit 65
fi

staging="$(mktemp -d "${TMPDIR:-/tmp}/make-dmg.XXXXXX")"
cleanup() { rm -rf "$staging"; }
trap cleanup EXIT

# ditto preserves code signatures, extended attributes and symlinks.
ditto "$app" "$staging/$(basename "$app")"
ln -s /Applications "$staging/Applications"

hdiutil create \
  -volname "Serbian eID Token $version" \
  -srcfolder "$staging" \
  -fs HFS+ \
  -format UDZO \
  -ov \
  "$out"

echo "created $out"
