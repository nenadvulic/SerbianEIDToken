#!/usr/bin/env bash
# Build a compressed, read-only DMG with a styled drag-to-install window: the app,
# an /Applications symlink, a background with an arrow and instructions, and the
# app icon as volume icon. Uses dmgbuild (writes the Finder layout directly, no
# AppleScript), so it also works on CI runners. Install: pip install dmgbuild==1.6.7
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

if [ ! -f "$app/Contents/Resources/AppIcon.icns" ]; then
  echo "error: '$app' has no AppIcon.icns" >&2
  exit 65
fi
command -v dmgbuild >/dev/null || { echo "error: dmgbuild not found (pip install dmgbuild==1.6.7)" >&2; exit 69; }

here="$(cd "$(dirname "$0")" && pwd)"
dmgbuild \
  -s "$here/dmg/settings.py" \
  -D app="$app" \
  -D background="$here/dmg/background.tiff" \
  "Serbian eID Token $version" \
  "$out"

echo "created $out"
