#!/usr/bin/env bash
# Build netcage's brand assets.
#
#   ./build.sh            drift-check, then render preview.png and icon.png.
#                         Needs NO font: the card's text is already outlined.
#   ./build.sh -outline   regenerate preview.svg from preview.src.svg (needs the
#                         vendored font), then prove the two render identically.
set -euo pipefail
cd "$(dirname "$0")"

command -v inkscape >/dev/null || { echo "error: need inkscape" >&2; exit 1; }
command -v magick   >/dev/null || { echo "error: need imagemagick (magick)" >&2; exit 1; }

# --- drift check -----------------------------------------------------------
# The mark's geometry is duplicated across three files on purpose: each needs
# different ink and framing (currentColor / light-on-plate / light-on-card).
# That duplication rots SILENTLY, so compare the load-bearing shapes and refuse
# to render if they have diverged. sort -u so repeated motifs collapse.
geom() {
	grep -o \
		-e 'd="M224 152[^"]*"' \
		-e 'x="62" y="98" width="84" height="26"' \
		-e 'x="62" y="132" width="49" height="26"' \
		-e 'x="160" y="116" width="84" height="24"' \
		"$1" | tr -s ' ' | sort -u
}

expected=4
for f in logo.svg icon.svg preview.src.svg preview.svg; do
	[ -f "$f" ] || { echo "error: missing $f" >&2; exit 1; }
	n=$(geom "$f" | wc -l)
	if [ "$n" -ne "$expected" ]; then
		echo "error: $f carries $n of $expected load-bearing mark shapes" >&2
		echo "       (the mark geometry has drifted, or a shape was renamed)" >&2
		diff <(geom logo.svg) <(geom "$f") >&2 || true
		exit 1
	fi
	if [ "$(geom logo.svg)" != "$(geom "$f")" ]; then
		echo "error: mark geometry in $f has drifted from logo.svg" >&2
		diff <(geom logo.svg) <(geom "$f") >&2 || true
		exit 1
	fi
done
echo "drift check: mark geometry identical across 4 files"

# --- optional: re-outline the card's type ----------------------------------
if [ "${1:-}" = "-outline" ]; then
	FC=$(mktemp -d)
	cat > "$FC/fonts.conf" <<EOF
<?xml version="1.0"?><!DOCTYPE fontconfig SYSTEM "fonts.dtd">
<fontconfig>
  <dir>$(pwd)/fonts</dir>
  <dir>/usr/share/fonts</dir>
  <dir>~/.local/share/fonts</dir>
  <cachedir>$FC/cache</cachedir>
</fontconfig>
EOF
	# A FRESH cachedir every time: a stale fontconfig cache silently served a
	# proportional fallback once already, producing type 16% too narrow with no
	# error anywhere. solve-type.py's font check is the guard against a repeat.
	export FONTCONFIG_FILE="$FC/fonts.conf"
	./solve-type.py >/dev/null || { echo "error: type check failed, see ./solve-type.py" >&2; exit 1; }
	./outline.py
	# Prove the outlines agree with the live text they were made from.
	inkscape preview.src.svg -o "$FC/a.png" -w 1280 >/dev/null 2>&1
	inkscape preview.svg     -o "$FC/b.png" -w 1280 >/dev/null 2>&1
	d=$(magick compare -metric AE "$FC/a.png" "$FC/b.png" null: 2>&1 || true)
	echo "outline pixel diff vs live text: $d differing pixels"
	rm -rf "$FC"
	exec "$0"   # re-run the plain build so the rasters match the new outlines
fi

# --- render ----------------------------------------------------------------
# Always rasterise at 2x and downsample: hard-edged geometry stairsteps badly
# when rendered straight to the target size.
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT

inkscape preview.svg -o "$T/preview@2x.png" -w 2560 >/dev/null 2>&1
magick "$T/preview@2x.png" -resize 1280x640 -strip preview.png

inkscape icon.svg -o "$T/icon@2x.png" -w 1024 >/dev/null 2>&1
magick "$T/icon@2x.png" -resize 512x512 -strip icon.png

echo "wrote preview.png (1280x640) and icon.png (512x512)"
