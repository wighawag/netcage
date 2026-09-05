# netcage brand assets

## What the mark means

A container sits inside a wall that is closed on every side but one, and the single gap is cut exactly as tall as the one channel allowed through it. That is netcage: a rootless Podman container whose network namespace has exactly one exit, so when the exit is gone nothing leaves at all.

## Files

| File | Authored or generated | Produced by |
| --- | --- | --- |
| `logo.svg` | authored | the mark, ink as `currentColor`, no background |
| `icon.svg` | authored | the mark on an opaque plate, light ink |
| `preview.src.svg` | authored | the card, with **live text** (needs the vendored font) |
| `preview.svg` | generated, committed | `./build.sh -outline` (text converted to outlines) |
| `preview.png` | generated | `./build.sh` (1280x640) |
| `icon.png` | generated | `./build.sh` (512x512) |
| `fonts/` | vendored | JetBrains Mono 2.304 variable font + its OFL licence |

`./build.sh` needs **no font installed**, because the card's text is already outlined. Only `./build.sh -outline` needs the font, and it uses the vendored copy.

## Palette

| Role | Value | Notes |
| --- | --- | --- |
| Accent | `#06b6d4` | the single permitted path, and **nothing else** |
| Ink (light bg) | `#0f172a` | the `currentColor` default set on `logo.svg` |
| Ink (dark bg) | `#eef1f6` | |
| Plate | `#0d1117` | icon plate and card background |
| Muted | `#94a3b8` | tagline only |

## Easy to fix by mistake

Each of these looks like a wart and is actually load-bearing.

- **The accent is opaque, never translucent.** A translucent accent goes muddy over the dark plate and washes out over white. Solid renders identically on both.
- **Exactly one thing wears the accent.** The channel. There is deliberately no accent rule under the wordmark and no accent glow on the card. Adding a second accent object costs the mark its focus.
- **The wall's corner radius is 22, not something softer.** At a generous radius this mark is a plain rounded rectangle, which is precisely the texture motif of the sibling project **memonaut**. Tight corners read as an enclosure instead.
- **The card's texture is lanes, not boxes.** memonaut's card texture is rounded-rect outlines, i.e. this mark's own silhouette. Reusing that idiom would make netcage's logo read as memonaut's background pattern.
- **The two payload bars are uneven (84 wide and 49 wide).** Two equal bars read as text lines and turn the mark into a generic document/database icon.
- **The gap in the wall is 48 tall against a 24-tall channel.** The hole being barely larger than the one thing allowed through it is the whole statement. Widening it turns "one port" into "a missing wall section".
- **`icon.svg` has an opaque plate and light ink.** A transparent icon with dark ink disappears on a dark browser tab, which is the smallest surface this mark has to survive.
- **`icon.svg` keeps the full mark.** Dropping the short payload bar was tested: the remaining single bar reads as a hyphen and the container is lost.
- **The mark is positioned by its ink box, not by its viewBox.** `logo.svg` is cropped to the ink (`viewBox="20 20 224 216"`), and `icon.svg`/`preview.src.svg` place it with an ink-box-derived transform. Centring it on the 256 canvas instead pushes it visibly off-centre.
- **`build.sh` renders at 2x and downsamples.** This geometry is all hard edges and stairsteps badly when rasterised straight to the target size.

## Type

Wordmark and tagline are both **JetBrains Mono** (OFL-1.1, so outlining is permitted; `fonts/OFL.txt`). It was chosen against Lato, Cantarell, Roboto and Carlito by rendering all of them beside the mark: it is monolinear like the mark's constant 24-unit stroke, has flat terminals like its butt caps, and squarish bowls like the wall.

| | Spec | Solved |
| --- | --- | --- |
| Wordmark | `font-weight:800; letter-spacing:-0.03em` | `164.103px` for **640px** ink width, ink box 640x146, offset dx=10 dy=-116 |
| Tagline | `font-weight:500` | `28.845px` for **650px** ink width, ink box 650x29, offset dx=2 dy=-23 |

Re-derive after any copy change with `FONTCONFIG_FILE=... ./solve-type.py` (or just `./build.sh -outline`, which runs it). The tagline's target is 650px rather than the usual 560 because this is a **monospace** face: at 560 its ink height collapsed to 21px against a 146px wordmark.

**`solve-type.py` verifies its own answer, and that is not paranoia.** During this build a stale fontconfig cache silently served a proportional fallback, so the solver returned `164.103px` for a 640px target while a direct render of that exact size produced 536px of ink. Nothing errored. The script now asserts the solved size re-measures to the target, and separately confirms the face is really monospace by checking that `iiiiiii` and `mmmmmmm` render to the same width.

## Directions tried and dropped

Each of these was drawn, rendered into a contact sheet (the mark at 256px on light and on dark, then the icon at 64, 32 and 16) and judged on the small sizes first. Those sheets were working scratch and are not tracked; this list is the record.

- **One gap in a closed wall** (round 1, circular): the ring plus payload plus channel fused into a lowercase **"e"** at 16px. Kept the idea, squared the wall.
- **The packet that cannot go straight**: the best *explanation* of netcage (traffic leaves, cannot go straight, is bent into the one gap, and a stub dies at the wall) but five ideas; unreadable below 64px. Would make a good README diagram, not a logo.
- **The dropped packet**: rendered as a hammer. And once its dead arm terminates against a real boundary it simply *is* the previous direction with the stub restored.
- **Aperture knockout**: strongest at 16px, but the accent carried the entire mark, and at full size it read as a padlock hasp or a wax seal.
- **Convergence** (many strands funnelling into one): reads as a crimped cable or a pitchfork, and contains no enclosure at all, which is half the name.
- **Amber accent** `#f0a02a`: dropped late. It is memonaut's colour (`#ffb020`) on memonaut's plate, and the two cards were nearly indistinguishable.

## Known gaps, accepted

- **At 16px the icon reduces to a silhouette**: a rounded square with a cyan nub. The payload bars and the wall's gap are both gone. The closure still reads, which is the half that matters, and no simplification recovered the detail without losing the container.
- **The accent is weak on white** (contrast 2.32 vs `#f8fafc`). It carries identity, not legibility, and the dark card and dark browser tab are the primary surfaces, where it is 7.58. memonaut's amber has the same profile (1.75 on white).
- **`preview.svg` differs from `preview.src.svg` by 20 pixels**, all below one 8-bit level (max channel deviation 238/65535). That is rasteriser rounding on glyph edges, not a shifted glyph.
- **No light-background card.** Add `preview-light.png` and a `<picture>` element in the README if it is ever wanted.
- **No web-app icon set.** netcage ships no web app. If one appears, generate the favicon/maskable/apple-touch set from `icon.svg` with a tool rather than by hand, and feed the generator a transparent-background variant so the maskable output is not a plate inside a plate.

## Verifying

```sh
./build.sh                                    # drift check, then render
./build.sh && md5sum preview.png icon.png     # run twice: hashes must match
```

The drift check exists because the mark's geometry is duplicated across four files (each needs different ink and framing) and that duplication rots silently. It compares the four load-bearing shapes and refuses to render on any mismatch. It has been proven to fire by perturbing the channel's width by one unit.
