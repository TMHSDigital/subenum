"""Render the README's highlight tiles.

    python tools/highlights-svg.py docs/assets/highlights.svg

Each tile names one claim from "Why subenum" and the flag behind it; keep
them in step with that section.
"""
import sys
from xml.sax.saxutils import escape

BG, EDGE = "#0E1726", "#22304A"
FG, MUTED, DIM = "#E8ECF2", "#94A3BA", "#6F7E97"
AMBER, GREEN, RED, BLUE = "#F2B441", "#4CC9A0", "#F47C7C", "#7AB8FF"
SANS = "ui-sans-serif, -apple-system, 'Segoe UI', Helvetica, Arial, sans-serif"
MONO = "ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, monospace"

W, TW, TH, GAP = 860, 424, 96, 12
H = 2 * TH + GAP


def icon_stats(x, y):
    # a stacked outcome bar: resolved / nxdomain / timeout / refused
    segs = [(GREEN, 14), (BLUE, 10), (AMBER, 6), (RED, 4)]
    out, cx = [], x
    for c, w in segs:
        out.append(f'<rect x="{cx}" y="{y + 13}" width="{w}" height="14" rx="2" fill="{c}"/>')
        cx += w + 2
    return "".join(out)


def icon_wild(x, y):
    # many answers in, few out: a funnel
    return (f'<path d="M{x} {y + 8}h40l-15 14v12l-10 4v-16z" fill="none" stroke="{AMBER}" '
            f'stroke-width="2.4" stroke-linejoin="round"/>'
            f'<text x="{x + 20}" y="{y + 4}" text-anchor="middle" fill="{AMBER}" font-family="{MONO}" '
            f'font-size="13" font-weight="700">* * *</text>')


def icon_rate(x, y):
    # a gauge pinned under its limit
    y -= 8
    return (f'<path d="M{x + 2} {y + 32}a18 18 0 0 1 36 0" fill="none" stroke="{EDGE}" stroke-width="5" stroke-linecap="round"/>'
            f'<path d="M{x + 2} {y + 32}a18 18 0 0 1 27 -15.6" fill="none" stroke="{GREEN}" stroke-width="5" stroke-linecap="round"/>'
            f'<path d="M{x + 20} {y + 32}l9 -11" stroke="{FG}" stroke-width="2.4" stroke-linecap="round"/>'
            f'<circle cx="{x + 20}" cy="{y + 32}" r="3" fill="{FG}"/>')


def icon_resolvers(x, y):
    # a shield with a check
    return (f'<path d="M{x + 20} {y + 4}l15 6v10c0 9-6.5 15-15 18c-8.5-3-15-9-15-18v-10z" fill="none" '
            f'stroke="{BLUE}" stroke-width="2.4" stroke-linejoin="round"/>'
            f'<path d="M{x + 13} {y + 21}l5 5l9 -10" fill="none" stroke="{GREEN}" stroke-width="2.6" '
            f'stroke-linecap="round" stroke-linejoin="round"/>')


tiles = [
    (icon_stats, "Every query accounted for", "Each lookup classified, with a verdict CI can gate on", "-stats"),
    (icon_wild, "Wildcards fingerprinted, not reported", "Rotating CDN pools too; wildcard branches skipped", "-force"),
    (icon_rate, "A rate limit that holds on the wire", "Retries, record types and probes all count", "-rate"),
    (icon_resolvers, "Resolvers that cannot lie to you", "Every hit re-checked; resolvers hiding names benched", "-r"),
]

parts = []
for i, (icon, title, desc, flag) in enumerate(tiles):
    x = (i % 2) * (TW + GAP)
    y = (i // 2) * (TH + GAP)
    chip_w = 16 + 7.8 * len(flag)
    parts.append(
        f'<rect x="{x + 0.5}" y="{y + 0.5}" width="{TW - 1}" height="{TH - 1}" rx="12" fill="{BG}" stroke="{EDGE}"/>'
        + icon(x + 18, y + 26)
        + f'<text x="{x + 76}" y="{y + 30}" fill="{FG}" font-family="{SANS}" font-size="15" font-weight="650">{escape(title)}</text>'
        + f'<text x="{x + 76}" y="{y + 51}" fill="{MUTED}" font-family="{SANS}" font-size="13">{escape(desc)}</text>'
        + f'<rect x="{x + 76}" y="{y + 62}" width="{chip_w}" height="22" rx="6" fill="#1A2740"/>'
        + f'<text x="{x + 76 + chip_w / 2}" y="{y + 77.5}" text-anchor="middle" fill="{AMBER}" font-family="{MONO}" font-size="13" font-weight="600">{escape(flag)}</text>'
    )

label = "; ".join(f"{t}: {d} ({f})" for _, t, d, f in tiles)
svg = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" role="img" '
       f'aria-label="{escape(label)}">\n' + "\n".join(parts) + "\n</svg>\n")
open(sys.argv[1], "w", encoding="utf-8", newline="\n").write(svg)
print(W, H, len(svg))
