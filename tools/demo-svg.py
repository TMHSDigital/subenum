"""Render the README demo: an animated terminal replay of labs 1 and 2.

    python tools/demo-svg.py docs/assets/demo.svg

The output text is copied from real runs of the subenum binary against the
built-in lab zones (-simulate-zone lab1 / lab2, so no network). When that
output changes, rerun the commands shown in the scenes and update the lines
below. It uses SMIL animation, which still plays inside GitHub's <img>
sandbox where scripts and external CSS do not.
"""
import sys
from xml.sax.saxutils import escape

BG, BAR = "#0E1726", "#16223A"
FG, MUTED, DIM = "#E8ECF2", "#94A3BA", "#6F7E97"
AMBER, GREEN, RED, BLUE = "#F2B441", "#4CC9A0", "#F47C7C", "#7AB8FF"

W, FS, LH, PADX, TOP = 860, 13, 20, 24, 64
T = 24.0  # loop length, seconds


def cmd(s):
    return [("$ ", GREEN), (s, FG)]


def host(name, rest="", color=MUTED):
    segs = [(name, FG)]
    if rest:
        segs.append((" " + rest, color))
    return segs


def tally(label, value, color=MUTED):
    return [("  " + label, DIM), (value, color)]


lab_banner = lambda scen, port: [
    [("LAB MODE: ", AMBER), (f"answers come from the built-in scenario {scen}, served on 127.0.0.1:{port}.", MUTED)],
    [("No DNS traffic leaves this machine.", MUTED)],
]

# Each scene: list of (kind, segments). kind "cmd" lines are typed out.
scene1 = [
    ("c", [("# Lab 1: a first scan against a local zone. Every query is accounted for.", DIM)]),
    ("cmd", cmd("subenum -w words.txt -simulate-zone lab1 -type A,AAAA,CNAME -show-records lab.example")),
    ("o", []),
    *[("o", l) for l in lab_banner("lab1-first-scan", 57614)],
    ("o", []),
    ("o", host("www.lab.example", "A=192.0.2.10 AAAA=2001:db8::10")),
    ("o", host("mail.lab.example", "A=192.0.2.20")),
    ("o", host("vpn.lab.example", "A=192.0.2.30")),
    ("o", host("jenkins.lab.example", "A=192.0.2.40")),
    ("o", host("shop.lab.example", "A=192.0.2.10 AAAA=2001:db8::10 CNAME=www.lab.example")),
    ("o", [("blog.lab.example", FG), (" CNAME=ghost-lab.example.net ", MUTED), ("TAKEOVER?=dangling", AMBER)]),
    ("o", [("Scan complete for lab.example", GREEN)]),
    ("o", tally("resolved:  ", "6", FG)),
    ("o", tally("nxdomain:  ", "24")),
    ("o", tally("timeout:   ", "0")),
    ("o", tally("refused:   ", "0")),
    ("o", tally("other:     ", "0")),
    ("o", tally("wildcard-filtered: ", "0")),
    ("o", tally("takeover candidates: ", "1 (DNS-only hints; verify each by hand)", AMBER)),
]

scene2 = [
    ("c", [("# Lab 2: every name resolves. subenum spots the wildcard instead of reporting noise.", DIM)]),
    ("cmd", cmd("subenum -w words.txt -simulate-zone lab2 lab.example")),
    *[("o", l) for l in lab_banner("lab2-wildcard", 55660)],
    ("o", [("WARNING: ", AMBER), ("Wildcard DNS detected - all subdomains resolve for lab.example", FG)]),
    ("o", [("Error: ", RED), ("Results would be meaningless. Use -force to scan anyway.", FG)]),
    ("o", []),
    ("c", [("# With -force it fingerprints the wildcard and keeps only the real hosts.", DIM)]),
    ("cmd", cmd("subenum -w words.txt -simulate-zone lab2 -force lab.example")),
    *[("o", l) for l in lab_banner("lab2-wildcard", 51127)],
    ("o", [("WARNING: ", AMBER), ("Wildcard DNS detected - all subdomains resolve for lab.example", FG)]),
    ("o", host("www.lab.example")),
    ("o", host("intranet.lab.example")),
    ("o", host("portal.lab.example")),
    ("o", [("Scan complete for lab.example", GREEN)]),
    ("o", tally("resolved:  ", "3", FG)),
    ("o", tally("nxdomain:  ", "0")),
    ("o", tally("timeout:   ", "0")),
    ("o", tally("refused:   ", "0")),
    ("o", tally("other:     ", "0")),
    ("o", tally("wildcard-filtered: ", "27", AMBER)),
]

ROWS = max(len(scene1), len(scene2))
H = TOP + ROWS * LH + 22


def kt(points):
    """points: [(time, value)] -> values/keyTimes strings over the loop."""
    if points[0][0] > 0:
        points = [(0, points[0][1])] + points
    if points[-1][0] < T:
        points = points + [(T, points[-1][1])]
    return ";".join(str(v) for _, v in points), ";".join(f"{t / T:.4f}" for t, _ in points)


def anim(attr, points, mode="discrete"):
    vals, times = kt(points)
    return (f'<animate attributeName="{attr}" values="{vals}" keyTimes="{times}" '
            f'dur="{T}s" repeatCount="indefinite" calcMode="{mode}"/>')


out = []
clips = []


def render(scene, start, end, visible_static, sid):
    t = start + 0.4
    for row, (kind, segs) in enumerate(scene):
        y = TOP + row * LH
        text = "".join(
            f'<tspan fill="{c}">{escape(s)}</tspan>' for s, c in segs)
        shown = t
        body = f'<text x="{PADX}" y="{y}" xml:space="preserve">{text}</text>'
        if kind == "cmd":
            n = sum(len(s) for s, _ in segs)
            typing = min(2.2, 0.035 * n)
            cid = f"c{sid}{row}"
            wfull = W - 2 * PADX
            clips.append(
                f'<clipPath id="{cid}"><rect x="{PADX}" y="{y - LH + 5}" height="{LH}" width="0">'
                + anim("width", [(0, 0), (t, 0), (t + typing, wfull), (end, wfull), (end, 0)], "linear")
                + "</rect></clipPath>")
            body = f'<g clip-path="url(#{cid})">{body}</g>'
            t += typing + 0.5
        else:
            t += 0.5 if kind == "c" else 0.09
        op = "1" if visible_static else "0"
        out.append(f'<g opacity="{op}">'
                   + anim("opacity", [(0, 0), (shown, 1), (end, 0)])
                   + body + "</g>")
        if kind == "o" and row + 1 < len(scene) and scene[row + 1][0] == "c":
            t += 0.9
    return t


e1 = render(scene1, 0.0, 10.5, False, "a")
e2 = render(scene2, 11.0, T - 0.01, True, "b")
assert e1 < 10.5 and e2 < T - 1.5, (e1, e2)

dots = "".join(
    f'<circle cx="{24 + i * 18}" cy="18" r="5.5" fill="{c}"/>'
    for i, c in enumerate(["#F47C7C", AMBER, GREEN]))

svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" role="img" aria-label="subenum in a terminal. Lab 1: six hosts resolve with their A, AAAA and CNAME records, blog.lab.example is flagged as a dangling-CNAME takeover candidate, and the tally shows 6 resolved and 24 nxdomain. Lab 2: every name resolves, so subenum reports a wildcard and refuses; with -force it fingerprints the wildcard, keeps www, intranet and portal, and filters 27 wildcard answers.">
<defs>{"".join(clips)}</defs>
<rect width="{W}" height="{H}" rx="12" fill="{BG}"/>
<path d="M0 12a12 12 0 0 1 12-12h{W - 24}a12 12 0 0 1 12 12v24H0z" fill="{BAR}"/>
{dots}
<text x="{W / 2}" y="22" text-anchor="middle" fill="{DIM}" font-family="ui-sans-serif, -apple-system, 'Segoe UI', Helvetica, Arial, sans-serif" font-size="12" font-weight="600">subenum · lab mode, no traffic leaves the machine</text>
<g font-family="ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, 'Liberation Mono', monospace" font-size="{FS}">
{chr(10).join(out)}
</g>
</svg>
'''
open(sys.argv[1], "w", encoding="utf-8", newline="\n").write(svg)
print(W, H, round(e1, 1), round(e2, 1), len(svg))
