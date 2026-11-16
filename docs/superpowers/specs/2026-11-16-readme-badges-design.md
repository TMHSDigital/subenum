# README badges and readability pass

**Intent.** Make the README's badges look like part of the brand and make
the 784-line README easier to move around in. Approved 2026-11-16.

**Goals**
- Badges match the wordmark's palette: navy `#0E1726`, amber `#F2B441`,
  teal `#4CC9A0`, slate `#6F7E97`.
- Readers can jump to a section and get back to the top.

**Non-goals.** No change to the wording, section order, or the website.

**Anti-goals.** Badges that show stale data, such as an old version number,
or that look broken on GitHub's light or dark theme.

## Approaches

1. Restyle shields.io badges in the brand palette. They stay live, but
   cannot match the wordmark's own look.
2. A custom SVG badge strip drawn to match the wordmark. It matches the
   look, but it is static.
3. Regroup the existing badges. Least change, and it fixes nothing visually.

**Picked: 1 and 2 combined.** Live data stays on shields.io, and facts that
never change go on a custom SVG.

## Design

- **Row 1, live shields.io badges**, all `for-the-badge` style with a navy
  label side: build and Go Reference in teal; release, GHCR and Go 1.26+ in
  amber. Each has a matching logo.
- **Row 2, `docs/assets/badges.svg`**: a navy rounded panel like the
  wordmark, reading `Linux · macOS · Windows · FreeBSD │ one static binary │
  no API keys │ GPL-3.0`. It replaces the `<sub>` line. Being on a navy
  panel, it reads well on both GitHub themes.
- **Readability fixes:**
  - a collapsed table of contents under the links row
  - "↑ back to top" links at the end of each long `##` section
  - the Development tech stack and project tree folded into one toggle,
    with the tree corrected against the repo (part of #379)
  - the Codespaces badge restyled to match row 1
  - links and anchors checked at the end

**Left to the builder:** the text font stack (system sans; GitHub serves the
SVG as an image), exact badge wording, and which sections get back-to-top
links.
