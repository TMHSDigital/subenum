# README Badges and Readability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restyle the README's badges in the brand palette, add a static SVG
facts strip, and add navigation aids.

**Architecture:** README.md edits plus one new SVG asset. There is no code,
so the checks are the repo's link checker and a rendered preview.

**Tech Stack:** GitHub-flavored Markdown, shields.io, hand-written SVG.

**Spec:** `docs/superpowers/specs/2026-11-16-readme-badges-design.md`

## Global Constraints

- Palette: navy `#0E1726`, amber `#F2B441`, teal `#4CC9A0`, slate `#6F7E97`,
  text `#E8ECF2` / `#94A3BA`.
- No wording or section-order changes. No website changes.
- Commit and push straight to main.

## Review Focus

- GitHub dark theme: the SVG must keep its own navy background.
- The SVG's text has no webfont, so it must fit when a wider fallback
  font is used. Leave generous padding.
- New TOC anchors must match GitHub's slug rules for headings containing
  `:`, `(` or `&`. The link checker covers this.
- Badge links must point to real targets: pkg.go.dev for `pkg/subenum`,
  and the GHCR package page.
- `<details>` blocks need a blank line after `<summary>`, or the Markdown
  inside them won't render.

---

### Task 1: Badge rows

**Files:** Create `docs/assets/badges.svg`. Modify `README.md`, lines 7-23
and the Codespaces badge.

- [ ] **Step 1:** Write `badges.svg`: a navy `rx=14` panel holding the four
  facts separated by slate dividers, with platform names in `#E8ECF2` and
  the other facts in `#94A3BA`. Include `role="img"` and an `aria-label`.
- [ ] **Step 2:** Replace the five shields with build (teal), release
  (amber), Go Reference (teal), GHCR (amber) and Go 1.26+ (amber). Use
  `labelColor=0E1726` on each. Swap the `<sub>` line for the SVG.
- [ ] **Step 3:** Restyle the Codespaces badge with `labelColor=0E1726`.
- [ ] **Step 4:** Run `python .github/scripts/check-links.py`. Expected:
  no failures.

### Task 2: Navigation and the Development section

**Files:** Modify `README.md`.

- [ ] **Step 1:** Add a `<details><summary>Contents</summary>` list of the
  `##` headings and their `###` children, under the links row.
- [ ] **Step 2:** Add `<sub>[↑ back to top](#readme)</sub>` before each `##`
  heading from Installation onward.
- [ ] **Step 3:** Fold the tech-stack table and the project tree into one
  `<details>` toggle. Correct the tree against `git ls-files`.
- [ ] **Step 4:** Run the link checker again. Then commit, push, and check
  that CI is green.
