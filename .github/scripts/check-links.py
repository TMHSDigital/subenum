#!/usr/bin/env python3
"""Check internal links in a built Jekyll site (#125).

Usage: check-links.py <site_dir> <baseurl>

Every href and src in every HTML file that points inside the site (relative,
or root-relative under baseurl) must resolve to a file in site_dir, and a
#fragment must name an id on the target page. External links are not
fetched. Exits 1 and lists each broken link.
"""
import html.parser
import os
import sys
import urllib.parse


class Links(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.links, self.ids = [], set()

    def handle_starttag(self, tag, attrs):
        for name, value in attrs:
            if name == "id" and value:
                self.ids.add(value)
            elif name in ("href", "src") and value:
                self.links.append(value)


def parse(path):
    p = Links()
    with open(path, encoding="utf-8") as f:
        p.feed(f.read())
    return p


def resolve(site, page_rel, url, baseurl):
    """Return the file a link points at, or None for external links."""
    u = urllib.parse.urlsplit(url)
    if u.scheme or u.netloc or url.startswith(("mailto:", "javascript:", "data:")):
        return None, None
    path = urllib.parse.unquote(u.path)
    if path == "":
        target = page_rel
    elif path.startswith("/"):
        if not path.startswith(baseurl + "/") and path != baseurl:
            return "outside", u.fragment
        target = path[len(baseurl):].lstrip("/")
    else:
        target = os.path.normpath(os.path.join(os.path.dirname(page_rel), path)).replace(os.sep, "/")
    full = os.path.join(site, target)
    if os.path.isdir(full) or target.endswith("/") or target in ("", "."):
        full = os.path.join(full, "index.html")
    elif not os.path.exists(full) and os.path.exists(full + ".html"):
        full += ".html"
    return full, u.fragment


def main():
    site, baseurl = sys.argv[1], sys.argv[2].rstrip("/")
    pages = {}
    for root, _, files in os.walk(site):
        for name in files:
            if name.endswith(".html"):
                full = os.path.join(root, name)
                pages[os.path.normpath(full)] = parse(full)
    if not pages:
        sys.exit(f"no HTML pages under {site}")
    broken = []
    for full, page in sorted(pages.items()):
        rel = os.path.relpath(full, site).replace(os.sep, "/")
        for link in page.links:
            target, fragment = resolve(site, rel, link, baseurl)
            if target is None:
                continue
            if target == "outside":
                broken.append(f"{rel}: {link} (root-relative link outside {baseurl}/)")
                continue
            target = os.path.normpath(target)
            if not os.path.exists(target):
                broken.append(f"{rel}: {link} (no such file)")
            elif fragment and target in pages and fragment not in pages[target].ids:
                broken.append(f"{rel}: {link} (no id {fragment!r} on the page)")
    for b in broken:
        print(b)
    print(f"checked {len(pages)} pages, {len(broken)} broken links")
    sys.exit(1 if broken else 0)


if __name__ == "__main__":
    main()
