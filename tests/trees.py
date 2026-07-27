"""Fixture trees.

A known good tree plus one deliberate break per rule. The breaks are applied as
mutations of the good tree rather than kept as copied directories, so a change
to the good tree cannot leave fifteen stale copies behind. That is the same
drift the gate exists to catch, and the fixture suite is not exempt from it.
"""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path

SITE = "https://example.test"

INLINE_JS = """
  (function () {
    var el = document.querySelector(".hero");
    if (el) { el.setAttribute("data-ready", "1"); }
  })();
"""

INLINE_CSS = """
  :root { --ink: #111; }
  body { color: var(--ink); font-family: system-ui, sans-serif; }
"""

DESC = ("A deliberately ordinary description that sits inside the eighty to two "
        "hundred character window the gate enforces on every indexable page.")


def sha256(body: str) -> str:
    return "sha256-" + base64.b64encode(
        hashlib.sha256(body.encode("utf-8")).digest()
    ).decode()


def page(route: str, title: str, *, jsonld: str | None = None,
         md: str | None = None, extra_head: str = "", body: str = "",
         desc: str = DESC) -> str:
    jsonld = jsonld if jsonld is not None else (
        '{"@context":"https://schema.org","@type":"WebPage","name":"%s"}' % title
    )
    md_link = ""
    if md:
        md_link = ('<link rel="alternate" type="text/markdown" href="%s" />'
                   % md)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>{title}</title>
<meta name="description" content="{desc}" />
<link rel="canonical" href="{SITE}{route}" />
{md_link}
<link rel="stylesheet" href="/style.css" />
{extra_head}
<style>{INLINE_CSS}</style>
<script type="application/ld+json">{jsonld}</script>
</head>
<body>
<h1>{title}</h1>
<img src="/img/hero.png" alt="A hero image" />
{body}
<script>{INLINE_JS}</script>
</body>
</html>
"""


ROUTES = {
    "index.html": ("/", "Home"),
    "about/index.html": ("/about/", "About"),
    "pricing/index.html": ("/pricing/", "Pricing"),
}


def build_good(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "img").mkdir(exist_ok=True)
    (root / "md").mkdir(exist_ok=True)
    (root / "img" / "hero.png").write_bytes(b"\x89PNG\r\n\x1a\n")

    for rel, (route, title) in ROUTES.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        body = "<p>From 250 EUR.</p>" if rel.startswith("pricing") else ""
        p.write_text(page(route, title, md=SITE + "/md/" + title.lower() + ".md",
                          body=body), encoding="utf-8")
        (root / "md" / (title.lower() + ".md")).write_text(
            "# %s\n" % title, encoding="utf-8")

    # A noindex page: present, deliberately absent from the sitemap.
    (root / "staging").mkdir(exist_ok=True)
    (root / "staging" / "index.html").write_text(
        page("/staging/", "Staging",
             extra_head='<meta name="robots" content="noindex" />'),
        encoding="utf-8")

    (root / "404.html").write_text(page("/404.html", "Not found"), encoding="utf-8")

    (root / "style.css").write_text(
        ".hero { background: url('/img/hero.png'); }\n", encoding="utf-8")

    (root / "robots.txt").write_text(
        "User-agent: *\nAllow: /\n\nSitemap: %s/sitemap.xml\n" % SITE,
        encoding="utf-8")

    locs = "".join("  <url><loc>%s%s</loc></url>\n" % (SITE, route)
                   for route, _ in ROUTES.values())
    (root / "sitemap.xml").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        "%s</urlset>\n" % locs, encoding="utf-8")

    (root / "llms.txt").write_text(
        "# Example\n\nPackages from 250 EUR.\n", encoding="utf-8")
    (root / "md" / "pricing.md").write_text(
        "# Prices\n\n- Basic: 250 EUR\n- Full: 900 EUR\n", encoding="utf-8")

    csp = (
        "default-src 'self'; base-uri 'self'; object-src 'none'; "
        "frame-ancestors 'self'; form-action 'self'; img-src 'self' data:; "
        "connect-src 'self'; "
        "script-src 'self' '%s'; style-src 'self' '%s'; font-src 'self'"
        % (sha256(INLINE_JS), sha256(INLINE_CSS))
    )
    (root / "_headers").write_text(
        "/*\n"
        "  X-Content-Type-Options: nosniff\n"
        "  Referrer-Policy: strict-origin-when-cross-origin\n"
        "  Permissions-Policy: camera=(), microphone=(), geolocation=()\n"
        "  X-Frame-Options: SAMEORIGIN\n"
        "  Strict-Transport-Security: max-age=31536000; includeSubDomains\n"
        "  Content-Security-Policy: %s\n"
        "\n"
        "/md/*\n"
        "  Content-Type: text/markdown; charset=utf-8\n" % csp,
        encoding="utf-8")

    (root / "gate.toml").write_text(GOOD_CONFIG, encoding="utf-8")
    return root / "gate.toml"


GOOD_CONFIG = f"""
[site]
name = "example.test"
url  = "{SITE}"
root = "."

[rules."pages.count"]
min_pages = 4

[rules."csp.style_hashes"]
enabled = true

[rules."md.alternate_link"]
enabled = true

[rules."legacy.retired_hosts"]
enabled = true
hosts = ["old-preview.example", "wixsite.com"]

[rules."prices.quoted_in_price_list"]
enabled = true
price_list = "md/pricing.md"
min_prices = 2
"""


# ------------------------------------------------------------------ mutations
def _edit(root: Path, rel: str, old: str, new: str) -> None:
    p = root / rel
    src = p.read_text(encoding="utf-8")
    assert old in src, "fixture anchor %r vanished from %s" % (old, rel)
    p.write_text(src.replace(old, new, 1), encoding="utf-8")


# name -> (rule id that must fire, severity it fires at by default, mutation)
BREAKS: dict[str, tuple[str, str, callable]] = {
    "robots_blanket_disallow": ("robots.no_blanket_disallow", "error", lambda r: _edit(
        r, "robots.txt", "Allow: /", "Disallow: /")),
    "robots_no_sitemap": ("robots.declares_sitemap", "error", lambda r: _edit(
        r, "robots.txt", "Sitemap: %s/sitemap.xml" % SITE, "# sitemap dropped")),
    "third_party_font": ("fonts.no_third_party", "error", lambda r: (r / "style.css").write_text(
        "@import url('https://fonts.googleapis.com/css2?family=Inter');\n"
        ".hero { background: url('/img/hero.png'); }\n", encoding="utf-8")),
    "missing_security_header": ("headers.required_present", "error", lambda r: _edit(
        r, "_headers", "  X-Frame-Options: SAMEORIGIN\n", "")),
    "script_edited_hash_not": ("csp.script_hashes", "error", lambda r: _edit(
        r, "index.html", 'data-ready", "1"', 'data-ready", "2"')),
    "stale_style_hash": ("csp.style_hashes", "error", lambda r: _edit(
        r, "_headers", "style-src 'self' '%s'" % sha256(INLINE_CSS),
        "style-src 'self' '%s' 'sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='"
        % sha256(INLINE_CSS))),
    "inline_event_handler": ("csp.no_inline_handlers", "error", lambda r: _edit(
        r, "about/index.html", "<h1>About</h1>",
        '<button onclick="go()">Go</button><h1>About</h1>')),
    "wrong_canonical": ("structure.canonical", "error", lambda r: _edit(
        r, "about/index.html", '%s/about/' % SITE, '%s/' % SITE)),
    "short_description": ("structure.description_length", "warn", lambda r: _edit(
        r, "about/index.html", DESC, "Too short.")),
    "unparseable_jsonld": ("schema.jsonld_parses", "error", lambda r: _edit(
        r, "about/index.html", '"@type":"WebPage"', '"@type":"WebPage",,')),
    "md_target_missing": ("md.alternate_link", "error", lambda r: (
        r / "md" / "about.md").unlink()),
    "broken_link": ("links.refs_resolve", "error", lambda r: (
        r / "img" / "hero.png").unlink()),
    "sitemap_missing_page": ("sitemap.matches_indexable", "error", lambda r: _edit(
        r, "sitemap.xml", "  <url><loc>%s/about/</loc></url>\n" % SITE, "")),
    "sitemap_foreign_host": ("sitemap.no_foreign_hosts", "error", lambda r: _edit(
        r, "sitemap.xml", "%s/about/" % SITE, "https://elsewhere.test/about/")),
    "retired_host": ("legacy.retired_hosts", "error", lambda r: _edit(
        r, "index.html", "<h1>Home</h1>",
        '<h1>Home</h1><a href="https://old-preview.example/x">old preview</a>')),
    "unknown_price": ("prices.quoted_in_price_list", "error", lambda r: _edit(
        r, "pricing/index.html", DESC, DESC[:100] + " Packages start at 175 EUR.")),
    "md_headers_entry_dropped": ("md.alternate_link", "error", lambda r: (
        _edit(r, "_headers", "/md/*\n  Content-Type: text/markdown; charset=utf-8\n", ""),
        _edit(r, "gate.toml", '[rules."md.alternate_link"]\nenabled = true',
              '[rules."md.alternate_link"]\nenabled = true\nrequire_headers_entry = true'),
    )),
    "md_link_missing": ("md.alternate_link", "error", lambda r: _edit(
        r, "about/index.html",
        '<link rel="alternate" type="text/markdown" href="%s/md/about.md" />' % SITE, "")),
    "missing_alt": ("a11y.img_alt", "warn", lambda r: _edit(
        r, "index.html", '<img src="/img/hero.png" alt="A hero image" />',
        '<img src="/img/hero.png" />')),
}
