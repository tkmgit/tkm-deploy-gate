"""The rules.

Every rule is registered under a stable id, reads only what the site config
gives it, and reports through the context so the engine can apply the site's
severity and the vacuous pass guard uniformly.

A rule must call ctx.seen() for each item it actually inspected. A rule that
inspects nothing and therefore passes is the checker's own version of the drift
it exists to catch, so the engine turns that into an error.
"""

from __future__ import annotations

import base64
import fnmatch
import hashlib
import json
import re
import urllib.parse
from html.parser import HTMLParser

RULES: dict[str, callable] = {}


def rule(rule_id: str):
    def deco(fn):
        RULES[rule_id] = fn
        fn.rule_id = rule_id
        return fn
    return deco


class Ctx:
    def __init__(self, site, config, rule_config, report):
        self.site = site
        self.config = config
        self.rc = rule_config
        self.report = report

    def fail(self, detail: str) -> None:
        self.report.add(self.rc.rule_id, self.rc.severity, detail)

    def seen(self, n: int = 1) -> None:
        self.report.count(self.rc.rule_id, n)

    def opt(self, key, default=None):
        return self.rc.opt(key, default)


# --------------------------------------------------------------------- pages
@rule("pages.count")
def pages_count(ctx: Ctx) -> None:
    minimum = int(ctx.opt("min_pages", 1))
    found = len(ctx.site.pages)
    ctx.seen(found)
    if found < minimum:
        ctx.fail(
            "only %d HTML file(s) found under %s, expected at least %d. Either the "
            "build dropped pages or min_pages is stale."
            % (found, ctx.site.root, minimum)
        )


# -------------------------------------------------------------------- robots
def _robots(ctx):
    return ctx.site.read_if(ctx.opt("path", "robots.txt"))


@rule("robots.no_blanket_disallow")
def robots_no_blanket_disallow(ctx: Ctx) -> None:
    src = _robots(ctx)
    if src is None:
        ctx.fail("robots.txt is missing")
        return
    for line in src.splitlines():
        ctx.seen()
        if re.match(r"^\s*Disallow:\s*/\s*$", line):
            ctx.fail(
                "robots.txt contains a blanket 'Disallow: /'. That removes the whole "
                "site from every index and nothing else would notice for days."
            )


@rule("robots.declares_sitemap")
def robots_declares_sitemap(ctx: Ctx) -> None:
    src = _robots(ctx)
    if src is None:
        ctx.fail("robots.txt is missing")
        return
    ctx.seen()
    expected = ctx.site.url + str(ctx.opt("sitemap", "/sitemap.xml"))
    if "Sitemap:" not in src:
        ctx.fail("robots.txt does not declare a Sitemap")
    elif expected not in src:
        ctx.fail("robots.txt does not point at %s" % expected)


# --------------------------------------------------------------------- fonts
@rule("fonts.no_third_party")
def fonts_no_third_party(ctx: Ctx) -> None:
    hosts = ctx.opt("forbidden_hosts", ["fonts.googleapis.com", "fonts.gstatic.com"])
    targets = dict(ctx.site.pages)
    for extra in ctx.opt("extra_files", ["style.css"]):
        src = ctx.site.read_if(extra)
        if src is not None:
            targets[extra] = src
    for path, src in targets.items():
        ctx.seen()
        for host in hosts:
            if host in src:
                ctx.fail(
                    "%s references %s. Self hosted fonts were a deliberate choice: "
                    "a reintroduced third party font origin is a performance "
                    "regression and a GDPR problem at once." % (path, host)
                )


# ---------------------------------------------------------------------- form
@rule("form.required_markup")
def form_required_markup(ctx: Ctx) -> None:
    page = ctx.opt("page", "contact/index.html")
    src = ctx.site.read_if(page)
    if src is None:
        ctx.fail("%s is missing, so the contact form cannot be checked" % page)
        return
    for needle in ctx.opt("required", []):
        ctx.seen()
        if needle not in src:
            ctx.fail("%s does not contain %s" % (page, needle))
    for banned in ctx.opt("forbidden_text", []):
        ctx.seen()
        if banned in src:
            ctx.fail("%s still carries the placeholder text %r" % (page, banned))


# ------------------------------------------------------------------- headers
def _headers_text(ctx):
    return ctx.site.read_if(ctx.opt("path", "_headers"))


def _blocks(headers_txt: str) -> list[tuple[str, dict[str, str]]]:
    """Every path pattern in _headers with the headers it sets.

    Netlify path patterns are globs, so a site may legitimately cover a whole
    directory with /md/* instead of naming each file. A checker that only looks
    for the literal path would report a false positive on every such site, and
    a false positive that has to be waved through teaches the bypass habit.
    """
    out: list[tuple[str, dict[str, str]]] = []
    current: tuple[str, dict[str, str]] | None = None
    for line in headers_txt.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line.startswith((" ", "\t")):
            if current is not None and ":" in line:
                key, _, value = line.strip().partition(":")
                current[1][key.strip()] = value.strip()
            continue
        current = (line.strip(), {})
        out.append(current)
    return out


def _global_block(headers_txt: str) -> str:
    """Every header applied to /*, from ALL /* blocks.

    A _headers file may declare /* more than once and Netlify merges them. A
    post-build step that appends its own /* block is the normal way to add a
    generated CSP, so reading only the first block misses exactly the header
    most worth checking, and reports it missing on a site that serves it.
    """
    out = ""
    for pattern, headers in _blocks(headers_txt):
        if pattern != "/*":
            continue
        for key, value in headers.items():
            out += "%s: %s\n" % (key, value)
    return out


@rule("headers.required_present")
def headers_required_present(ctx: Ctx) -> None:
    txt = _headers_text(ctx)
    if txt is None:
        ctx.fail("_headers is missing, so no security header is served")
        return
    block = _global_block(txt)
    required = ctx.opt("required", [
        "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
        "X-Frame-Options", "Strict-Transport-Security", "Content-Security-Policy",
    ])
    for header in required:
        ctx.seen()
        if header not in block:
            ctx.fail("_headers has no %s in the /* block" % header)


# ----------------------------------------------------------------------- CSP
def _csp(ctx) -> str:
    txt = _headers_text(ctx)
    if txt is None:
        return ""
    for line in _global_block(txt).splitlines():
        if line.startswith("Content-Security-Policy:"):
            return line.split(":", 1)[1].strip()
    return ""


def _directive(csp: str, name: str) -> str:
    for part in csp.split(";"):
        if part.strip().startswith(name):
            return part.strip()
    return ""


def _sha256(body: str) -> str:
    return "sha256-" + base64.b64encode(
        hashlib.sha256(body.encode("utf-8")).digest()
    ).decode()


def _hash_rule(ctx: Ctx, directive: str, extract, what: str) -> None:
    csp = _csp(ctx)
    if not csp:
        ctx.fail("no Content-Security-Policy in the /* block of _headers")
        return
    allowed = set(re.findall(r"'(sha256-[A-Za-z0-9+/=]+)'", _directive(csp, directive)))
    used = set()
    for path, src in ctx.site.pages.items():
        for body in extract(src):
            ctx.seen()
            digest = _sha256(body)
            used.add(digest)
            if digest not in allowed:
                ctx.fail(
                    "%s has an inline %s whose hash %s is not in %s. The browser "
                    "will refuse it and the page ships broken."
                    % (path, what, digest, directive)
                )
    for stale in sorted(allowed - used):
        ctx.fail(
            "%s allows %s but no page contains that %s any more. A stale hash is "
            "how a real edit gets published while the policy still describes the "
            "old one." % (directive, stale, what)
        )


@rule("csp.script_hashes")
def csp_script_hashes(ctx: Ctx) -> None:
    _hash_rule(ctx, "script-src", ctx.site.inline_scripts, "script")


@rule("csp.style_hashes")
def csp_style_hashes(ctx: Ctx) -> None:
    _hash_rule(ctx, "style-src", ctx.site.inline_styles, "style block")


@rule("csp.external_script_origins")
def csp_external_script_origins(ctx: Ctx) -> None:
    csp = _csp(ctx)
    origins = set(re.findall(r"https://[^\s']+", _directive(csp, "script-src")))
    for path, src in ctx.site.pages.items():
        for url in ctx.site.external_scripts(src):
            ctx.seen()
            origin = "https://" + urllib.parse.urlparse(url).netloc
            if origin not in origins:
                ctx.fail("%s loads %s, which script-src does not allow" % (path, origin))


@rule("csp.no_inline_handlers")
def csp_no_inline_handlers(ctx: Ctx) -> None:
    csp = _csp(ctx)
    if "'unsafe-inline'" in _directive(csp, "script-src"):
        return
    for path, src in ctx.site.pages.items():
        ctx.seen()
        for m in re.finditer(r"\son(click|load|error|submit|change|input)=\"", src):
            ctx.fail(
                "%s uses an inline %s handler, which a hash based policy blocks"
                % (path, m.group(1))
            )


@rule("scripts.approved_set")
def scripts_approved_set(ctx: Ctx) -> None:
    """Every inline script in the output is one somebody approved.

    This is the rule for a site that GENERATES its CSP from the build output.
    There, re-checking that the policy matches the scripts is a tautology: the
    generator just derived one from the other and will happily hash a script
    nobody wanted. Generation answers "does the policy match the output".
    This answers the different and harder question: "does the output match
    intent".

    Both directions are errors. An unapproved script is a script that shipped
    without anyone deciding it should. An approved hash with no matching script
    is a stale approval, which quietly widens what would pass next time.
    """
    approved = set(ctx.opt("hashes", []))
    if not approved:
        ctx.fail(
            "scripts.approved_set is enabled but no hashes are approved. Run the "
            "build, hash the inline scripts, and list the ones you intend to ship."
        )
        return
    seen: dict[str, str] = {}
    for path, src in ctx.site.pages.items():
        for body in ctx.site.inline_scripts(src):
            ctx.seen()
            digest = _sha256(body)
            seen.setdefault(digest, path)
    for digest, path in sorted(seen.items()):
        if digest not in approved:
            ctx.fail(
                "%s carries an inline script %s that is not in the approved set. "
                "The CSP generator would have hashed it and the policy would "
                "have looked correct, which is why this is checked separately."
                % (path, digest)
            )
    for stale in sorted(approved - set(seen)):
        ctx.fail(
            "%s is approved but no page carries that script any more. Remove it "
            "from the approved set, or it silently pre-approves nothing while "
            "looking like oversight." % stale
        )


# ----------------------------------------------------------------- structure
@rule("structure.single_h1")
def structure_single_h1(ctx: Ctx) -> None:
    for path, src in ctx.site.indexable.items():
        ctx.seen()
        n = len(re.findall(r"<h1[\s>]", src))
        if n != 1:
            ctx.fail("%s has %d h1 elements, expected exactly 1" % (path, n))


@rule("structure.canonical")
def structure_canonical(ctx: Ctx) -> None:
    for path, src in ctx.site.indexable.items():
        ctx.seen()
        m = re.search(r'<link[^>]*rel="canonical"[^>]*href="([^"]+)"', src)
        expected = ctx.site.url + ctx.site.route_of(path)
        if not m:
            ctx.fail("%s has no canonical link" % path)
        elif m.group(1) != expected:
            ctx.fail("%s canonical is %s, expected %s" % (path, m.group(1), expected))


def _description(src: str):
    return re.search(r'<meta[^>]*name="description"[^>]*content="([^"]*)"', src)


@rule("structure.meta_description")
def structure_meta_description(ctx: Ctx) -> None:
    for path, src in ctx.site.indexable.items():
        ctx.seen()
        if not _description(src):
            ctx.fail("%s has no meta description" % path)


@rule("structure.description_length")
def structure_description_length(ctx: Ctx) -> None:
    lo = int(ctx.opt("min", 80))
    hi = int(ctx.opt("max", 200))
    for path, src in ctx.site.indexable.items():
        m = _description(src)
        if not m:
            continue
        ctx.seen()
        n = len(m.group(1))
        if not lo <= n <= hi:
            ctx.fail("%s meta description is %d characters, outside %d to %d"
                     % (path, n, lo, hi))


# -------------------------------------------------------------------- schema
@rule("schema.jsonld_present")
def schema_jsonld_present(ctx: Ctx) -> None:
    for path, src in ctx.site.indexable.items():
        ctx.seen()
        if not ctx.site.jsonld_blocks(src):
            ctx.fail("%s carries no JSON-LD" % path)


@rule("schema.jsonld_parses")
def schema_jsonld_parses(ctx: Ctx) -> None:
    for path, src in ctx.site.pages.items():
        for block in ctx.site.jsonld_blocks(src):
            ctx.seen()
            try:
                json.loads(block)
            except ValueError as exc:
                ctx.fail("%s has JSON-LD that does not parse: %s" % (path, exc))


# ------------------------------------------------------------------ md layer
def _served_as_markdown(headers_txt: str, path: str) -> bool:
    for pattern, headers in _blocks(headers_txt):
        if not fnmatch.fnmatch(path, pattern):
            continue
        if "markdown" in headers.get("Content-Type", "").lower():
            return True
    return False



@rule("md.alternate_link")
def md_alternate_link(ctx: Ctx) -> None:
    """Every indexable page declares a markdown rendition and that file exists.

    Two things this rule deliberately does NOT decide:

    * Whether the file is actually SERVED as markdown. Netlify already maps .md
      to text/markdown, so demanding an explicit _headers entry reports a false
      positive on a site that is correct, and a false positive that has to be
      waved through teaches the bypass habit. Set require_headers_entry = true
      on a site that pins the type itself. What the wire actually returns is the
      post-deploy live probe's question; a repo-side gate cannot see it.
    * Which pages need a rendition. A site may deliberately leave legal pages
      out of its md layer. List them in exempt; an empty exempt list means every
      indexable page must have one.
    """
    headers_txt = ctx.site.read_if(ctx.opt("headers_path", "_headers")) or ""
    require_entry = bool(ctx.opt("require_headers_entry", False))
    exempt = set(ctx.opt("exempt", []))
    for path, src in ctx.site.indexable.items():
        if path in exempt:
            continue
        ctx.seen()
        m = re.search(
            r'<link[^>]*rel="alternate"[^>]*type="text/markdown"[^>]*href="([^"]+)"', src
        )
        if not m:
            ctx.fail(
                "%s has no markdown alternate link. If that is deliberate, list "
                "it in exempt so the decision is written down." % path
            )
            continue
        target = m.group(1).replace(ctx.site.url, "").lstrip("/")
        if not ctx.site.exists(target):
            ctx.fail("%s points at %s which does not exist" % (path, target))
        elif require_entry and not _served_as_markdown(headers_txt, "/" + target):
            ctx.fail(
                "%s is not covered by an _headers rule that sets a markdown "
                "Content-Type, and this site requires one" % target
            )


# --------------------------------------------------------------------- links
@rule("links.refs_resolve")
def links_refs_resolve(ctx: Ctx) -> None:
    site = ctx.site
    origin_re = re.escape(site.url)
    for path, src in site.pages.items():
        refs = re.findall(r'(?:href|src)="([^"]+)"', src)
        for m in re.finditer(r'srcset="([^"]+)"', src):
            refs += [part.strip().split(" ")[0] for part in m.group(1).split(",")]
        refs += re.findall(r'content="(%s[^"]*)"' % origin_re, src)
        for block in site.jsonld_blocks(src):
            refs += re.findall(r'"(%s[^"]*)"' % origin_re, block)
        for ref in refs:
            target = site.resolve(ref, path)
            if target is None:
                continue
            ctx.seen()
            if not site.exists(target):
                ctx.fail("%s references %s which does not exist" % (path, ref))
    for extra in ctx.opt("extra_files", ["style.css"]):
        src = site.read_if(extra)
        if src is None:
            continue
        for m in re.finditer(r'url\(["\']?([^)"\']+)', src):
            target = site.resolve(m.group(1), extra)
            if target is None:
                continue
            ctx.seen()
            if not site.exists(target):
                ctx.fail("%s references %s which does not exist" % (extra, m.group(1)))


# ------------------------------------------------------------------- sitemap
def _sitemap_locs(ctx):
    src = ctx.site.read_if(ctx.opt("path", "sitemap.xml"))
    if src is None:
        return None
    return re.findall(r"<loc>([^<]+)</loc>", src)


@rule("sitemap.matches_indexable")
def sitemap_matches_indexable(ctx: Ctx) -> None:
    locs = _sitemap_locs(ctx)
    if locs is None:
        ctx.fail("sitemap.xml is missing")
        return
    listed = {loc.replace(ctx.site.url, "") or "/" for loc in locs}
    real = {ctx.site.route_of(p) for p in ctx.site.indexable}
    for r in sorted(real | listed):
        ctx.seen()
    for missing in sorted(real - listed):
        ctx.fail("%s is indexable but not in sitemap.xml" % missing)
    for extra in sorted(listed - real):
        ctx.fail("sitemap.xml lists %s which is not an indexable page" % extra)


@rule("sitemap.no_foreign_hosts")
def sitemap_no_foreign_hosts(ctx: Ctx) -> None:
    locs = _sitemap_locs(ctx)
    if locs is None:
        ctx.fail("sitemap.xml is missing")
        return
    for loc in locs:
        ctx.seen()
        if not loc.startswith(ctx.site.url):
            ctx.fail("sitemap.xml contains a foreign host: %s" % loc)


# ----------------------------------------------------------------- redirects
@rule("redirects.targets_exist")
def redirects_targets_exist(ctx: Ctx) -> None:
    """Every local target in _redirects is a file that exists.

    A redirect to a missing file still returns the status you asked for, so the
    rule looks like it works and nothing complains. What you actually serve is
    the platform's generic page instead of yours, and the only way to notice is
    to read the redirects file next to the tree, which is precisely the
    cross-file comparison a diff hides.

    External targets, splats and placeholders are skipped: they cannot be
    resolved against the tree.
    """
    src = ctx.site.read_if(ctx.opt("path", "_redirects"))
    if src is None:
        return
    for line in src.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        source, target = parts[0], parts[1]
        if not target.startswith("/"):
            continue
        if "*" in target or ":" in target or "*" in source:
            continue
        ctx.seen()
        rel = target.lstrip("/")
        if rel == "" or rel.endswith("/"):
            rel += "index.html"
        if not ctx.site.exists(rel):
            ctx.fail(
                "_redirects sends %s to %s, which does not exist. The status "
                "code is still honoured, so this fails silently and serves the "
                "platform's generic page instead of yours." % (source, target)
            )


# -------------------------------------------------------------------- legacy
@rule("legacy.retired_hosts")
def legacy_retired_hosts(ctx: Ctx) -> None:
    ghosts = ctx.opt("hosts", [])
    if not ghosts:
        return
    commented = set(ctx.opt("comment_prefixed_files",
                            ["_redirects", "_headers", "robots.txt", "llms.txt"]))
    files = list(ctx.site.html_files) + list(ctx.opt("extra_files", [
        "robots.txt", "sitemap.xml", "llms.txt", "style.css", "_headers", "_redirects",
    ]))
    for path in files:
        src = ctx.site.read_if(path)
        if src is None:
            continue
        if path in commented:
            src = "\n".join(
                line for line in src.splitlines() if not line.lstrip().startswith("#")
            )
        ctx.seen()
        for ghost in ghosts:
            if ghost in src:
                ctx.fail("%s still references the retired host %s" % (path, ghost))


# -------------------------------------------------------------------- prices
def _normalise(value: str) -> str:
    return value.replace(",", "").replace(".", "")


@rule("prices.quoted_in_price_list")
def prices_quoted_in_price_list(ctx: Ctx) -> None:
    """Every price quoted anywhere must exist in the machine readable price list.

    Limitation, stated rather than hidden: this catches a figure that exists
    nowhere in the price document, which is what a forgotten update looks like.
    It cannot catch a figure that is real for one service being quoted on
    another.
    """
    list_path = ctx.opt("price_list", "md/pricing.md")
    price_list = ctx.site.read_if(list_path)
    if price_list is None:
        ctx.fail("price list %s is missing" % list_path)
        return
    known = {_normalise(m) for m in re.findall(r"(\d[\d.,]*)\s*EUR", price_list)}
    minimum = int(ctx.opt("min_prices", 1))
    if len(known) < minimum:
        ctx.fail("only %d price(s) found in %s, the file shape changed"
                 % (len(known), list_path))
        return

    def quoted(text):
        found = set()
        for m in re.finditer(r"(?:(\d[\d.,]*)\s*(?:EUR|€)|€\s*(\d[\d.,]*))", text):
            found.add(_normalise(m.group(1) or m.group(2)))
        return found

    sources: dict[str, str] = {}
    for path, src in ctx.site.pages.items():
        for m in re.finditer(
            r'<meta[^>]*(?:name="description"|property="og:description"'
            r'|name="twitter:description")[^>]*content="([^"]*)"', src
        ):
            key = path + " description"
            sources[key] = sources.get(key, "") + " " + m.group(1)
        for block in ctx.site.jsonld_blocks(src):
            sources[path + " JSON-LD"] = sources.get(path + " JSON-LD", "") + block
    for extra in ctx.opt("extra_files", ["llms.txt"]):
        src = ctx.site.read_if(extra)
        if src is not None:
            sources[extra] = src

    for where, text in sources.items():
        ctx.seen()
        for price in sorted(quoted(text) - known):
            ctx.fail("%s quotes %s EUR, which is not in the price list %s"
                     % (where, price, list_path))


# ---------------------------------------------------------------------- a11y
@rule("a11y.img_alt")
def a11y_img_alt(ctx: Ctx) -> None:
    for path, src in ctx.site.pages.items():
        for m in re.finditer(r"<img([^>]*)>", src):
            ctx.seen()
            if 'alt="' not in m.group(1):
                ctx.fail("%s has an img with no alt attribute" % path)


# ----------------------------------------------------------------- landmarks
RE_BODY = re.compile(r"<body[^>]*>(.*)</body>", re.S | re.I)
FOCUSABLE_TAGS = {"a", "button", "input", "select", "textarea"}
VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link",
             "meta", "source", "track", "wbr"}


class _FirstFocusable(HTMLParser):
    """The first element a Tab press can actually reach.

    Regex alone answers the wrong question. A Netlify forms blueprint is a
    `<form hidden>` full of inputs that sits near the top of the body and is
    not in the tab order at all; reading it as the first focusable element
    would fail a site that is correct, and a gate that fails correct sites is
    the one people learn to wave through. So this walks the tree, tracks how
    deep it is inside anything hidden, and ignores what the browser ignores.
    """

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack: list[tuple[str, bool]] = []
        self.hidden_depth = 0
        self.found: tuple[str, dict, int] | None = None
        self._text: list[str] = []
        self._capture = False

    @staticmethod
    def _is_hidden(attrs: dict) -> bool:
        return ("hidden" in attrs
                or attrs.get("aria-hidden") == "true"
                or attrs.get("tabindex") == "-1"
                or attrs.get("type", "").lower() == "hidden")

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v if v is not None else "") for k, v in attrs}
        hidden = self._is_hidden(a)
        if self.found is None and not self.hidden_depth and not hidden \
                and tag.lower() in FOCUSABLE_TAGS:
            self.found = (tag.lower(), a, self.getpos()[0])
            self._capture = (tag.lower() == "a")
            return
        if tag.lower() in VOID_TAGS:
            return
        self.stack.append((tag.lower(), hidden))
        if hidden:
            self.hidden_depth += 1

    def handle_endtag(self, tag):
        if self._capture and tag.lower() == "a":
            self._capture = False
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag.lower():
                for _, h in self.stack[i:]:
                    if h:
                        self.hidden_depth -= 1
                del self.stack[i:]
                return

    def handle_data(self, data):
        if self._capture:
            self._text.append(data)

    @property
    def label(self) -> str:
        return " ".join("".join(self._text).split())


def _body(src: str) -> str:
    m = RE_BODY.search(src)
    return m.group(1) if m else src


def _exempt(ctx: Ctx, path: str) -> bool:
    return any(fnmatch.fnmatch(path, pat) for pat in ctx.opt("exempt", []))


@rule("a11y.main_landmark")
def a11y_main_landmark(ctx: Ctx) -> None:
    """Exactly one main landmark on every indexable page.

    Not a style preference. Without it a screen reader has no way to jump past
    the repeated header, and a skip link has nothing to point at, so this rule
    and a11y.skip_link are two halves of one thing.
    """
    for path, src in ctx.site.indexable.items():
        if _exempt(ctx, path):
            continue
        ctx.seen()
        n = len(re.findall(r"<main[\s>]", src))
        if n != 1:
            ctx.fail("%s has %d main landmark(s), expected exactly 1" % (path, n))


@rule("a11y.skip_link")
def a11y_skip_link(ctx: Ctx) -> None:
    """The first focusable element is a skip link that resolves.

    Checking only that a skip link exists somewhere would pass a link placed
    after the navigation, which helps nobody: the whole point is that the first
    Tab reaches it. So the rule reads the first focusable element in the body
    and requires that to be the skip link, and requires its fragment to name an
    id that actually exists on the page.
    """
    pattern = re.compile(str(ctx.opt("text_pattern", r"skip")), re.I)
    for path, src in ctx.site.indexable.items():
        if _exempt(ctx, path):
            continue
        ctx.seen()
        parser = _FirstFocusable()
        parser.feed(_body(src))
        parser.close()
        if parser.found is None:
            ctx.fail("%s has no focusable element in the body, so no skip link "
                     "can be first" % path)
            continue
        tag, attrs, _line = parser.found
        href = attrs.get("href", "")
        haystack = parser.label + " " + " ".join("%s=%s" % kv for kv in attrs.items())
        if tag != "a" or not href.startswith("#") or not pattern.search(haystack):
            ctx.fail(
                "%s: the first focusable element is <%s>, not a skip link. A "
                "skip link placed after the navigation is not a skip link."
                % (path, tag)
            )
            continue
        target = href[1:]
        if target and ('id="%s"' % target) not in src:
            ctx.fail("%s has a skip link to #%s and no element carries that id"
                     % (path, target))


# ------------------------------------------------------------------- content
@rule("content.forbidden_patterns")
def content_forbidden_patterns(ctx: Ctx) -> None:
    """Values that must not appear outside the pages that are required to carry
    them.

    Written for the case that produced it: a national identity number belongs
    on a statutory legal notice and nowhere else, yet a bulk machine readable
    rendition quietly republished it on the home page. The engine holds no
    patterns of its own. A site declares its own, and declares which paths are
    allowed to match, because only the site knows which of its pages is a legal
    disclosure.

    Configure patterns by shape, not by literal value. This repository is
    public and a report line names the pattern that matched, never the text.
    """
    raw = ctx.opt("patterns", [])
    if not raw:
        ctx.fail("content.forbidden_patterns is enabled with no patterns. An "
                 "empty pattern set inspects everything and objects to nothing, "
                 "which looks like oversight and is not.")
        return
    compiled = []
    for p in raw:
        try:
            compiled.append((str(p), re.compile(str(p))))
        except re.error as exc:
            ctx.fail("pattern %r does not compile: %s" % (p, exc))
            return

    allow = [str(a) for a in ctx.opt("allow", [])]
    files: dict[str, str] = dict(ctx.site.pages)
    for glob in ctx.opt("files", []):
        for p in sorted(ctx.site.root.glob(str(glob))):
            if not p.is_file():
                continue
            rel = p.relative_to(ctx.site.root).as_posix()
            if any(part in {".git", "node_modules", ".netlify"} for part in rel.split("/")):
                continue
            try:
                files[rel] = p.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue

    matched_allowed = 0
    for path, src in sorted(files.items()):
        if any(fnmatch.fnmatch(path, pat) for pat in allow):
            if any(rx.search(src) for _, rx in compiled):
                matched_allowed += 1
            continue
        ctx.seen()
        for label, rx in compiled:
            if rx.search(src):
                ctx.fail(
                    "%s matches forbidden pattern %s. If this file is a "
                    "required legal disclosure add it to allow; otherwise the "
                    "value must not be published here." % (path, label)
                )

    for pat in allow:
        if not any(fnmatch.fnmatch(path, pat) for path in files):
            ctx.fail("allow entry %r matches no file. An exemption for a page "
                     "that no longer exists silently widens on the next rename."
                     % pat)


# --------------------------------------------------------------------- schema
ORG_TYPES = {"Organization", "LocalBusiness", "ProfessionalService",
             "Corporation", "NGO", "EducationalOrganization"}


def _nodes(ctx: Ctx, src: str):
    """Every typed node in every JSON-LD block, however deeply nested."""
    def walk(node):
        if isinstance(node, dict):
            t = node.get("@type")
            types = t if isinstance(t, list) else [t] if t else []
            if types:
                yield [str(x) for x in types], node
            for v in node.values():
                yield from walk(v)
        elif isinstance(node, list):
            for v in node:
                yield from walk(v)

    for block in ctx.site.jsonld_blocks(src):
        try:
            data = json.loads(block)
        except (ValueError, TypeError):
            continue          # schema.jsonld_parses owns that finding
        yield from walk(data)


@rule("schema.entity_ids")
def schema_entity_ids(ctx: Ctx) -> None:
    """Organisation and Person nodes carry a stable @id.

    A node without an @id cannot be referred to, merged or corrected. It is a
    description that happens to sit on a page rather than a claim about a thing
    that exists, and two pages describing the same company without ids describe
    two companies as far as a consumer is concerned.
    """
    types = set(ctx.opt("types", sorted(ORG_TYPES | {"Person"})))
    for path, src in ctx.site.pages.items():
        if any(fnmatch.fnmatch(path, pat) for pat in ctx.opt("exempt", [])):
            continue
        for node_types, node in _nodes(ctx, src):
            if not types.intersection(node_types):
                continue
            ctx.seen()
            if not str(node.get("@id", "")).strip():
                ctx.fail("%s declares a %s node with no @id (name %r)"
                         % (path, "/".join(node_types), node.get("name", "")))


@rule("schema.pinned_nodes")
def schema_pinned_nodes(ctx: Ctx) -> None:
    """A shared node says the same thing on every site that repeats it.

    Referring to a node by @id alone is correct and is not what this checks.
    The failure it catches is a site that repeats the node AND gives it a
    different sameAs set, because then the portfolio asserts two different
    truths about one identifier and a consumer merging them gets neither.

    Configure the canonical set once per shared node. A node that carries no
    sameAs on a given page is a reference, not a contradiction, and passes.
    """
    pins = ctx.opt("node", [])
    if not pins:
        ctx.fail("schema.pinned_nodes is enabled with no node declared. A pin "
                 "table with nothing in it inspects everything and objects to "
                 "nothing, which looks like oversight and is not.")
        return
    expected = {}
    for entry in pins:
        node_id = str(entry.get("id", "")).strip()
        if not node_id:
            ctx.fail("a schema.pinned_nodes entry has no id"); return
        expected[node_id] = sorted(str(x) for x in entry.get("same_as", []))

    found = set()
    for path, src in ctx.site.pages.items():
        for _types, node in _nodes(ctx, src):
            node_id = str(node.get("@id", "")).strip()
            if node_id not in expected:
                continue
            found.add(node_id)
            raw = node.get("sameAs")
            if raw is None:
                continue          # a reference, not a second claim
            ctx.seen()
            actual = sorted(str(x) for x in (raw if isinstance(raw, list) else [raw]))
            if actual != expected[node_id]:
                missing = [x for x in expected[node_id] if x not in actual]
                extra = [x for x in actual if x not in expected[node_id]]
                ctx.fail("%s repeats %s with a different sameAs set. missing=%s "
                         "extra=%s. Change the pin and every site together, or "
                         "reference the node by @id and do not repeat sameAs."
                         % (path, node_id, missing, extra))

    for node_id in expected:
        if node_id not in found:
            ctx.fail("pinned node %s appears nowhere on this site. A pin for a "
                     "node that is no longer referenced stops protecting "
                     "anything the moment it is forgotten." % node_id)


@rule("schema.forbidden_sameas")
def schema_forbidden_sameas(ctx: Ctx) -> None:
    """Hosts that must never appear in an organisation's sameAs.

    Two sibling companies claiming each other as the same entity is not a
    stronger signal, it is a false one. Where a real relationship exists it
    belongs on the node that actually holds it, such as a shared founder.
    """
    hosts = [str(h).lower() for h in ctx.opt("hosts", [])]
    if not hosts:
        ctx.fail("schema.forbidden_sameas is enabled with no hosts declared.")
        return
    for path, src in ctx.site.pages.items():
        for node_types, node in _nodes(ctx, src):
            if not ORG_TYPES.intersection(node_types):
                continue
            raw = node.get("sameAs")
            if raw is None:
                continue
            ctx.seen()
            for url in (raw if isinstance(raw, list) else [raw]):
                host = urllib.parse.urlparse(str(url)).netloc.lower()
                host = host[4:] if host.startswith("www.") else host
                if host in hosts:
                    ctx.fail("%s lists %s in the sameAs of %s. A sibling brand "
                             "is not the same entity."
                             % (path, host, node.get("@id") or "/".join(node_types)))
