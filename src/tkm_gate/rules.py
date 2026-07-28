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
