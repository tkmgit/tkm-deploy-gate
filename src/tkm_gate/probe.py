"""Post deploy live probe.

The gate reads the tree that is about to be published. It cannot see what the
edge actually returns, and that gap is not theoretical: a _headers syntax error
leaves the file in the tree, passes every repo side check, and removes every
header from the wire. A sitemap can list a URL that the redirect rules quietly
send somewhere else. A CSP can be demoted to report only by one edited suffix.

So this is a sibling to the gate, not part of it. Different question, different
time: it runs after the publish, against the real domain, over HTTP.

Standard library only, same as the gate.
"""

from __future__ import annotations

import argparse
import re
import sys
import urllib.error
import urllib.request

UA = "tkm-deploy-gate probe"
DEFAULT_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
]


class Result:
    def __init__(self) -> None:
        self.failures: list[str] = []
        self.checks = 0

    def check(self, ok: bool, detail: str) -> bool:
        self.checks += 1
        if not ok:
            self.failures.append(detail)
        return ok


def fetch(url: str, method: str = "GET", headers: dict | None = None,
          data: bytes | None = None, timeout: int = 20):
    req = urllib.request.Request(url, method=method, data=data)
    req.add_header("User-Agent", UA)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}, b""
    except Exception as exc:  # noqa: BLE001
        return None, {"__error__": str(exc)}, b""


def probe(site: str, *, want_md: bool, want_collector: bool,
          csp_report_only: bool, required: list[str], max_urls: int) -> Result:
    site = site.rstrip("/")
    r = Result()

    status, headers, body = fetch(site + "/")
    if not r.check(status == 200, "%s/ returned %s" % (site, status)):
        return r

    # Headers on the wire, which is the only place they are real.
    for name in required:
        if name == "content-security-policy" and csp_report_only:
            name = "content-security-policy-report-only"
        r.check(name in headers, "%s/ is missing the %s header" % (site, name))

    if "content-security-policy" in required and not csp_report_only:
        r.check(
            "content-security-policy-report-only" not in headers,
            "%s/ sends CSP as report-only. A policy that only reports is a "
            "policy that is not enforcing." % site,
        )

    # Every URL the sitemap advertises has to resolve. The gate proved the
    # sitemap agrees with the files; only this proves the edge agrees too.
    sitemap = None
    _, _, robots = fetch(site + "/robots.txt")
    m = re.search(rb"^\s*Sitemap:\s*(\S+)", robots, re.M | re.I)
    if r.check(bool(m), "%s/robots.txt declares no Sitemap" % site) and m:
        sitemap = m.group(1).decode()

    urls: list[str] = []
    if sitemap:
        st, _, xml = fetch(sitemap)
        r.check(st == 200, "%s returned %s" % (sitemap, st))
        locs = [x.decode() for x in re.findall(rb"<loc>([^<]+)</loc>", xml)]
        if b"<sitemapindex" in xml:
            for child in locs:
                cst, _, cxml = fetch(child)
                r.check(cst == 200, "%s returned %s" % (child, cst))
                urls += [x.decode() for x in re.findall(rb"<loc>([^<]+)</loc>", cxml)]
        else:
            urls = locs
    r.check(bool(urls), "%s advertises no URLs in its sitemap" % site)

    for url in urls[:max_urls]:
        st, _, _ = fetch(url)
        r.check(st == 200, "sitemap URL %s returned %s" % (url, st))

    if want_md:
        st, h, _ = fetch(site + "/", headers={"Accept": "text/markdown"})
        r.check(
            st == 200 and "markdown" in h.get("content-type", ""),
            "%s/ with Accept: text/markdown returned %s %s, expected a markdown "
            "content type" % (site, st, h.get("content-type")),
        )

    if want_collector:
        # Deliberately NOT a POST. On three of these sites the collector now
        # persists every report to a Netlify Blobs store, so a daily probe
        # posting a fake violation would inject a junk record a day into the
        # exact data the store exists to collect. A monitor that corrupts what
        # it monitors is worse than no monitor.
        #
        # A GET proves the same thing with no side effect: the function is
        # deployed and routed, because only a deployed collector answers 405
        # with Allow: POST. A missing one answers 404.
        st, h, _ = fetch(site + "/api/csp-report")
        r.check(
            st == 405,
            "%s/api/csp-report returned %s to a GET, expected 405 from a "
            "deployed collector (404 means it is not there)" % (site, st),
        )
        if st == 405:
            r.check("POST" in h.get("allow", ""),
                    "%s/api/csp-report answered 405 without Allow: POST" % site)

    return r


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="tkm-probe",
        description="Check what a deployed site actually serves. Sibling to the "
                    "deploy gate: the gate reads the tree, this reads the wire.")
    p.add_argument("sites", nargs="+", help="site origins, e.g. https://example.com")
    p.add_argument("--md", action="store_true",
                   help="expect Accept: text/markdown to return markdown")
    p.add_argument("--collector", action="store_true",
                   help="expect POST /api/csp-report to return 204")
    p.add_argument("--csp-report-only", action="store_true",
                   help="this site is deliberately still report-only")
    p.add_argument("--max-urls", type=int, default=60,
                   help="cap on sitemap URLs fetched per site")
    p.add_argument("--require", action="append", default=None, metavar="HEADER",
                   help="required response header, repeatable; replaces the default set")
    args = p.parse_args(argv)

    required = [h.lower() for h in (args.require or DEFAULT_HEADERS)]
    total_failures = 0
    for site in args.sites:
        r = probe(site, want_md=args.md, want_collector=args.collector,
                  csp_report_only=args.csp_report_only, required=required,
                  max_urls=args.max_urls)
        if r.failures:
            total_failures += len(r.failures)
            print("FAIL %s  (%d checks, %d failed)" % (site, r.checks, len(r.failures)))
            for f in r.failures:
                print("       %s" % f)
        else:
            print("ok   %s  (%d checks)" % (site, r.checks))

    if total_failures:
        print("")
        print("%d live check(s) failed. These are things the deploy gate cannot "
              "see, because it reads the repository and not the wire." % total_failures)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
