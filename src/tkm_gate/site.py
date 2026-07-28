"""The tree under inspection.

Loaded once, read many times. Nothing here writes, moves or fixes anything:
the gate's only output is a verdict.
"""

from __future__ import annotations

import fnmatch
import re
from functools import cached_property
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", ".netlify", "__pycache__"}

RE_ROBOTS_META = re.compile(r'<meta\s+name="robots"\s+content="([^"]*)"', re.I)
RE_SCRIPT = re.compile(r"<script([^>]*)>(.*?)</script>", re.S | re.I)
RE_STYLE = re.compile(r"<style([^>]*)>(.*?)</style>", re.S | re.I)
RE_JSONLD = re.compile(
    r'<script[^>]*type="application/ld\+json"[^>]*>(.*?)</script>', re.S | re.I
)


class Site:
    def __init__(self, root: Path, url: str, *, trailing_slash: bool = True,
                 exclude: list[str] | None = None, route_map: str | None = None):
        self.root = root
        self.url = url.rstrip("/")
        # Route convention. A site that publishes /about and a site that
        # publishes /about/ are both internally consistent; the engine must not
        # pick for them. What matters is that canonical, sitemap and the file
        # layout agree, and that is what the rules check once they know which
        # convention this site uses.
        self.trailing_slash = trailing_slash
        # Files that are not pages at all. A Netlify forms blueprint has no
        # canonical, no h1 and no JSON-LD by design; reporting it as a broken
        # page trains the reader to skim the output, which is how a real
        # finding gets missed.
        self.exclude = list(exclude or [])
        # Prerendered sites do not publish their pages at the paths they occupy.
        # A build may write dist/_prerendered/es--about.html and serve it at
        # /es/about through a rewrite rule. Deriving the route from the file
        # path is then simply wrong, and the file layout is not the truth: the
        # rewrite map is. Point this at the redirects file and the engine reads
        # the same mapping the edge uses.
        self.route_map_file = route_map

    # ------------------------------------------------------------------ files
    def path(self, rel: str) -> Path:
        return self.root / rel

    def exists(self, rel: str) -> bool:
        return (self.root / rel).exists()

    def read(self, rel: str) -> str:
        return (self.root / rel).read_text(encoding="utf-8")

    def read_if(self, rel: str) -> str | None:
        p = self.root / rel
        if not p.is_file():
            return None
        return p.read_text(encoding="utf-8")

    @cached_property
    def html_files(self) -> list[str]:
        found = []
        for p in self.root.rglob("*.html"):
            rel = p.relative_to(self.root)
            if SKIP_DIRS & set(rel.parts):
                continue
            posix = rel.as_posix()
            if any(fnmatch.fnmatch(posix, pat) for pat in self.exclude):
                continue
            found.append(posix)
        return sorted(found)

    @cached_property
    def pages(self) -> dict[str, str]:
        return {rel: self.read(rel) for rel in self.html_files}

    # ----------------------------------------------------------------- routes
    @cached_property
    def _routes_by_file(self) -> dict[str, str]:
        if not self.route_map_file:
            return {}
        src = self.read_if(self.route_map_file)
        if src is None:
            raise FileNotFoundError(
                "route_map points at %s which does not exist under %s"
                % (self.route_map_file, self.root)
            )
        mapping: dict[str, str] = {}
        for line in src.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 3 or parts[2].rstrip("!") != "200":
                # Only a rewrite defines where a file is served. A 301 sends the
                # visitor somewhere else and says nothing about this file.
                continue
            route, target = parts[0], parts[1]
            if not target.startswith("/") or "*" in line or ":" in route:
                continue
            target = target.lstrip("/")
            if target.endswith("/"):
                target += "index.html"
            mapping.setdefault(target, route)
        return mapping

    @cached_property
    def _files_by_route(self) -> dict[str, str]:
        return {route: f for f, route in self._routes_by_file.items()}

    def route_of(self, rel: str) -> str:
        mapped = self._routes_by_file.get(rel)
        if mapped is not None:
            return mapped
        if rel == "index.html":
            return "/"
        if rel.endswith("/index.html"):
            route = "/" + rel[: -len("index.html")]
            return route if self.trailing_slash else route.rstrip("/")
        return "/" + rel

    @staticmethod
    def is_noindex(src: str) -> bool:
        m = RE_ROBOTS_META.search(src)
        return bool(m and "noindex" in m.group(1).lower())

    @cached_property
    def indexable(self) -> dict[str, str]:
        return {
            rel: src
            for rel, src in self.pages.items()
            if not self.is_noindex(src) and rel != "404.html"
        }

    # ---------------------------------------------------------------- extract
    @staticmethod
    def inline_scripts(src: str) -> list[str]:
        """Bodies of inline scripts the browser will execute.

        JSON-LD is data, not script, and is never hashed. A script with a src
        attribute has no body to hash.
        """
        out = []
        for attrs, body in RE_SCRIPT.findall(src):
            if "application/ld+json" in attrs.lower():
                continue
            if re.search(r'\ssrc\s*=', attrs, re.I):
                continue
            out.append(body)
        return out

    @staticmethod
    def external_scripts(src: str) -> list[str]:
        out = []
        for attrs, _ in RE_SCRIPT.findall(src):
            m = re.search(r'src="([^"]+)"', attrs)
            if m and m.group(1).startswith("http"):
                out.append(m.group(1))
        return out

    @staticmethod
    def inline_styles(src: str) -> list[str]:
        return [body for _, body in RE_STYLE.findall(src)]

    @staticmethod
    def jsonld_blocks(src: str) -> list[str]:
        return RE_JSONLD.findall(src)

    # ------------------------------------------------------------------ links
    def resolve(self, ref: str, from_path: str) -> str | None:
        """Map a reference to a repo relative file, or None if it is off site.

        Absolute URLs on our own origin are still our files: schema blocks and
        og:image tags use that form, so they get checked like any other link.
        """
        if ref.startswith(self.url):
            ref = ref[len(self.url):] or "/"
        ref = ref.split("#")[0].split("?")[0]
        if not ref or ref.startswith(("http", "mailto:", "tel:", "data:", "//")):
            return None
        # A link points at a route, not at a file. On a prerendered tree those
        # differ: /es/about is served from _prerendered/es--about.html and
        # nothing exists at es/about/index.html. Resolve through the rewrite map
        # first, or every internal link on such a site reads as broken.
        for candidate in (ref, ref.rstrip("/"), ref.rstrip("/") + "/"):
            mapped = self._files_by_route.get(candidate)
            if mapped is not None:
                return mapped
        if ref.startswith("/"):
            target = ref.lstrip("/")
        else:
            target = _normpath(Path(from_path).parent.as_posix() + "/" + ref)
        if target == "" or target.endswith("/"):
            target = target + "index.html"
        if (self.root / target).is_dir():
            target = target.rstrip("/") + "/index.html"
        return target


def _normpath(p: str) -> str:
    parts: list[str] = []
    for seg in p.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if parts:
                parts.pop()
            continue
        parts.append(seg)
    trailing = "/" if p.endswith("/") else ""
    return "/".join(parts) + trailing
