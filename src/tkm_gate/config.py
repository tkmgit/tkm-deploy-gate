"""gate.toml loading.

Site specific truth lives here, never in the engine. The engine ships defaults
that suit a hand written static site; a site file turns rules on or off, moves
a severity, and supplies the facts only that site knows (its URL, its retired
hostnames, where its price list is).

Two deliberate refusals:
  * an unknown rule id in gate.toml is fatal, not ignored. A typo that silently
    disables a rule is the same failure as not having the rule.
  * a missing gate.toml is fatal. The engine never guesses a site's identity.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .report import ConfigError, Severity

# rule id -> (default severity, default min_matches, enabled by default)
DEFAULTS: dict[str, tuple[Severity, int, bool]] = {
    "pages.count":                    (Severity.ERROR, 0, True),
    "robots.no_blanket_disallow":     (Severity.ERROR, 1, True),
    "robots.declares_sitemap":        (Severity.ERROR, 1, True),
    "fonts.no_third_party":           (Severity.ERROR, 1, True),
    "form.required_markup":           (Severity.ERROR, 1, False),
    "headers.required_present":       (Severity.ERROR, 1, True),
    "csp.script_hashes":              (Severity.ERROR, 1, True),
    "csp.style_hashes":               (Severity.ERROR, 0, False),
    "csp.external_script_origins":    (Severity.ERROR, 0, True),
    "csp.no_inline_handlers":         (Severity.ERROR, 1, True),
    "scripts.approved_set":           (Severity.ERROR, 1, False),
    "structure.single_h1":            (Severity.WARN,  1, True),
    "structure.canonical":            (Severity.ERROR, 1, True),
    "structure.meta_description":     (Severity.ERROR, 1, True),
    "structure.description_length":   (Severity.WARN,  1, True),
    "schema.jsonld_present":          (Severity.ERROR, 1, True),
    "schema.jsonld_parses":           (Severity.ERROR, 1, True),
    "md.alternate_link":              (Severity.ERROR, 1, False),
    "links.refs_resolve":             (Severity.ERROR, 1, True),
    "sitemap.matches_indexable":      (Severity.ERROR, 1, True),
    "sitemap.no_foreign_hosts":       (Severity.ERROR, 1, True),
    "redirects.targets_exist":        (Severity.ERROR, 0, True),
    "legacy.retired_hosts":           (Severity.ERROR, 1, False),
    "prices.quoted_in_price_list":    (Severity.ERROR, 1, False),
    "a11y.img_alt":                   (Severity.WARN,  1, True),
}


@dataclass
class RuleConfig:
    rule_id: str
    severity: Severity
    min_matches: int
    enabled: bool
    options: dict = field(default_factory=dict)

    def opt(self, key, default=None):
        return self.options.get(key, default)


@dataclass
class Config:
    name: str
    url: str
    root: Path
    config_path: Path
    rules: dict[str, RuleConfig]
    trailing_slash: bool = True
    exclude: list[str] = field(default_factory=list)
    route_map: str | None = None
    extra_text_files: list[str] = field(default_factory=list)

    def rule(self, rule_id: str) -> RuleConfig:
        return self.rules[rule_id]


def load(config_path: Path) -> Config:
    if not config_path.is_file():
        raise ConfigError(
            "no gate.toml at %s. The engine does not guess a site's identity; "
            "every gated site carries its own config." % config_path
        )
    try:
        raw = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError("%s is not valid TOML: %s" % (config_path, exc)) from None

    site = raw.get("site")
    if not isinstance(site, dict):
        raise ConfigError("%s has no [site] table" % config_path)
    for key in ("name", "url"):
        if not site.get(key):
            raise ConfigError("%s: [site] %s is required" % (config_path, key))

    url = str(site["url"]).rstrip("/")
    if not url.startswith("https://"):
        raise ConfigError("%s: [site] url must be an https origin" % config_path)

    root = (config_path.parent / str(site.get("root", "."))).resolve()
    if not root.is_dir():
        raise ConfigError(
            "%s: [site] root %r does not exist. For a site that builds, the gate "
            "runs after the build against the output directory." % (config_path, str(site.get("root", ".")))
        )

    declared = raw.get("rules", {})
    if not isinstance(declared, dict):
        raise ConfigError("%s: [rules] must be a table" % config_path)
    unknown = sorted(set(declared) - set(DEFAULTS))
    if unknown:
        raise ConfigError(
            "%s: unknown rule id(s) %s. A typo that silently disables a rule is "
            "the same failure as not having the rule, so this is fatal. Known "
            "ids: %s" % (config_path, ", ".join(unknown), ", ".join(sorted(DEFAULTS)))
        )

    rules: dict[str, RuleConfig] = {}
    for rule_id, (sev, min_matches, enabled) in DEFAULTS.items():
        block = declared.get(rule_id, {})
        if not isinstance(block, dict):
            raise ConfigError(
                "%s: [rules.%s] must be a table, for example "
                '[rules.%s]\\n  severity = "warn"' % (config_path, rule_id, rule_id)
            )
        options = {k: v for k, v in block.items()
                   if k not in ("severity", "min_matches", "enabled")}
        severity = (Severity.parse(block["severity"], "%s [rules.%s]" % (config_path, rule_id))
                    if "severity" in block else sev)
        rule_enabled = bool(block.get("enabled", enabled))
        if severity is Severity.OFF:
            rule_enabled = False
        mm = int(block.get("min_matches", min_matches))
        if mm < 0:
            raise ConfigError("%s [rules.%s]: min_matches cannot be negative" % (config_path, rule_id))
        rules[rule_id] = RuleConfig(rule_id, severity, mm, rule_enabled, options)

    return Config(
        name=str(site["name"]),
        url=url,
        root=root,
        config_path=config_path,
        rules=rules,
        trailing_slash=bool(site.get("trailing_slash", True)),
        exclude=[str(x) for x in site.get("exclude", [])],
        route_map=(str(site["route_map"]) if site.get("route_map") else None),
        extra_text_files=[str(x) for x in site.get("extra_text_files", [])],
    )
