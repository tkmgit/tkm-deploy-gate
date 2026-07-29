"""Permanent fixture suite.

Run whenever the engine changes:

    python3 -m unittest discover -s tests -v

Two things are asserted, and the second matters as much as the first:
  1. every deliberate break is caught, by the rule that is supposed to catch it
  2. the good tree passes clean, so the suite cannot pass by failing everything
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import trees  # noqa: E402
from tkm_gate.cli import main, run  # noqa: E402
from tkm_gate.report import ConfigError, Severity  # noqa: E402


class TreeCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="gate-fixture-"))
        self.config = trees.build_good(self.tmp / "site")
        os.environ["GATE_COMMIT_MESSAGE"] = "a commit with no bypass token"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)
        os.environ.pop("GATE_COMMIT_MESSAGE", None)

    @property
    def root(self) -> Path:
        return self.tmp / "site"

    def errors(self):
        report, _ = run(self.config)
        return report.errors

    def error_rules(self):
        return {f.rule for f in self.errors()}

    def warn_rules(self):
        report, _ = run(self.config)
        return {f.rule for f in report.findings
                if getattr(f.severity, "name", str(f.severity)).lower() == "warn"}


class TestGoodTree(TreeCase):
    def test_good_tree_has_no_errors(self):
        errors = self.errors()
        self.assertEqual(
            [], [(f.rule, f.detail) for f in errors],
            "the known good tree must pass clean, otherwise every break test "
            "below could be passing for the wrong reason",
        )

    def test_good_tree_exits_zero(self):
        self.assertEqual(0, main(["-c", str(self.config)]))

    def test_every_rule_inspected_something(self):
        report, _ = run(self.config)
        vacuous = [f.detail for f in report.errors if f.rule == "engine.vacuous_pass"]
        self.assertEqual([], vacuous)
        self.assertGreater(sum(report.seen.values()), 50)


class TestBreaks(TreeCase):
    pass


def _make_break_test(name, rule_id, severity, mutate):
    def test(self):
        mutate(self.root)
        report, _ = run(self.config)
        bucket = report.errors if severity == "error" else report.warnings
        caught = {f.rule for f in bucket}
        self.assertIn(
            rule_id, caught,
            "break %r was not caught by %s at %s. Caught: errors=%s warnings=%s"
            % (name, rule_id, severity,
               sorted({f.rule for f in report.errors}) or "none",
               sorted({f.rule for f in report.warnings}) or "none"),
        )
        # A warning must not block. That is the whole point of the split: a
        # judgement threshold never stops a deploy, a broken invariant always does.
        self.assertEqual(1 if severity == "error" else 0,
                         main(["-c", str(self.config)]))
    test.__name__ = "test_break_" + name
    return test


for _name, (_rule_id, _sev, _mutate) in trees.BREAKS.items():
    setattr(TestBreaks, "test_break_" + _name,
            _make_break_test(_name, _rule_id, _sev, _mutate))


class TestVacuousPassGuard(TreeCase):
    def test_rule_that_matches_nothing_is_an_error(self):
        # md.alternate_link requires at least one match. Remove every page it
        # could inspect and the rule would otherwise pass forever.
        for rel in ("index.html", "about/index.html", "pricing/index.html",
                    "legal/index.html"):
            (self.root / rel).unlink()
        rules = self.error_rules()
        self.assertIn("engine.vacuous_pass", rules)

    def test_guard_fires_even_when_the_rule_is_only_a_warning(self):
        cfg = self.config.read_text(encoding="utf-8")
        cfg += '\n[rules."a11y.img_alt"]\nseverity = "warn"\nmin_matches = 99\n'
        self.config.write_text(cfg, encoding="utf-8")
        report, _ = run(self.config)
        vacuous = [f for f in report.errors if f.rule == "engine.vacuous_pass"]
        self.assertTrue(vacuous, "the guard protects the gate, not the site, so "
                                 "it is an error whatever severity the rule has")


class TestSeverity(TreeCase):
    def test_warn_does_not_block(self):
        trees.BREAKS["missing_alt"][2](self.root)  # a11y.img_alt defaults to warn
        report, _ = run(self.config)
        self.assertIn("a11y.img_alt", {f.rule for f in report.warnings})
        self.assertEqual([], report.errors)
        self.assertEqual(0, main(["-c", str(self.config)]))

    def test_site_can_promote_a_warning_to_an_error(self):
        cfg = self.config.read_text(encoding="utf-8")
        cfg += '\n[rules."a11y.img_alt"]\nseverity = "error"\n'
        self.config.write_text(cfg, encoding="utf-8")
        trees.BREAKS["missing_alt"][2](self.root)
        self.assertIn("a11y.img_alt", self.error_rules())

    def test_site_can_switch_a_rule_off(self):
        cfg = self.config.read_text(encoding="utf-8")
        cfg += '\n[rules."structure.canonical"]\nseverity = "off"\n'
        self.config.write_text(cfg, encoding="utf-8")
        trees.BREAKS["wrong_canonical"][2](self.root)
        self.assertNotIn("structure.canonical", self.error_rules())


class TestBypass(TreeCase):
    def test_bypass_publishes_a_failing_tree(self):
        trees.BREAKS["wrong_canonical"][2](self.root)
        os.environ["GATE_COMMIT_MESSAGE"] = (
            "hotfix: restore the booking link\n\n"
            "[gate-bypass: canonical rule is wrong, live page is right]"
        )
        self.assertEqual(0, main(["-c", str(self.config)]))

    def test_bypass_without_a_real_reason_does_not_count(self):
        trees.BREAKS["wrong_canonical"][2](self.root)
        os.environ["GATE_COMMIT_MESSAGE"] = "hotfix\n\n[gate-bypass: x]"
        self.assertEqual(1, main(["-c", str(self.config)]))

    def test_bypass_does_not_suppress_the_findings(self):
        trees.BREAKS["wrong_canonical"][2](self.root)
        os.environ["GATE_COMMIT_MESSAGE"] = (
            "[gate-bypass: shipping anyway, see the incident note]")
        self.assertIn("structure.canonical", self.error_rules())


class TestMdLayer(TreeCase):
    def test_headers_entry_is_not_required_by_default(self):
        # Netlify already serves .md as text/markdown. Demanding an explicit
        # _headers entry would fail a site that is correct.
        trees._edit(self.root, "_headers",
                    "/md/*\n  Content-Type: text/markdown; charset=utf-8\n", "")
        self.assertNotIn("md.alternate_link", self.error_rules())

    def test_exempt_page_needs_no_rendition(self):
        trees._edit(self.root, "about/index.html",
                    '<link rel="alternate" type="text/markdown" href="%s/md/about.md" />'
                    % trees.SITE, "")
        self.assertIn("md.alternate_link", self.error_rules())
        cfg = self.config.read_text(encoding="utf-8").replace(
            '[rules."md.alternate_link"]\nenabled = true',
            '[rules."md.alternate_link"]\nenabled = true\n'
            'exempt = ["about/index.html"]')
        self.config.write_text(cfg, encoding="utf-8")
        self.assertNotIn("md.alternate_link", self.error_rules())


class TestVersionIsDeclaredOnce(unittest.TestCase):
    """The engine printed 1.7.0 while running 1.8.1 for two whole tags.

    Not because anyone was careless, but because the version lived in two files
    and nothing compared them. A published version string is part of the
    artifact: it is what a log, a bug report and a rollback all read.
    """

    def test_pyproject_agrees_with_the_package(self):
        import tomllib
        from tkm_gate import __version__
        root = Path(__file__).resolve().parent.parent
        declared = tomllib.load(open(root / "pyproject.toml", "rb"))["project"]["version"]
        self.assertEqual(
            declared, __version__,
            "pyproject.toml says %s and tkm_gate.__version__ says %s. Bump both "
            "in the same commit as the tag." % (declared, __version__))


class TestMdFactParity(TreeCase):
    """Compare facts, never prose, and calibrate against how pages really look."""

    def _on(self):
        trees._edit(self.root, "gate.toml", '[rules."pages.count"]',
                    '[rules."md.fact_parity"]\nenabled = true\n\n[rules."pages.count"]')

    def test_a_price_the_page_does_not_show_is_a_finding(self):
        self._on()
        trees._edit(self.root, "md/pricing.md", "- Full: 900 EUR", "- Full: 999 EUR")
        self.assertIn("md.fact_parity", self.warn_rules())

    def test_a_price_split_from_its_currency_is_not(self):
        # A page routinely prints the number in one element and the currency in
        # another. That is a layout choice, not a contradiction, and treating
        # it as one produced 42 false findings on a real site.
        self._on()
        trees._edit(self.root, "pricing/index.html", "Full 900 EUR.",
                    "Full <span>900</span> <span>EUR</span>.")
        self.assertNotIn("md.fact_parity", self.warn_rules())

    def test_an_address_only_in_a_mailto_href_is_not(self):
        # Stripping tags hides it, but the page genuinely offers it.
        self._on()
        trees._edit(self.root, "md/pricing.md", "- Full: 900 EUR",
                    "- Full: 900 EUR\n- Write to hello@example.com")
        trees._edit(self.root, "pricing/index.html", "Full 900 EUR.",
                    'Full 900 EUR. <a href="mailto:hello@example.com">Write</a>')
        self.assertNotIn("md.fact_parity", self.warn_rules())


class TestForbiddenSameAs(TreeCase):
    def test_an_org_with_no_sameas_still_counts_as_inspected(self):
        # Three of six portfolio sites publish organisations that are simply
        # not cross linked. If only nodes carrying sameAs were counted, the
        # vacuous pass guard would fire exactly where the rule had nothing to
        # complain about, and the rule could never be switched on there.
        trees._edit(self.root, "gate.toml", '[rules."pages.count"]',
                    trees.SCHEMA_BLOCK + '[rules."pages.count"]')
        for rel in ("index.html", "about/index.html", "pricing/index.html",
                    "legal/index.html"):
            trees._edit(self.root, rel,
                        ',"sameAs":["https://www.linkedin.com/company/example/"]', "")
        self.assertNotIn("schema.forbidden_sameas", self.error_rules())


class TestPinnedNodes(TreeCase):
    """Referencing a shared node is not the same as contradicting it."""

    def test_a_page_that_references_by_id_without_sameas_is_not_a_finding(self):
        trees._edit(self.root, "gate.toml", '[rules."pages.count"]',
                    trees.SCHEMA_BLOCK + '[rules."pages.count"]')
        trees._edit(self.root, "about/index.html",
                    ',"sameAs":["https://www.linkedin.com/in/aperson/"]', "")
        self.assertNotIn("schema.pinned_nodes", self.error_rules())

    def test_a_site_that_never_repeats_the_node_is_not_a_vacuous_pass(self):
        # couplephotographers.com references the shared founder by @id on every
        # page and repeats sameAs nowhere, which is the pattern this rule wants.
        # Counting only repeats refused it, so the rule punished exactly the
        # behaviour it exists to encourage.
        trees._edit(self.root, "gate.toml", '[rules."pages.count"]',
                    trees.SCHEMA_BLOCK + '[rules."pages.count"]')
        for rel in ("index.html", "about/index.html", "pricing/index.html",
                    "legal/index.html"):
            trees._edit(self.root, rel,
                        ',"sameAs":["https://www.linkedin.com/in/aperson/"]', "")
        self.assertNotIn("engine.vacuous_pass", self.error_rules())
        self.assertNotIn("schema.pinned_nodes", self.error_rules())

    def test_but_repeating_it_with_a_different_set_is(self):
        trees._edit(self.root, "gate.toml", '[rules."pages.count"]',
                    trees.SCHEMA_BLOCK + '[rules."pages.count"]')
        trees._edit(self.root, "about/index.html",
                    '"https://www.linkedin.com/in/aperson/"',
                    '"https://www.linkedin.com/in/aperson/","https://x.example/a"')
        self.assertIn("schema.pinned_nodes", self.error_rules())


class TestSkipLink(TreeCase):
    """What the browser ignores, the rule must ignore.

    A gate that fails a correct site is the one people learn to wave through,
    and a waved-through gate is worse than no gate.
    """

    def test_a_hidden_form_blueprint_is_not_the_first_focusable_element(self):
        # Netlify's forms blueprint is a <form hidden> full of inputs sitting
        # near the top of the body. It is not in the tab order.
        trees._edit(self.root, "index.html", '<a class="skip-link"',
                    '<form hidden name="contact">'
                    '<input type="text" name="name" /></form>'
                    '<a class="skip-link"')
        self.assertNotIn("a11y.skip_link", self.error_rules())

    def test_but_a_visible_control_before_it_still_fails(self):
        trees._edit(self.root, "index.html", '<a class="skip-link"',
                    '<button type="button">Menu</button><a class="skip-link"')
        self.assertIn("a11y.skip_link", self.error_rules())

    def test_a_spanish_label_passes_on_the_class_name(self):
        # The default text pattern is English. A site does not translate its
        # markup class names, so the class carries the signal when the visible
        # label is in another language.
        trees._edit(self.root, "index.html", ">Skip to main content<",
                    ">Saltar al contenido principal<")
        self.assertNotIn("a11y.skip_link", self.error_rules())


class TestRouteConvention(TreeCase):
    """A site that publishes /about and one that publishes /about/ are both
    internally consistent. The engine must not pick for them."""

    def _switch_to_no_trailing_slash(self):
        for rel in ("about/index.html", "pricing/index.html", "legal/index.html"):
            trees._edit(self.root, rel, '%s/%s/"' % (trees.SITE, rel.split("/")[0]),
                        '%s/%s"' % (trees.SITE, rel.split("/")[0]))
        sm = (self.root / "sitemap.xml").read_text(encoding="utf-8")
        for slug in ("about", "pricing", "legal"):
            sm = sm.replace("%s/%s/</loc>" % (trees.SITE, slug),
                            "%s/%s</loc>" % (trees.SITE, slug))
        (self.root / "sitemap.xml").write_text(sm, encoding="utf-8")

    def test_no_trailing_slash_site_fails_under_the_default(self):
        self._switch_to_no_trailing_slash()
        rules = self.error_rules()
        self.assertIn("structure.canonical", rules)
        self.assertIn("sitemap.matches_indexable", rules)

    def test_and_passes_once_the_convention_is_declared(self):
        self._switch_to_no_trailing_slash()
        cfg = self.config.read_text(encoding="utf-8").replace(
            'root = "."', 'root = "."\ntrailing_slash = false')
        self.config.write_text(cfg, encoding="utf-8")
        self.assertEqual([], [(f.rule, f.detail) for f in self.errors()])


class TestExclude(TreeCase):
    def test_a_non_page_file_breaks_every_page_rule(self):
        # A Netlify forms blueprint: no canonical, no h1, no JSON-LD, by design.
        (self.root / "__forms.html").write_text(
            "<html><body><form name='contact'></form></body></html>",
            encoding="utf-8")
        rules = self.error_rules()
        self.assertIn("structure.canonical", rules)
        self.assertIn("schema.jsonld_present", rules)

    def test_until_it_is_excluded(self):
        (self.root / "__forms.html").write_text(
            "<html><body><form name='contact'></form></body></html>",
            encoding="utf-8")
        cfg = self.config.read_text(encoding="utf-8").replace(
            'root = "."', 'root = "."\nexclude = ["__forms.html"]')
        self.config.write_text(cfg, encoding="utf-8")
        self.assertEqual([], [(f.rule, f.detail) for f in self.errors()])


class TestRouteMap(TreeCase):
    """A prerendered build does not publish pages at the paths they occupy."""

    def _flatten(self):
        # Move about/index.html to _prerendered/about.html and serve it through
        # a rewrite, which is what a prerendering build actually produces.
        pre = self.root / "_prerendered"
        pre.mkdir()
        (pre / "about.html").write_text(
            (self.root / "about" / "index.html").read_text(encoding="utf-8"),
            encoding="utf-8")
        shutil.rmtree(self.root / "about")
        (self.root / "_redirects").write_text(
            "# comment\n"
            "/old-about  /  301\n"
            "/about/  /_prerendered/about.html  200\n", encoding="utf-8")

    def test_path_derived_routes_are_wrong_for_a_prerendered_tree(self):
        self._flatten()
        rules = self.error_rules()
        self.assertIn("structure.canonical", rules)
        self.assertIn("sitemap.matches_indexable", rules)

    def test_reading_the_rewrite_map_fixes_it(self):
        self._flatten()
        cfg = self.config.read_text(encoding="utf-8").replace(
            'root = "."', 'root = "."\nroute_map = "_redirects"')
        self.config.write_text(cfg, encoding="utf-8")
        self.assertEqual([], [(f.rule, f.detail) for f in self.errors()])

    def test_a_301_does_not_define_where_a_file_is_served(self):
        self._flatten()
        # Downgrade the rewrite to a redirect. It no longer maps the file, so
        # the path-derived route comes back and the tree fails again.
        (self.root / "_redirects").write_text(
            "/about/  /_prerendered/about.html  301\n", encoding="utf-8")
        cfg = self.config.read_text(encoding="utf-8").replace(
            'root = "."', 'root = "."\nroute_map = "_redirects"')
        self.config.write_text(cfg, encoding="utf-8")
        self.assertIn("structure.canonical", self.error_rules())

    def test_a_missing_route_map_file_is_reported_not_ignored(self):
        cfg = self.config.read_text(encoding="utf-8").replace(
            'root = "."', 'root = "."\nroute_map = "_redirects"')
        self.config.write_text(cfg, encoding="utf-8")
        self.assertIn("engine.rule_crashed", self.error_rules())


class TestApprovedScriptSet(TreeCase):
    """For a site that generates its CSP, matching policy to output proves
    nothing. This rule asks whether the output matches intent."""

    def _enable(self, hashes):
        cfg = self.config.read_text(encoding="utf-8")
        cfg += '\n[rules."scripts.approved_set"]\nenabled = true\nhashes = %s\n' % (
            "[" + ", ".join('"%s"' % h for h in hashes) + "]")
        self.config.write_text(cfg, encoding="utf-8")

    def test_the_approved_script_passes(self):
        self._enable([trees.sha256(trees.INLINE_JS)])
        self.assertNotIn("scripts.approved_set", self.error_rules())

    def test_a_new_script_fails_even_though_its_hash_is_in_the_policy(self):
        # Simulate a generator: add a script AND add its hash to the policy, so
        # csp.script_hashes is satisfied. Only intent verification catches it.
        extra = "\n  window.__t = 1;\n"
        trees._edit(self.root, "index.html", "</body>",
                    "<script>%s</script></body>" % extra)
        trees._edit(self.root, "_headers", "script-src 'self' '%s'"
                    % trees.sha256(trees.INLINE_JS),
                    "script-src 'self' '%s' '%s'"
                    % (trees.sha256(trees.INLINE_JS), trees.sha256(extra)))
        self._enable([trees.sha256(trees.INLINE_JS)])
        report, _ = run(self.config)
        caught = {f.rule for f in report.errors}
        self.assertNotIn("csp.script_hashes", caught,
                         "the policy agrees with the output, which is exactly "
                         "the blind spot this rule exists for")
        self.assertIn("scripts.approved_set", caught)

    def test_a_stale_approval_fails(self):
        self._enable([trees.sha256(trees.INLINE_JS), "sha256-nolongerpresent="])
        self.assertIn("scripts.approved_set", self.error_rules())

    def test_enabled_with_no_hashes_fails_rather_than_passing_vacuously(self):
        cfg = self.config.read_text(encoding="utf-8")
        cfg += '\n[rules."scripts.approved_set"]\nenabled = true\n'
        self.config.write_text(cfg, encoding="utf-8")
        self.assertIn("scripts.approved_set", self.error_rules())


class TestHeadersMerging(TreeCase):
    def test_a_second_global_block_still_counts(self):
        # A post-build step appending its own /* block is the normal way to add
        # a generated CSP. Reading only the first block would report the header
        # missing on a site that serves it.
        h = self.root / "_headers"
        src = h.read_text(encoding="utf-8")
        csp = [l for l in src.splitlines()
               if l.strip().startswith("Content-Security-Policy:")][0]
        src = src.replace(csp + "\n", "")
        src += "\n/*\n" + csp + "\n"
        h.write_text(src, encoding="utf-8")
        self.assertNotIn("headers.required_present", self.error_rules())

    def test_a_genuinely_missing_header_is_still_caught(self):
        trees.BREAKS["missing_security_header"][2](self.root)
        self.assertIn("headers.required_present", self.error_rules())


class TestRedirectTargets(TreeCase):
    def test_a_redirect_to_a_missing_file_is_caught(self):
        # The exact bug this rule was written for: hiding a file behind a 404
        # rule that points at a page the site does not have. The status is still
        # 404, so it looks like it works, and the platform's generic page ships
        # instead of yours.
        (self.root / "_redirects").write_text(
            "/gate.toml  /not-here.html  404!\n", encoding="utf-8")
        self.assertIn("redirects.targets_exist", self.error_rules())

    def test_it_passes_once_the_target_exists(self):
        (self.root / "_redirects").write_text(
            "/gate.toml  /404.html  404!\n", encoding="utf-8")
        self.assertNotIn("redirects.targets_exist", self.error_rules())

    def test_external_targets_and_splats_are_skipped(self):
        (self.root / "_redirects").write_text(
            "# comment\n"
            "/out  https://example.org/  301\n"
            "/en/*  /:splat  301\n", encoding="utf-8")
        self.assertNotIn("redirects.targets_exist", self.error_rules())

    def test_no_redirects_file_is_not_an_error(self):
        self.assertNotIn("redirects.targets_exist", self.error_rules())


class TestConfig(TreeCase):
    def test_unknown_rule_id_is_fatal(self):
        cfg = self.config.read_text(encoding="utf-8")
        cfg += '\n[rules."structure.canonicl"]\nseverity = "off"\n'
        self.config.write_text(cfg, encoding="utf-8")
        with self.assertRaises(ConfigError):
            run(self.config)
        self.assertEqual(2, main(["-c", str(self.config)]))

    def test_missing_config_is_fatal(self):
        self.config.unlink()
        self.assertEqual(2, main(["-c", str(self.config)]))

    def test_missing_root_is_fatal(self):
        cfg = self.config.read_text(encoding="utf-8")
        self.config.write_text(cfg.replace('root = "."', 'root = "dist"'),
                               encoding="utf-8")
        self.assertEqual(2, main(["-c", str(self.config)]))

    def test_non_https_url_is_fatal(self):
        cfg = self.config.read_text(encoding="utf-8")
        self.config.write_text(cfg.replace(trees.SITE, "http://example.test"),
                               encoding="utf-8")
        self.assertEqual(2, main(["-c", str(self.config)]))


class TestCrashHandling(TreeCase):
    def test_a_rule_that_raises_is_an_error_not_a_pass(self):
        from tkm_gate import rules as rulemod

        def boom(ctx):
            raise RuntimeError("deliberate")

        original = rulemod.RULES["a11y.img_alt"]
        rulemod.RULES["a11y.img_alt"] = boom
        try:
            self.assertIn("engine.rule_crashed", self.error_rules())
        finally:
            rulemod.RULES["a11y.img_alt"] = original


if __name__ == "__main__":
    unittest.main()
