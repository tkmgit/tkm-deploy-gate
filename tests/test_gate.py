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
        for rel in ("index.html", "about/index.html", "pricing/index.html"):
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
