"""Engine entry point.

Exit codes:
  0  published: no ERROR finding stands, or an audited per commit bypass applies
  1  refused: at least one ERROR finding
  2  the gate could not run (bad config, unreadable tree)

A refusal is not an outage. Netlify keeps the previously published deploy live
when the build command fails, so the cost of a false positive is minutes.
"""

from __future__ import annotations

import argparse
import sys
import traceback
from pathlib import Path

from . import __version__, bypass
from .config import load
from .report import ConfigError, Report, Severity
from .rules import RULES, Ctx
from .site import Site

VACUOUS = "engine.vacuous_pass"
CRASHED = "engine.rule_crashed"


def run(config_path: Path) -> tuple[Report, object]:
    config = load(config_path)
    site = Site(config.root, config.url,
                trailing_slash=config.trailing_slash,
                exclude=config.exclude)
    report = Report()

    for rule_id, fn in RULES.items():
        rc = config.rule(rule_id)
        if not rc.enabled:
            report.skipped[rule_id] = "disabled in %s" % config.config_path.name
            continue
        report.ran.append(rule_id)
        try:
            fn(Ctx(site, config, rc, report))
        except Exception:
            report.add(CRASHED, Severity.ERROR,
                       "%s raised:\n%s" % (rule_id, traceback.format_exc()))
            continue
        # Vacuous pass guard. A selector that matches nothing passes forever,
        # which is the checker's own version of generator drift. Always an
        # error, whatever severity the site gave the rule: this protects the
        # gate, not the site.
        seen = report.seen.get(rule_id, 0)
        if seen < rc.min_matches:
            report.add(
                VACUOUS, Severity.ERROR,
                "%s inspected %d item(s), its config requires at least %d. "
                "It passed without checking anything, so either the tree "
                "changed shape or the rule no longer matches it."
                % (rule_id, seen, rc.min_matches),
            )
    return report, config


def _print(report: Report, config, argv_root: Path) -> None:
    print("tkm-deploy-gate %s | site %s | root %s"
          % (__version__, config.name, config.root))
    print("  %d rule(s) ran, %d disabled, %d item(s) inspected"
          % (len(report.ran), len(report.skipped), sum(report.seen.values())))

    for group, findings in (("WARN", report.warnings), ("ERROR", report.errors)):
        if not findings:
            continue
        print("")
        print("%s, %d:" % (group, len(findings)))
        width = max(len(f.rule) for f in findings)
        for f in findings:
            print("  %-*s  %s" % (width, f.rule, f.detail))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="tkm-gate", description=__doc__)
    parser.add_argument("-c", "--config", default="gate.toml",
                        help="path to the site's gate.toml (default: ./gate.toml)")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)

    config_path = Path(args.config).resolve()
    try:
        report, config = run(config_path)
    except ConfigError as exc:
        print("tkm-deploy-gate %s: CONFIGURATION ERROR" % __version__)
        print("  %s" % exc)
        print("")
        print("The gate did not run. A gate that cannot read its own config must "
              "not fall back to passing, so this stops the deploy.")
        return 2

    _print(report, config, config_path.parent)

    if not report.errors:
        print("")
        print("all checks passed, publishing")
        return 0

    reason = bypass.requested(bypass.commit_message(config.root))
    if reason:
        print("")
        print("=" * 72)
        print("BYPASS APPLIED. %d error(s) above were overridden by the commit."
              % len(report.errors))
        print("reason: %s" % reason)
        print("This is scoped to this commit and recorded permanently in git "
              "history. Publishing anyway.")
        print("=" * 72)
        return 0

    print("")
    print("BUILD REFUSED, %d error(s). Nothing was deployed and the previously "
          "published deploy stays live." % len(report.errors))
    print("Fix the above and push again, or, if this is an emergency and the "
          "gate is wrong, put [gate-bypass: your reason here] in the commit "
          "message.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
