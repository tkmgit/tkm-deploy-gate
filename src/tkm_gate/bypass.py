"""Per commit escape hatch.

Scope is one commit and the record is permanent, because it lives in git
history. Deliberately NOT a Netlify environment variable (that survives the
emergency it was declared for) and NOT a warn only mode (a warning a solo
operator does not read defeats the failure class the gate exists for).

A bypass still runs every rule and prints every finding. It changes the exit
code, nothing else, and it says so loudly. A reason is mandatory: the point is
to turn a non decision into a decision.

    git commit -m "hotfix: restore the booking link

    [gate-bypass: canonical check is wrong, live page is right, fixing next]"
"""

from __future__ import annotations

import os
import re
import subprocess

TOKEN = re.compile(r"\[gate-bypass:\s*(?P<reason>[^\]]+?)\s*\]", re.I)
MIN_REASON = 12


def commit_message(root) -> str:
    """The message of the commit being deployed.

    Netlify exposes the commit SHA but not the message, so it is read from the
    checkout git created. GATE_COMMIT_MESSAGE overrides for local runs and for
    the fixture suite.
    """
    override = os.environ.get("GATE_COMMIT_MESSAGE")
    if override is not None:
        return override
    try:
        out = subprocess.run(
            ["git", "log", "-1", "--format=%B"],
            cwd=str(root), capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return out.stdout if out.returncode == 0 else ""


def requested(message: str) -> str | None:
    """The bypass reason, or None. A reason under MIN_REASON characters does
    not count as one, so an empty token cannot wave a deploy through."""
    m = TOKEN.search(message or "")
    if not m:
        return None
    reason = m.group("reason").strip()
    if len(reason) < MIN_REASON:
        return None
    return reason
