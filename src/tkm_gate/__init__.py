"""tkm-deploy-gate: one engine, per-site config, version pinned.

The engine never writes. It reads a published tree, evaluates the rules the
site's gate.toml turns on, and exits non zero if any ERROR finding stands.
Netlify treats that as a failed build and keeps the previously published
deploy live, so a refusal never takes a site down.
"""

# One literal, and a fixture asserts pyproject.toml agrees with it. The engine
# printed 1.7.0 while running 1.8.1 for exactly as long as there were two
# places to update and no check that they matched.
__version__ = "1.9.2"
