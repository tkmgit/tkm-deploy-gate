"""tkm-deploy-gate: one engine, per-site config, version pinned.

The engine never writes. It reads a published tree, evaluates the rules the
site's gate.toml turns on, and exits non zero if any ERROR finding stands.
Netlify treats that as a failed build and keeps the previously published
deploy live, so a refusal never takes a site down.
"""

__version__ = "1.4.0"
