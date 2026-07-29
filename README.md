# tkm-deploy-gate

A read-only deploy gate for the TKM static site portfolio. It runs as the
Netlify build command, reads the tree that is about to be published, and exits
non zero if a declared invariant is broken. Netlify treats that as a failed
build and keeps the previously published deploy live, so a refusal never takes
a site down. It only stops a bad change.

Zero dependencies, standard library only, Python 3.11 or newer.

## Why it exists

A solo operator has no reviewer. The gate is the reviewer. Low change frequency
makes this worse rather than better: the longer the gap between changes, the
staler the context, and the easier it is to ship a stale CSP hash or a sitemap
that disagrees with the pages.

What a gate catches that reading a diff does not is **cross file consistency**,
which diffs structurally hide. A stale CSP hash lives in a file the commit did
not touch. A deleted image's referrers are not in the diff. A sitemap that no
longer matches the indexable set looks fine from either side.

## Install and run

Pin a version. Never track a branch: one engine bug must not be able to block
every site's deploy on the same afternoon.

```toml
# netlify.toml
[build]
  command = "pip install 'tkm-deploy-gate @ git+https://github.com/tkmgit/tkm-deploy-gate@v1.0.0' && tkm-gate"
  publish = "."

[build.environment]
  PYTHON_VERSION = "3.11"
```

For a site that builds, run the gate **after** the build and point it at the
output, never at the source. Source side checks miss build introduced failures,
such as a prerender step silently dropping a route, which are the most likely
failures on those sites.

```toml
[build]
  command = "npm run build && pip install 'tkm-deploy-gate @ git+https://github.com/tkmgit/tkm-deploy-gate@v1.0.0' && tkm-gate"
  publish = "dist"
```

Locally, exactly what Netlify does:

```
tkm-gate                 # reads ./gate.toml
tkm-gate -c site/gate.toml
```

## Configuration

Site specific truth lives in the site's `gate.toml`, never in the engine.
Site specific rules go in the site's config or a site local plugin, never into
the engine core. There are no vendored copies of the engine: six copies drift
into six versions, which is the failure this project was built to stop.

```toml
[site]
name = "example.com"
url  = "https://example.com"
root = "."          # "dist" for a site that builds

[rules."pages.count"]
min_pages = 15

[rules."a11y.img_alt"]
severity = "error"  # generated output: one component change fans out
                    # hand written pages: leave it at the default warn
```

Each `[rules."<id>"]` table accepts `severity` (`error`, `warn`, `off`),
`enabled`, `min_matches`, and any options the rule documents. See
`gate.example.toml` for every rule with its defaults.

An unknown rule id is a fatal configuration error, not a warning. A typo that
silently disables a rule is the same failure as not having the rule.

## Accessibility and forbidden content

`a11y.main_landmark` and `a11y.skip_link` are two halves of one thing: a skip
link with nothing to point at helps nobody, and a main landmark nobody can
reach helps nobody either. The skip link rule reads the **first focusable
element in the body** rather than searching the page, because a skip link
placed after the navigation is not a skip link.

`content.forbidden_patterns` is off until a site declares its own patterns. The
engine ships none. It exists for the case that produced it: a national identity
number belonged on a statutory legal notice, and a bulk markdown rendition
republished it on the home page where nothing required it. Declare patterns by
shape, not by literal value, and list the pages that are *required* to match
under `allow`. An `allow` entry that matches no file is an error, because an
exemption for a page that no longer exists silently widens on the next rename.

## Entity rules

`schema.entity_ids` requires an `@id` on organisation and person nodes. A node
without one cannot be referred to, merged or corrected: it is a description
that happens to sit on a page rather than a claim about a thing that exists.

`schema.pinned_nodes` guards a node that several sites share. Referring to it
by `@id` alone is correct and passes. What fails is a site that repeats the
node **and** gives it a different `sameAs` set, because then the portfolio
asserts two truths about one identifier and a consumer merging them gets
neither. A pin whose node appears nowhere on the site is also an error: a pin
for something no longer referenced stops protecting anything the moment it is
forgotten.

`schema.forbidden_sameas` names hosts that must never appear in an
organisation's `sameAs`. Two sibling brands claiming each other is not a
stronger signal, it is a false one. Where a real relationship exists it belongs
on the node that holds it, such as a shared founder.

All three ship OFF. The engine holds no entity truth; the site does.

## Rendition parity

`md.fact_parity` compares a page with the markdown rendition it advertises. It
exists because the same failure was found twice in one portfolio pointing both
ways: a rendition published a national identity number the page never showed,
and three renditions quoted a price a visitor to the same URL could not see.
Both passed every check that existed, because the gate only ever asked whether
a rendition was present.

It compares facts, never prose. Two calibrations were learned by measuring six
real sites before it shipped: a quantity matches on its number alone, because a
page routinely prints `320` in one element and its currency in another, and a
contact detail matches against raw HTML, because an address inside a `mailto`
href is genuinely offered even though stripping tags hides it.

Ships as a warning and OFF.

## Severity

`error` blocks the deploy. `warn` prints and does not block.

The split is not about how annoying a finding is. **Cross file and intent
rules are errors**: broken references, CSP hashes versus actual scripts,
sitemap versus the indexable set, a blanket `Disallow: /`, retired hostnames,
markdown alternate targets. **Judgement thresholds are warnings**: meta
description length, and `alt` and `h1` on hand written sites.

## The vacuous pass guard

Every rule declares `min_matches`. If a rule inspects fewer items than that and
therefore passes, the engine reports `engine.vacuous_pass` as an **error**,
whatever severity the site gave the rule. A selector that matches zero pages
and passes forever is the checker's own version of the drift it exists to
catch, and the guard protects the gate, not the site.

A rule that raises is reported as `engine.rule_crashed`, also an error. A gate
never falls back to passing.

## The escape hatch

Put a token in the commit message. It is scoped to that one commit and the
record is permanent, because it lives in git history.

```
git commit -m "hotfix: restore the booking link

[gate-bypass: canonical rule is wrong, live page is right, fixing next]"
```

A reason under twelve characters does not count, so an empty token cannot wave
a deploy through. A bypass still runs every rule and prints every finding; it
changes the exit code and says so loudly.

Deliberately **not** a Netlify environment variable, which survives the
emergency it was declared for, and **not** a warn only mode, because a warning
a solo operator does not read defeats the failure class the gate exists for.

The hatch does not defeat the gate. The threat model is a forgetful operator,
not a malicious one. A logged bypass is a decision; the gate exists to prevent
non decisions. A gate with no hatch gets one installed at 2am by commenting out
the build command.

The sharpest case for it: because the previous deploy stays live, a false
positive on a commit that fixes a real live problem actively preserves the bad
state. That alone justifies a per commit override.

## What this gate deliberately does not check, and the probe that does

Served behaviour. A repo side gate reads the tree that is about to be published;
it cannot see what the edge actually returns. A `_headers` syntax error leaves
the file in the tree and every header absent on the wire, and no amount of
repo side checking finds that. `md.alternate_link` therefore checks that a
rendition is declared and that the file exists, and leaves the served
`Content-Type` alone unless a site sets `require_headers_entry = true`.

`tkm-probe` is the sibling. Same package, opposite side of the publish:

```
tkm-probe https://example.com --md --collector
tkm-probe https://a.com https://b.com          # several at once
```

It checks what only the wire can answer: the security headers are actually
present, the CSP is enforced rather than quietly demoted to report only, every
URL the sitemap advertises returns 200, content negotiation really returns
markdown, and the CSP collector is deployed.

The collector check is a GET expecting 405, not a POST. On sites whose collector
persists reports, a daily probe posting a fake violation would inject a junk
record a day into the exact data the store exists to collect. A monitor that
corrupts what it monitors is worse than no monitor.

`--csp-report-only` for a site deliberately still in report only, `--require`
to replace the default header set, `--max-urls` to cap the sitemap crawl. Exit
non zero on any failure, so it schedules cleanly.

## Tests

The fixture suite is permanent and runs whenever the engine changes.

```
python3 -m unittest discover -s tests -v
```

It asserts two things, and the second matters as much as the first: every
deliberate break is caught **by the rule that is supposed to catch it**, and
the known good tree passes clean, so the suite cannot pass by failing
everything.

## Scope

This is an internal tool for the tkmgit portfolio. It is public only so that
private site repositories can install a pinned version without a credential in
every Netlify environment. It contains no site content and no secrets.
