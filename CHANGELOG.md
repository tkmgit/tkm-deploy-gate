# Changelog

Entries start at 1.14.0. Earlier versions are described in their tagged
commit messages (`git log --oneline`).

## 1.15.0

- `redirects.targets_exist` resolves a target as a route, not as a file. It
  uses the same resolution as link checking (`route_map` rewrites, then the
  file layout with `index.html` for a directory) plus the pretty URL form
  (`/en` served from `en.html`). Before, `/en/blog /en 301!` failed on a site
  that serves `/en` through a `200` rewrite to `_prerendered/en.html`, although
  the target answers 200 on the wire.
- A target that is a bare directory without `index.html` now fails; before,
  the directory itself counted as the target existing.
- A target with nothing behind it still fails. Link resolution for other rules
  is unchanged. Fixtures cover both directions.

## 1.14.0

- `form.required_markup` checks several pages. New option `pages`, a list of
  paths. `page` keeps its exact meaning; when both are given the union is
  checked, each page once. `required` and `forbidden_text` apply to every
  checked page. A listed page that does not exist is an error. Every finding
  names its page.
- New option `page_required`, a table of page to strings required on that page
  only, for markup that differs per page by design (a form action pointing at
  that language's thanks page). A key not in `page` or `pages` is an error.
- A non-string `page` or a non-list `pages` is reported as a finding instead of
  crashing the rule.
- Backward compatible: a config with only `page`, or with neither option, is
  evaluated exactly as in 1.13.0. Fixtures cover both directions and the
  single page regression.
