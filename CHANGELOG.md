# Changelog

Entries start at 1.14.0. Earlier versions are described in their tagged
commit messages (`git log --oneline`).

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
