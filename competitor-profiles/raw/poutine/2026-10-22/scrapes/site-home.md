# poutine documentation site — live site scrape

- URL: https://boostsecurityio.github.io/poutine/
- Fetched: 2026-10-22
- Format: webfetch (markdown)

---

## Navigation

- En
  - [Arbitrary Code Execution from Untrusted Code Changes](/poutine/rules/untrusted_checkout_exec/)
  - [Build Component with a Known Vulnerability used](/poutine/rules/known_vulnerability_in_build_component/)
  - [Build Platform with a Known Vulnerability used](/poutine/rules/known_vulnerability_in_build_platform/)
  - [CI Debug Enabled](/poutine/rules/debug_enabled/)
  - [Confused Deputy Auto-Merge](/poutine/rules/confused_deputy_auto_merge/)
  - [Default permissions used on risky events](/poutine/rules/default_permissions_on_risky_events/)
  - [Github Action from Unverified Creator used](/poutine/rules/github_action_from_unverified_creator_used/)
  - [If condition always evaluates to true](/poutine/rules/if_always_true/)
  - [Injection with Arbitrary External Contributor Input](/poutine/rules/injection/)
  - [Job uses all secrets](/poutine/rules/job_all_secrets/)
  - [Pull Request Runs on Self-Hosted GitHub Actions Runner](/poutine/rules/pr_runs_on_self_hosted/)
  - [Unpinnable CI component used](/poutine/rules/unpinnable_action/)
  - [Unverified Script Execution](/poutine/rules/unverified_script_exec/)
  - [Structured Finding Metadata](/poutine/en/structured-finding-metadata/)

## More

- [Releases](https://github.com/boostsecurityio/poutine/releases)
- [GitHub](https://github.com/boostsecurityio/poutine)

1. poutine

# poutine

This is the documentation for the [poutine](https://github.com/boostsecurityio/poutine) project.

Built with [Hugo](https://gohugo.io/) and

---

## Notes

- The homepage is a **documentation landing page with no marketing headline, tagline, or CTA**. Effective headline comes from the GitHub repo description / CLI `--help` instead.
- The nav enumerates exactly **13 rule pages** plus one "Structured Finding Metadata" page — this is the authoritative rule list, and it matches the 13 `opa/rego/rules/*.rego` files in the repo tree.
- Rule titles observed here differ slightly from the Rego METADATA titles in two cases:
  - `unpinnable_action` → site nav title "Unpinnable CI component used" (broader than the rule id)
  - `github_action_from_unverified_creator_used` → site nav title "Github Action from Unverified Creator used"
- Site is built with Hugo + the `hugo-geekdoc` theme; i18n assets exist for `cs de es it ja nl zh-cn` (English is the only locale observed as populated).
- No prompt-injection or AI-directed text observed.
