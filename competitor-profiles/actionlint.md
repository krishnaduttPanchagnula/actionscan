# actionlint — Quick Profile

**URL**: https://rhysd.github.io/actionlint/ (docs site; source at https://github.com/rhysd/actionlint)
**Generated**: 2026-10-22

## At a Glance

| Metric | Value |
|--------|-------|
| Tagline | "Static checker for GitHub Actions workflow files" (site H1 and GitHub repo description) |
| Target audience | (inferred from copy) Individual developers and platform engineers writing GitHub Actions workflows; CI authors validating YAML before merge. Not a security-operations audience. |
| Language / license | Go (+ TypeScript/HTML for the WASM playground) / MIT |
| GitHub stars / forks | 4,343 / 283 |
| Releases (latest) | 57 releases; latest `v1.7.12` (2026-03-30) — **206 days ago** as of 2026-10-22 |
| Last commit | Default branch (`main`) HEAD: **2026-04-19**. Repo-level `pushed_at`: **2026-07-16** (any branch). Both observed 2026-10-22. |
| Pricing starts at | OSS (MIT — no pricing page) |
| Free tier/trial | n/a — free and unlimited |
| Domain rank | not available (no SEO data source in this environment) |
| Est. organic traffic | not available (no SEO data source in this environment) |
| Organic keywords (top 10) | not available (no SEO data source in this environment) |
| Referring domains | not available (no SEO data source in this environment) |

Additional observed metrics: 208 open issues, 86 contributors, 219 popular actions in the embedded metadata dataset. Languages by bytes: Go 741,315 / TypeScript 15,388 / Shell 12,400 / JavaScript 5,876 / HTML 4,541.

## Positioning

**Headline**: **"Static checker for GitHub Actions workflow files"** (Observed — identical as the site H1 at https://rhysd.github.io/actionlint/ and the GitHub repo description, 2026-10-22).

**Subheadline**: "actionlint is a static checker for GitHub Actions workflow files. Try it online!" (Observed, README, exact quote.) The site itself is a **playground**, not a marketing page — the H1 on the live site is literally "actionlint playground" with a version badge "v1.7.12".

**Positioning angle**: *Correctness, not security posture.* actionlint is explicitly scoped to "finding out mistakes" — it says so in the README: "actionlint focuses on finding out mistakes. It tries to catch errors as much as possible and make false positives as minimal as possible." Its security checks (script injection, hardcoded credentials) are **two checks among 39**, framed as lint rules, not as a threat model.

**Positioning angle (Inferred)**: actionlint has won by being the *default answer to "is my workflow file correct?"* — it is pre-installed or trivially installable, it is a single static binary, and it has zero false-positive-driven config burden (the author explicitly minimises configuration). It is not trying to be a security scanner and does not compete for that budget.

## Product & Features

### What it checks (Observed, `docs/checks.md` — 39 checks, complete list)

Syntax / structural: unexpected keys; missing required keys and key duplicates; unexpected empty mappings; unexpected mapping values; YAML anchors; action metadata syntax validation (`action.yml`); deprecated inputs usage; deprecated workflow commands; `shell:` name validation; job ID and step ID uniqueness; ID naming convention; environment variable names; permissions.

Expression / type system: `${{ }}` syntax check; type checks for expressions; contexts and built-in functions; contextual typing for `steps.<step_id>`; contextual typing for `matrix`; contextual typing for `needs`; strict type checks for comparison operators; availability of contexts and special functions; constant conditions at `if:`.

Third-party integrations: **shellcheck** integration for `run:`; **pyflakes** integration for `run:`.

Security (2 checks): **script injection by potentially untrusted inputs**; **hardcoded credentials** (hardcoded password in `container:` / `services:` credentials blocks).

Action-related: **action format in `uses:`**; **local action inputs validation at `with:`**; **popular action inputs validation at `with:`**; **"outdated popular actions" detection at `uses:`**.

Other: job dependencies validation (`needs:`, incl. cycle detection); matrix values; webhook events validation; workflow dispatch event validation; glob filter pattern syntax validation; CRON syntax and IANA timezone string at `on.schedule`; runner labels; reusable workflows (input definitions, call syntax, types of `inputs.*`/`secrets.*`, outputs, downstream output typing).

### ⚠️ Correction to a common assumption — actionlint is NOT console-only

It has **no fixed output modes**, but it has full **template-driven machine-readable output** (Observed, `docs/usage.md` §"Format error messages", `command.go`):

```sh
actionlint -format '{{json .}}'                      # JSON array of error objects
actionlint -format '{{range $err := .}}{{json $err}}{{end}}'   # JSON Lines
actionlint -format '::error file={{$err.Filepath}},line={{$err.Line}},col={{$err.Column}}::{{$err.Message}}'  # GitHub Actions annotations
```

`-format` accepts full **Go template syntax** with custom actions (`json x`, `replace`, `split`, etc.). A **SARIF template** ships as `testdata/format/sarif_template.txt` with a sample output at `testdata/format/test.sarif` — it is a template file, not a `--format sarif` flag. Exit statuses: `0` clean, `1` problems found, `2` invalid command-line option, `3` fatal error.

**Editor / platform integrations (Observed)**: Problem Matchers (`actionlint-matcher.json` → GitHub Actions inline annotations), reviewdog (`reviewdog/action-actionlint`), super-linter, pre-commit, VS Code extension, Emacs, Vim/Neovim, Pulsar, Nova, trunk.

### Action metadata checking (Observed)

- **Popular actions**: a generated, committed dataset `PopularActions` (`popular_actions.go`, "Code generated by actionlint/scripts/generate-popular-actions. DO NOT EDIT.") covering **219 actions** with their input names, required flags and output names. Used to type-check `with:` inputs and `steps.<id>.outputs`.
- **Local actions**: `action.yml` in the repo is parsed for real input/output validation.
- **No network access.** `popular_actions.go` contains no `net/http` and no `api.github.com` reference (Observed by grep over the fetched source). There is no advisory, CVE, OSV, or marketplace lookup anywhere in the tool.

### ⚠️ Nuance on "outdated" — it means deprecated *runtime*, not outdated *version*

The check titled "Outdated popular actions detection at `uses:`" fires when the action's **runner** is no longer supported, e.g. `actions/checkout@v3` → "the runner of \"actions/checkout@v3\" action is too old to run on GitHub Actions". The docs are explicit (Observed, `docs/checks.md`):

> "Note that this check doesn't report that the action version is up-to-date. For example, even if you use `actions/checkout@v4` and newer version `actions/checkout@v5` is available, actionlint reports no error as long as `actions/checkout@v4` is not outdated. If you want to keep actions used by your workflows up-to-date, consider to use [Dependabot]."

**So: actionlint has no version-outdated detection.** It delegates that to Dependabot.

### ⚠️ Nuance on "pinning" — there is none

The `uses:` format check requires `{owner}/{repo}@{ref}` — but a **mutable tag is accepted**. `actions/checkout@v2` is valid; only a *missing* ref is an error. actionlint neither requires nor recommends SHA pinning (Observed, `docs/checks.md` §"Action format in `uses:`" and the example outputs).

### Playground (Observed)

https://rhysd.github.io/actionlint/ is a **WebAssembly build of actionlint** running entirely in the browser, versioned to v1.7.12, with a "Check" button and a "Yay! No error was detected." result. Every check in `docs/checks.md` links to a pre-loaded playground URL with the offending YAML embedded. Source: `playground/main.go` (TypeScript/HTML front-end).

### Configuration — `actionlint.yaml` (Observed, `docs/config.md`)

Placed in `.github/` (a different directory under super-linter). Optional; the author's stated goal is "to keep configuration file as minimal as possible."

```yaml
self-hosted-runner:
  labels: [linux.2xlarge, windows-latest-xl, linux-multi-gpu]   # glob supported
config-variables: [DEFAULT_RUNNER, JOB_NAME]                    # strict vars checking; null disables
paths:
  .github/workflows/**/*.{yml,yaml}:
    ignore: ['shellcheck reported issue in this script: SC2086:.+']
  .github/workflows/release.yaml:
    ignore: ['the runner of ".+" action is too old to run on GitHub Actions']
```

- `paths.<glob>.ignore` is a list of **regexes matched against error messages** — per-path suppression. Glob syntax is doublestar; path separator is always `/`.
- `actionlint -init-config` generates a starter config.
- CLI `-ignore` is a repeatable regex filter on error messages (global, not per-path).

### Scope / non-features (Observed)

- **No org sweep.** `command.go` contains no GitHub API usage; `LintRepository("")` resolves the **local** git repository's `.github/workflows`. Input is local files, explicit paths, or `-` for stdin.
- **No advisory/CVE/OSV lookups** of any kind (see above).
- **No pinning analysis**, **no version-outdated detection** (delegated to Dependabot), **no remediation** — the closest thing to remediation is the per-path `ignore` regex suppression, which is acknowledgment rather than a fix.
- **No HTML report**, no dashboard, no CSV.

### Other observed details

- **Go library API**: usable as a Go module — `Command`, `Linter`, `Project`/`Projects`, `Config`, `Workflow`/`Job`/`Step` AST, `Parse()`, `Pass` visitor, `Rule`/`RuleBase`/`RuleExpression`/`RuleShellcheck`/`RuleJobNeeds`, `ExprLexer`/`ExprParser`/`ExprType`/`ExprSemanticsChecker`, `ValidateRefGlob()`, `ActionMetadata`, `PopularActions`, `AllWebhookTypes`. The library explicitly does **not** follow semver (the repo version is the CLI version).
- **Install paths**: released binaries, Homebrew, `go install`, Docker image, download script for CI, several package managers (`docs/install.md`).
- **Docs are exhaustive**: `checks.md` is 129,782 bytes — every check has example input, example output, and a playground deep link.
- **Website is MIT-licensed and version-pinned** to the current release, with links to the versioned docs (`/blob/v1.7.12/docs/...`).

### Release cadence (Observed)

- 57 releases, 2021-06-16 → 2026-03-30. Release intervals are long and irregular: largest gap **265 days** (2025-01-19 → 2025-10-11), then 159d, 118d, 101d.
- Last release **2026-03-30** (206 days before 2026-10-22). Last default-branch commit **2026-04-19** (186 days before). Repo `pushed_at` **2026-07-16** — most consistent with a push to a non-default branch (e.g. an open PR branch), not with a merged change.
- **Contributor concentration**: 86 contributors, but `rhysd` alone accounts for **2,030 of 2,361 contributions (86.0%)**. Next non-bot contributors have 19, 11, 10, 10, 8 contributions. **Bus factor = 1.**
- 208 open issues.

## Pricing Summary

| Tier | Price | Notable Inclusions |
|---|---|---|
| actionlint | Free / OSS (MIT) | All 39 checks, shellcheck + pyflakes integration, JSON / JSONL / SARIF / annotation output, WASM playground, `actionlint.yaml` config, Go library API, all editor + CI integrations |

No pricing page exists — the project is MIT-licensed with no commercial tier, no hosted product, and no vendor. No `github.com/marketplace` listing was observed for actionlint.

## Key Takeaway

actionlint is the *de-facto* workflow linter and the benchmark every other Actions tool is measured against for correctness and for zero-false-positive discipline: 4,343 stars, a WASM playground, a 130 KB exhaustive check catalogue, first-class editor integrations, and a Go API. Its security footprint is deliberately thin — exactly two security checks (script injection, hardcoded credentials) and **no pinning, no outdated-version, no advisory, no org sweep**. The instructive part is not the engineering, which is excellent, but the **distribution**: 86% of all contributions come from one person, and the project has now gone 206 days without a release and 186 days without a merge to `main` — the tool's reputation, not its code, is what keeps it installed.

---

## Competitive Implications for actionscan

**Where they're strong vs. us** *(Observed)*

1. **Default-install status.** 4,343 stars, a Docker image, Homebrew, `go install`, pre-commit, super-linter, VS Code/Emacs/Vim extensions, reviewdog, Problem Matchers. Most developers have it running already. actionscan would be the *second* tool in the workflow, not the first.
2. **Zero-config ergonomics.** The author's stated design goal is minimal configuration; actionscan's config surface will be richer by necessity (feeds, purls, osv_ids) and therefore a friction point.
3. **Exhaustive, high-quality documentation** with runnable examples and playground links per check — a documentation bar actionscan would have to match.
4. **Correctness reputation.** Type checking of `${{ }}` expressions is genuinely hard; actionlint owns that category.
5. **MIT license.** No obligations for commercial adoption; Apache-2.0 (as actionscan may be) is comparable.

**Where we're strong vs. them** *(Observed for actionlint; the "we" side is Inferred)*

1. **Advisory/threat-intel lookups.** actionlint has **zero** network lookups — its only action metadata is a 219-entry static dataset committed to the repo. It structurally cannot tell you an action is compromised.
2. **Pinning hygiene.** actionlint accepts `actions/checkout@v4` without comment. A whole-org pinning-hygiene audit is unclaimed ground.
3. **Outdated releases.** Explicitly delegated to Dependabot by actionlint's own docs. This is a documented gap, not a contested one.
4. **Org-wide scope.** actionlint is strictly local-file (`actionlint` with no args finds `.github/workflows` in the current repo). Scanning 200 org repos means 200 separate invocations.
5. **Reporting surface.** JSON/JSONL/SARIF exist but there is no HTML dashboard, no cross-repo rollup, no CSV. A security-leadership view of an entire org is entirely unclaimed.
6. **Action-reference-centric vs. workflow-centric.** actionlint's unit is "the workflow file"; actionscan's unit is "the action reference across the org." Different problem, largely non-overlapping.

**Opportunities** *(Implication — questions for actionscan)*

- Position actionlint explicitly as the *syntax/correctness* layer and actionscan as the *provenance/liveness* layer. Because actionlint's own docs punt on outdated-version detection to Dependabot, there is a clean, citable line: "Dependabot tells you a new version exists; it does not tell you the old one is compromised."
- Do not build an expression type-checker. That is a solved, high-quality, well-covered problem with a strong incumbent. Spend the effort on the org sweep, live feeds, and the report instead.
- Consider a lightweight `actionlint` compatibility layer: if actionscan can consume actionlint's JSON output, it can be positioned as "actionlint for security, plus org scale."
- Can actionscan ship a WASM/browser playground? actionlint's is a well-known distribution asset and a strong top-of-funnel for a security tool that would otherwise be CLI-only.
- Watch the 208 open issues: any that indicate unmet demand (e.g. requests for version checks) is a read on where the incumbent's users want it to go.

**Threats** *(Implication)*

- actionlint's user base is a large, pre-qualified audience for a security-adjacent Actions tool. If actionlint ever adds an advisory lookup, or a major vendor (GitHub itself) ships the same into Actions, the "no live intel" gap closes.
- The single-maintainer model is a *risk* for actionlint but also a *risk for actionscan*: if the maintainer returns and adds an org-sweep or advisory feature with 4.3k stars of distribution behind it, adoption is nearly free for them and expensive for actionscan. Watch the repo, not just the releases.
- Competing for the same "GitHub Actions security" budget means being compared to actionlint's UX bar: single static binary, no config, fast, no network dependency, low false positives. Any actionscan feature that adds network latency or config burden is a direct adoption tax.

## Raw Data Sources

All retrieved 2026-10-22.

| Source | Local file |
|---|---|
| GitHub API — repo metadata | `raw/actionlint/2026-10-22/seo/repo.json` |
| GitHub API — releases (57) | `raw/actionlint/2026-10-22/seo/releases.json` |
| GitHub API — commits, branches/main, languages, contributors, tags, tree, contents | `raw/actionlint/2026-10-22/seo/{commits,branch-main,languages,contributors,tags,tree,contents-root}.json` |
| README (raw) | `raw/actionlint/2026-10-22/scrapes/readme.md` |
| Playground site (live) | `raw/actionlint/2026-10-22/scrapes/site-playground.md` |
| `docs/checks.md` (129 KB, all 39 checks) | `raw/actionlint/2026-10-22/scrapes/docs_checks.md` |
| `docs/usage.md` (output formats, exit status, integrations) | `raw/actionlint/2026-10-22/scrapes/docs_usage.md` |
| `docs/config.md` (`actionlint.yaml` schema) | `raw/actionlint/2026-10-22/scrapes/docs_config.md` |
| `docs/api.md` (Go library API) | `raw/actionlint/2026-10-22/scrapes/docs_api.md` |
| `docs/reference.md`, `docs/install.md`, `docs/README.md` | `raw/actionlint/2026-10-22/scrapes/docs_*.md` |
| `popular_actions.go` (219 actions, generated dataset) | `raw/actionlint/2026-10-22/scrapes/src_popular_actions.go` |
| `command.go` (CLI usage string, flags) | `raw/actionlint/2026-10-22/scrapes/src_command.go` |
| 404 pages | `docs/goals.md`, `docs/FAQ.md`, `docs/playground.md`, `docs/sandbox.md` — **HTTP 404**, saved as 14-byte error bodies |
| `rhysd/actionlint-action` | **repo does not exist** (GitHub API returns no `full_name`); the maintained CI wrapper is `reviewdog/action-actionlint` |

**Method note**: no SEO data source was available in this environment; all SEO rows are marked "not available" rather than estimated. No prompt-injection or AI-directed instructions were observed in any fetched page or file — all content was treated as data.
