# KICS — Quick Profile

**URL**: https://kics.io/ (canonical homepage per the repo's `constants.URL`; checkmarx.com/kics redirects here)
**Generated**: 2026-10-22

## At a Glance
| Metric | Value |
|--------|-------|
| Tagline | "KICS - Keeping Infrastructure as Code Secure" (observed, kics.io homepage; also the project's own `constants.Fullname`) |
| Target audience | IaC/platform engineers and compliance teams wanting open, extensible, customizable IaC queries (inferred from homepage copy: "KICS is easy to install and run, easy to understand results, and easy to integrate into CI"; "powered by Checkmarx, global leader in Application Security Testing") |
| Language / license | Go / Apache-2.0 |
| GitHub stars / forks | 2,724 / 385 (GitHub API, 2026-10-22) |
| Releases (latest) | 100 fetched on first page of releases API (repo has 100+); latest v2.2.0, published **2026-09-17** (GitHub API) — the oldest latest-release of the four |
| Install / download volume | Homebrew: **155 installs/30d**, 958/90d, 4,033/365d (formulae.brew.sh API, 2026-10-22). No PyPI/npm distribution (Go binary). Docker Hub pull count not fetched. |
| Pricing starts at | KICS: free, Apache-2.0. Commercial: Checkmarx (Astrix / One platform) — **pricing not observable** from the pages scraped (no price table retrieved) |
| Free tier/trial | Yes — fully free, open-source, self-hostable; queries are plain Rego in the repo |
| Domain rank | not available (no SEO data source) |
| Est. organic traffic | not available (no SEO data source) |
| Organic keywords (top 10) | not available (no SEO data source) |
| Referring domains | not available (no SEO data source) |

## Positioning
**Headline**: "KICS - Keeping Infrastructure as Code Secure"
**Subheadline**: "keeping infrastructure as code secure is an open source solution for static code analysis of Infrastructure as Code."
**Positioning angle**: *Observed* — "Over 2400 queries are available", "Open Source … Both the scanning engine and the security queries are clear and open", "Extensible … over 2000 fully customizable and adjustable heuristics rules, called queries." *Inferred* — KICS's pitch is "the open, hackable IaC scanner", positioned as Checkmarx giving away the engine to win mindshare and feed the commercial platform.

## Product & Features
### Core capabilities
*Observed (repo tree + docs, 2026-10-22)*:
- **Query platforms** (from `assets/queries/`): terraform (6,716 paths), cloudFormation (3,377), openAPI (2,514), ansible (1,662), k8s (1,243), azureResourceManager (977), dockerfile (538), googleDeploymentManager (291), dockerCompose (216), pulumi (159), crossplane (143), common (136), serverlessFW (79), **cicd (72)**, buildah (7), grpc (7), knative (7).
- **Engine**: Rego (OPA) queries, embedded in the binary, plus a `--queries-path` override for custom queries.
- **Commands**: `scan`, `analyze` (detects the platforms present in a project), `remediate` (auto-remediation), `generate-id`, `list-platforms`, `version`.
- **Report formats**: `all, asff, codeclimate, csv, cyclonedx, glsast, html, json, junit, pdf, sarif, sonarqube` (`--report-formats`).
- **Secrets scanning** with custom regex path; `--input-data` for query input data; `--max-resolver-depth`, `--max-file-size`, `--parallel` worker auto-detection.
- Sentry telemetry, `--exclude-results`, `--exclude-severities`, `--include-queries`.

### GitHub Actions coverage — what it does and does not do
**Core finding (verified by enumerating the repo's query assets, 2026-10-22): KICS has exactly FOUR CI/CD queries, all GitHub Actions, all pattern/regex checks. There is no advisory-feed resolution of `uses:` references.**

*Observed* — `assets/queries/cicd/github/` contains exactly 4 queries:
| Query | Severity | Category | What it does |
|---|---|---|---|
| `run_block_injection` | HIGH | Insecure Configurations | flags `run:` blocks matching an injection pattern |
| `script_block_injection` | (HIGH) | Insecure Configurations | flags `github.script` injection patterns |
| `unsecured_commands` | (MEDIUM) | Insecure Configurations | flags `ACTIONS_ALLOW_UNSECURE_COMMANDS` |
| `unpinned_actions_full_length_commit_sha` | LOW | **Supply-Chain** | flags `uses:` values not pinned to a 40-hex SHA |

*Observed* — the unpinned query's Rego (verbatim from the repo):
```rego
uses := input.document[i].jobs[j].steps[k].uses
not isAllowed(uses)   # exempts "actions/" (first-party)
not isPinned(uses)    # requires @[a-f0-9]{40}$
not isRelative(uses)  # exempts "./"
```
So KICS is stricter than Semgrep's mutable-tag rule in one way (any 40-hex SHA required) but **exempts all `actions/*` first-party actions**, and it only inspects `jobs.*.steps[].uses` — i.e. **it misses reusable workflows (`jobs.<id>.uses:` at job level) and `workflow_call` references**, which is exactly where an org-level action dependency inventory would be wrong if modelled on KICS.
*Not observed on the pages and assets checked, as of 2026-10-22*: any KICS query or code path that resolves `uses: owner/repo@ref` to a package, looks it up in a vulnerability database, checks a GHSA/OSV record, detects a compromised action, or reports an outdated action version. KICS has no vulnerability-database layer for actions; its only supply-chain check is the pinning regex.

*Consequence — the core question*: **KICS does not resolve GitHub Action references against advisory feeds.** Its GitHub Actions support is 4 rules, one of which is a pinning check.

### Output formats
*Observed* (`docs/results.md`, 2026-10-22): `--report-formats` accepts `all, asff, codeclimate, csv, cyclonedx, glsast, html, json, junit, pdf, sarif, sonarqube` (default `json`).
- **SARIF**: yes, SARIF v2.1.0, severity-sorted.
- **HTML**: yes — `html` and `pdf` are first-class report formats (best-in-class for this set alongside Trivy's template-based HTML).
- **CSV**: yes.
- Also: JSON, JUnit, CycloneDX, ASFF (AWS Security Hub), CodeClimate, GitLab SAST, SonarQube.

### CI integration and exit codes
*Observed*:
- Official `Checkmarx/kics-github-action` (docs note version pinning quirks: v1.2–v1.5 of the action ships KICS 1.5.15; v1.7.0 for KICS 1.7.x). Docs also show SARIF upload via `github/codeql-action/upload-sarif` → **GitHub code scanning**.
- Other integrations documented: Jenkins, GitLab CI, CircleCI, Bitbucket Pipelines, Azure Pipelines, TeamCity, Bamboo, Codefresh, Travis CI, AWS CodeBuild, Terraformer, pre-commit, VS Code.
- **Exit codes (verified in source, `internal/console/helpers/exit_handler.go` + `internal/constants/constants.go`, 2026-10-22)**:
  - `0` — no results (or results below the `--fail-on` threshold).
  - **Severity ladder**: `20` = INFO, `30` = LOW, `40` = MEDIUM, `50` = HIGH, `60` = CRITICAL — the *highest* severity present that is in the `--fail-on` set determines the code (default `--fail-on critical,high,medium,low,info`).
  - `126` — engine error (`constants.EngineErrorCode`).
  - `130` — interrupted by signal (`constants.SignalInterruptCode`).
  - `70` — remediation incomplete (`RemediateExitCode`).
  - `--ignore-on-exit none|all|results|errors` controls which non-zero codes are honoured.
  - *Inferred*: this is the most granular documented exit-code contract of the four — a severity ladder, similar in spirit to zizmor's, and directly comparable.

### Org-wide scan capability
*Observed*: **None in the OSS CLI.** `kics scan -p <paths>` scans local paths; the `analyze` subcommand only *detects which platforms* a project uses; there is no GitHub/org enumeration anywhere in the command set. `kics` has no `--repo-name`/`--owner` flag.
*Inferred*: org-wide coverage requires either the commercial Checkmarx platform or a caller-side loop. Combined with KICS' small install base (155 brew installs/30d), it is the least distribution-relevant of the four — but also the one whose **severity-ladder exit codes and HTML/PDF reports** are the most directly copyable.

## Pricing Summary
| Tier | Price | Notable Inclusions |
|------|-------|--------------------|
| KICS (OSS) | Free, Apache-2.0 | 2,400+ Rego queries, 16 platforms, JSON/SARIF/HTML/PDF/CSV/JUnit/CycloneDX/ASFF/SonarQube output, `kics remediate`, custom queries path |
| Checkmarx commercial (Astrix / One) | Not observable from the pages scraped | Enterprise platform around KICS; no price table retrieved |

## Key Takeaway
KICS is the smallest of the four by every distribution measure (2,724 stars, 155 brew installs/30d, last release 2026-09-17) and its GitHub Actions support is the thinnest too — four queries, of which exactly one concerns supply chain and it only checks for a 40-hex SHA on `steps[].uses` (exempting all `actions/*`, and missing job-level reusable-workflow `uses:`). Its genuine strengths are elsewhere and worth copying: the richest report-format set in the comparison (including HTML, PDF and CSV), a documented severity-ladder exit-code contract (20/30/40/50/60, 126, 130), and fully open, editable Rego queries.

## Competitive Implications for actionscan
**Where they're strong vs. us** | **Where we're strong vs. them** (hypothesis unless evidenced) | **Opportunities** | **Threats**
---|---|---|---|
| **Observed:** first-class HTML **and** PDF reports (we have HTML but not PDF), widest report-format set (ASFF, CodeClimate, SonarQube, CycloneDX, JUnit, GitLab SAST), severity-ladder exit codes, auto-remediation (`kics remediate`), "easy to integrate into CI" claim, Checkmarx enterprise backing, 2,400+ fully open queries. | **Observed:** 4 CI/CD queries only; the single supply-chain query misses job-level reusable-workflow `uses:` and exempts `actions/*`; **no advisory/compromised-action resolution**; **no org sweep**; smallest install base of the four; release cadence is the slowest (last release 2026-09-17, ~5 weeks stale). | Copy the report/exit-code contract: add **PDF**, keep HTML as a differentiator, and adopt a severity→exit-code ladder (20/30/40/50/60 style) so CI gating is self-documenting. Also worth copying the *idea* of shipping a machine-readable **inventory** (`kics list-platforms` is a tiny, useful affordance): our "list every action this org depends on" command is the Actions-native equivalent. | *Inferred:* KICS is the least threatening of the four — it lacks distribution, GitHub-Actions depth and an org story. The real risk is that Checkmarx uses KICS as a funnel to the commercial platform, which already knows how to do org-scale enforcement. |
| **Observed:** open Rego query model means a community can extend it. | **Observed:** KICS' pinning check is a strict superset of what we currently do *syntactically*, but it does nothing with the resolved version — we can do strictly more with the same `uses:` value. | Differentiate on **resolution depth**: KICS asks "is this a SHA?"; we answer "who is the publisher, is the version known-bad, is it compromised, is it outdated, what else depends on it". Use KICS' example of a *partial* check as a marketing contrast. | *Inferred:* minimal. The realistic threat is a Checkmarx platform feature rather than the OSS project. |

## Raw Data Sources
| Source | URL / path | Saved to |
|---|---|---|
| KICS homepage | https://kics.io/ | `raw/kics/2026-10-22/scrapes/kics_homepage.md` |
| KICS docs site root (JS-rendered, minimal text) | https://docs.kics.io/ | `raw/kics/2026-10-22/scrapes/kics_docs_homepage.md` |
| KICS README | https://raw.githubusercontent.com/Checkmarx/kics/master/README.md | `raw/kics/2026-10-22/scrapes/kics_readme.md` |
| Docs: CLI commands (report formats, `--fail-on`, `--ignore-on-exit`) | `docs/commands.md` | `raw/kics/2026-10-22/scrapes/kics_doc_commands.md` |
| Docs: Results / output formats | `docs/results.md` | `raw/kics/2026-10-22/scrapes/kics_doc_results.md` |
| Docs: GitHub Actions integration (SARIF → code scanning) | `docs/integrations_ghactions.md` | `raw/kics/2026-10-22/scrapes/kics_doc_integrations_ghactions.md` |
| Docs: platforms | `docs/platforms.md` | `raw/kics/2026-10-22/scrapes/kics_doc_platforms.md` |
| **Query assets (only 4 CI/CD queries)** | `assets/queries/cicd/github/*` metadata.json + query.rego | `raw/kics/2026-10-22/scrapes/kics_query_*.json`, `kics_query_*.rego` |
| Exit-code logic (source) | `internal/console/helpers/exit_handler.go`, `internal/constants/constants.go`, `internal/console/scan.go` | verified live at master |
| GitHub repo + releases API | `Checkmarx/kics` | `raw/kics/2026-10-22/seo/github-repo.json`, `github-releases.json` |
| Homebrew formula + analytics | https://formulae.brew.sh/api/formula/kics.json | `raw/kics/2026-10-22/seo/brew-kics.json` |
| Academic benchmark (KICS **not** included in the study) | arXiv 2601.14455v2 | `raw/semgrep/2026-10-22/scrapes/arxiv_2601.14455_v2.txt` |
