# Semgrep — Quick Profile

**URL**: https://semgrep.dev/
**Generated**: 2026-10-22

## At a Glance
| Metric | Value |
|--------|-------|
| Tagline | "Semgrep App Security Platform — AI-assisted SAST, SCA and Secrets Detection" (observed, page title) |
| Target audience | AppSec engineers + developers, moving from legacy AppSec (Checkmarx/Snyk) to a developer-first platform; large engineering orgs via AppSec Platform (inferred from homepage copy: banner "Ready to move off legacy AppSec? The New Shift Program helps you switch from Checkmarx or Snyk.") |
| Language / license | OCaml/Python core, OSS engine + rules / **LGPL-2.1-or-later** (repo license field LGPL-2.1; PyPI `license_expression: LGPL-2.1-or-later`). Rules in `semgrep/semgrep-rules` are under the **Semgrep Rules License v1.0**, not the repo license. |
| GitHub stars / forks | 17,180 / 1,116 (GitHub API, 2026-10-22). Rules repo `semgrep/semgrep-rules`: 1,279 stars (same date). |
| Releases (latest) | 100 fetched on first page of releases API (repo has 100+); latest v1.182.0, published 2026-10-20 (GitHub API). Note PyPI latest is 1.182.1. |
| Install / download volume | PyPI `semgrep`: **17,837,688/month** (pypistats `/recent`, last_month); **20,972,693** over the trailing 30 days without mirrors (computed from `/overall`); 927,787 last day; 5,313,263 last week; 207.6M total over 2026-04-08→2026-10-21 without mirrors. Homebrew: 6,664 installs/30d, 17,733/90d, 73,653/365d. **Correction to the briefed metric: the npm package `semgrep` (11,550/month) is NOT the Semgrep CLI** — it is an unrelated 0.0.1 package (`returntocorp/sgrep`, "a npm module for semgrep tool"). The honest number is the PyPI figure. |
| Pricing starts at | Free Edition $0 (Code + Supply Chain $0/month/contributor); Teams **from $30/month per contributor** (Code $30, Supply Chain $30, Secrets $15); Enterprise: custom / contact sales (observed, semgrep.dev/pricing, 2026-10-22) |
| Free tier/trial | Yes — "Free Edition": scan up to 10 repositories, max 10 contributors, 60 AI credits, cross-file analysis with Pro rules, GitHub/GitLab auth. The OSS CLI is fully free. |
| Domain rank | not available (no SEO data source) |
| Est. organic traffic | not available (no SEO data source) |
| Organic keywords (top 10) | not available (no SEO data source) |
| Referring domains | not available (no SEO data source) |

## Positioning
**Headline**: "Semgrep App Security Platform — AI-assisted SAST, SCA and Secrets Detection"
**Subheadline**: "Find and fix the issues that matter in your code (SAST) / Fix vulnerabilities in open source dependencies and block malware / Find and fix hardcoded secrets with semantic analysis" (observed, homepage product nav). Platform angle: "Automate, manage, and enforce security across your organization" (observed).
**Positioning angle**: *Observed* — Semgrep has repositioned from "fast static analysis CLI" to a **commercial AppSec Platform** (SAST + SCA + Secrets + Guardian + Multimodal) with a "New Shift Program" aimed at displacing Checkmarx and Snyk. The OSS engine/CLI remains the acquisition funnel. *Inferred* — it is now a vendor with a platform motion, not just a rules project; the OSS CLI is the top-of-funnel.

## Product & Features
### Core capabilities
*Observed (README + docs, 2026-10-22)*:
- **CLI is now subcommand-based**: `semgrep scan`, `semgrep ci`, `semgrep test`, `semgrep validate`, `semgrep login/logout`, `semgrep lsp`, `semgrep mcp`, `semgrep publish`, `semgrep show`, `semgrep install-semgrep-pro`.
- **30+ languages** (general), 20+ package ecosystems for SCA (npm, PyPI, Maven, Go, Cargo, …).
- **Registry**: 6,104 rules live at `semgrep.dev/api/registry/rules` (observed 2026-10-22), including first-party `p/` rulesets, `yaml/`, `trailofbits`, `mobsf`, `problem-based-packs`, etc.
- **AppSec Platform**: cross-file analysis, AI-powered detection/triage/remediation, SSO, private rules, deployment at scale, Semgrep Guardian (AI-generated-code scanning), Multimodal.
- **CI**: `semgrep ci` runs on a git diff; `semgrep` GitHub Action uploads SARIF to code scanning.
- `semgrep scan --oss-only` to force the OSS engine; `--pro` for the Pro Engine.

### GitHub Actions coverage — what it does and does not do
**Core finding (verified against the live registry ruleset, 2026-10-22): the `p/github-actions` ruleset contains 12 rules. All are pattern/taint rules over the workflow file. None resolves `uses:` to a package or consults an advisory feed.**

*Observed* — `https://semgrep.dev/c/p/github-actions` (12 rules, with severities):
| Severity | Rule | Focus |
|---|---|---|
| ERROR | `pull-request-target-code-checkout` | `pull_request_target` + checkout of PR head |
| ERROR | `run-shell-injection` | `${{ github.* }}` interpolation in `run:` |
| ERROR | `github-script-injection` | interpolation in `github.script` |
| ERROR | `gha-curl-pipe-shell` | `curl`/`wget` piped into a shell |
| ERROR | `secrets-inherit` | `secrets: inherit` |
| ERROR | `curl-eval` | `eval` of `curl` output |
| ERROR | `detect-shai-hulud-backdoor` | hard-coded signature of the Shai-Hulud backdoor action (`discussion.yaml` + `$SHELL` + `${{ github.event.issue.body }}` etc.) — a **static signature of one known incident**, not a live feed |
| WARNING | `github-actions-mutable-action-tag` | **pinning hygiene**: `uses:` with a mutable tag/branch rather than a 40-hex SHA (message explicitly cites the "trivy-action and kics-github-action compromises") |
| WARNING | `allowed-unsecure-commands` | `ACTIONS_ALLOW_UNSECURE_COMMANDS` |
| WARNING | `workflow-run-target-code-checkout` | `workflow_run` + checkout |
| WARNING | `unsafe-add-mask-workflow-command` | `add-mask` misuse |
| WARNING | `gha-workflow-env-secret` | secret in workflow-level `env:` |

*Observed*:
- The upstream rules repo `semgrep/semgrep-rules` has 14 GitHub-Actions YAML rule files under `yaml/github-actions/security/` (2 more than the published ruleset: `audit/third-party-action-not-pinned-to-commit-sha` and `semgrep-configuration/semgrep-github-action-push-without-branches`).
- The `github-actions-mutable-action-tag` rule only matches `uses:` values that are **not** a 40-hex SHA and not `./`-relative or `docker://` — i.e. it is a pinning check, not a vulnerability check. It does not ask "is this version vulnerable?" or "is this action compromised?".
- `detect-shai-hulud-backdoor` is a hand-written signature rule for one 2025 supply-chain incident.
- The old docs URL `semgrep.dev/docs/semgrep/semgrep-rules/rules-for-github-actions` now **404s** (redirects to docs.semgrep.dev and fails, observed 2026-10-22); the docs were restructured into a Mintlify site (`docs.semgrep.dev/llms.txt` lists 237 pages; there is no longer a "Rules for GitHub Actions" page).

*Consequence — the core question*: Semgrep **does not resolve GitHub Action references against an advisory feed**. Its registry has no package/advisory resolution for actions, and `semgrep scan` has no `--package`/OSV-style vulnerability mode for `uses:` values.

**The 2026 academic benchmark (verified):**
*Observed* — arXiv **2601.14455v2**, "Unpacking Security Scanners for GitHub Actions Workflows": 9 scanners, 2,722 real workflows from 388 repos (Microsoft, Google, NVIDIA orgs).
- **Correction to the brief**: the 9 scanners are actionlint, frizbee, ggshield, pinny, poutine, scharf, scorecard, **semgrep**, zizmor. **Trivy is explicitly excluded** ("We also exclude … Trivy that scans Container Images and the file system"), and **Checkov and KICS are not in the study at all**. So the paper says nothing directly about Trivy/Checkov/KICS.
- **Semgrep timing confirmed**: "semgrep stands apart as the slowest scanner in our setup. Its runtime forms a high and nearly flat band across the full dataset… its median elapsed time ranges from **26.13s to 39.19s**, far above the other scanners." The paper's framing is that the median per-workflow time is **2.71 s for 7 of 9 scanners**; the other fast ones are actionlint (<0.53 s), poutine (0.39 s), zizmor (0.26 s), scorecard (1.31 s), pinny (≤0.06 s), scharf (≤0.03 s), ggshield (~1 s).
- **Fewest findings confirmed**: the paper's findings table shows semgrep detecting only **255 injection findings across 128 workflows** and **15 privileged-trigger findings across 10 workflows**, with **0** for Artifact Integrity, Control Flow, Excessive Permissions, Guardrail, Hardcoded-secret, **Known-Vulnerable-Component**, Secrets Exposure and **Unpinned-Dependency** weaknesses. The paper's feature table credits Semgrep with only **3 rules** (it was run at commit `7d387d2`, 2025-06-08 — roughly a year before today, so the ruleset has since grown from ~3 to 12).
- The paper's recommendation tier for Semgrep is the optional "advanced" layer, explicitly noting the runtime overhead.

### Output formats
*Observed* (`semgrep scan --help`, docs.semgrep.dev CLI reference, 2026-10-22):
- **Text** (default, `--text` / `--text-output`)
- **JSON** (`--json`, `--json-output`)
- **SARIF** (`--sarif`, `--sarif-output`) — SARIF is the format used for GitHub code scanning
- **GitLab SAST** (`--gitlab-sast`) and **GitLab Secrets** (`--gitlab-secrets`)
- `--output FILE` to save/post results
- **No HTML report and no CSV output** in the current CLI.
- The AppSec Platform has a "JSON and SARIF" ingestion path (`docs.semgrep.dev/semgrep-appsec-platform/json-and-sarif`).

### CI integration and exit codes
*Observed*:
- `semgrep ci` (diff-based), `semgrep scan` (full), the official `semgrep` GitHub Action, and `semgrep scan --error` to fail on findings. Semgrep is the reference implementation for SARIF→GitHub code scanning.
- **Exit codes (documented in `semgrep scan --help` / `semgrep ci --help`, 2026-10-22)**:
  - `0` — OK (note: **findings alone do not change the exit code unless `--error` is passed**)
  - `1` — some findings (with `--error`)
  - `2` — fatal error
  - `3` — invalid target code
  - `4` — invalid pattern
  - `5` — unparseable YAML
  - `7` — missing configuration
  - `8` — invalid language
  - `13` — invalid API key
  - `99` — not implemented in osemgrep
  - *Inferred*: this is the richest documented exit-code contract of the four, and it distinguishes "tool error" (2) from "policy failure" (1) — a convention worth matching.

### Org-wide scan capability
*Observed*: **Not in the OSS CLI** — `semgrep scan` takes local paths; `semgrep ci` takes a diff. Org-wide is a **paid platform** feature: "Automate, manage, and enforce security across your organization", "Deployment at scale", "No limit on number of repositories scanned" (Enterprise), with the Free Edition capped at **10 repositories / 10 contributors**.
*Inferred*: Semgrep's org sweep is real but metered and priced per contributor — a structural opening for a free, unlimited, action-specific org sweep.

## Pricing Summary
| Tier | Price | Notable Inclusions |
|------|-------|--------------------|
| Semgrep Community Edition (OSS CLI) | Free | `semgrep scan`/`ci`, full OSS rule registry incl. `p/github-actions`, local scanning; LGPL-2.1-or-later |
| Free Edition (platform) | $0/month/contributor (Code + Supply Chain) | Up to 10 repositories, max 10 contributors, cross-file analysis with Pro rules, 60 AI credits, GitHub/GitLab auth |
| Teams | from $30/month/contributor (Code $30, Supply Chain $30, Secrets $15) | SSO, 20 AI credits/dev/month, one-click CI/CD deploy, support |
| Enterprise | Custom / contact sales | On-prem SCM support, custom CI/CD integrations, 50 AI credits/dev/month, dedicated infra, unlimited repos & contributors, dedicated AM |

## Key Takeaway
Semgrep has the largest measured download volume in this set (≈17.8–21M PyPI downloads/month — real distribution, not just stars), an enormous rule registry, and the best-documented exit-code contract and SARIF story of the four. Its GitHub Actions support is real but shallow — 12 registry rules, of which exactly one is about pinning and one is a hardcoded signature of a single 2025 incident. The 2026 academic benchmark confirms it is both the slowest (26–39 s/workflow) and the lowest-yield (255 injection findings) of the nine scanners studied; Trivy was excluded from that study and Checkov/KICS were never in it.

## Competitive Implications for actionscan
**Where they're strong vs. us** | **Where we're strong vs. them** (hypothesis unless evidenced) | **Opportunities** | **Threats**
---|---|---|---|
| **Observed:** ~17.8M PyPI downloads/month, 17.2k stars, 6,104-rule registry, category leadership ("Shift Program" displacing Checkmarx/Snyk), enterprise platform with org-wide enforcement, best-in-class exit-code docs, native SARIF/code-scanning path. | **Observed:** `p/github-actions` = 12 rules; only 1 pinning rule; **no advisory/compromised-action resolution**; **no org sweep without a paid plan** (10-repo cap on Free); **no HTML report**; **slowest** of 9 benchmarked scanners (26–39 s/workflow) and **fewest findings** in that study. | Position the **speed** contrast head-on: our org-wide sweep over N repos should be orders of magnitude faster than per-file Semgrep analysis. Own the **"semgrep finds 255 injections but 0 unpinned and 0 known-vulnerable components"** gap: our unit of analysis is the dependency graph of action *references*, which is precisely what Semgrep's pattern rules don't reach. Copy their exit-code contract (0/1/2/3/4/5/7/8/13) so CI integrators can swap tools without changing gate logic. | *Inferred:* Semgrep's platform already ingests SCA dependency data and has an AI-driven triage/remediation engine; adding "resolve action refs → advisory lookup" is a plausible roadmap item for a company already selling "Software Supply Chain" as a product pillar, and it would arrive with 17.8M monthly installs. |
| **Observed:** registry extensibility means a community rule ecosystem; our scope could be replicated by a single well-written Semgrep rule (as `github-actions-mutable-action-tag` shows). | **Observed:** Semgrep has no HTML output — but we ship HTML, so we can win "shareable org report" scenarios where a Semgrep user has to fall back to the platform dashboard. | Offer an HTML org dashboard + CSV inventory that Semgrep Free cannot produce at org scale, and make the inventory (every action + version + pin status + advisory status) the hero artifact. Consider shipping our findings in Semgrep's JSON schema for easy ingestion. | *Inferred:* Semgrep's rule-plus-AI model is the most likely to reach "resolve and look up actions" quickly via its AI-driven detection; if it lands, our differentiation narrows to speed, HTML/CSV output and the free/unlimited org sweep. |

## Raw Data Sources
| Source | URL / path | Saved to |
|---|---|---|
| Semgrep homepage | https://semgrep.dev/ | `raw/semgrep/2026-10-22/scrapes/semgrep_homepage.md` |
| Semgrep pricing | https://semgrep.dev/pricing | `raw/semgrep/2026-10-22/scrapes/semgrep_pricing.md` |
| CLI reference / exit statuses | https://semgrep.dev/docs/cli-usage | `raw/semgrep/2026-10-22/scrapes/semgrep_cli_usage.md` |
| `semgrep scan --help` (output + exit codes) | `docs/snippets/cli-reference/help-scan.mdx` | `raw/semgrep/2026-10-22/scrapes/semgrep_cli_help_scan.md` |
| `semgrep ci --help` | `docs/snippets/cli-reference/help-ci.mdx` | `raw/semgrep/2026-10-22/scrapes/semgrep_cli_help_ci.md` |
| `semgrep --help` (subcommands) | `docs/snippets/cli-reference/help-main.mdx` | `raw/semgrep/2026-10-22/scrapes/semgrep_cli_help_main.md` |
| Semgrep README | https://raw.githubusercontent.com/semgrep/semgrep/develop/README.md | `raw/semgrep/2026-10-22/scrapes/semgrep_readme.md` |
| **Live `p/github-actions` ruleset** | https://semgrep.dev/c/p/github-actions | `raw/semgrep/2026-10-22/scrapes/semgrep_p_github_actions_ruleset.yaml` |
| Semgrep registry dump (6,104 rules) | https://semgrep.dev/api/registry/rules | `raw/semgrep/2026-10-22/scrapes/semgrep_registry_p_github_actions.json` |
| Upstream GHA rules (14 files) + key rules | `semgrep/semgrep-rules@develop: yaml/github-actions/security/*` | `raw/semgrep/2026-10-22/scrapes/semgrep_rule_detect_shai_hulud.yaml`, `semgrep_rule_mutable_action_tag.yaml` |
| **Academic benchmark** | arXiv 2601.14455v2 "Unpacking Security Scanners for GitHub Actions Workflows" | `raw/semgrep/2026-10-22/scrapes/arxiv_2601.14455_v2.html` + `.txt`, `arxiv_2601.14455_abs.html` |
| Benchmark discovery note | The built-in `websearch` tool returned no results for every query in this session (verified with the trivial query "semgrep"). Discovery was done with DuckDuckGo's HTML endpoint fetched via `webfetch`; the paper was then read directly from arxiv.org. | — |
| Benchmark dataset repo | https://github.com/NeesimEra/ActionsBench | referenced from DDG results (not scraped) |
| GitHub repo + releases API | `semgrep/semgrep` | `raw/semgrep/2026-10-22/seo/github-repo.json`, `github-releases.json` |
| PyPI download stats | https://pypistats.org/api/packages/semgrep/recent + /overall | `raw/semgrep/2026-10-22/seo/pypistats-semgrep.json`, `pypistats-semgrep-overall.json` |
| npm package identity check (npm `semgrep` is unrelated) | https://registry.npmjs.org/semgrep | verified live (v0.0.1, `returntocorp/sgrep`) |
| Homebrew formula + analytics | https://formulae.brew.sh/api/formula/semgrep.json | `raw/semgrep/2026-10-22/seo/brew-semgrep.json` |
