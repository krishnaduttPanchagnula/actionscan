# poutine — Quick Profile

**URL**: https://boostsecurityio.github.io/poutine/ (docs site; source at https://github.com/boostsecurityio/poutine)
**Generated**: 2026-10-22

## At a Glance

| Metric | Value |
|--------|-------|
| Tagline | "poutine, a supply chain vulnerability scanner for build pipelines" (GitHub repo description); CLI `--help` long string: "A Supply Chain Vulnerability Scanner for Build Pipelines" |
| Target audience | (inferred from copy) AppSec / DevSecOps engineers and platform teams auditing CI/CD pipelines at repo and org scope; secondary audience = AI coding agents via MCP |
| Language / license | Go + Rego (Open Policy Agent) / Apache-2.0 |
| GitHub stars / forks | 528 / 43 |
| Releases (latest) | 30 releases; latest `v1.1.6` (2026-05-22) |
| Last commit | 2026-10-21 (default branch HEAD) |
| Pricing starts at | OSS (Apache-2.0). Parent vendor BoostSecurity.io is commercial, but **no public pricing page** — `https://boostsecurity.io/pricing` returned **404** on 2026-10-22 |
| Free tier/trial | n/a — CLI is free and unlimited. Commercial product is "Contact"-gated ("Get Started" / "For clients / Login" nav on boostsecurity.io) |
| Domain rank | not available (no SEO data source in this environment) |
| Est. organic traffic | not available (no SEO data source in this environment) |
| Organic keywords (top 10) | not available (no SEO data source in this environment) |
| Referring domains | not available (no SEO data source in this environment) |

Additional observed metrics: 20 open issues, 21 contributors, 30 releases with a median gap of ~2 months (largest gap 126 days, 2025-06-02 → 2025-10-06). Latest release is 153 days old as of 2026-10-22. Languages by bytes: Go 428,906 / Open Policy Agent 67,648.

## Positioning

**Headline**: The docs site homepage carries no marketing headline — it reads "poutine" with the body "This is the documentation for the `poutine` project." (Observed, https://boostsecurityio.github.io/poutine/, 2026-10-22). The effective headline is the GitHub repo description: **"poutine, a supply chain vulnerability scanner for build pipelines"** and the CLI's own long help: **"A Supply Chain Vulnerability Scanner for Build Pipelines"** (Observed, `cmd/root.go`).

**Subheadline**: "Created by BoostSecurity.io, `poutine` is a security scanner that detects misconfigurations and vulnerabilities in the build pipelines of a repository. It supports parsing CI workflows from GitHub Actions and Gitlab CI/CD. When given an access token with read-level access, `poutine` can analyze all the repositories of an organization to quickly gain insights into the security posture of the organization's software supply chain." (Observed, README, exact quote)

**Positioning angle**: *Supply-chain security for the CI pipeline itself* — not for the application. The unit of analysis is the workflow file and the third-party actions it references, and the unit of deployment is the repository or the whole GitHub organization. Rules are written in Rego, so the extension story is "write your own rule," and the AI-agent story is "we ship an MCP server."

**Positioning angle (Inferred)**: poutine is positioned as the *workflow misconfiguration linter* in the `zizmor`/`actionlint` family, but with two moves that neither of them makes: (1) it ships an org-wide sweep as a first-class subcommand, and (2) it is a Rego engine, so the "custom rule" story is genuinely open-ended rather than a hardcoded list.

## Product & Features

### Subcommands (Observed, `cmd/*.go`)

| Command | Purpose |
|---|---|
| `analyze_local <path>` | Scan a local repo checkout |
| `analyze_repo <org/repo>` | Scan a remote GitHub/GitLab repo (`--token`) |
| `analyze_org <org>` | Scan **all repos in an org** |
| `analyze_repo_stale_branches` | Find `pull_request_target` workflows in *stale* (non-default) branches; flags deleted-branch exposure |
| `analyze_manifest` | Scan a single YAML manifest passed as content (used by the MCP tool) |
| `mcp-server` | Model Context Protocol server (stdio JSON-RPC) |
| `version`, `completion` | Standard |

### `analyze_org` — the org-sweep axis (Observed, `cmd/analyzeOrg.go`, `analyze/analyze.go`)

- **UX**: `poutine analyze_org org --token "$GH_TOKEN"`. One positional arg (org/group). Self-hosted GitLab supported via `--scm gitlab --scm-base-url https://gitlab.example.com`.
- **Flags**: `--token/-t` (env `GH_TOKEN`), `--threads/-j` (default **2**), `--ignore-forks/-i`, `--exclude-repo/-e` (repeatable; added 2026-10-09, PR #462).
- **Auth model**: a read-level SCM token (GitHub PAT / GitLab token). No OAuth flow, no keyring, no service account. Token is read from `--token` or `GH_TOKEN`.
- **Mechanics**: lists org repos via the SCM API, then **full `git clone`s each repository** (token-embedded URL) and scans the working tree. Concurrency is a weighted semaphore of `--threads` (default 2). Repos are skipped if excluded, forked (when `--ignore-forks`), or empty (`GetSize() == 0`). **Archived repositories are skipped** (stated in the command's own long help: "This command will scan all repositories in the organization except those that are Archived.").
- **Progress**: a progress-bar observer (`analyze.NewProgressBarObserver`) reports discovery → per-repo start/complete/error → finalize; `--quiet` disables it.
- **Output**: one aggregated result set across all scanned repos. `pretty` prints a per-rule summary table (rule id, title, count, status) and per-finding detail blocks (rule title, severity, description, a docs deep link `https://boostsecurityio.github.io/poutine/rules/<rule_id>`, and a GitHub line-link). `json` emits `{findings, rules}` with structured `meta`. `sarif` emits SARIF 2.1.0 with level→confidence mapping.

### Rego rules — 13 built-in (Observed, `opa/rego/rules/`, `docs/content/en/rules/`)

Confirmed present:
- `github_action_from_unverified_creator_used` — "Github Action from Unverified Creator used". Flags actions whose owner is not in a **verified-creator allowlist** (regenerated via `make update-verified-creators` from the Marketplace publisher list; ~380 orgs embedded in the rule). Level: `note`.
- `unpinnable_action` — **"Unpinnable CI component used"** (title is broader than the rule id). Flags a composite/docker action whose *transitive* dependencies are unpinned or themselves unpinnable. Level: `note`. Docs include recommended/anti-pattern YAML for composite actions, remote docker images, and Dockerfile-based actions.
- `pr_runs_on_self_hosted` — "Pull Request Runs on Self-Hosted GitHub Actions Runner". Level: `warning`. **Configurable** via `rulesConfig.pr_runs_on_self_hosted.allowed_runners` (runner name, label, or group).

Full rule list (Observed, docs site nav + `opa/rego/rules/`):
`confused_deputy_auto_merge`, `debug_enabled`, `default_permissions_on_risky_events`, `github_action_from_unverified_creator_used`, `if_always_true`, `injection`, `job_all_secrets`, `known_vulnerability_in_build_component`, `known_vulnerability_in_build_platform`, `pr_runs_on_self_hosted`, `unpinnable_action`, `untrusted_checkout_exec`, `unverified_script_exec`.

### ⚠️ Correction to a common assumption — poutine DOES ship advisory data, but it is static, not live

Two advisory databases are **embedded in the repo** as Rego data (Observed):

| File | Size | Contents |
|---|---|---|
| `opa/rego/external/osv.rego` | 19 advisories | GHSA/OSV advisories **for GitHub Action packages** (`hashicorp/vault-action`, `atlassian/gajira-create`, `check-spelling/check-spelling`, …), each with `vulnerable_version_ranges`, CVSS vector, CWE IDs |
| `opa/rego/external/build_platform.rego` | 705 advisories | **43** for `github` (GitHub Enterprise Server CVEs) + **662** for `gitlab` (GitLab CI CVEs) |

- `known_vulnerability_in_build_component` matches a workflow `uses:` ref against the 19-entry OSV table. **Matching requires a semver tag** (`regex.match("^[0-9]+(\\.[0-9]+)*?$", version)`) — so a SHA-pinned or tagless `uses:` is **not** matched.
- `known_vulnerability_in_build_platform` matches `input.provider` + `input.version`, i.e. the **CI platform product version** (GitHub Enterprise Server, GitLab CI), not the actions used inside it.
- The build_platform DB is regenerated by `make update-vulndb` (a `.claude/skills/update-vulndb/SKILL.md` documents it) from the CVE Project's `cvelistV5` repo. The OSV table has no equivalent update script observed.
- **Net**: poutine's advisory coverage is a **19-entry curated snapshot for actions** plus a **705-entry product-CVE snapshot for the CI platforms**. Neither is a live feed, and there is no evidence of a background refresh. The action-level table is ~2 orders of magnitude smaller than the live feeds actionscan uses.

### Threat-intel / reputation data (Observed)

`providers/pkgsupply/` contains exactly one implementation: `static.go`, which loads an **embedded list `unpinnable_actions.txt` — 6,123 purls** of actions known to be unpinnable. The client makes **no network calls** (no `net/http` in the package). So poutine's "reputation" source is a committed file, not a feed.

### Multi-CI support (Observed)

`models/` + `scanner/parsers.go` contain parsers for: **GitHub Actions** (`github_actions.go`), **GitLab CI** (`gitlab.go`), **Azure DevOps** (`azure_pipelines.go`), **Tekton / Pipelines-as-Code** (`pipeline_as_code_tekton.go`). README's "Supported Platforms" list matches exactly.

### Output formats & SARIF upload (Observed)

- `--format` accepts `pretty` (default), `json`, `sarif`. The formatter registry in `cmd/root.go` also has a `noop` format (used by the MCP server).
- **Poutine does NOT upload SARIF to GitHub code scanning.** No code-scanning API call exists in the CLI source. The README's GitHub Actions example requires the user to run `github/codeql-action/upload-sarif` as a separate step.
- **No HTML report.** Formatters are exactly `json`, `noop`, `pretty`, `sarif` (`formatters/`). No HTML formatter exists in the tree.
- **Exit codes** (`cmd/root.go`): `0` success, `1` error, `2` interrupt, **`10`** violations found — but only when `--fail-on-violation` is passed. Without the flag, findings do **not** fail the build.

### Config: `.poutine.yml` (Observed, `.poutine.sample.yml`)

Discovery order: `.poutine.yml` in the working dir → `.github/poutine.yml` → explicit `--config` (which wins). Viper-backed, so `.yaml`/`.json`/`.toml` extensions work.

```yaml
include:            # custom Rego rule directories
  - path: ./custom_rules
ignoreForks: true   # org sweep skips forks
disableVersionCheck: true
rulesConfig:        # per-rule config
  pr_runs_on_self_hosted:
    allowed_runners: [self-hosted, label:gpu, group:prdeploy]
skip:               # find acknowledgment filters
  - rule: unpinnable_action
    path: [.github/workflows/pr.yml]
    level: note
    job: build
    purl: [pkg:githubactions/dorny/paths-filter]
    osv_id: [GHSA-mcph-m25j-8j63]
allowedRules:       # allowlist — only these rules run
  - pr_runs_on_self_hosted
```

**All six `skip:` keys confirmed**: `rule`, `path`, `job`, `level`, `purl`, `osv_id`. Each accepts a string or list of strings. Note the CLI `--skip` flag is **rule-name-only** — the granular filters are config-file-only (README states this explicitly).

### Custom Rego rules (Observed, README "Custom Rules")

Rules live in `*.rego` files under an `include:` directory, follow `package rules.<rule_name>`, define `rule := poutine.rule(rego.metadata.chain())`, and a `results` set built with `poutine.finding(rule, pkg.purl, {...})`. METADATA comments carry `title`, `description`, and `level` (`note`/`warning`/`error`). External example repo: `boost-rnd/poutine-rules`.

### MCP server (Observed, `MCP_INTEGRATION.md`, `cmd/mcp_server.go`)

`poutine mcp-server` exposes five tools: `analyze_org` (org, scm_provider, scm_base_url, threads, ignore_forks), `analyze_repo` (repo, ref), `analyze_local` (path), `analyze_repo_stale_branches` (repo, threads, expand, regex), `analyze_manifest` (content, manifest_type ∈ github-actions | gitlab-ci | azure-pipelines | tekton). Picks up `GH_TOKEN` from the environment. Documented setup for Claude Code (`claude mcp add poutine poutine mcp-server`) and Gemini CLI.

### Other observed details

- **Telemetry**: a once-per-day release-version check sends current version, an anonymous instance id persisted in `~/.poutine/config.yaml`, and an invocation counter. No source/repo/finding data. Disable via `--disable-version-check`, `POUTINE_DISABLE_VERSION_CHECK=1`, or `disableVersionCheck: true`. (Observed, README + `versioncheck/`.)
- **Install paths**: Homebrew (`brew install poutine`), Docker (`ghcr.io/boostsecurityio/poutine`), pre-commit hook (`.pre-commit-hooks.yaml`).
- **Badges**: OpenSSF Best Practices, OpenSSF Scorecard, SLSA Level 3, CodeQL, Go Report Card. (Observed, README.)
- **Agent-native repo**: the repo ships its own `.claude/skills/{docs,quality,snapshot,update-vulndb}` — Claude Code skill definitions for maintaining the project. (Observed, repo tree.)
- **Demo corpus**: the `messypoutine` GitHub org is a public playground of real-world vulnerable workflows. (Observed, README.)

## Pricing Summary

| Tier | Price | Notable Inclusions |
|---|---|---|
| poutine CLI | Free / OSS (Apache-2.0) | All 13 rules, org sweep, SARIF/JSON/pretty output, MCP server, custom Rego rules, local + GitHub + GitLab support |
| BoostSecurity platform (vendor) | Not published — `boostsecurity.io/pricing` → 404 on 2026-10-22 | Commercial DevSecOps platform: Developer Endpoint Protection, Software Supply Chain Security (incl. "Pipeline Integrity" — verifying CI/CD machinery), AI-Native ASPM. "Get Started" / "For clients → Login" |

## Key Takeaway

poutine is the closest thing to actionscan's org-sweep axis in the ecosystem: `analyze_org` with a read token really does clone and scan every non-archived repo in a GitHub org, and its `--skip`/`rulesConfig`/`allowedRules` config model is more expressive than actionscan's likely baseline. But its intelligence is **entirely static** — a 19-entry curated OSV table for actions, a 705-entry CVE table for the CI *platforms* themselves, and a 6,123-line embedded unpinnable-actions list — so it cannot answer "is this action version currently compromised or outdated," and it produces no HTML report and does not upload SARIF itself.

---

## Competitive Implications for actionscan

**Where they're strong vs. us** *(Observed)*

1. **Org sweep already exists.** `analyze_org` with `--threads`/`--ignore-forks`/`--exclude-repo` is a shipped, documented feature, not a roadmap item. actionscan cannot claim org-wide scanning as a novel capability.
2. **Multi-CI breadth.** GitHub Actions + GitLab + Azure DevOps + Tekton in one binary with one rule set.
3. **Rego extensibility.** Users can author their own rules; the "custom rule" story is a whole ecosystem (`boost-rnd/poutine-rules`).
4. **MCP server shipped.** First-class agent integration, documented for Claude Code and Gemini CLI.
5. **Enterprise surface.** Backed by a funded vendor (BoostSecurity, $12M seed + $4M raise) with a commercial platform that includes "Pipeline Integrity" — i.e. they can already sell an org-wide CI security control beyond the free CLI.
6. **Brand & policy hygiene.** OpenSSF Best Practices, OpenSSF Scorecard, SLSA L3, CodeQL, SBOM, signed releases.

**Where we're strong vs. them** *(Observed for poutine; the "we" side is Inferred)*

1. **Live threat intel.** poutine's action-level advisory table is 19 static entries, matched only against semver tags — SHA-pinned and tagless `uses:` refs are not evaluated at all. Live GHSA/OSV feeds + a compromised-actions feed is a categorical gap.
2. **Outdated-release detection.** poutine has no notion of "this action is 3 majors behind." actionlint explicitly delegates this to Dependabot; poutine does not raise it at all.
3. **Pinning hygiene as a first-class axis.** poutine's `unpinnable_action` is a note-level, narrow rule about transitive deps of composite actions. actionscan's pinning-hygiene sweep (unpinned refs, tag-not-SHA, floating major tags) across the whole org is broader.
4. **HTML dashboard + CSV + JSON + SARIF.** poutine has three machine formats and no dashboard; actionscan's HTML report is a different consumption path (exec/security-review audiences, not just CI logs).
5. **No clone tax.** poutine's org sweep full-clones every repo. An actionscan that extracts `uses:` refs via the API would be materially cheaper and faster over a large org — a real, checkable differentiator.

**Opportunities** *(Implication — questions for actionscan)*

- Can actionscan offer the org sweep *without* a per-repo clone, and quantify the cost difference (time, API calls, bandwidth) against `poutine analyze_org`? A published benchmark would be a strong wedge.
- Can actionscan's `skip:` / allowlist model match poutine's six-key `skip` (rule/path/job/level/purl/osv_id) plus `allowedRules` and `rulesConfig` on day one? If not, poutine's config is the bar.
- Should actionscan ship an MCP server? poutine already does; being absent there is a visible gap for AI-assisted security workflows.
- Can actionscan offer a Rego-compatible or custom-rule extension point? Rego is a high bar to match; a simpler declarative rule DSL may be enough.

**Threats** *(Implication)*

- If BoostSecurity ships a live-feed commercial version of poutine's action advisory data behind a free tier, the "no live feed" gap closes fast — their 705-entry build_platform pipeline shows they already do offline DB curation well.
- Their multi-CI + MCP + vendor distribution combination is hard to match on breadth; actionscan may need to win decisively on the *live-intel org sweep* axis rather than try to match breadth.
- `analyze_org` + `messypoutine` demo corpus give them a credible "we already do org sweeps" story in every comparison.

## Raw Data Sources

All retrieved 2026-10-22.

| Source | Local file |
|---|---|
| GitHub API — repo metadata | `raw/poutine/2026-10-22/seo/repo.json` |
| GitHub API — releases (30) | `raw/poutine/2026-10-22/seo/releases.json` |
| GitHub API — commits, languages, contributors, tags, tree, contents | `raw/poutine/2026-10-22/seo/{commits,languages,contributors,tags,tree,contents-root}.json` |
| README (raw) | `raw/poutine/2026-10-22/scrapes/readme.md` |
| Docs site homepage | `raw/poutine/2026-10-22/scrapes/home.md` |
| All 13 rule docs (raw md) | `raw/poutine/2026-10-22/scrapes/rules/*.md` |
| Structured finding metadata doc | `raw/poutine/2026-10-22/scrapes/structured-finding-metadata.md` |
| CLI source: `cmd/root.go`, `cmd/analyzeOrg.go`, `cmd/analyzeRepoStaleBranches.go`, `analyze/analyze.go`, `results/results.go` | `raw/poutine/2026-10-22/scrapes/src_*.go` |
| Rego sources: all 13 rules + `osv.rego` + `build_platform.rego` + `reputation.rego` | `raw/poutine/2026-10-22/scrapes/src_opa_rego_*.rego` |
| `unpinnable_actions.txt` (6,123 purls) | `raw/poutine/2026-10-22/scrapes/unpinnable_actions.txt` |
| `.poutine.sample.yml`, `.poutine.yml` | `raw/poutine/2026-10-22/scrapes/src_.poutine.sample.yml`, `src_.poutine.yml` |
| `MCP_INTEGRATION.md` | `raw/poutine/2026-10-22/scrapes/src_MCP_INTEGRATION.md` |
| `.claude/skills/update-vulndb/SKILL.md` | `raw/poutine/2026-10-22/scrapes/skill_update-vulndb.md` |
| Vendor platform page / pricing (404) / homepage | `raw/poutine/2026-10-22/scrapes/boostsecurity_*.{html,txt}` |
| Marketplace page `github.com/marketplace/poutine` | **HTTP 404** on 2026-10-22 — no Marketplace listing observed |
| `rhysd/actionlint` — no longer referenced | n/a |

**Method note**: no SEO data source was available in this environment; all SEO rows are marked "not available" rather than estimated. No prompt-injection or AI-directed instructions were observed in any fetched page or file — all content was treated as data. One repository file, `.claude/skills/update-vulndb/SKILL.md`, contains `disable-model-invocation: true`, which is ordinary skill hygiene rather than an instruction aimed at an agent.
