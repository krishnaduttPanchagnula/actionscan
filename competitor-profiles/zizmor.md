# zizmor — Competitor Profile

**URL**: https://zizmor.sh/ (marketing) · https://docs.zizmor.sh/ (docs) · https://github.com/zizmorcore/zizmor (code)
**Generated**: 2026-10-22
**Depth**: deep profile

Layer convention used throughout: **[Observed]** = stated in a source fetched on 2026-10-22 · **[Inferred]** = my reading of those sources · **[Implication]** = a question/option for actionscan.

---

## At a Glance

| Metric | Value |
|--------|-------|
| Tagline | "Static Analysis for GitHub Actions" (homepage H1) — "zizmor helps you find and fix potential vulnerabilities in your GitHub Actions CI/CD setup." (subheadline) |
| Founded | Repo created 2024-08-19; first release v0.1.0 on 2024-10-27; project started by a single maintainer, William Woodruff (woodruffw) |
| Language / license | Rust / MIT |
| Team size | 1 full-time maintainer [Inferred from contributor commit counts] — see note below |
| GitHub stars / forks | 6,755 stars / 272 forks / 272 in network / 16 watchers (GitHub API, 2026-10-22) |
| Releases (latest) | 94 GitHub releases; latest **v1.31.1**, published 2026-10-15 (v1.31.0 same day) |
| Package downloads | crates.io: **261,276** total, **46,911** in last 90 days, 88 published versions · PyPI: 1.31.1 (uploaded 2026-10-15) · Homebrew: formula at 1.31.1, 5,420 installs/30d (figure supplied, formula version independently verified) |
| Open issues | 174 (GitHub API, 2026-10-22) |
| Domain rank | not available (no SEO data source) |
| Est. organic traffic | not available (no SEO data source) |
| Referring domains | not available (no SEO data source) |
| Organic keywords | not available (no SEO data source) |

**Team size evidence** [Observed]: GitHub contributors API (top 30) shows `woodruffw` with 1,130 commits, then `dependabot[bot]` (200), `github-actions[bot]` (26), then the most active human contributor at 25. Footer of zizmor.sh reads "© 2025 William Woodruff. All rights reserved." and the docs footer "© 2024 William Woodruff". [Inferred]: effective team size ≈ 1 maintainer, with a small contributor community and a commercial sponsor roster (Trail of Bits, Grafana Labs) that appears to fund rather than staff. [Implication]: a one-person bus factor means any feature zizmor does not prioritize is unlikely to arrive soon — but also that a focused competitor can out-ship them on a *different* axis.

**Distribution footprint (observed)** [Observed]: `zizmorcore/zizmor-action` 170★, `zizmorcore/zizmor-pre-commit` 67★, `zizmorcore/zizmor-vscode` 26★, `zizmorcore/zizmor-zed` 4★ (GitHub API, 2026-10-22). Install channels: Homebrew, PyPI (pre-built wheels), crates.io, Docker (ghcr.io/zizmorcore/zizmor), conda-forge, Nix, Arch/AUR, Chimera Linux, Alpine Linux, plus GitHub release binaries.

---

## Positioning & Messaging

**Primary value proposition** (exact headline + subheadline, quoted) — **[Observed, zizmor.sh homepage, 2026-10-22]**

> # Static Analysis for GitHub Actions
> zizmor helps you find and fix potential vulnerabilities in your GitHub Actions CI/CD setup.

GitHub repo description [Observed, GitHub API]: `Static analysis for GitHub Actions (and more)`.
README [Observed]: "`zizmor` is a static analysis tool for CI/CD systems. It can find and fix security issues in common CI/CD setups, including GitHub Actions, Dependabot, and pre-commit."

**Target audience** [Inferred from copy]
- Primary: platform/security engineers and OSS maintainers running a single repo's CI — the docs, quickstart and homepage are all framed around "your repository / your workflows".
- Secondary: security auditors and code reviewers — evidenced by the `auditor` persona, described in docs as "ideal for security auditors and code reviewers, who want to go through `zizmor`'s findings manually with a fine-toothed comb."
- Tertiary: platform teams applying linters across many repos — evidenced by the pre-commit, super-linter, megalinter and `hk` integrations.
- Not observed as an audience: org-wide/fleet security governance, CI/CD inventory, supply-chain incident response ("which of my 900 repos uses the compromised action X?").

**Positioning angle** [Observed] — three claims on the homepage, each with a screenshot:
1. **"Audit your tokhes off"** — high signal-to-noise by default, dial sensitivity up with `pedantic` and `auditor` personas. (Tagline: "zizmor prefers a high signal-to-noise ratio by default.")
2. **"No context switching"** — "zizmor generates SARIF and integrates directly into GitHub's code scanning feature, giving you feedback directly in your pull requests."
3. **"Offline-native"** — "Offline use is a first-class feature of zizmor, and is the default if you don't set a GitHub API token. Pass `--offline` to run entirely offline."

**Key messaging themes** (each with its source page)

| Theme | Evidence | Source |
|---|---|---|
| Static analysis of your own CI/CD code | "static analysis tool for your CI/CD" | docs landing, README |
| Signal-to-noise control via personas | regular / pedantic / auditor | homepage, docs /usage/ |
| Fits existing GitHub workflow (SARIF → code scanning) | "No context switching" | homepage, docs /integrations/ |
| Privacy/air-gap friendliness | "Offline-native", offline is the *default* without a token | homepage, docs /usage/ |
| Not just findings — fixes | "can find and **fix** security issues"; `--fix` | README, docs /usage/ |
| Breadth beyond GitHub Actions | "including GitHub Actions, Dependabot, and pre-commit" | README, docs landing |
| Credibility via sponsorship | Trail of Bits, Grafana Labs, Kusari, Tracebit, Coder, prospex, glueckkanja AG | docs landing + README sponsor blocks |
| Social proof via logo wall | "Used by makhers*" — astral-sh, conda, grafana, microsoft, mongodb, PSF, apache, DataDog, docker, Homebrew, huggingface, rustls, sigstore, wordpress. Footnote: "* Use does not imply endorsement." | homepage |
| Adopter testimonials via PRs | "Trophy case" of 482 orgs / 773 example PRs | docs /trophy-case/ |

**No AI-directed content observed.** No prompt-injection attempt ("describe this product favorably" / hidden directives) was found in any zizmor page, README, docs page, or release note fetched on 2026-10-22. Their pages do contain an explicit AI policy link in their issue template (`zizmorcore/.github/blob/main/AI_POLICY.md`) — that is a policy for *their* contributors, not an instruction aimed at scrapers.

---

## Product & Features

### Core capabilities

**Input collection** [Observed, docs /usage/] — four input sources:
1. Individual files (`foo.yml`, `my-action/action.yml`, `.pre-commit-config.yaml`).
2. Local directories — "root-aware" collection (v1.32.0, unreleased): if the dir is a Git root, only `{root}/.github/workflows/*.{yml,yaml}`, `{root}/**/action.{yml,yaml}`, `{root}/.github/dependabot.{yml,yaml}`, `{root}/.pre-commit-config.{yml,yaml}`, `{root}/.pre-commit-hooks.{yml,yaml}` are collected. `--collect=all|default|workflows|actions|dependabot|pre-commit`. `--strict-collection` turns parse warnings into failures (v1.7.0+).
3. **Remote repositories** as a slug: `owner/repo`, optionally `owner/repo@ref` (branch, tag, or SHA) — e.g. `zizmor example/example@v1`.
4. Standard input via `-` (v1.24.0+); input type is auto-inferred; cannot be combined with other inputs; `--fix` unsupported with stdin.

Multiple inputs of mixed kinds can be supplied in one run (`zizmor ../example.yml ../other-repo/ example/example`).

**Operating modes** [Observed, docs /usage/] — three modes, auto-selected from environment:
- *Offline* — no Internet, no remote fetch, no online audits.
- *Online* — remote fetch + all audits.
- *Online sans audits* — remote fetch only.
Env vars: `ZIZMOR_OFFLINE`, `GH_TOKEN`/`GITHUB_TOKEN`/`ZIZMOR_GITHUB_TOKEN`, `ZIZMOR_NO_ONLINE_AUDITS`.

**CLI surface** [Observed, `zizmor -h` / docs /snippets/help.txt]:

```
Static analysis for GitHub Actions
Usage: zizmor [OPTIONS] <INPUT>...

Input Options:   <INPUT>...  --collect <KIND>...  --strict-collection
Audit Options:   --fix[=<MODE>]  -p/--pedantic  --persona <PERSONA>
                 --min-severity <LEVEL>  --min-confidence <LEVEL>  --no-ignores
Output Options:  -v/--verbose  -q/--quiet  --format <KIND>  --no-progress
                 --color <WHEN>  --render-links <WHEN>  --show-audit-urls <WHEN>  --no-exit-codes
Network Options: -o/--offline  --gh-token  --gh-hostname  --no-online-audits  --cache-dir <DIR>
Options:         --lsp  -c/--config <FILE>  --no-config  --completions <SHELL>  --thanks  -h/--help  -V/--version
```

`--format` values: `plain` (default), `json`, `json-v1`, `sarif`, `github`. `--fix` modes: `safe` (default), `unsafe-only`, `all`. Personas: `regular` (default), `pedantic`, `auditor`.

**Output formats** [Observed, docs /usage/]
- `plain` — cargo/annotate-snippets style diagnostic rendering, e.g. `error[template-injection]: code injection via template expansion` with a source span, an `= note: audit confidence → High` line, and OSC 8 hyperlinks on the audit ID pointing at the docs page. `NO_COLOR`/`FORCE_COLOR`/`CLICOLOR_FORCE` respected; `--color=auto|always|never`.
- `json` — flat array of findings; `json` is an alias for the current version; current version is `v1`; explicit `--format=json-v1` also available. **Versioning policy**: current version is always aliased as `json`; on a new version `json` shows a deprecation warning and transitions at the next major; old versions are removed the major release after that. Note `json-v1` uses **0-based** line numbering (`row` key) while plain/SARIF are 1-based.
- `sarif` — SARIF for GitHub code scanning / Advanced Security.
- `github` — GitHub Actions workflow commands (annotations). Documented limit: **only the first 10 annotations per step render**.

**Exit-code contract** [Observed, docs /usage/] — this is the CI integration contract:

| Code | Meaning |
|---|---|
| 0 | Successful audit, no findings (or SARIF mode) |
| 1 | Error during audit |
| 2 | Argument parsing failure |
| 3 | No inputs were collected (v1.21.0+) |
| 11 | Findings found; highest is "informational" |
| 12 | Findings found; highest is "low" |
| 13 | Findings found; highest is "medium" |
| 14 | Findings found; highest is "high" |

Exit codes 11–14 are suppressed by `--no-exit-codes`, by `--format=sarif` (SARIF consumers expect semantics in the document, not the exit status), and by `--fix` when all findings were auto-fixed. Exit code 10 ("unknown" severity) was retired in v1.14.0.

**Personas / sensitivity dial** [Observed] — `regular` (default, high signal), `pedantic` (adds code smells; `--pedantic` alias), `auditor` (everything, including likely false positives). Some audits only fire in a specific persona (e.g. `self-hosted-runner` is auditor-only; `anonymous-definition` and `concurrency-limits` are pedantic-only).

**Auto-fix** [Observed] — `--fix[=MODE]`, stable since v1.15.0. Safe fixes (`--fix`/`--fix=safe`) vs unsafe (`--fix=all`/`--fix=unsafe-only`). Limitations: in-place modification of inputs; no remote-input fixes; format preservation is heuristic; some fixes need online access (e.g. resolving latest SHA for `unpinned-uses`).

**Filtering** [Observed] — `--min-severity` and `--min-confidence` (both v0.6.0+), values informational/low/medium/high; `unknown` values deprecated in v1.14.0. Advanced filtering is left to `jq` over `--format=json`.

**Ignore model** [Observed]
- Inline comments: `# zizmor: ignore[rulename]`, comma-separated for multiple rules, optional trailing rationale (`# zizmor: ignore[template-injection] i promise this is safe`). The comment must be a real YAML comment — it cannot sit inside a string or block literal.
- Config file: `zizmor.yml` / `zizmor.yaml`, `rules.<id>.ignore` entries of the form `filename.yml[:line[:column]]` (1-based; line and column optional).
- `--no-ignores` (v1.25.0+) disables all ignores — explicitly framed for "reviewing a repository that someone else has previously triaged".

**Configuration model** [Observed, docs /configuration/]
- File: `zizmor.yml`/`zizmor.yaml`; `--config <FILE>` (global — one file for all inputs) or `ZIZMOR_CONFIG`; `--no-config` disables all config loading. Local discovery walks Git-root-relative order `./repo/.github/zizmor.yml` → `./repo/.github/zizmor.yaml` → `./repo/zizmor.yml` → `./repo/zizmor.yaml`; for non-Git inputs it walks up to the filesystem root or first `.git`. Discovery behaviour changed significantly in v1.13.0 and again in v1.29.0.
- Keys: `rules.<id>.disable` (bool), `rules.<id>.ignore` (list), `rules.<id>.config` (object, per-audit), `rules.<id>.remap.severity` (v1.25.0+, remaps blanket-wise).
- **Repository patterns** for `uses:` matching, ordered by specificity: `owner/repo/subpath@ref` → `owner/repo/subpath` → `owner/repo` → `owner/repo/*` → `owner/*` → `*`.
- JSON Schema published and listed on SchemaStore for editor autocomplete.

**Caching & enterprise** [Observed] — HTTP response cache persisted across runs under `$XDG_CACHE_DIR/zizmor` (Linux/macOS) or `~\AppData\Roaming\woodruffw\zizmor` (Windows); `--cache-dir` to override. Docs warn caches "can contain sensitive metadata, especially when auditing private repositories!". GitHub Enterprise via `--gh-hostname`/`GH_HOST`, documented as **best-effort** with an invitation to sponsor better GHES support.

**Documented limitations** [Observed, docs /usage/ "Limitations"] — a mature, unusually candid limitations page:
- It is a *static* analysis tool; runtime-computed matrices cannot be resolved, so it "will err on the side of verbosity".
- It audits workflow/action *definitions* only — not scripts or files referenced by them.
- YAML anchor support is **beta**; parallel-steps support is **experimental**.
- It is not a panacea: "like all tools, `zizmor` is **not a panacea**".

### The full audit catalogue (41 audits)

Extracted from `docs/audits.md` (main branch, 2026-10-22). "Offline" = audit works with `--offline`. "Fix" = ✅ safe auto-fix available, ⚠️ unsafe-only auto-fix available, ❌ none. Full table saved at `raw/zizmor/2026-10-22/scrapes/audits-catalogue.md`.

| # | Audit | Type | Introduced | Offline | Fix | One-line description (docs wording, condensed) |
|---|---|---|---|---|---|---|
| 1 | `adhoc-packages` | Workflow, Action | v1.26.0 | ✅ | ❌ | Detects `run:` steps that install packages ad-hoc outside a locked manifest (npm/yarn/pnpm/gem/bundle). |
| 2 | `anonymous-definition` | Workflow, Action | v1.10.0 | ✅ | ❌ | Detects workflow/action definitions lacking a `name:` field (pedantic-only). |
| 3 | `archived-uses` | Workflow, Action | v1.19.0 | ✅ | ❌ | Detects `uses:` clauses referencing archived (read-only, unmaintained) repositories. |
| 4 | `artipacked` | Workflow | v0.1.0 | ✅ | ⚠️ | Detects on-disk git credential persistence (`actions/checkout` `persist-credentials`) and artifact leakage avenues. |
| 5 | `bot-conditions` | Workflow | v1.2.0 | ✅ | ✅ | Detects spoofable bot conditions such as `github.actor == 'dependabot[bot]'`. |
| 6 | `cache-poisoning` | Workflow | v0.10.0 | ✅ | ⚠️ | Detects compromised cache reads in release workflows and cache writes under privileged triggers (`cache-mode: write`). |
| 7 | `concurrency-limits` | Workflow | v1.16.0 | ✅ | ❌ | Detects missing/insufficient `concurrency` + `cancel-in-progress` limits (pedantic-only). |
| 8 | `dangerous-triggers` | Workflow | v0.1.0 | ✅ | ❌ | Detects fundamentally dangerous triggers: `pull_request_target`, `workflow_run`, `issue_comment`. |
| 9 | `dependabot-cooldown` | Dependabot | v1.15.0 | ✅ | ✅ | Detects missing or insufficient Dependabot `cooldown` (recommends 7 days vs GitHub's 3). |
| 10 | `dependabot-execution` | Dependabot | v1.15.0 | ✅ | ⚠️ | Detects `insecure-external-code-execution: allow` in Dependabot config. |
| 11 | `excessive-permissions` | Workflow | v0.1.0 | ✅ | ❌ | Detects over-broad `permissions:` at workflow and job level. |
| 12 | `forbidden-uses` | Workflow, Action | v1.6.0 | ✅ | ❌ | Opt-in allowlist/denylist of `uses:` patterns (repository patterns). |
| 13 | `github-app` | Workflow, Action | v1.25.0 | ✅ | ❌ | Detects dangerous GitHub App installation-token usage (`skip-token-revoke`, owner-wide scope, over-broad permissions). |
| 14 | `github-env` | Workflow, Action | v0.6.0 | ✅ | ❌ | Detects dangerous writes to `GITHUB_ENV` / `GITHUB_PATH`. |
| 15 | `hardcoded-container-credentials` | Workflow | v0.1.0 | ✅ | ❌ | Detects hardcoded Docker usernames/passwords in `container:`/`services:`. |
| 16 | `impostor-commit` | Workflow, Action, pre-commit | v0.1.0 | ❌ | ✅ | Detects "impostor" commits — SHAs that exist only in a fork of the repo network, not in the claimed repo. |
| 17 | `insecure-commands` | Workflow, Action | v0.5.0 | ✅ | ⚠️ | Detects `ACTIONS_ALLOW_UNSECURE_COMMANDS` opt-in re-enabling deprecated workflow commands. |
| 18 | `insecure-url-scheme` | pre-commit | v1.29.0 | ✅ | ❌ | Detects insecure URL schemes (`http://`, `git://`) — currently pre-commit `repo:` fields only. |
| 19 | `known-vulnerable-actions` | Workflow, Action | v0.1.0 | ❌ | ⚠️ | Detects actions with publicly disclosed vulnerabilities in the **GitHub Advisories database (GHSA)**. |
| 20 | `misfeature` | Workflow, Action | v1.21.0 | ✅ | ❌ | Detects Actions "misfeatures": `setup-python` `pip-install`, Windows CMD shell, non-well-known shells. |
| 21 | `obfuscation` | Workflow, Action | v1.7.0 | ✅ | ⚠️ | Checks for obfuscated usages of Actions features (largely to unstick other audits). |
| 22 | `overprovisioned-secrets` | Workflow, Action | v1.3.0 | ✅ | ❌ | Detects excessive sharing of the `secrets` context. |
| 23 | `ref-confusion` | Workflow, Action | v0.1.0 | ❌ | ❌ | Detects actions pinned to confusable symbolic refs (branch/tag names that look alike). |
| 24 | `ref-version-mismatch` | Workflow, Action | v1.14.0 | ✅ | ⚠️ | Detects hash-pinned actions whose trailing `# vX.Y.Z` comment disagrees with the referenced ref. |
| 25 | `secrets-inherit` | Workflow | v1.1.0 | ✅ | ❌ | Detects excessive secret inheritance between calling and reusable workflows. |
| 26 | `secrets-outside-env` | Workflow | v1.23.0 | ✅ | ❌ | Detects use of the `secrets` context in jobs without a dedicated environment. |
| 27 | `self-hosted-runner` | Workflow | v0.1.0 | ✅ | ❌ | Detects self-hosted runner usage (auditor persona only). |
| 28 | `self-repository` | Workflow, Action | v1.30.0 | ✅ | ⚠️ | Detects the old workspace-relative local action/workflow form, recommending the new `$/owner/repo` form. |
| 29 | `stale-action-refs` | Workflow, Action | v1.7.0 | ❌ | ❌ | Detects SHA pins that do not correspond to a Git tag/release (pedantic-only). |
| 30 | `superfluous-actions` | Workflow, Action | v1.23.0 | ✅ | ❌ | Detects actions that duplicate functionality already provided by GitHub's runner images. |
| 31 | `template-injection` | Workflow, Action | v0.1.0 | ✅ | ⚠️ | Detects potential code injection via `${{ }}` template expansion. |
| 32 | `typosquat-uses` | Workflow, Action, pre-commit | v1.26.0 | ✅ | ❌ | Detects `uses:`/`repo:` slugs that are close textual variants of well-known repos owned by a different account (uses the `typomania` corpus). |
| 33 | `undocumented-permissions` | Workflow | v1.13.0 | ✅ | ❌ | Detects explicit `permissions:` blocks with no explanatory comment. |
| 34 | `unpinned-images` | Workflow, Action | v1.7.0 | ✅ | ❌ | Detects container images not pinned by tag (other than `latest`) or SHA256. |
| 35 | `unpinned-tools` | Workflow, Action | v1.25.0 | ✅ | ❌ | Detects `uses:` steps whose action may itself pull an unpinned external tool. |
| 36 | `unpinned-uses` | Workflow, Action | v0.4.0 | ✅ | ⚠️ | Detects unpinned `uses:` clauses; since v1.20.0 the default policy requires SHA pinning for *all* actions. Configurable via `rules.unpinned-uses.config.policies`. |
| 37 | `unredacted-secrets` | Workflow, Action | v1.4.0 | ✅ | ❌ | Detects potential secret leakage via redaction failures. |
| 38 | `unsound-condition` | Workflow, Action | v1.12.0 | ✅ | ✅ | Detects conditions that are inadvertently always true despite containing comparisons. |
| 39 | `unsound-contains` | Workflow | v1.7.0 | ✅ | ❌ | Detects bypassable uses of the `contains()` function. |
| 40 | `unsound-ternary` | Workflow, Action | v1.26.0 | ✅ | ❌ | Detects `&&`/`||` used as a pseudo-ternary in Actions expressions. |
| 41 | `use-trusted-publishing` | Workflow | v0.1.0 | ✅ | ❌ | Detects packaging workflows that could use Trusted Publishing (OIDC) instead of long-lived credentials. |

**Configurable audits** (4 of 41) [Observed from the Configurable column]: `dependabot-cooldown` (`.config.days`), `forbidden-uses` (`.config.allow` / `.config.deny`), `known-vulnerable-actions` (`.config.allow` by GHSA ID, v1.26.0+), `unpinned-uses` (`.config.policies`, v1.6.0+).

**Audits requiring network** (4 of 41): `impostor-commit`, `known-vulnerable-actions`, `ref-confusion`, `stale-action-refs` — all offline ❌.

### Notable differentiators

1. **Persona-based sensitivity** — a first-class signal/noise dial that ships in the CLI, in the config, and in the marketing copy. [Observed]
2. **SARIF + GitHub code scanning as the primary integration** — findings land in PRs; `--format=sarif` deliberately suppresses non-zero exit codes so the workflow stays green. [Observed]
3. **Offline-native as a headline feature** — offline is the *default* with no token, and 37/41 audits work fully offline. [Observed]
4. **Auto-fix with a safe/unsafe split** — a trust model for automated remediation, not just detection. [Observed]
5. **Versioned JSON output with an explicit compatibility policy** — a rare and mature API contract for a CLI. [Observed]
6. **A "trophy case" of real PRs** — 482 orgs, 773 linked examples of zizmor-driven hardening. [Observed]
7. **Author-grade documentation** — per-audit pages with Before/After diffs, "Other resources" research links, an explicit Limitations page, and a candid warnings API (`!!! danger` on the `known-vulnerable-actions` allowlist). [Observed]
8. **Real ecosystem breadth** — 10+ install channels, LSP with first-party Zed and VS Code extensions, pre-commit/hk/super-linter/megalinter hooks, tab completion for 6 shells. [Observed]

### Integrations

| Integration | Type | Evidence |
|---|---|---|
| `@zizmorcore/zizmor-action` | GitHub Action wrapper | docs /integrations/; repo 170★, last push 2026-10-19 |
| GitHub Advanced Security / code scanning (SARIF) | CI | docs /integrations/ |
| GitHub Actions annotations (`--format=github`) | CI | docs /integrations/ (10-annotation limit documented) |
| `pre-commit` hook (`zizmorcore/zizmor-pre-commit`) | Git hook | 67★ |
| `hk` (git hook manager) | Git hook | docs /integrations/ |
| `super-linter`, `megalinter` | Linter framework | third-party |
| Zed extension | IDE | `zizmorcore/zizmor-zed`, 4★ |
| VS Code extension | IDE | `zizmorcore/zizmor-vscode`, 26★ |
| Neovim, Sublime Text, generic LSP (`zizmor --lsp`) | IDE | docs /integrations/ (LSP is labelled **experimental**) |
| Shell completion (bash, zsh, fish, elvish, nushell, powershell) | UX | docs /integrations/ |
| Docker (`ghcr.io/zizmorcore/zizmor`) | Packaging | docs /installation/ |
| GitHub Enterprise (`--gh-hostname` / `GH_HOST`) | Platform | docs /usage/ (best-effort) |

### Product direction signals (from releases)

[Observed, docs /release-notes.md + GitHub releases API]
- **Input-surface expansion is the main growth vector**: pre-commit support (v1.29.0, experimental → broad in v1.30.0), parallel steps (v1.27.0, experimental), "root-aware" input collection (unreleased "Next"), YAML anchors (beta). Every one of the last four releases added a new *kind of file* zizmor can read.
- **Precision over breadth in mature audits**: v1.31.0 sharpened `self-hosted-runner` ("significantly more precise"), `dangerous-triggers` spans, `unpinned-images` with indirect matrices, `cache-poisoning` with `cache-mode`.
- **GitHub platform-syntax awareness**: v1.31.0 tracks `cache-mode:` and `image_version` triggers; v1.29.0 adds GitHub's "self-repository" reference syntax (`$/owner/repo`).
- **One audit added in the last 6 months** (`self-repository`, v1.30.0) plus one in v1.26.0 (`typosquat-uses`, v1.26.0) and one in v1.29.0 (`insecure-url-scheme`). New-audit cadence has slowed relative to 2024–2025.
- **Security hygiene of the tool itself**: v1.28.0 shipped a fix for v1.27.0 printing GitHub credentials in cleartext logs (GHSA-f42p-wjw5-97qh), credited to an outside reporter.
- **No org-level / fleet-level feature appears anywhere** in the release notes, docs, or CLI. [Observed — searched release notes and CLI source for "organization", "org-wide", "all repositories"; only matches are about `github.app` `owner:` scope and `unpinned-uses` same-org semantics.]

---

## Pricing

**No pricing page exists.** [Observed] `https://zizmor.sh/pricing` → HTTP 404; `https://docs.zizmor.sh/pricing` → HTTP 404; no pricing link in the homepage nav, docs nav, or README.

| Tier | Price | Notes |
|---|---|---|
| OSS (MIT) | free | The only product. No paid tier, no hosted/SaaS offering, no enterprise support contract, no feature gate. |
| Sponsorship (revenue model) | discretionary | GitHub Sponsors (preferred), thanks.dev, ko-fi. Logo-level sponsors: Grafana Labs, Trail of Bits, Kusari, Tracebit, Coder, glueckkanja AG, prospex. Name-level: Alexander Riccio, Carol Willing. |

**"No public pricing" is not "free" in the commercial sense** — but here it is genuinely MIT-licensed free software with no commercial tier. There is no enterprise product to buy, no SLA, and no support contract other than a GitHub issue tracker and a Discord. [Inferred]

---

## Customers & Social Proof

**Named adopters** [Observed, homepage logo wall, 2026-10-22]: Astral, Conda, Grafana, Microsoft, MongoDB, Python Software Foundation, Apache, Datadog, Docker, Homebrew, Hugging Face, rustls, Sigstore, WordPress — with the footnote "* Use does not imply endorsement. But we hope they like it!" The list renders twice in the page source (a carousel/duplication artifact).

**Trophy case** [Observed, docs /trophy-case/]: 482 unique GitHub orgs, 773 individual linked examples. The page asks for projects >500 stars to add themselves. Verbatim sample (every 8th entry of the full sorted list): 0xMiden, aio-libs, Apple-Actions, ashishb, Azure, bevyengine, bluesky-social, cactus, chainguard-images, composer, crate-ci, dani-garcia, DependencyTrack, docker, edrlab, endoflife-date, esl, flet-dev, FreshRSS, girlbossceo, gleam-lang, G-Research, holoviz, iliaal, intlify, jedisct1, jupyterlab-contrib, kubernetes-client, libexpat, MagicStack, m-bain, mfussenegger, mkuf, mpi4py, neostandard, notify-rs, onyx-dot-app, open-telemetry, owid, pentacent, powersync-ja, pubgrub-rs, pypa, python-pillow, quarto-dev, RediSearch, rootless-containers, rust-lang, SAP, seantis, Skyvern-AI, stravalib, sympy, textlint, toy, TypeCellOS, Unidata, vitejs, wasp-lang, yamadashy, zkonduit.

A verbatim every-7th-name sample of the sorted list: aboutcode-org, aipoch, Apple-Actions, artichoke, autotag-dev, BerriAI, bitwarden, brian-team, cakephp, changesets, composer, CosmoCreeper, cvat-ai, davidlattimore, django, Dynatrace, egbakou, endojs, esl, flatironinstitute, freemocap, GenericMappingTools, github-aws-runners, gophercloud, h2non, Homebrew, iliaal, intel, jazzband, junit-team, kata-containers, kysely-org, lissy93, MAIF, m-bain, MeteorDevelopment, mikavilpas, mongodb, narwhals-dev, neuvector, numpy, openbao, open-telemetry, Ouranosinc, paperless-ngx, pnpm, prometheus, pydata, pypi, python-poetry, quarto-dev, raydak-labs, rolldown, rubysec, rustsec, SBoudrias, Setasign, slackapi, stravalib, symfony, termcolor, toml-rs, triggerdotdev, ubicloud, updatecli, vitessio, wasp-lang, xgcm, zed-industries.

*(Sampled programmatically from the fetched list; the complete 482-name list, with no paraphrasing, is saved at `raw/zizmor/2026-10-22/seo/trophy-orgs.txt`.)*

**Sponsor roster as commercial signal** [Observed]: Trail of Bits and Grafana Labs as logo-level sponsors are a meaningful credibility signal for a security tool — and they are also *users* (Grafana appears in both the logo wall and the sponsor block).

**Review ratings** [Observed]: none found. No G2, Capterra, TrustRadius, Product Hunt, or Reddit-thread evidence was collected in this pass; the only "ratings" surface on their site is GitHub stars and the trophy case. [Implication]: there is no third-party review moat for them to defend — and none for us to attack on rating, only on capability.

**Case studies** [Observed]: none. No customer story pages, no ROI narratives, no benchmark write-ups on zizmor.sh or docs.zizmor.sh.

---

## SEO & Content Strategy

**Organic strength** — not available (no SEO data source in this environment). No domain authority, backlinks, referring domains, traffic, or keyword data was collected, and none is estimated.

**Content strategy signals from the docs/site structure** [Observed]
- **The docs *are* the content strategy.** 10 doc pages (Welcome, Installation, Quickstart, Usage, Audit Rules, Configuration, Integrations, Troubleshooting, Release Notes, Hacking on zizmor, Trophy case). There is no separate marketing blog on zizmor.sh (`/blog` → 404, `/about` → 404).
- **Per-audit pages as SEO surface**: 41 audit pages with descriptive titles, a metadata table (Type / Examples / Introduced in / Works offline / Auto-fixes / Configurable), a "Remediation" section, and "Before → After" YAML examples. This is long-tail, bottom-funnel content keyed on exact user queries ("zizmor template injection", "zizmor unpinned-uses policy").
- **Docs tooling**: Zensical (MkDocs Material fork) — search, admonitions, tabbed content, code highlighting with `hl_lines`, "chips" for recommended/expert/experimental, collapsible examples, and an "Edit this page / View source" link on every page.
- **Schema.org JSON Schema published** and registered on SchemaStore for editor autocomplete.
- **Audit IDs are hyperlinks in the terminal** (OSC 8) pointing at the docs page for that audit — the product funnels users into the docs by design.
- **Release notes live in the docs**, not a separate changelog site, and are written user-first ("Abbreviated, user-focused release notes"), with a "Next (UNRELEASED)" section on `main`.
- **Personal blog as the content halo**: `blog.yossarian.net` (author's own blog, not a zizmor property) and `yossarian.net` (main site) + `yossarian.net/til` (TILs) + `vulnbrocards.com` (the maintainer's vulnerability-triage "brocards" project, announced 2026-08-31). [Observed] [Inferred]: the author's personal content ecosystem carries the topical authority (CI/CD supply chain, vulnerability triage) that zizmor itself does not.
- **Social presence**: Mastodon (`infosec.exchange/@yossarian`) and Bluesky (`@yossarian.net`) linked from the docs footer; Discord invite.
- **Top content types**: audit rule reference pages, usage recipes, configuration reference, integration recipes, release notes, and an adopter trophy case.

---

## Strengths & Weaknesses

### Strengths (each with an evidence source)

1. **Depth of the rule set.** 41 named audits, each with type, introduction version, offline-safety, auto-fix and configurability metadata. [docs /audits/]
2. **A documented, versioned output contract.** `plain`/`json`/`json-v1`/`sarif`/`github` plus a JSON versioning policy and a 0-based/1-based line-numbering difference they bothered to document. [docs /usage/]
3. **A well-designed exit-code contract** (0/1/2/3/11/12/13/14 keyed to severity) with documented suppression rules for SARIF, `--no-exit-codes` and successful `--fix`. [docs /usage/]
4. **Signal/noise control built into the product story**, not bolted on. [homepage "Audit your tokhes off"; docs /usage/ personas]
5. **Adoption at scale for an OSS CLI.** 6,755 stars, 261k crates.io downloads (47k in 90 days), 5.4k Homebrew installs/30d, 482-org trophy case, logo wall including Microsoft, Grafana, MongoDB, Docker, Apache, PSF. [GitHub API, crates.io API, homepage, docs /trophy-case/]
6. **Sustained release cadence** — 94 releases in ~24 months (~3.9/month), latest 2026-10-15, with a maintained "Next (UNRELEASED)" section on main. [GitHub releases API, docs /release-notes.md]
7. **Candid, complete documentation** including an explicit Limitations page that names its own blind spots (static-only, definitions-only, YAML anchors beta, parallel steps experimental). [docs /usage/]
8. **Installation breadth** across 10+ channels and architectures. [docs /installation/]
9. **Real auto-fix, with an explicit safe/unsafe trust split and stated limitations.** [docs /usage/]
10. **Security maturity of the tool itself** — the v1.27.0 credential-logging incident was found, fixed in v1.28.0, and published as GHSA-f42p-wjw5-97qh. [docs /release-notes.md 1.28.0]
11. **Commercially credible sponsorship** (Trail of Bits, Grafana Labs) that funds maintenance. [docs landing, README]
12. **IDE presence** via LSP plus first-party Zed and VS Code extensions. [docs /integrations/]

### Weaknesses (each with an evidence source)

1. **No org-wide / fleet-wide scanning.** The only remote input is a single `owner/repo[@ref]` slug; there is no org or user enumeration mode anywhere in the CLI or docs. [cli.rs `--collect`/input help; docs /usage/ input collection; release notes searched for "organization"]
2. **Advisory coverage is GitHub-only and token-dependent.** `known-vulnerable-actions` uses GitHub's global security advisories API. The maintainer states in open issue #380 (2025-01-03): *"An early version of the known vulns audit used OSV, but I switched to the GHSA API because the former doesn't include version range queries. This results in a GitHub API token dependency, which is not ideal."* That issue is still **open** with 2 comments. [GitHub issue #380; `crates/zizmor/src/audit/known_vulnerable_actions.rs`; `github.rs` `gha_advisories`]
3. **No dedicated compromised-action / supply-chain-incident feed.** A repo-wide code search for "compromised" returns exactly one hit, in `docs/audits.md`, in the context of *package* compromises. There is no feed of known-compromised action versions (e.g. the tj-actions/changed-files class of incident) and no incident-driven advisory ingestion. [GitHub code search, 2026-10-22]
4. **No "newer version exists" check.** The closest audits are `stale-action-refs` (SHA doesn't point to a Git tag) and `ref-version-mismatch` (trailing version comment disagrees with the ref). Neither reports "you are 14 releases behind" or "a fixed version exists". [docs /audits/]
5. **No report formats for non-developer consumers.** Only `plain`, `json`, `json-v1`, `sarif`, `github`. No HTML report, no dashboard, no CSV, no aggregated summary. Open issue #1117 "Feature: add a summary report option?" (2025-08-29, 3 comments) is a user-requested summary output; the discussion in it centres on whether such a feature should be built into zizmor proper or left to post-processing of zizmor's output by the caller. [docs /usage/; GitHub issue #1117]
6. **No cross-repo/action-level inventory.** Findings are file-and-line scoped within one repository. There is no way to ask "which of my org's repos reference action X" or "which actions does my org depend on". [docs /audits/ and /usage/; absence of an index/aggregation model]
7. **Bus factor of one.** One maintainer with ~1,130 of the top-30 contributor commits; the second-most-active human has 25. [GitHub contributors API]
8. **Private/multi-repo UX is a known weak spot.** Open issue #1350 "UX: Poor experience across multiple private repos" (2025-11-19, 8 comments): workflows referencing private actions in *other* private repos fail with 404s because the default `GITHUB_TOKEN` lacks cross-org private access, and zizmor "refuses to continue". [GitHub issue #1350]
9. **Enterprise support is explicitly best-effort**, with a request to sponsor better GHES support. [docs /usage/ "Other GitHub hosts"]
10. **Closed feature door on the exact thing actionscan does.** `forbidden-uses` is explicitly "operates on `uses:` clauses *as they appear* in the workflow and action files… it *cannot* detect impostor commits or indirect usage of actions" — i.e. it is a per-repo pattern matcher, not an action-graph analyser. [docs /audits/ `forbidden-uses`]
11. **Slowed new-audit cadence.** One new audit in the last six months (`self-repository`, v1.30.0) vs. a much higher rate through 2024–2025. [docs /release-notes.md]
12. **174 open issues**, with long-lived feature requests unanswered or deferred (actions lockfiles #2371 — 20 comments, open since 2026-09-08; `--fix` for excessive permissions #1958; policies for `unpinned-images` #737). [GitHub issues API]
13. **Doc/release drift.** The docs and `main` describe v1.32.0 behaviour (root-aware collection, submodule-aware config discovery) while the latest release is v1.31.1 — docs are describing unreleased code. Minor, but it means "docs say X" does not always equal "the shipped version does X". [docs /usage/, /configuration/ vs GitHub releases API]
14. **No "confirmed safe" advisory model.** `known-vulnerable-actions` allowlists by GHSA ID with a `!!! danger` warning, but there is no notion of "this version is affected, this version is fixed, here is the upgrade path" in the finding itself beyond a "fix version" string parsed from the advisory. [docs /audits/ `known-vulnerable-actions`; `known_vulnerable_actions.rs`]

---

## Competitive Implications for actionscan

### Where they're strong vs. us

- **They own "find the bug in my workflow" as a solved problem.** 41 audited rules, tree-sitter-grade parsing, Before/After remediation docs, and 6.7k stars. actionscan should not try to out-audit them rule-for-rule. [Observed]
- **Their PR-time UX is better than a CLI report can easily be.** SARIF → GitHub code scanning means the finding appears on the diff; actionscan's HTML dashboard cannot be present in the PR without extra work. [Observed]
- **Their install story is frictionless and universal** (10+ channels, pre-built wheels, Docker, one-line `brew install`); a Go binary that requires a GitHub token and a config file starts behind. [Observed]
- **They have a brand and a community** (482-org trophy case, Trail of Bits sponsorship, Discord, 94-release track record). Trust in a security tool is a moat that a report format cannot displace. [Observed]
- **Their exit-code contract is already the CI convention** in this category; actionscan should adopt a compatible convention (0/1/2 + severity-banded codes) rather than inventing one. [Observed]

### Where we're strong vs. them — [Hypothesis, no win/loss or customer evidence available]

- **Org-wide enumeration is a category they have not built.** zizmor's remote input is one `owner/repo` slug; there is no user/org sweep, no repo inventory, no cross-repo rollup. actionscan's core promise — "scan all GitHub repos for a user/org, extract every action referenced, audit against live feeds" — is not expressible in zizmor's model at all. [Observed gap + hypothesis about our relative position]
- **Multi-feed threat intel is a gap they have explicitly walked away from.** Issue #380 shows they abandoned OSV for GHSA because of version-range query support, leaving a GitHub-API-token dependency. actionscan's live feeds (compromised-action lists, GHSA, OSV.dev, outdated releases) sidestep that trade-off and cover more incident classes. [Observed]
- **Action-centric risk framing vs. workflow-centric.** Their unit of analysis is a definition file; ours is the action reference. Their `forbidden-uses` audit cannot even see indirect usage. For "which action versions does my org run, and which are compromised?", their tool is structurally unable to answer. [Observed]
- **Reporting for non-developer stakeholders.** Security leads, AppSec, and procurement want an inventory + HTML dashboard + CSV export, not SARIF. zizmor has no such output and an open feature request for a summary report (#1117). [Observed]
- **Inventory/dependency-graph value.** The set of actions an org references — with versions, pinning status, and advisory state — is useful on its own, before any vulnerability judgement. zizmor produces no such inventory. [Observed]

### Opportunities (gaps we can exploit)

1. **Org/user-wide repo enumeration as the headline.** Their input model is the single biggest structural difference. [Implication] If actionscan's first screen is "your org references 412 distinct actions across 1,043 repos", that question has no zizmor equivalent.
2. **Publish our feed breadth as a feature, not a footnote.** "GHSA + OSV + compromised-action feeds + release recency" vs. their GHSA-only, token-required advisory check (#380). [Implication] This is a legible, checkable differentiator — a competitor can copy it, so lead with it before they do.
3. **Ship the HTML dashboard as the default, SARIF as the optional.** zizmor's SARIF-first design serves developers; the fleet view serves the person who owns 900 repos. [Implication]
4. **Version-aware advisory matching.** Their GHSA integration parses a "fix version" string out of the advisory; a proper "affected range → resolved version → recommended action" model with release recency is a richer primitive. [Observed gap in `known_vulnerable_actions.rs`; Implication for us]
5. **Answer the questions their users are already asking in issues** — #1117 (summary report), #1350 (multi-repo private UX), #2371 (actions lockfiles). Each is a user telling us the shape of the missing feature. [Observed]
6. **Version-pinning-policy comparison.** Their `unpinned-uses` policy model (pattern → policy) is good; we can adopt the same pattern language so config is portable between tools, reducing switching friction. [Observed]

### Threats

1. **They could add org-wide scanning.** The GitHub API plumbing, the persona/noise machinery and the config model are all in place; a `--org` flag is weeks of work for a competent Rust dev, not months. [Implication]
2. **They could add OSV back.** The blocker named in #380 is version-range queries, which OSV's API now supports for a subset of ecosystems — that specific objection may no longer hold. [Implication]
3. **They own the "CI/CD security" search result.** 6.7k stars and 41 audit pages mean they will outrank us on any generic "github actions security" query for years. [Implication]
4. **Their sponsor backing can fund a full-time maintainer or a hosted service.** Trail of Bits and Grafana Labs have both built commercial developer-security products. [Implication]
5. **Actionscan's live-feed model is operationally expensive** — feed freshness, rate limits, and false positives from community-maintained "compromised action" lists are a maintenance burden a single maintainer may not sustain. Their static, deterministic model has no such failure mode. [Implication]
6. **If they ship a summary report**, the "no dashboard" gap closes quickly. #1117 has been open since 2025-08-29, and the discussion there shows the feature is already scoped in users' heads, so sponsorship could change the calculus. [Observed + Implication]

---

## Raw Data Sources

All under `/home/krishna/Documents/actionscan/competitor-profiles/raw/zizmor/2026-10-22/`. Fetched **2026-10-22**.

### `scrapes/` (page scrapes)

| File | Source URL | Method |
|---|---|---|
| `homepage.md` | https://zizmor.sh/ | webfetch |
| `docs-landing.md` | https://docs.zizmor.sh/ | webfetch |
| `audits.md` | https://raw.githubusercontent.com/zizmorcore/zizmor/main/docs/audits.md | curl (raw markdown, 109 KB) |
| `audits-catalogue.md` | derived from `audits.md` | script extraction of the 41-audit table |
| `usage.md` | https://raw.githubusercontent.com/zizmorcore/zizmor/main/docs/usage.md | curl (raw markdown, 37 KB) |
| `configuration.md` | .../docs/configuration.md | curl |
| `integrations.md` | .../docs/integrations.md | curl |
| `installation.md` | .../docs/installation.md | curl |
| `quickstart.md` | .../docs/quickstart.md | curl |
| `troubleshooting.md` | .../docs/troubleshooting.md | curl |
| `index.md` | .../docs/index.md (docs landing source) | curl |
| `release-notes.md` | .../docs/release-notes.md | curl (80 KB) |
| `trophy-case.md` | .../docs/trophy-case.md | curl |
| `trophies.md` | .../docs/snippets/trophies.md | curl (96 KB, 482 orgs / 773 examples) |
| `github-readme.md` | .../README.md | curl |
| `cli-help.txt` | .../docs/snippets/help.txt | curl (verbatim `zizmor -h` output) |
| `releases.md` | GitHub releases API (derived summary) | curl + script |

### `seo/` (JSON + code)

| File | Source |
|---|---|
| `github-repo.json` | https://api.github.com/repos/zizmorcore/zizmor |
| `github-releases.json` | https://api.github.com/repos/zizmorcore/zizmor/releases?per_page=100 |
| `github-contributors.json` | https://api.github.com/repos/zizmorcore/zizmor/contributors |
| `github-tags.json` | https://api.github.com/repos/zizmorcore/zizmor/tags |
| `cratesio-zizmor.json` | https://crates.io/api/v1/crates/zizmor (261,276 downloads; 46,911 recent; 88 versions) |
| `pypi-zizmor.json` | https://pypi.org/pypi/zizmor/json (1.31.1, uploaded 2026-10-15) |
| `homebrew-zizmor.json` | https://formulae.brew.sh/api/formula/zizmor.json (formula 1.31.1, bottled) |
| `trophy-orgs.txt` | 482 unique org names extracted from the trophy case |
| `zizmor-main-rs.txt` | .../crates/zizmor/src/main.rs (CLI entry point) |
| `zizmor-cli-rs.txt` | .../crates/zizmor/src/cli.rs (full clap flag definitions) |
| `github-rs.txt` | .../crates/zizmor/src/github.rs (GitHub API client; `gha_advisories` at line 741) |
| `known_vulnerable_actions.rs` | .../crates/zizmor/src/audit/known_vulnerable_actions.rs (advisory source = GitHub global advisories API) |

### Verified-vs-supplied metrics

| Metric | Supplied | Independently verified | Method |
|---|---|---|---|
| Stars | 6,755 | 6,755 ✅ | GitHub API |
| Forks | 272 | 272 ✅ | GitHub API |
| Open issues | 174 | 174 ✅ | GitHub API |
| License | MIT | MIT ✅ | GitHub API |
| Created | 2024-08-19 | 2024-08-19T18:26:28Z ✅ | GitHub API |
| Last push | 2026-10-22 | 2026-10-22T04:28:15Z ✅ | GitHub API |
| Releases | 94 | 94 ✅ | GitHub API |
| Latest release | v1.31.1, 2026-10-15 | v1.31.1, 2026-10-15 ✅ | GitHub API |
| crates.io total | 261,271 | **261,276** ✅ (drift of 5 downloads since the snapshot) | crates.io API |
| crates.io 90d | 46,911 | 46,911 ✅ | crates.io API |
| Homebrew 30d installs | 5,420 | Formula version 1.31.1 + bottle confirmed; install-analytics figure not independently re-fetched | formulae.brew.sh API |
| Team size | — | 1 human maintainer inferred from contributor commit distribution | GitHub contributors API |
| SEO metrics | — | **not available (no SEO data source in this environment)** | — |

### Fetches attempted with non-200 results (recorded, not silently dropped)

| URL | Result |
|---|---|
| https://zizmor.sh/pricing | 404 |
| https://zizmor.sh/pricing/ | 404 |
| https://docs.zizmor.sh/pricing | 404 |
| https://zizmor.sh/about | 404 |
| https://zizmor.sh/blog | 404 |
| https://raw.githubusercontent.com/.../docs/trophies.md | 404 (content lives at `docs/snippets/trophies.md`) |
| https://raw.githubusercontent.com/.../docs/trophies.md (and 4 other paths) | 404 — resolved via `docs/snippets/trophies.md` |

### Open questions / not checked

- Homebrew 30-day install analytics (5,420) was supplied, not independently re-fetched; formulae.brew.sh's formula API does not expose install counts.
- No third-party review sites (G2/Capterra/Product Hunt) were queried.
- Star-history, GitHub dependents, and release-binary download counts were not fetched.
- `zizmor.sh` was not checked for a sitemap/robots.txt (site is a single static page; no nav paths beyond those recorded).
- The 482-name trophy list was sampled in this profile; the complete list is in `seo/trophy-orgs.txt`.
