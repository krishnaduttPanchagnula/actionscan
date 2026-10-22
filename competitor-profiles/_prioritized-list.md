# Competitor Priority List — actionscan

**Generated**: 2026-10-22
**Our product**: `actionscan` — OSS CLI that scans GitHub org/user repos, extracts every Action referenced in CI workflow `uses:` lines, audits them against live threat-intel feeds (compromised actions, GHSA, OSV.dev, outdated releases, pinning hygiene), and emits HTML/CSV/JSON/SARIF.
**Goal of this exercise**: decide what "full-blown open-source product" means for actionscan — i.e. which capabilities the field already covers, which are unclaimed, and where to build.

**Data sources**: GitHub REST API (stars/forks/issues/releases/commit recency), crates.io, PyPI, npm, Homebrew analytics, and the projects' own documentation. No SEO/traffic API was available in this environment, so domain-authority, backlink and organic-traffic metrics are **unavailable — not estimated**. For open-source tools, star/release/download counts are the honest substitute and are used below.

---

## The landscape in one line

Nobody does exactly what actionscan does. The field splits into four camps, and the gap is in the middle:

| Camp | Representatives | What it answers |
|---|---|---|
| **Static workflow linters** | zizmor, actionlint, poutine, semgrep, checkov, KICS | "Is this workflow file misconfigured?" |
| **Repo posture scorers** | OpenSSF Scorecard | "How secure is this repo, 0–10?" |
| **Runtime agents** | StepSecurity Harden-Runner, Cimon | "What is the runner doing right now?" |
| **Vulnerability databases** | osv-scanner, Trivy, Grype, Dependabot | "Is this *package* at a vulnerable version?" |

**actionscan sits in the hole between the last two**: it takes *action references* (not packages), resolves them, and audits them against *live threat feeds* across an entire org. The two closest things are StepSecurity's commercial "Compromised Actions Policy" (closed, Enterprise-only) and zizmor's single `known-vulnerable-actions` audit (GHSA only, first-level refs only).

---

## Tier 1 — Direct competitors (same job, same buyer) — **profile deeply**

These define the product. Anything we build has to be judged against them.

### 1. zizmor — `zizmor.sh` / `zizmorcore/zizmor`
**The closest OSS competitor.** Rust, MIT, **6,755 stars**, 272 forks, **94 releases** (latest v1.31.1, 2026-10-15), **261k crates.io downloads** (46.9k in 90 days), **5,420 brew installs/30d**, last push 2026-10-22 (very active).

- 41 static audits over workflows, action definitions, Dependabot and pre-commit configs
- Overlapping ours: `known-vulnerable-actions` (GHSA), `unpinned-uses`, `archived-uses`, `typosquat-uses`, `ref-confusion`, `stale-action-refs`
- Overlapping our *adjacent* scope: `excessive-permissions`, `template-injection`, `dangerous-triggers`, `cache-poisoning`, `artipacked`, `self-hosted-runner`, `forbidden-uses`
- **We should copy**: severity→exit-code ladder (0/1/2/3/11/12/13/14), `--min-severity`/`--min-confidence`, inline ignores (`# zizmor: ignore[rule] reason`) + `zizmor.yml` per-rule config, `--fix=safe|unsafe|all`, `--format=sarif`, `--persona` (regular/pedantic/auditor), `--offline` + `--cache-dir`
- **Gap for us**: no live threat-intel feed, no org-wide sweep, no transitive dependency traversal, no "outdated" reporting, no HTML/CSV output

### 2. StepSecurity — `stepsecurity.io`
**The commercial threat and, historically, our feed source.** `step-security/secure-repo` (Go, **AGPL-3.0**, 335 stars, 41 releases, last push 2026-09-10), `step-security/harden-runner` (Apache-2.0, 1,288 stars, 74 releases, last push 2026-10-19).

- Harden-Runner: runtime EDR for the runner (egress filtering, job network baselines, tamper detection, secret-exfil protection)
- Compromised Actions Policy: pre-execution gate blocking known-malicious actions
- Threat Center + Threat Center API (Enterprise-only) — "am I affected?" across the org
- secure-repo: opens PRs that set least-privilege `GITHUB_TOKEN`, add Harden-Runner, SHA-pin actions, add Dependabot/CodeQL/dependency-review
- **We should copy**: the "define policy once, PRs everywhere" model; the blast-radius/"am I affected" question; one-click remediation PRs
- **Gap for us**: nothing — it is closed-source and priced at Enterprise tier
- **Note**: their compromised-actions JSON feed is **404**. We now derive the malicious layer from GHSA's CWE-506 advisories and use a community feed. Worth tracking if they restore a public feed.

### 3. osv-scanner (Google) — `google/osv-scanner`
**The vulnerability-database layer we emulate.** Go, Apache-2.0, **11,233 stars**, 818 forks, 56 releases (v2.7.0, 2026-10-12), **3,535 brew installs/30d** (24,822/365d), last push 2026-10-21.

- Scans lockfiles for 11+ ecosystems, container images, OS packages, licenses
- **Critical gap for us**: osv-scanner's supported-lockfile table contains no workflow parsing, and the `GitHub Actions` OSV ecosystem (55 advisories) is unreachable through it. **However**: Google already wrote a `github/actions` extractor for osv-scalibr (Copyright 2026) — it is registered in scalibr's `MiscSource` preset but absent from osv-scanner's own presets, so it is opt-in only. And the OSV API returns `{}` for *any* Actions version query, so even the enabled path finds actions and reports 0 vulnerabilities.
- **We should copy**: `--offline --download-offline-databases` (air-gapped, rate-limit-proof); the "Data Sources and Privacy" README section
- **Gap for us**: it cannot answer "which of my org's repos use a vulnerable action"
- **Also has**: an interactive HTML report (`--serve`) and SARIF — so our dashboard and SARIF are **parity** against osv-scanner, not differentiation. It lacks CSV, which we have.

---

## Tier 2 — Adjacent competitors (same buyer, different mechanism) — **quick profile**

### 4. poutine — `boostsecurityio/poutine`
Go, Apache-2.0, 528 stars, 30 releases (v1.1.6, 2026-05-22), last push 2026-10-21.
**The closest on the org-sweep axis**: `analyze_org` scans every repo of an org with a read token; Rego-based rules; `--ignore-forks --threads`; `--format json|sarif`; `skip:` config filters; **MCP server for AI assistants**. Multi-CI (Actions, GitLab, Azure, Tekton). Has `github_action_from_unverified_creator_used`, `unpinnable_action`, `pr_runs_on_self_hosted`.
**No advisory/CVE feed for actions, no HTML report.**

### 5. actionlint — `rhysd/actionlint`
Go, MIT, 4,343 stars, 283 forks, 57 releases (v1.7.12, 2026-03-30), **last push 2026-07-16 (3 months stale)**.
The de-facto workflow linter: syntax + type checking of `${{ }}`, action input/output validation, reusable-workflow input/output checking, shellcheck + pyflakes integration, script-injection detection, hardcoded credentials, runner-label/cron validation. Console-only output.
**No advisory lookups, no pinning analysis, no org sweep, no remediation.** Note the low release cadence — a distribution opportunity.

### 6. OpenSSF Scorecard — `ossf/scorecard`
Go, Apache-2.0, 5,774 stars, 750 forks, 49 releases (v5.6.0, 2026-10-12), last push 2026-10-19.
Repo-level posture score. Relevant checks: `Pinned-Dependencies`, `Token-Permissions`, `Dangerous-Workflow`, `Vulnerabilities` (OSV), `Dependency-Update-Tool`. JSON + SARIF via `scorecard-action` into Code Scanning.
**Repo-level, not finding-level, and no org sweep.** Huge mindshare, different unit of analysis.

### 7. Snyk — `snyk.io`
Commercial ASPM with GitHub Actions IaC rules, SARIF to Code Scanning, developer-brand distribution, free tier for OSS. We could not scrape its pricing without a JS-heavy page — see the profile for what was and was not observed.

---

## Tier 3 — Distribution giants + small specialists — **quick profile**

### 8. Trivy (Aqua Security) — `aquasecurity/trivy`
**38,608 stars**, 790 forks, 95 releases (v0.76.1, 2026-10-21), **13,806 brew installs/30d** — the distribution leader in this space by an order of magnitude. Covers vuln, misconfig, secret, SBOM, container. Has a CI/CD ecosystem section. **Does not index GitHub Action references against advisory feeds and does not do org sweeps of action refs.** Its exit-code pattern (0 clean / 1 error / 2 findings) and multi-scanner composition are good patterns.

### 9. Checkov (Palo Alto / bridgecrew) — `bridgecrewio/checkov`
9,092 stars, 1,446 forks, 100+ releases (3.3.30, 2026-10-20), **3.97M PyPI downloads/month** — enormous Python-ecosystem distribution. Has GitHub Actions policies. Actions-specific depth lags purpose-built tools.

### 10. Semgrep — `semgrep/semgrep`
17,180 stars, 1,116 forks, 100+ releases (v1.182.0, 2026-10-20). Has a `p/github-actions` ruleset, SARIF native. But the academic benchmark measured it as **by far the slowest** (26–39 s per workflow vs <2.71 s for the rest) and it reported the fewest findings — pattern matching inside YAML, not dependency resolution.

### 11. KICS (Checkmarx) — `Checkmarx/kics`
2,724 stars, 385 forks, 100+ releases (v2.2.0, 2026-09-17). IaC scanner with CI/CD rules. No action-ref→advisory resolution.

### 12. scharf — `cybrota/scharf`
**15 stars**, 0 forks, 22 releases (v1.4.2, 2026-10-08), last push 2026-10-10. But the **most feature-complete pinning tool we found**: `audit/autofix/find/list/lookup/upgrade/upgrade-all-sha`, `--policy-from-ref`, `--baseline-ref origin/main`, `--changed-lines`, `--ignore`, `--out json|csv|sarif|github|human`, `--raise-error`, `.scharf-policy.yml`, cooldown hours, `--verify-provenance`, and a **read-only transitive dependency audit** (`--dependencies`) walking composite actions + reusable workflows at resolved commits, depth 12 / 5k structures / 8 MiB budgets, reporting incomplete ≠ clean. Tiny audience, serious engineering — **the blueprint for our transitive-dependency work.**

### 13. frizbee (Stacklok) — `stacklok/frizbee`
186 stars, 24 forks, 30 releases (v0.1.11, 2026-08-14). Tag→checksum for actions and images; `frizbee actions <dir>` rewrites refs to SHAs; `--dry-run`; **exits non-zero if replacements found**; `.frizbee.yml` excludes; excludes `main`/`master` by default. No advisories, no org sweep.

### 14. pinny (Koala) — `koalalab-inc/pinny`
17 stars, 5 releases (v0.0.9, 2024-04-11), **last push 2025-03-15 (stale)**. Unpinned-dependency focused.

### 15. Harden-Runner (StepSecurity) — `step-security/harden-runner`
1,288 stars, 74 releases (v2.22.2, 2026-10-19), last push 2026-10-19. Runtime EDR — different layer, but the strongest brand in CI/CD security and a potential ecosystem partner (or predator).

### 16. Raven (Cycode) — `CycodeLabs/raven`
746 stars, 10 releases (v1.0.9, **2024-05-01 — stale**), last push 2026-10-21. Massive GitHub Actions workflow scanning into a Neo4j graph. The closest thing to a "fleet inventory/graph" product, but dormant commercially.

### 17. octoscan (Synack) — `synacktiv/octoscan`
274 stars, 8 releases (v0.1.7, 2026-03-30), last push 2026-03-30. Legacy static Actions vulnerability scanner, largely superseded.

---

## Tier 4 — Adjacent market, out of charter (do not build)

Grype (no workflow awareness at all), ggshield (secret scanning), Bearer (Ruby SAST, superseded), Checkmarx ASM (enterprise, no OSS scanner), Cimon (runtime, commercial), Trajan / Gato-X (offensive/red-team), Dependabot + GitHub dependency graph (**free and native — but blind to SHA-pinned actions**, which is exactly the gap we fill).

**Dependabot's blind spot is our wedge.** GitHub's own docs: *"Dependabot only creates alerts for vulnerable actions that use semantic versioning and will not create alerts for actions pinned to SHA values."* Best practice is to SHA-pin; Dependabot then goes silent. Our finding is that `actions/checkout` pinned to a 40-char SHA still has an advisory range covering it.

---

## What the field already covers well (do not rebuild)

| Capability | Best-in-class owner | Our status |
|---|---|---|
| Workflow linting / static audits | zizmor (41 audits) | ❌ out of scope — recommend, don't build |
| Repo posture score | Scorecard | ❌ out of scope |
| Runtime runner protection | Harden-Runner | ❌ out of scope |
| Package vulnerability DBs | osv-scanner / Trivy | ⚠️ we consume OSV, don't rebuild it |
| Secret scanning | ggshield | ❌ out of scope |
| Secret scanning | ggshield | ❌ out of scope |
| Pinning / SHA rewriting | frizbee, scharf | ⚠️ scharf's model is better than ours |
| Transitive dependency graph | scharf (read-only, depth 12) | ❌ **unclaimed by anyone popular** — biggest differentiator |
| Org-wide action inventory | nobody (poutine is closest) | ✅ **ours** |
| Live threat-intel for actions | StepSecurity (closed) | ✅ **ours (OSS)** |
| SARIF output | everyone | ✅ ours (just added) |
| CI exit-code gating | zizmor, poutine, frizbee | ✅ ours (just added) |
| Baseline / delta mode | scharf only | ❌ **unclaimed** — top user ask |
| Ignore / allowlist config | zizmor, poutine, scharf | ❌ **unclaimed** |
| PR annotations / step summary | zizmor | ❌ unclaimed |
| Blast-radius view | StepSecurity (commercial) | ✅ ours (dashboard panel) |

---

## Recommended product direction

**Own the org-wide action-reference inventory + threat-intel layer, and be the best-in-class at the two things nobody popular does: transitive dependency resolution and delta/baseline scanning.**

1. **Keep the wedge.** Org-wide, live-feed, action-reference auditing is genuinely unclaimed in OSS. StepSecurity proves the demand (it prices this at $16/dev/mo).
2. **Do not rebuild zizmor.** Static workflow analysis is a solved, crowded, well-funded category (41 audits, 6.7k stars, 47k monthly downloads). Recommend it; do not compete. The README should say so explicitly — it is a cheap, honest differentiator.
3. **Build the transitive dependency graph.** scharf proved it is doable (depth 12, budgeted, "incomplete ≠ clean") and no popular tool has it. It is the one feature that would make actionscan non-substitutable.
4. **Build baseline/delta mode.** The #1 user complaint across the field ("show me what changed since last scan"). Needs stable finding fingerprints; nobody popular has them.
5. **Ship an ignore/allowlist config** before anything else — every competitor has it and its absence makes us noisy in exactly the orgs that need us.
6. **Keep the dashboard.** It is our distribution advantage over zizmor/poutine/scharf, all of which are console/SARIF-only.
7. **Add PR annotations + `$GITHUB_STEP_SUMMARY`.** Cheapest path to "developers actually read our findings".

---

## Corrections (verified 2026-10-22 after deep profiling)

Six claims above were wrong. The full evidence is in `_summary.md` §5.

| Original claim | Corrected |
|---|---|
| osv-scanner has no Actions extractor | The extractor **exists** in `osv-scalibr` (Copyright 2026, `extractor/filesystem/misc/githubactions/`), but osv-scanner does not enable it by default. The OSV API's Actions **version matching is broken** — any version query returns `{}` — which is why even the enabled path finds actions and reports 0 vulns |
| poutine has no advisory feed | It ships a **static** 19-entry GHSA table (`opa/rego/external/osv.rego`, no update script) + 705 CVEs; only semver tags are evaluated, so SHA-pinned refs are never checked |
| actionlint is console-only | `-format` accepts Go templates; it ships a SARIF template, Problem Matchers, reviewdog and editor integrations |
| Scorecard has no org sweep | `--org` / `--repos` landed 2025-10-31 (PR #4793). Still one report per repo — no shared action-reference inventory |
| Trivy exit codes are 0/1/2 | Findings exit code is **user-set** (`--exit-code N`, default 0 — Trivy does not fail the build by default) |
| frizbee exits non-zero by default | Opt-in via `--error` |

### New competitor found during profiling

**`step-security/trivy-compromise-scanner`** — MIT, 21 stars, Go. Org-wide (`--org`/`--repo`), JSON/CSV output. But hardcoded to one incident window (2026-03-19→20) and it scans **workflow run logs**, not workflow files. No live feed, no SARIF, no HTML. It is the closest OSS analogue to our scope and a useful model for how StepSecurity wants that use case served.

---

## Next

Profiles complete: see `_summary.md` for the cross-competitor synthesis and the recommended product direction. Raw scraped data in `competitor-profiles/raw/<slug>/2026-10-22/`.

