# Competitive Landscape Summary — actionscan

**Generated**: 2026-10-22
**Our product**: `actionscan` — OSS Go CLI. Scans all GitHub repos for a user/org, extracts every Action referenced in CI workflow `uses:` lines, audits them against live threat-intel feeds (compromised actions, GHSA, OSV.dev, outdated releases, pinning hygiene). Emits HTML dashboard, CSV, JSON, SARIF.
**Competitors profiled**: 15 (3 deep, 12 quick)
**Raw data**: `competitor-profiles/raw/<slug>/2026-10-22/`

**Data caveat**: no SEO/traffic API (Firecrawl, DataForSEO, Ahrefs, Semrush, Ubersuggest) was available in this environment. Domain authority, backlinks, referring domains and organic traffic are **unavailable — not estimated**. For open-source tools, GitHub stars / releases / registry downloads are the honest substitute and are used below. All numbers were re-verified against the GitHub API on 2026-10-22.

---

## 1. Landscape overview

The field splits into four camps that barely overlap:

| Camp | Representatives | Unit of analysis | Answers |
|---|---|---|---|
| **Static workflow linters** | zizmor, actionlint, poutine, semgrep, checkov, KICS | one workflow file | "Is this file misconfigured?" |
| **Repo posture scorers** | Scorecard | one repository → 0–10 score | "How secure is this repo?" |
| **Runtime agents** | Harden-Runner, Cimon | one runner, live | "What is the runner doing now?" |
| **Vulnerability DBs** | osv-scanner, Trivy, Grype, Dependabot | one package@version | "Is this package vulnerable?" |

**actionscan's unit of analysis is unique: one *action reference* across an entire org, resolved against *live threat feeds*.** Every competitor either analyses YAML as text, scores a repo, watches a runtime, or checks a lockfile.

The single most important structural fact: **not one of them resolves `uses: owner/repo@ref` into a package and checks it against an advisory database.**
- Trivy: no Actions analyzer at all
- Checkov: 8 YAML-pattern checks, no pinning check
- Semgrep: 12 rules, 1 pinning rule (`mutable-action-tag`), 0 known-vulnerable-component detections
- KICS: 4 CI/CD queries, 1 unpinned-SHA check that exempts `actions/*` and misses job-level reusable workflows
- actionlint: no advisory lookups, no pinning analysis
- zizmor: `known-vulnerable-actions` (GHSA only), but only first-level refs

---

## 2. Side-by-side comparison

| | **actionscan** | zizmor | StepSecurity | osv-scanner | poutine | actionlint | Scorecard | Trivy | Checkov | Semgrep |
|---|---|---|---|---|---|---|---|---|---|---|
| **Tagline** | org-wide action threat intel | static analysis for Actions | CI/CD supply-chain defense | dependency vuln scanner | CI/CD pipeline scanner | linter for Actions workflows | repo security score | all-in-one scanner | IaC misconfig scanner | pattern-based SAST |
| **Language / license** | Go / MIT | Rust / MIT | Go / AGPL-3.0 (+Apache for runner) | Go / Apache-2.0 | Go / Apache-2.0 | Go / MIT | Go / Apache-2.0 | Go / Apache-2.0 | Python / Apache-2.0 | OCaml / LGPL-2.1 |
| **GitHub stars** | — | 6,755 | 335 (+1,288 runner) | 11,233 | 528 | 4,343 | 5,774 | **38,608** | 9,092 | 17,180 |
| **Install volume** | — | 46.9k/90d crates, 5.4k/30d brew | — | 3.5k/30d brew | — | — | — | **13.8k/30d brew** | **3.97M/mo PyPI** | **17.8M/mo PyPI** |
| **Org-wide sweep** | ✅ core | ❌ no org mode | ✅ Enterprise only | ❌ | ⚠️ `analyze_org` (git clone per repo) | ❌ | ⚠️ `--org` (per-repo reports) | ❌ | ❌ | ❌ (free tier caps at 10 repos) |
| **Resolves `uses:` → advisory DB** | ✅ | ⚠️ GHSA only, first-level | ✅ (closed, paid) | ❌ no workflow parsing | ⚠️ 19 static entries, semver tags only | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Supply-chain compromise detection** | ✅ GHSA CWE-506 + community feed | ❌ | ✅ (Threat Center) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | 1 backdoor signature |
| **Outdated / newer-version check** | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ (deprecated runtimes only) | ⚠️ Dependency-Update-Tool presence | ❌ | ❌ | ❌ |
| **Pinning analysis** | ✅ | ✅ (`unpinned-uses`) | ✅ | ❌ | ✅ | ❌ | ✅ | ❌ | ⚠️ | ✅ (1 rule) |
| **Transitive deps** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **SARIF output** | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ (template) | ✅ (action only) | ✅ | ✅ | ✅ |
| **HTML report** | ✅ dashboard | ❌ | ✅ (dashboard, Enterprise) | ✅ (`--serve`) | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ |
| **CSV output** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **CI exit-code gating** | ✅ 0/1/2 | ✅ 0/1/2/3/11–14 | ✅ | ✅ | ✅ (10 w/ flag) | ✅ | ❌ | ⚠️ opt-in | ✅ | ✅ |
| **Ignore / policy config** | ❌ | ✅ `zizmor.yml` + inline | ✅ policy | ❌ | ✅ `.poutine.yml` | ✅ `actionlint.yaml` | ⚠️ `--policy` stubbed | ❌ | ✅ | ❌ |
| **Baseline / delta** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ⚠️ only scharf |
| **Pricing** | free / OSS | free (Sponsors) | Community free / **$16 per contributing dev/mo** / $8 per device | free | free | free | free | free + paid cloud | free + paid | free + paid |

---

## 3. Positioning map

```
                    STATIC ANALYSIS  ←──────────────────────→  RUNTIME / FLEET
   single file                                                      ↑  StepSecurity
   ↑  actionlint, semgrep,                        Scorecard ↑        │  (Enterprise)
   │  checkov, KICS                   poutine ↑    (per repo) │     │  Harden-Runner
   │  zizmor                        (org, static) │              │     │
   │                                              │              │     │
   │  ── our position ──────────────────────┐     │              │     │
   │      actionscan: org-wide × live threat │     │              │     │
   │      intel × action references         │     │              │     │
   └────────────────────────────────────────┘     └──────────────┴─────┘
              ORG-WIDE                                          SINGLE-UNIT
```

The lower-right quadrant — **org-wide × reference-level × live feeds** — is empty in OSS. StepSecurity occupies it commercially; their own API confirms the gap on the data side.

---

## 4. Five findings that change the product plan

### 4.1 Google already wrote the workflow extractor — it is just not enabled
`google/osv-scalibr` contains `extractor/filesystem/misc/githubactions/githubactions.go` (Copyright 2026) — it reads `.github/workflows/*.{yml,yaml}`, parses them with `yaml.v3`, and recognises 40-char commit SHAs. It is registered in scalibr's `MiscSource` preset but **absent from osv-scanner's own `ExtractorPresets`** (`internal/scalibrplugin/presets.go`), so it is opt-in via `--x-plugins github/actions` only. Their feature request #2821 ("Scan GitHub Actions Workflows") was auto-closed as stale on 2026-08-17.

**The reason it returns nothing even when enabled is an API bug, not a code gap:** `POST api.osv.dev/v1/query` for a `GitHub Actions` package returns the advisories **only when no version is supplied**. Adding *any* version — `45.0.7`, `v45.0.7`, `41`, `46.0.1` — returns `{}`. 13 version formats were swept; all empty. The same request for `npm` works with a version.

**Implication for actionscan:** our OSV layer works *because* we query by package and match the affected ranges locally. If Google fixes the API and flips the preset on, osv-scanner inherits a working Actions scanner. **This is a deadline, not a moat.** The window is the org-wide layer and the threat-intel layer, not the OSV layer.

### 4.2 StepSecurity's own API says `actions` is an unsupported ecosystem
They publish unauthenticated machine-readable feeds at `agent.api.stepsecurity.io`:
- `GET /v1/global-blocklist` → 200, 11 IPs + 32 domains with `reason` slugs (e.g. `GHOSTACTION_GITHUB_ACTIONS_CREDENTIAL_THEFT`)
- `GET /v1/application/packages/{eco}/compromised` → pypi 1,303 / packagist 700 / cargo 11 / nuget 5 entries
- `GET /v1/application/packages/actions/compromised` → **400 `{"error":"unsupported ecosystem: actions"}`**

The GitHub Actions compromised list is the one asset they do not publish. Their "GitHub Actions In Use" (org-wide inventory with per-repo SHA/tag/age) and "GitHub Actions Advisor" carry **Enterprise-only** banners — that is our product behind a $16/dev/mo paywall.

**Implication:** a free, public, machine-readable *Actions* threat feed is an unclaimed public-good. We already have the machinery (GHSA CWE-506 + community feed); publishing it as a stable, versioned JSON feed is a cheap way to become the source other tools consume.

### 4.3 Our HTML dashboard and SARIF are parity, not differentiation
osv-scanner already ships an interactive HTML report (`--serve`) and SARIF. zizmor, poutine, actionlint, scharf and frizbee are console/SARIF-only. So the dashboard is differentiation against the *specialist* tools (zizmor/poutine/scharf/frizbee) but parity against osv-scanner. We also lack SPDX/CycloneDX (osv-scanner has them); we have CSV (osv-scanner does not).

### 4.4 poutine and Scorecard both have org sweeps — the wedge is narrower than I thought
- **poutine** has `analyze_org` (full git clone per repo, `--threads` default 2, `--ignore-forks`, `--exclude-repo`). It also ships a **static** advisory DB: `opa/rego/external/osv.rego` with 19 GHSA entries for Actions packages, and `opa/rego/external/build_platform.rego` with 705 CVEs. The OSV one has **no update script**, and `known_vulnerability_in_build_component` only matches **semver tags** — SHA-pinned and tagless refs are never evaluated. A 19-entry static table is two orders of magnitude below a live feed, but it means "poutine has no advisory data" is false.
- **Scorecard** landed `--org` and `--repos` on 2025-10-31 (PR #4793, `cmd/internal/org/org.go`) — confirmed present in the source. It still emits **one posture report per repo**: no shared action-reference inventory, no cross-repo finding roll-up. The unit-of-analysis wedge survives, but "no org sweep" was wrong.

### 4.5 The best engineering in the field is in a 15-star repo
**scharf** (`cybrota/scharf`, 15 stars, 0 forks, NOASSERTION license) has six ADRs documenting budgets and failure semantics in unusual detail. Its `audit --dependencies` is the only read-only, budgeted, cycle-aware `uses:` graph in the landscape:

| Budget | Value |
|---|---|
| traversal depth | 12 |
| YAML structures / aliases / mapping keys | 5,000 |
| unique metadata | 8 MiB |
| HTTP requests | 500 |
| per-API-response | 2 MiB |
| per-metadata-file | 1 MiB |
| per-request timeout | 15 s |

Incompleteness is first-class: `complete-clean` / `complete-with-findings` / `incomplete`, `executionSuccessful=false`, non-zero exit. Graph mode **rejects** policy/ignore/baseline flags rather than pretending they cover transitive edges. It also has baseline/merge-base multiset delta mode, accountable expiring exceptions, `--policy-from-ref` trusted-policy loading, and `--verify-provenance` (branch-membership proof, not just immutability).

**This is the blueprint for our next two features, and it costs us nothing to read it.**

---

## 5. Corrected facts (from this session's verification)

| I previously said | Actually |
|---|---|
| osv-scanner has no Actions extractor | The **extractor exists** in osv-scalibr (2026); osv-scanner does not enable it by default, and the OSV API's Actions version matching is broken |
| poutine has no advisory feed | It ships a **static** 19-entry GHSA table + 705 CVEs; no update script; semver tags only |
| actionlint is console-only | It has `-format` with **Go templates**, ships a SARIF template, and integrates with reviewdog/Problem Matchers/VS Code |
| Scorecard has no org sweep | It has `--org` / `--repos` since 2025-10-31 (per-repo reports only) |
| Trivy exit codes are 0/1/2 | Findings exit code is **user-set** via `--exit-code N` (default 0 — Trivy does not fail the build by default) |
| frizbee exits non-zero by default | That is **opt-in** via `--error` |
| Semgrep has 11.5k npm downloads/mo | That measured an unrelated package; real volume is **17.8M/mo on PyPI** |
| Our HTML + SARIF are differentiation | osv-scanner has both — they are parity vs. osv-scanner, differentiation vs. the specialists |
| The StepSecurity feed is simply dead | It was likely **never** in that repo's history; their real feeds live on `agent.api.stepsecurity.io` and exclude Actions |

**New competitor found:** `step-security/trivy-compromise-scanner` — MIT, 21 stars, Go. Org-wide (`--org`/`--repo`), JSON/CSV output. But hardcoded to one incident window (2026-03-19→20) and it scans **workflow run logs**, not workflow files. No live feed, no SARIF, no HTML. Closest OSS analogue to our scope; also a model for how StepSecurity wants that use case served.

---

## 6. Where the market is underserved

| Gap | Owner today | Our opportunity |
|---|---|---|
| **Transitive action dependency graph** | scharf only (15★, read-only) | Build it properly, with org-wide roll-up. No popular tool has it. |
| **Delta / baseline scanning** | scharf only | The #1 user complaint across the field. Needs stable finding fingerprints. |
| **Ignore / allowlist config** | zizmor, poutine, scharf, actionlint | Missing from ours — blocks adoption in noisy orgs. Cheapest high-value fix. |
| **Public machine-readable Actions threat feed** | nobody (StepSecurity's API explicitly 400s on `actions`) | We already compute it. Publish it; become the source others consume. |
| **PR annotations + step summary** | zizmor (`--format=github`) | Cheapest path to developers actually reading findings. |
| **Org-wide *reference* inventory (not per-repo)** | StepSecurity Enterprise; Scorecard per-repo | Our dashboard's blast-radius panel is the seed. |
| **CSV + HTML together** | osv-scanner has HTML, not CSV | Small, free, we already have both. |

---

## 7. Recommended product direction

**Own the org-wide action-reference inventory and the live threat-intel layer — and be first to the two things nobody popular has: transitive resolution and delta scanning.**

1. **Keep the wedge, but narrow it.** Org-wide + live feeds + reference-level is real, but poutine and Scorecard both now sweep orgs, and Google has the extractor. The defensible core is: *live threat intel* (ours) × *org-wide roll-up* (ours) × *transitive resolution* (unclaimed).
2. **Do not rebuild zizmor.** 41 audits, 6.7k stars, 47k monthly downloads, 94 releases — a solved, well-funded category. Recommend it in the README. That is an honest, free differentiator.
3. **Ship transitive dependency resolution next.** Copy scharf's budget constants and incompleteness semantics verbatim; they are already reasoned out. It is the only feature that makes actionscan non-substitutable.
4. **Ship baseline/delta mode second.** Needs stable finding fingerprints (hash of repo+workflow+job+action+advisory). No popular tool has them.
5. **Ship the ignore/allowlist config before anything else.** Every competitor has one. Its absence makes us unusable in exactly the large orgs that need us. Lowest effort, highest unblock.
6. **Publish our threat feed.** We already derive it from GHSA CWE-506. A stable, versioned, public JSON feed is the cheapest possible way to become infrastructure — and it is the one thing StepSecurity demonstrably does not do.
7. **Treat the OSV layer as temporary.** It works only because the API is broken. Assume Google fixes it within a year and rebuilds that layer on top of their extractor.
8. **Add PR annotations + `$GITHUB_STEP_SUMMARY`.** Cheap, and it is how findings reach developers.
9. **Distribution is the real threat, not features.** Semgrep 17.8M/mo, Checkov 4.0M/mo, Trivy 13.8k brew installs/mo. If any of them ships a GitHub Actions scanner, they inherit an install base we cannot match. Mitigation: own a niche so deep the giants ignore it (org-wide Actions reference threat intel) and ship a public feed so we are a dependency, not a competitor.
10. **Dependabot's blind spot is the wedge.** GitHub's docs: *"Dependabot only creates alerts for vulnerable actions that use semantic versioning and will not create alerts for actions pinned to SHA values."* Best practice is SHA-pinning; Dependabot then goes silent. `actions/checkout` pinned to a 40-char SHA still has an advisory range covering it. Say this in the README — it is the clearest statement of why this tool exists.

---

## 8. Profiles

| Profile | Depth | File |
|---|---|---|
| zizmor | deep | [zizmor.md](zizmor.md) |
| StepSecurity | deep | [stepsecurity.md](stepsecurity.md) |
| osv-scanner (Google) | deep | [osv-scanner.md](osv-scanner.md) |
| poutine | quick | [poutine.md](poutine.md) |
| actionlint | quick | [actionlint.md](actionlint.md) |
| Scorecard | quick | [scorecard.md](scorecard.md) |
| scharf | quick | [scharf.md](scharf.md) |
| frizbee | quick | [frizbee.md](frizbee.md) |
| pinny | quick | [pinny.md](pinny.md) |
| Harden-Runner | quick | [harden-runner.md](harden-runner.md) |
| Trivy | quick | [trivy.md](trivy.md) |
| Checkov | quick | [checkov.md](checkov.md) |
| Semgrep | quick | [semgrep.md](semgrep.md) |
| KICS | quick | [kics.md](kics.md) |
| Prioritised list | — | [_prioritized-list.md](_prioritized-list.md) |

## 9. Limits of this research

- No SEO, backlink, traffic, or share-of-voice data (no source available). Reach is measured by stars and registry downloads only.
- No third-party review sites (G2/Capterra/Product Hunt) were scraped — no ratings or review themes in these profiles.
- Commercial pricing was observed for StepSecurity only. Trivy, Checkov, Semgrep, KICS and Snyk cloud pricing pages were not retrievable and are marked *not observable*.
- zizmor's, poutine's and actionlint's commercial/vendor pricing pages 404 — the free OSS CLI is the only confirmed price point.
- The Trivy/Checkov/KICS pages were profiled as quick scans; their GitHub Actions rule coverage was verified at source level, but their non-Actions feature sets were not exhaustively profiled.
