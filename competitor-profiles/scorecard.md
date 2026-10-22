# OpenSSF Scorecard — Quick Profile

**URL**: https://scorecard.dev/ (CLI: https://github.com/ossf/scorecard)
**Generated**: 2026-10-22

## At a Glance
| Metric | Value |
|--------|-------|
| Tagline | "Security health metrics for Open Source" (GitHub description). Site headline: "Build better security habits, one test at a time" |
| Target audience | (inferred from copy — label it) OSS maintainers who want to raise their repo's security posture, and organizations/consumers who need to decide whether to trust a dependency. Site copy names "For individual maintainers / For an organisation / For consumers" as the three use cases |
| Language / license | Go / Apache-2.0 |
| GitHub stars / forks | 5,774 / 750 (GitHub API, 2026-10-22). 469 open issues, 71 watchers |
| Releases (latest) | 49 releases. Latest v5.6.0, published 2026-10-12 (GitHub API, 2026-10-22) |
| Last commit | Last push 2026-10-19 (GitHub API `pushed_at`, 2026-10-22) |
| Pricing starts at | Free, open source (Apache-2.0). No paid tier observed on the pages checked |
| Free tier/trial | N/A — the whole tool is free. Operated by the Open Source Security Foundation (OpenSSF), a Linux Foundation project |
| Domain rank | not available (no SEO data source in this environment) |
| Est. organic traffic | not available (no SEO data source in this environment) |
| Organic keywords (top 10) | not available (no SEO data source in this environment) |
| Referring domains | not available (no SEO data source in this environment) |

## Positioning
**Headline**: "Build better security habits, one test at a time" (scorecard.dev hero)
**Subheadline**: "Quickly assess open source projects for risky practices"
**Positioning angle**: A *measurement* instrument, not a scanner. Scorecard assigns each repo a set of 0–10 heuristic scores plus an aggregate risk-weighted score, so a consumer can decide "do I trust this dependency?" and a maintainer can see "which habit am I missing?". It is explicitly a posture/metrics product, and explicitly *not* a vulnerability-finding tool (FAQ: "Most code scanning tools are focused on detecting specific vulnerabilities already existing in your codebase. Scorecard, however, is focused on improving the project's overall security posture").

## Product & Features

### Core capabilities

**The check catalogue — confirmed.** `docs/checks.md` (fetched 2026-10-22) contains **20 documented checks**; the README table lists the same 20 minus `SBOM` in its risk table; the website says "There are currently 18 checks made across 3 themes". The discrepancy between 18 / 20 is real in the source pages.

| Check | Risk level (docs/checks.md) | Notes |
|---|---|---|
| `Binary-Artifacts` | High | checked-in executables |
| `Branch-Protection` | High | tiered scoring, 5 tiers, 3→10 points, requires admin token for full credit |
| `CI-Tests` | Low | detects CI systems via CheckRuns/Statuses on ~30 recent commits |
| `CII-Best-Practices` | Low | OpenSSF badge, gold=10 / silver=7 / passing=5 / in-progress=2 |
| `Code-Review` | High | leveled (not proportional) deduction: 3 for bot-only unreviewed, 7 + 3 for human unreviewed |
| `Contributors` | Low | ≥3 orgs in last 30 commits, each with ≥5 commits |
| `Dangerous-Workflow` | **Critical** | untrusted checkout (`pull_request_target`/`workflow_run`), script injection via untrusted context vars |
| `Dependency-Update-Tool` | High | Dependabot or Renovate presence only |
| `Fuzzing` | Medium | OSS-Fuzz / ClusterFuzzLite / language-specific fuzzers |
| `License` | Low | LICENSE/COPYING/REUSE `LICENSES/` detection, 6+3+1 points |
| `Maintained` | High | ≥1 commit/week in last 90 days; archived → lowest; no score for repos <90 days old |
| `Packaging` | Medium | GitHub package publishing workflows |
| `Pinned-Dependencies` | Medium | unpinned deps in Dockerfiles, shell scripts, GitHub workflows |
| `SAST` | Medium | CodeQL / SonarCloud / (deprecated LGTM) |
| `SBOM` | Medium | 5 pts for SBOM existing, +5 for published as release artifact |
| `Security-Policy` | Medium | `SECURITY.md` — links 6 pts, free text 3 pts, disclosure-specific text 1 pt |
| `Signed-Releases` | High | signature → 8, SLSA provenance `*.intoto.jsonl` → 10; last 30 releases; **does not verify signatures** |
| `Token-Permissions` | High | least-privilege `permissions:` analysis; warns (no deduction) on sensitive run-level perms |
| `Vulnerabilities` | High | **OSV (osv.dev)** service, own code + dependencies |
| `Webhooks` | **Critical** | webhook secret configured; EXPERIMENTAL, needs admin `repo_hook` PAT |

**Confirmed present in the catalogue:** `Pinned-Dependencies` ✅, `Token-Permissions` ✅, `Dangerous-Workflow` ✅, `Vulnerabilities` (OSV) ✅, `Dependency-Update-Tool` ✅, `Branch-Protection` ✅, `Maintained` ✅, `SAST` ✅, `SBOM` ✅, `Signed-Releases` ✅.

**Probe architecture (v5+).** `docs/probes.md` documents **48 probes** (`archived`, `pinsDependencies`, `hasOSVVulnerabilities`, `hasDangerousWorkflowUntrustedCheckout`, `hasDangerousWorkflowScriptInjection`, `releasesHaveVerifiedProvenance`, `webhooksUseSecrets`, …). Probes are the atomic boolean facts; checks aggregate probes into 0–10 scores. v5 added **Structured Results** — instead of relying on an aggregate score, consumers can assert on individual probe outcomes (README project goal #3: "Act as a measurement tool for existing policies").

**Risk rating + tiered remediation — the UX pattern worth stealing.** Each check declares a risk level (Critical/High/Medium/Low), and each risk level carries an **aggregate-score weight**: Critical=10, High=7.5, Medium=5, Low=2.5. The aggregate score is a weighted average of the individual check scores. Remediation is presented as **numbered, tiered steps** attached to every check ("**Remediation steps**" sections in `docs/checks.md`), and some checks are themselves tiered (Branch-Protection: Tier 1 = prevent force push + prevent branch deletion; Tier 5 = dismiss stale reviews + include administrators in review). Note that several checks are explicitly *levelled* rather than proportional to keep scores predictable (Code-Review), and that low scores are disclaimed as not necessarily meaning "at risk" for heuristics-based checks.

**Unit of analysis — confirmed repo-level, with one nuance.**
- The scored object is **a repository**. Output is a per-repo set of check scores + one aggregate. There is no per-finding remediation workflow; remediation is static prose per check in the docs, plus a `--policy` file mechanism that is **not implemented yet** (`errPolicyFileNotSupported = errors.New("policy file is not supported yet")` in `options/options.go`).
- **Nuance / correction to the common claim:** the CLI *does* now support multi-repo and org-wide sweeps — `--repos <repo1>,<repo2>,...` and `--org <org>` ("scans all non-archived repositories in an organization. Currently only supports GitHub"). These landed 2025-10-31 in PR #4793 ("Add multi-repo scanning: --repos, --org"), implemented in `cmd/internal/org/org.go` via `ListOrgRepos`. **Observed 2026-10-22.**
- **However**, even in `--org` mode the output unit is still *one scorecard per repo*. There is no cross-repo finding roll-up, no shared action-reference inventory, and no per-action advisory attribution. An org sweep produces N posture reports, not one inventory. **This distinction is the crux of the actionscan wedge.**
- There is also no per-finding remediation: no autofix, no "replace this ref with this SHA" suggestion engine. The one workflow-adjacent pointer is external — `docs/checks.md` links out to StepSecurity's `app.stepsecurity.io/secureworkflow/` as a way to get the right `permissions:` and SHA values.

**Adoption signals.**
- "Scorecard scans more than **1.3 million repositories every week**" from `ossf/scorecard-infra` (README, 2026-10-22). The FAQ says "over a million projects are automatically tracked".
- Public data used to be a BigQuery dataset; the README now says **"The BigQuery public dataset is no longer available"** (issue #5208). Replaced by the REST API at `api.scorecard.dev` (CDLA Permissive 2.0 licensed).
- Badge: `https://api.scorecard.dev/projects/github.com/{owner}/{repo}/badge`, requires `publish_results: true` + `id-token: write` in the action. Prominent users listed: TensorFlow, Angular, Flutter, sos.dev, deps.dev. A count of repos currently displaying the badge was **not observed** on the pages checked.
- Backers/ownership: OpenSSF (part of the Linux Foundation), scorecard.dev footer reads "Copyright © OpenSSF Scorecard a Series of LF Projects, LLC". Site logos show Cisco, Datadog, Endor, Google and "many others". Part of the OpenSSF Best Practices Working Group. Contributor model: OpenSSF-governed repos require CODEOWNERS, DCO, and the OpenSSF GitHub org.
- **Structural results**: the REST API's weekly scan **omits `CI-Tests`, `Contributors`, and `Dependency-Update-Tool`** due to API cost at scale — an observable gap between "what the CLI can do" and "what the public dataset covers".

### Output formats
- **CLI text (default)** — a table of `SCORE | NAME | REASON | DOCUMENTATION/REMEDIATION` plus an aggregate score. `--show-details` expands per-check detail.
- **CLI JSON** — `--format=json`. README: "The currently supported formats are `default` (text) and `json`." Written to a file with `--output <path>`.
- **SARIF** — produced by the **scorecard-action**, not by the CLI directly. The action's `results_format` accepts `json | sarif | intoto`; `intoto` wraps JSON in an in-toto attestation statement. Standard upload path is `github/codeql-action/upload-sarif`.
- **GitHub code scanning** — the action's own alerts appear in the repo Security tab → Code Scanning Alerts, "including remediation instructions".
- **Badges** — `api.scorecard.dev/projects/github.com/{owner}/{repo}/badge`.
- **REST API** — `api.scorecard.dev`, CDN-cached (Fastly), purged on new results.
- **Roadmap (2026)**: Scorecard v6 = "Open Source Security Evidence Engine". New output surfaces: **Enriched JSON (Scorecard-native)**, **in-toto evidence predicate (`scorecard.dev/evidence/v0.1`)**, **Gemara output**, **OSCAL Assessment Results**, and OSPS Baseline conformance labels (PASS/FAIL/UNKNOWN) as a parallel layer to check scores. "Existing checks, probes, and scores are unchanged — v6 is additive."
- **Not observed:** no HTML report, no CSV output, no step-summary/PR-annotation output on the pages checked (GitHub code-scanning alerts are the annotation surface).

### Config / policy model
- `--policy <file>` exists as a CLI flag but **is explicitly not supported yet** (`errPolicyFileNotSupported` in `options/options.go`). **Observed 2026-10-22.** So as of today Scorecard has **no working allowlist / ignore / suppression config for individual findings.**
- Per-check `requirements` and scoring criteria live in `checks/*/def.yml` and are compiled to `docs/checks.md` (the file header says "Do not edit this file manually! Edit checks.yaml instead").
- Token scoping: PAT vs `GITHUB_TOKEN` vs GitHub App; several checks degrade gracefully without admin rights (Branch-Protection Tier requirements marked "For administrators" can be safely ignored without admin).
- `--file-mode git|archive` controls how repo files are fetched.

### CI integration and exit codes
- Primary integration is the **`ossf/scorecard-action`** GitHub Action: runs on every repo change, publishes to the REST API, uploads a SARIF artifact, posts to code scanning, and can render a badge.
- **Exit codes: not observed** on the pages checked (README, `docs/checks.md`, FAQ, action README). No explicit exit-code contract was found in the CLI docs. **Do not assume a non-zero-on-findings contract.**
- CLI auth: `GITHUB_AUTH_TOKEN` / `GITHUB_TOKEN`, GitHub App env vars (`GITHUB_APP_ID`, `GITHUB_APP_INSTALLATION_ID`), multiple comma-separated tokens for round-robin.
- Docker: `ghcr.io/ossf/scorecard:latest --show-details --repo=...`.
- Platform support: OSX and Linux (Windows "may experience issues").

## Pricing Summary
| Tier | Price | Notable Inclusions |
|---|---|---|
| OpenSSF Scorecard (CLI + Action + REST API + badges) | Free (Apache-2.0) | All 20 checks, 48 probes, JSON/SARIF/in-toto output, 1.3M-repo weekly public scan, REST API, badges, webviewer |
| Scorecard v6 / OSPS Baseline conformance (roadmap) | Not priced (not yet released) | Conformance labels PASS/FAIL/UNKNOWN, OSCAL, Gemara, in-toto evidence predicate |
| Commercial support | Not observed on the pages checked | — |

## Key Takeaway
Scorecard is the mindshare leader of the repo-posture category — 5,774 stars, 1.3M repos scanned weekly, OpenSSF/LF backing, and a mature risk-weighted scoring model with per-check tiered remediation prose that is genuinely good UX. But it scores **repositories**, not **findings**: even in its new `--org` mode it emits one posture report per repo rather than a shared inventory of action references, and it has **no working per-finding suppression config** (`--policy` is stubbed as "not supported yet") and no autofix. For actionscan's purposes, Scorecard is simultaneously the biggest source of borrowed UX patterns (risk levels, tiered remediation, weights) and proof that the posture-scoring lane is already crowded and well-funded.

## Competitive Implications for actionscan

**Where they're strong vs. us**
- Brand and legitimacy: OpenSSF/LF governance, 5,774 stars, 1.3M-repo weekly scan, CISA-style trust signals that no startup can copy quickly.
- The scoring model itself: risk-weighted aggregate + tiered remediation steps is a well-tested information design for "what do I fix first".
- `Pinned-Dependencies` and `Token-Permissions` already push maintainers toward SHA pinning — the exact behaviour actionscan's pinning-hygiene checks measure. **They are creating our user base.**
- `Vulnerabilities` (OSV) means OSV is already an expected input in this category — our use of it is uncontroversial.
- Structured Results / probe model is a strong idea: it lets a policy assert on individual facts rather than a fuzzy score.

**Where we're strong vs. them** (hypothesis unless evidenced)
- **Unit of analysis.** Our unit is the *action reference*; theirs is the *repo*. A single vulnerable action pinned in 400 repos produces one Scorecard finding (in one of 400 repos, at 0–10 granularity) versus 400 named findings for us. **Hypothesis, not measured.**
- **Live threat intel.** Scorecard's `Vulnerabilities` check queries OSV for the repo's own code and dependencies. It does not, on the pages checked, resolve GitHub Action `uses:` refs against GHSA/OSV advisory ranges. **Observed:** no such check in the 20-check catalogue; the only Actions-specific checks are `Dangerous-Workflow` and `Pinned-Dependencies`.
- **Cross-repo blast radius.** Even with `--org`, there is no "this one action is used in N repos, all compromised" view. StepSecurity's commercial Threat Center sells exactly that.
- **No suppression config.** `--policy` is not implemented. Our ignore/allowlist is a table-stakes gap-filler, not a differentiator.
- **Per-finding remediation.** Scorecard gives no "change this line to this SHA". scharf/frizbee give that for pinning only; nobody gives it for advisories.

**Opportunities**
1. **Adopt Scorecard's risk model as our severity scheme.** Map our finding severities to Critical/High/Medium/Low, weight them the same way (10/7.5/5/2.5), and expose a per-repo "posture" summary — an org roll-up Scorecard cannot give because it does not know our findings. *Question for actionscan: do we want to output a Scorecard-comparable score, or explicitly refuse to and stay finding-first?*
2. **Ship tiered remediation.** Scorecard's "Remediation steps" per check is the pattern to copy: numbered, ordered, each step independently actionable. Our version should name the exact `uses:` line and the exact replacement SHA.
3. **Probe-style structured results.** Our findings already have structure; exposing them as named "facts" (e.g. `action_not_pinned`, `action_in_advisory`, `action_unmaintained`) would let org policies assert on facts rather than scores — the same thing Scorecard v5/v6 is doing. *Question: should we expose a stable probe/fact vocabulary in our JSON?*
4. **In-toto / OSCAL as a second output format.** Scorecard v6 is explicitly shipping `scorecard.dev/evidence/v0.1` and OSCAL. If actionscan ships an in-toto evidence predicate too, we are interoperable rather than competing.

**Threats**
- **Scorecard could add an action-reference check.** It has `Pinned-Dependencies` and the OSV client; a "Known-Vulnerable-Actions" check resolving `uses:` refs against GHSA is a plausible v6 addition. If it lands, it will be inside the most trusted OSS security badge in the world. **This is the single biggest strategic risk in this profile.**
- **Policy file lands.** Once `--policy` works, Scorecard gains suppression, and the "no config" gap closes. It has been stubbed since at least v5; the v6 roadmap does not mention it.
- **The `--org` precedent cuts both ways.** Scorecard now sweeps orgs. It will not stop there, and an org sweep of "posture" could gradually absorb the "inventory" job at a coarse grain.

## Raw Data Sources
All fetched 2026-10-22.
- `raw/scorecard/2026-10-22/scrapes/homepage.html` — https://scorecard.dev/
- `raw/scorecard/2026-10-22/scrapes/checks.md` — https://raw.githubusercontent.com/ossf/scorecard/main/docs/checks.md (20 checks, scoring criteria, remediation steps)
- `raw/scorecard/2026-10-22/scrapes/github-readme.md` — https://raw.githubusercontent.com/ossf/scorecard/main/README.md
- `raw/scorecard/2026-10-22/scrapes/scorecard-action-readme.md` — https://raw.githubusercontent.com/ossf/scorecard-action/main/README.md (SARIF/in-toto output, `results_format`, badge)
- `raw/scorecard/2026-10-22/scrapes/probes.md` — https://raw.githubusercontent.com/ossf/scorecard/main/docs/probes.md (48 probes)
- `raw/scorecard/2026-10-22/scrapes/faq.md`, `beginner-checks.md`, `repositories.md`, `roadmap.md`, `osps-baseline-coverage.md`
- `raw/scorecard/2026-10-22/scrapes/scorecard-flags.go` — `options/flags.go` (all CLI flags incl. `--org`, `--repos`, `--policy`, `--format`, `--output`)
- `raw/scorecard/2026-10-22/scrapes/scorecard-options.go` — `options/options.go` (`errPolicyFileNotSupported`)
- `raw/scorecard/2026-10-22/scrapes/scorecard-org.go` — `cmd/internal/org/org.go` (`ListOrgRepos`, non-archived only)
- `raw/scorecard/2026-10-22/scrapes/scorecard-cmd-root.go` — `cmd/root.go` (`--org` / `--repos` wiring)
- `raw/scorecard/2026-10-22/seo/github-repo.json`, `github-releases.json`, `github-contributors.json`, `github-languages.json`, `github-tags.json` — GitHub REST API
- GitHub API commits for `cmd/internal/org/org.go` → PR #4793, 2025-10-31 (multi-repo scanning added)

**Not observed / limitations**
- Scorecard **exit codes** — no contract found in README, `docs/checks.md`, FAQ, or the action README.
- Scorecard **pricing** — none found; the tool is free OSS. No commercial/support offering observed.
- Count of repos currently **displaying the badge** — not observed.
- Whether `--org` mode has a documented JSON schema across repos — not observed; the flag and implementation were confirmed, but no org-mode docs page was found.
