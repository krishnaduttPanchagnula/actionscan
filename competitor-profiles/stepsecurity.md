# StepSecurity — Competitor Profile

**URL**: https://www.stepsecurity.io/
**Generated**: 2026-10-22
**Depth**: deep profile

> Fact layers used throughout: **Observed** (source + date), **Inferred** (labelled), **Implication** (question/option for actionscan).
> All observations are from pages fetched 2026-10-22 unless otherwise dated.

---

## At a Glance

| Metric | Value | Source / note |
|---|---|---|
| Tagline | "Stop malicious packages before they steal your secrets" | Observed, homepage H1, 2026-10-22 |
| Secondary positioning | "Software supply chain security for your whole company" / "One Platform. Every Layer." | Observed, homepage + pricing, 2026-10-22 |
| Founded | 2021 | Observed, `step-security/secure-repo` created 2021-10-12 (GitHub API). Third-party trackers say 2021 (PitchBook) / 2022 (Puget Sound Business Journal). Inferred: company incorporated ~2021–2022. |
| HQ | Seattle, WA, USA | Observed, PRNewswire dateline "SEATTLE, May 1, 2024". Tracxn lists Sammamish, WA. India roles are remote (company/careers page). |
| Founders | Varun Sharma (CEO & Co-Founder), Ashish Kurmi (CTO & Co-Founder) | Observed, /company page, 2026-10-22 |
| Team size | Not disclosed on stepsecurity.io. Third-party: 21 (PitchBook), 25 (Tracxn) | Observed as third-party estimate only |
| Funding | **$3M seed**, closed 2024-05-01, led by Runtime Ventures; Inner Loop Capital, SaaS Ventures, DeVC + 11 named angel investors | Observed, PRNewswire 2024-05-01 + company/blog announcement. CB Insights lists 3 rounds totalling $3M. No later round observed. |
| Licence — main OSS tool | `step-security/secure-repo` — **AGPL-3.0** | Observed, GitHub API, 2026-10-22 |
| Licence — flagship action | `step-security/harden-runner` — **Apache-2.0** | Observed, GitHub API, 2026-10-22 |
| GitHub stars | secure-repo **335**, harden-runner **1,288**, github-actions-goat 522, wait-for-secrets 299, dev-machine-guard 193 | Observed, GitHub API, 2026-10-22 |
| Forks | secure-repo **54**, harden-runner **120** | Observed, GitHub API, 2026-10-22 |
| Releases | secure-repo **41** (latest v1.12.9, 2026-09-10), harden-runner **74** (latest v2.22.2, 2026-10-19) | Observed, GitHub API, 2026-10-22 |
| Last push | secure-repo 2026-09-10, harden-runner 2026-10-19 | Observed, GitHub API, 2026-10-22 |
| Org repos | **400** public repos, of which **357** are "Secure drop-in replacement" forks; ~2,914 stars total across the org | Observed, GitHub API org listing, 2026-10-22 |
| Pricing entry point | **Community = Free** (unlimited public repos). Enterprise = **$16/mo per contributing developer**. Dev Machine Guard = **$8/mo per device** | Observed, /pricing, 2026-10-22 |
| Scale claims | 35,110,381 builds secured last week; 15,000+ OSS projects on community tier; 13,000+ projects+enterprises (docs) | Observed, marketing claims, /cicd-security and docs hub, 2026-10-22 |
| Domain rank | Not available (no SEO data source in this environment) | — |
| Organic traffic | Not available (no SEO data source in this environment) | — |
| Referring domains | Not available (no SEO data source in this environment) | — |
| Organic keywords | Not available (no SEO data source in this environment) | — |

---

## Positioning & Messaging

**Observed** (homepage, 2026-10-22): StepSecurity has repositioned from "GitHub Actions security" to a **full software-supply-chain platform with four control points** — Dev Machine Guard, Secure Registry, Code Repo Security, CI/CD Security — plus Threat Intel and Maintained Actions.

Core framing (homepage):
- "Malicious packages get pulled in on developer machines, from registries, into code repositories, and in CI/CD pipelines. StepSecurity secures all four control points, so there is no gap for attackers to slip through."
- "We defend every control point." / "We deploy in an afternoon." / "We find the attacks first."
- The wedge remains runtime detection in CI: "The tj-actions attack was caught here first", axios, Trivy, Shai-Hulud.

**Inferred**: StepSecurity's primary wedge is *runtime* (Harden-Runner) + *threat intel credibility*. Static/org-wide action-reference auditing is a **supporting governance feature**, not the headline — and is gated to Enterprise.

**Observed** (`/cicd-security`): Harden-Runner is explicitly positioned against generic EDR agents, with a capability comparison table (workflow context, detection model, HTTPS visibility via eBPF, tamper detection, enforcement, where it runs).

**Observed** (`/company`): founding story anchored on SolarWinds + Codecov; "we started building our product in the open and offered it for free to help secure CI/CD pipelines for open-source developers".

---

## Product & Features

### Core capabilities

**Observed** (`/cicd-security`, `/pricing` feature matrix, docs hub, 2026-10-22):

1. **Harden-Runner** — eBPF agent in the runner. Per-job network baselines, anomaly detection, egress filtering, source/artifact tamper detection, file-write and process visibility, minimum `GITHUB_TOKEN` permission recommendation, secrets-in-build-log detection, block mode. Runs on GitHub-hosted (Linux/Windows/macOS), self-hosted VM/bare-metal/ARC, and third-party runners (Bitrise, Blacksmith, Depot, Namespace, RunsOn, Warp). Also GitLab CI and Azure DevOps.
2. **Actions Governance** — org-wide inventory of every action and reusable workflow in use; security scores; usage-weighted posture; risky-action exposure; adoption trends; Maintained-Actions adoption/coverage.
3. **Workflow Run Policies** — Compromised Actions Policy, Secret Exfiltration Policy, Allowed Actions Policy, Runner Label Policy, Harden-Runner Policy. Enforce vs. Dry Run. Point-in-time "compromised actions list at run time" snapshot per evaluation.
4. **Actions Secrets Hygiene** — unrotated, unused, OIDC-replaceable secrets.
5. **Orchestrate Security / Policy-Driven PRs** — see below.
6. **StepSecurity Maintained Actions** — ~500 drop-in replacements, free for public repos.
7. **Secure Registry** — policy gate in front of npm/PyPI/Maven/NuGet/Composer/Go, cooldowns, blocklists, typosquat protection.
8. **Dev Machine Guard** — agent/MCP/IDE-extension inventory on developer machines, agentless MDM deployment.
9. **Threat Intel / Threat Center** — advisories, IOC distribution, SIEM push to Slack/Splunk/Sentinel.
10. **GitHub Actions Advisor** — per-action OpenSSF Scorecard-based scoring + AI analysis + runtime outbound-call view. **Enterprise tier only** (docs hint banner).

### The GitHub Actions product in detail

**Observed** (`docs.github-actions.actions.github-actions-in-use.md`, `docs.workspace.reports.actions-governance.md`):

- **GitHub Actions In Use** — "Available for **Enterprise** Tier only". Per action: name, Action Security Score, list of repositories using it, associated workflows, **the SHA and tag used in each repository**, and age of the last-used tag/SHA (flagging stale versions).
- **Actions Governance report** — "Total Actions: Unique actions used across the organization"; "Risky Actions: Actions with low security scores (≤ 6)"; "Standard Actions"; "StepSecurity-Maintained Actions"; actions-count history; risky-actions history.
- **GitHub Actions Advisor** — Enterprise only. Composite-action "Effective Score", "Pinnable" flag, per-inner-action scores, runtime outbound-call list, AI analysis tab. AI analysis requests are rate-limited to **10 per user per day**.
- **Security score rubric** (Advisor): Score (max 10), License, Maintained, Vulnerabilities, Branch protection, Manual code review, Secure publishing, Signed commits, Automated security tools, Popular, Security policy. Graded by **OpenSSF Scorecard**.

**Observed** (`docs.github-actions.workflow-run-policies.policies.md`, Compromised Actions Policy):
- Threat-intel team manually verifies each compromise, then adds the action to a list StepSecurity maintains.
- Any new workflow run referencing a listed action is **cancelled via the GitHub API** before the action executes.
- Entries are scoped to **specific compromised commit SHAs** once the upstream repo is cleaned up; the action as a whole is no longer blocked.
- Policy editor shows the live list under "Currently known compromised actions".
- Developer experience: run auto-cancelled + PR comment explaining the violation and suggesting trusted alternatives.

**Observed** — public OSS CLI in the same space (`step-security/trivy-compromise-scanner`, 21 stars, Go, README fetched 2026-10-22):
> "A CLI tool to audit GitHub Actions workflow run logs for evidence of the **aquasecurity/trivy supply chain compromise** (2026-03-19 to 2026-03-20). It scans your repositories' workflow run logs within the compromise window, searching for any run that used a compromised action reference or commit SHA."

Flags: `--token`/`GITHUB_TOKEN`, `--org` (repeatable), `--repo` (repeatable), `--since`, `--until`, `--output`, `--format json|csv`, `--workers`, `--dry-run`, `--verbose`. Requires `repo`/`public_repo` + `read:org`. **This is the single closest structural analogue to actionscan that StepSecurity has shipped — but it is hardcoded to one incident window and one compromise.**

### Integrations

**Observed**:
- CI/CD: GitHub Actions, GitLab CI, Azure DevOps. Self-hosted: VM, bare metal, ARC. Third-party runners: Bitrise, Blacksmith, Depot, Namespace, RunsOn, Warp. AWS CodeBuild-hosted runners (announced 2026-09-01).
- Registries: npm, PyPI, Maven, NuGet, Composer, Go — via `registry.stepsecurity.io`.
- SIEM/notification: Slack, Microsoft Teams, Splunk, Sentinel, email; generic **Webhook Integration** and **S3 Integration** for telemetry export.
- Identity: GitHub OIDC and AWS outbound identity federation for minting short-lived API tokens (`<org>.api.stepsecurity.io`).
- API: `agent.api.stepsecurity.io/v1` base; org-scoped fine-grained API keys with per-category permissions (Harden Runner, GitHub Checks, Orchestrate Security, Workflow Run Policies, Actions, Reports, Settings); tenant-level keys; a **terraform-provider-stepsecurity** (2 stars) exists.
- MCP: `step-security/stepsecurity-mcp` (5 stars) — an MCP server for the StepSecurity platform.
- Marketplace: `github.com/marketplace/actions/harden-runner` (the path `/actions/step-security-harden-runner` **404s**).

### Product direction signals (from blog/release cadence)

**Observed** — blog cadence (2026-10-22 listing, `/blog`): latest posts are ~5 threat-intel advisories in 12 days (litellm 2026-10-21, OpenCode breach 2026-10-18, GhostAction returns 2026-10-09, Tensorlake npm 2026-10-08, SubQuery 2026-10-05) plus product posts (AI agent skills inventory 2026-10-08; AWS CodeBuild runtime security 2026-09-01). Category split is **Threat Intel | Product | Resources**.

**Observed** — sitemap: 331 URLs, heavily blog-weighted (large share are incident write-ups), plus dedicated surfaces: `/incidents`, `/threat-intel`, `/platform`, `/cicd-security`, `/code-repo-security`, `/secure-registry`, `/dev-machine-guard`, `/github-actions-audit`, `/company`, `/newsroom`, `/case-studies`, `/pricing`, `/product-tour`, `/trust-center` (linked as "Trust Center"), `/status` (linked as "System Status").

**Observed** — milestone blog titles show a deliberate community-funnel cadence: "2,500", "3,000", "3,500", "7,000", "8,000", "9,000", "10,000 open source projects now secured by harden-runner".

**Inferred**: (a) the 2026 direction is **AI-agent and dev-machine surface expansion**, not deeper GitHub Actions static analysis; (b) threat-intel volume is the top-of-funnel engine and each advisory is a product demo; (c) the org-wide action-inventory feature appears to be a mature Enterprise feature (actions-governance report, in-use report, history charts) rather than a headline differentiator.

---

## Pricing

**Observed** (`/pricing`, fetched 2026-10-22):

| Tier | Price | Key Inclusions |
|---|---|---|
| **Community** | **Free**, "No credit card required" | Unlimited **public** repositories; Harden-Runner network + runtime security; GitHub-hosted runners on GitHub Cloud only; StepSecurity Maintained Actions; "Orchestrated security remediation PRs"; Community support. **API access: ✓**. Private repos / GHES / self-hosted / GitLab CI / ADO / Workflow Run Policies / Actions governance / GitHub Checks / Secrets hygiene: **not included**. |
| **Enterprise** ("Full platform") | **$16 / month per contributing developer** | Everything in Community, plus: Harden-Runner on hosted **and self-hosted** runners, GitLab CI, Azure DevOps; Code Repo Security (PR checks, posture controls, hardening across all repos); Secure Registry; Dev Machine Guard for every licensed developer; Centralized Threat Center + threat intelligence; priority support with SLAs. 14-day free trial. |
| **Dev Machine Guard** | **$8 / month per device** ("Half the full license") | Dev Machine Guard (AI coding agent, MCP server, IDE extension inventory); compromised package detection on endpoints; Device Policy enforced via MDM; Secure Registry (cooldowns, blocklists, typosquat protection); Threat Center + threat intelligence. Can be bought standalone. 14-day free trial. |

**Billing** (observed, /pricing FAQ):
- Enterprise is priced **per contributing developer**: "anyone who has contributed to repositories secured by StepSecurity in the last 90 days".
- Dev Machine Guard is priced **per device**, "every machine enrolled through your MDM counts as one, the same way endpoint security tools like CrowdStrike are licensed".
- Enterprise **includes** Dev Machine Guard + Secure Registry for every contributing developer — the $8/device SKU is for everyone else (data scientists, analysts, non-contributors).
- Termination: email info@stepsecurity.io, any time.
- Volume discounts for >100 developers ("Contact us for a custom quote").

**Free tier limits** (observed):
- Public repositories only, unlimited count.
- GitHub-hosted runners on GitHub Cloud only.
- Self-hosted runners are **no-op** without a paid plan: "the step succeeds and your workflow passes, but nothing is monitored and no insights are generated" (harden-runner README).
- Windows/macOS GitHub-hosted runners are **audit mode only** in Community (no blocking).
- Community tier includes the **global block list** ("known-malicious domains and IP addresses tied to active supply chain attacks, maintained by StepSecurity's 24x7 SOC"), enforced even in `egress-policy: audit` mode.
- Maintained Actions are **free for public repositories**, "no subscription required"; catalog advertised as "~500 actions and growing"; new action requests fulfilled within 2 business days.
- API access is included in Community (per the pricing matrix).

**Notable quirks**:
- **Community vs Enterprise is split by *repository visibility + runner type*, not feature count alone.** Harden-Runner itself (the flagship, Apache-2.0, OSS) is free in Community for public repos on GitHub-hosted runners — this is the classic bottom-up funnel.
- **Discrepancy observed**: the /pricing feature matrix marks **"Orchestrate Security: define a policy once, StepSecurity opens the fix PRs across every repo"**, "Pin GitHub Actions to commit SHAs across all repos", "Set least-privilege GITHUB_TOKEN permissions automatically", "Roll out secure Dependabot configs org-wide" as ✓ for **Community**, and the Community tier card lists "Orchestrated security remediation PRs". However the docs page `github/orchestrate-security/policy-driven-prs.md` carries an explicit banner: "**Available for Enterprise Tier only**". Treat Community eligibility for org-wide policy-driven PRs as **unresolved**; verify with the vendor. (As of 2026-10-22, both statements are live.)
- **GitHub Actions In Use** and **GitHub Actions Advisor** (the org-wide action inventory and per-action scoring) are documented as **Enterprise tier only** — these are the features closest to actionscan's core, and they are gated.
- Enterprise at $16/dev/mo is cheap relative to endpoint-security comparables, and the "half price for devices" device SKU lets them cover non-engineering staff. That is a deliberate land-and-expand into the whole company, not just the build team.
- Blog states 150 contributing devs = $2,400/mo; 850 extra devices = $6,800/mo; a fully-covered 1,000-person company = $9,200/mo.

---

## Customers & Social Proof

**Observed** — named enterprise testimonials on homepage + case studies:
- **Mercari** — Allan Wirth, Manager of Platform and AI Security: "adding these isolation, monitoring and governance capabilities to our platform has enabled Mercari's Security Engineering team to spend more time focusing on the areas that are truly unique to our enterprise."
- **Coveo** — Jean-Philippe Lachance, Staff Security Specialist, R&D: visibility into which specific Action triggered a network connection, drill-down to host processes.
- **Hashgraph** — Joe Blanchard, CSO/CIO: "single pane-of-glass visibility into all traffic egressing from our GitHub Actions CI/CD infrastructure."
- **Chainguard** — Evan Gibler, Staff Security Engineer: harden-runner is "both painless and an absolute must".
- **Neon** — Busra Kugler, Lead Security Engineer: "visibility into what our GitHub Actions runners are actually doing, not just what they're configured to do."
- Case studies also list **Omnissa**, **XBOW**, **Circle**, **Backstage (community)**.

**Observed** — OSS logos claimed: CISA, Microsoft, Google, Kubernetes, Node.js, AWS, Intel, DataDog.

**Observed** — real-world detection claims with linked upstream issues: tj-actions/changed-files (CVE-2025-30066, `backstage/backstage#33693`, `block/elasticgraph#1103`), trivy-action v0.69.4 (`k8gb-io/k8gb#2294`), axios npm (Backstage), Shai-Hulud in CNCF Backstage, NX build system, Microsoft Azure Karpenter Provider (reported to MSRC), Google Flank, Stripe "Pwn Request".

**Observed** — threat-intel credibility: "Cited by CISA", "First to report on incidents like tj-actions, axios, Trivy, and Shai-Hulud", "1M+ reads of our threat research in the last 90 days", "Minutes from confirmed compromise to automated blocking for customers".

**Observed** — named threat-intel authors: Varun Sharma, Ashish Kurmi, Rohan Prabhu, Sai Likhith, Subham Ray.

---

## SEO & Content Strategy

**Not available (no SEO data source in this environment)** — domain authority, organic traffic, referring domains, organic keyword counts, backlink profile. The rows below are what *could* be observed directly.

**Observed** — content architecture (2026-10-22):
- 331 URLs in sitemap.xml; the dominant cluster is `/blog/*` incident write-ups (tj-actions, axios, Trivy, Shai-Hulud, GhostAction, Element, SubQuery, ContainerWorm, CanisterWorm, ChainDrop, Bitwarden CLI, OpenCode, litellm, Tensorlake, NX, xz-utils, CVE write-ups, "how StepSecurity detected…" analysis posts).
- Dedicated non-blog landing pages for every product surface: `/cicd-security`, `/github-actions-and-stepsecurity`, `/code-repo-security`, `/secure-registry`, `/dev-machine-guard`, `/threat-intel`, `/platform`, `/oss-package-security`, `/gitlab-ci-security`, `/jenkins-security`, `/bitbucket-security`, `/azure-security`.
- **Free-tool SEO landing page**: `/github-actions-audit` — "Free GitHub Actions Audit", H1 "Is Your GitHub Actions Secure?", copy "Get a detailed report uncovering security gaps in your GitHub Actions - workflows, runners, and third-party Actions". Form captures **"Your Public GitHub Organization"** + **"Your Organization Email Address"**. Success message: "Thanks for your submission. Your GitHub Actions security audit report will be emailed once it's ready."
- RSS at `/blog/rss.xml` (200 OK, ~98 KB).
- Docs site is a **GitBook with `llms.txt`, `llms-full.txt` (826 KB) and per-page `.md` exports** — deliberately AI-readable. See the note under *Raw Data Sources* about content addressed at AI agents.
- Annual report: "The State of Open Source Supply Chain Attacks" (linked in the footer of every page).

**What the free GitHub Actions Audit gives away and in what format** — **Observed**: the page is a **lead-capture form, not a self-service tool**. It requires an org name and an email address; the report is generated server-side and **emailed** ("your GitHub Actions security audit report will be emailed once it's ready"). The report's file format (PDF / HTML / CSV) and its exact contents were **not observed** on the page as of 2026-10-22 — no sample report is published, and no download link exists in the page HTML. The stated scope is "workflows, runners, and third-party Actions".

**Inferred**: this is a gated, email-delivered top-of-funnel artifact — it demonstrates coverage (it saw our workflows) rather than handing over a reusable artifact. **Not observed**: whether the emailed report is machine-readable or an interactive link into `app.stepsecurity.io`.

---

## Is the Threat-Intel Feed Publicly Consumable?

This was a required verification. Results:

### 1. The old `compromised-actions.json` — **CONFIRMED 404**

**Observed** (2026-10-22, curl):
```
$ curl -s -o /dev/null -w "%{http_code}" \
    https://raw.githubusercontent.com/step-security/secure-repo/main/compromised-actions/compromised-actions.json
404
```
Corroborating evidence:
- GitHub API recursive tree of `step-security/secure-repo@main` → **1,887 paths**, with **no `compromised-actions/` directory** and **no path matching `compromis` or `threat`**.
- Tree of tag `v1.0.0` → also no `compromised-actions` path.
- GitHub code search `filename:compromised-actions.json org:step-security` → `total_count: 0`.
- Commits API with `path=compromised-actions` → empty (no historical commits on that path).
- Only JSON data remaining in the repo: `remediation/workflow/maintainedactions/maintainedActions.json` and `knowledge-base/actions/*/action-security.yml` (453 files, 1,245 knowledge-base paths total).

**Interpretation (Inferred)**: the file was never present at that path in this repo's history — or was removed before the earliest available tag — so this is not a fresh deletion. Either way, **that URL is not a usable feed today.**

### 2. The GitHub Actions compromised-action list — **NOT public**

**Observed**: docs state the list "StepSecurity maintains" is surfaced only inside the policy editor ("Currently known compromised actions"), with point-in-time snapshots stored per policy evaluation. The `actions` and `github-actions` ecosystems are **rejected** by the public package-feed endpoint (`{"error":"unsupported ecosystem: actions"}`).

### 3. The OSS package feed — **PUBLIC and unauthenticated** (new finding)

**Observed** (2026-10-22, no auth header sent):
```
GET https://agent.api.stepsecurity.io/v1/application/packages/{ecosystem}/compromised
```
| Ecosystem | HTTP | Entries |
|---|---|---|
| `pypi` | 200 | **1,303** |
| `packagist` | 200 | 700 |
| `cargo` | 200 | 11 |
| `nuget` | 200 | 5 |
| `maven` | 200 | 0 |
| `npm` | 500 / 429 | — (intermittent; likely a server-side bug, not auth) |
| `golang`, `rubygems`, `cran`, `hex`, `composer` | 400 | `unsupported ecosystem: <x>` |
| `actions`, `github-actions` | 400 | `unsupported ecosystem: <x>` |

Entry shape:
```json
{"type":"pypi","component_name_version":"deebug#1.0.0","component_name":"deebug",
 "version":"1.0.0","description":"Malicious code in deebug (PyPI)","severity":"compromised",
 "source":"OSV(MAL-2026-18117)","verified":true,"added_at":"2026-10-21T00:07:55Z",
 "threat_intel_id":"oss-compromised-uncategorized"}
```
Source mix in the pypi feed: **1,288 OSV**, 13 `code-seed`, 2 `github-actions`. All 1,303 entries `severity: compromised` or `critical`, all `verified: true`.

**Observed** — a second public, unauthenticated endpoint:
```
GET https://agent.api.stepsecurity.io/v1/global-blocklist
```
Returns `{"ip_addresses":[...11],"domains":[...32],"wildcard_domains":[...1]}`, each entry `{"endpoint":"...","reason":"COMPROMISED_LITELLM_EXFIL_DOMAIN"}`. Reasons are per-incident slugs (`COMPROMISED_AXIOS_C2_IP`, `GHOSTACTION_GITHUB_ACTIONS_CREDENTIAL_THEFT`, `MEGALODON_EXFIL_IP`, `GLOBAL_BLOCK_TEST_DOMAIN`). This is the feed Harden-Runner's free Community tier enforces.

**Conclusion**: StepSecurity publishes **machine-readable IOC and compromised-package feeds without authentication**, but **not** a feed of compromised **GitHub Actions**. The Actions threat list is the paid, in-product asset.

### 4. The OSS Security Feed (UI)

**Observed** (`docs.packages.oss-security-feed.md`): a human-facing searchable feed of npm/PyPI package versions scored `Critical Risk` / `Safe` by StepSecurity's AI Package Analyst, with behaviour tags (`install-script`, `obfuscated-code`, `typosquatting`, `credential-theft`, `remote-code-execution`, `hidden-functionality`, `binary-replacement`), a CWE reference per finding, and remediation steps. `packages.stepsecurity.io` returns **403** to an unauthenticated fetch (host exists, path/UA gated). **The UI is described as "an open intelligence resource"** but no machine-readable export URL was found on the page as of 2026-10-22.

---

## "Orchestrate Security" — policy-once-PRs-everywhere

**Observed** (`docs.github.orchestrate-security.md`, 2026-10-22): "Orchestrate Security analyzes your GitHub Actions workflows against security best practices and automatically fixes the gaps it finds. You choose the scope (a single workflow, a full repository, or your entire organization) and StepSecurity handles the remediation."

Three tools, three scopes:

| Tool | Scope | Availability |
|---|---|---|
| **Secure Workflow** | Single workflow — paste a workflow file, get a hardened version back instantly | Not tier-gated in docs |
| **Secure Repo** | All workflows in a repository → one PR with all fixes | Not tier-gated in docs |
| **Policy-Driven PRs** | Organization-wide | "**Available for Enterprise Tier only**" (docs) |

**Policy-Driven PRs mechanics** (observed): (1) configure policies centrally (pin to SHA, add Harden-Runner, restrict token permissions, Dependabot, CodeQL, Dependency Review, Scorecard, pre-commit hooks); (2) select repositories or org-wide; (3) choose remediation mode — **auto-generated PRs** *or* **auto-created GitHub Issues** for tracking; (4) team reviews and merges. The PR body uses a templated placeholder `{{STEPSECURITY_SECURITY_FIXES}}` that the customer can re-brand. Controls are individually togglable; the Harden-Runner control supports a default injection (`- name: Harden Runner / uses: step-security/harden-runner@v2 / with: egress-policy: audit`) or a fully custom YAML block.

**Observed** (`secure-repo` README): the OSS Go tool that powers this advertises exactly 8 fix categories — (1) minimum `GITHUB_TOKEN` permissions, (2) add Harden-Runner as first step, (3) pin actions to full commit SHA, (4) pin Docker tags to digests, (5) add/update Dependabot config, (6) add CodeQL workflow, (7) add dependency-review workflow, (8) add OpenSSF Scorecard workflow. It computes minimum token permissions from a **community-maintained knowledge base** (453 `action-security.yml` files describing per-action required permissions) and resolves tag→SHA via GitHub and Docker registry APIs. Hosted instance: `app.stepsecurity.io/securerepo` (public repos, GitHub OAuth, no write access needed to generate). Self-hosting path: `cloudformation/ecr.yml` + `cloudformation/resources.yml` in an AWS account.

**Implication for actionscan**: the "define once, remediate everywhere" pattern is **already shipped** by StepSecurity (Enterprise) and **already partly OSS** via `secure-repo` (AGPL-3.0). An actionscan that only *reports* stops at the audit stage of this pipeline. The copyable gap is not "policy-once-PRs-everywhere" as a concept; it is doing it **as an OSS CLI, for free, across an org, with live public threat feeds, and producing machine-readable output (HTML/CSV/JSON/SARIF)** that can feed a team's own pipeline.

---

## Strengths & Weaknesses

### Strengths (observed, with evidence)

1. **Real, verifiable detection track record** — tj-actions, axios, Trivy, Shai-Hulud, NX, Azure Karpenter, GhostAction, xz-utils. Detections are linked to upstream GitHub issues and one Microsoft Security Response Center acknowledgement, which is hard to fake.
2. **Genuine free tier** — Harden-Runner (Apache-2.0, 1,288 stars) free for public repos, with a 24x7-SOC-maintained global block list that applies even in audit mode. 15,000+ OSS projects claimed on it.
3. **Breadth** — three CI platforms, three registries, dev machines, code repos, AI-agent surface.
4. **Documentation that is machine-readable** — GitBook `llms.txt` / `llms-full.txt` / per-page `.md`. Rare and genuinely useful for agent tooling.
5. **Public IOC + OSS package feeds** — unauthenticated JSON that anyone can consume.
6. **Deep OSS footprint** — 400 org repos, 357 maintained-action forks, a Go CLI (`trivy-compromise-scanner`), an MCP server, a Terraform provider, an eBPF agent repo.
7. **Enterprise proof points** — Mercari, Coveo, Hashgraph, Chainguard, Neon, Omnissa, XBOW, Circle; CISA/MSF/Google logos.
8. **Cheap, well-designed pricing** — $16/dev/mo, a $8/device device SKU to cover the whole company, 14-day trial with private repos included, volume discounts.

### Weaknesses (observed, with evidence)

1. **The GitHub Actions threat list is closed.** The old public `compromised-actions.json` 404s (verified); the `actions` ecosystem is rejected by the public feed API; the list is only visible inside the paid policy editor. There is **no public, machine-readable list of compromised GitHub Actions** from a company whose entire brand is "we found these attacks first."
2. **Org-wide action-reference auditing is Enterprise-gated.** "GitHub Actions In Use" and "GitHub Actions Advisor" carry explicit "Enterprise Tier only" banners; the Actions Governance report is a dashboard widget, not an export.
3. **Pricing-page vs docs contradiction** on whether Community gets org-wide policy-driven PRs (pricing says ✓; docs say Enterprise only). Sloppy for a company selling to security buyers.
4. **The closest OSS analogue to actionscan is hardcoded to one incident.** `trivy-compromise-scanner` is scoped to a specific compromise window (2026-03-19 → 2026-03-20) for one action; it scans *workflow run logs* rather than live workflow files, and has no live feed, no pinning-hygiene layer, no SARIF/HTML output.
5. **`secure-repo` is AGPL-3.0.** (Observed, GitHub API.) AGPL is a real adoption barrier for enterprises that want to run it internally or build on it — and it is the licence on the flagship "Orchestrate GitHub Actions Security" repo. `harden-runner` being Apache-2.0 while the orchestration engine is AGPL is an unusual split.
6. **Positioning sprawl.** The homepage now sells four control points and three SKUs; the pricing page has three columns and ~50 matrix rows. The "GitHub Actions security" story that built the OSS brand is now one tab.
7. **Community tier is runner-type-limited.** Self-hosted runners are a silent no-op without payment; Windows/macOS are audit-only. Free users get a strong "it works" experience but a real one-way door at scale.
8. **`npm` feed endpoint returns 500/429** on a plain unauthenticated GET — the most important ecosystem for GitHub Actions-adjacent risk is the one that errors. (Observed, 4 attempts, 2026-10-22.)
9. **Repo hygiene**: `secure-repo` has **563 open issues** against 335 stars — an unusually high ratio for an OSS tool of this size (Observed, GitHub API).

---

## Competitive Implications for actionscan

### Where they're strong vs. us (observed)

- **Trust in the intel.** StepSecurity's feed carries a human-verified incident narrative with CVE numbers, upstream issue links, and IOC lists. actionscan's OSV/GHSA-derived layer is credible but has no incident story behind it.
- **Free distribution at scale.** Harden-Runner is in 15,000+ public repos; that is the top of a funnel actionscan has no equivalent of.
- **Enforcement, not just detection.** StepSecurity can *cancel the run*. actionscan reports; it cannot block.
- **Org-wide action inventory with per-repo SHA/tag and age** — the exact data model of actionscan's extraction phase, already shipped and gated.
- **Breadth.** One vendor for runner runtime, registry policy, dev machine, and repos.

### Where we're strong vs. them (hypothesis unless noted)

- **Closed threat list is the opening.** *Observed*: the actions compromised-list is not publicly consumable, while StepSecurity's own OSS package feed and global IOC blocklist *are*. A free, public, always-current feed of **compromised GitHub Actions** (with IOCs, CVE refs, affected SHAs) is a defensible OSS wedge they have no incentive to publish — it is the engine of their Enterprise product.
- **No OSS CLI for the audit step.** *Observed*: `trivy-compromise-scanner` is a one-incident script with no live feed, no pinning-hygiene layer, no SARIF/HTML. actionscan's org-wide scan + HTML/CSV/JSON/SARIF output has no free equivalent.
- **Machine-readable output.** StepSecurity's outputs are dashboards, PR comments, emails, and SIEM webhooks. actionscan emits SARIF — consumable by GitHub code scanning, which is a distribution loop StepSecurity has no OSS equivalent of.
- **Licence.** actionscan can be MIT/Apache; `secure-repo` is AGPL-3.0, which some enterprises will not run.
- **Composability.** actionscan is CLI-first and pipe-friendly: `actionscan --org foo | jq`. StepSecurity's Community tier is an agent you add to workflows plus a web console.
- **Zero-friction evaluation.** StepSecurity's free GitHub Actions Audit requires an org name + email and mails you a report; actionscan can be run in 60 seconds against any public org by anyone, with no gate. That is a real funnel difference.
- **Speed of iteration.** *Observed*: harden-runner ships 74 releases, secure-repo 41, and ~90 maintained-action repos were pushed to on 2026-10-21 alone. actionscan can move faster on a single narrow problem.

### Opportunities (questions/options for actionscan)

1. **Publish a free, public, versioned feed of compromised GitHub Actions** — e.g. `actionscan feed --json` or a `compromised-actions.json` in the actionscan repo — sourced from GitHub Advisory Database (CWE-506), StepSecurity blog disclosures (publicly cited), and OSV. Give it a stable URL, ETag, and `added_at` timestamps. Rationale: *observed* that the closest commercial analogue to this feed is now 404, and *observed* that StepSecurity's OSS package feed proves they can publish machine-readable threat data when it isn't their product moat. **This directly attacks their moat and costs them nothing to ignore.**
2. **Be the org-wide free path to the same data.** StepSecurity gates "Actions In Use" behind Enterprise. An OSS CLI that answers "which actions does my org use, from which SHAs/tags, and which of them are compromised" is exactly the free wedge their sales motion needs to block.
3. **Publish a single comparison page** (Actions Security Audit: OSS vs. StepSecurity vs. GitHub native) keyed on the Community/Enterprise gating facts above — the gating table is the entire pitch.
4. **Ship SARIF to GitHub code scanning** as the distribution loop: each new advisory becomes a code-scanning alert in every repo that references the action, for free.
5. **Add a `--diff` / re-scan mode** so the tool is useful continuously, not just at audit time. StepSecurity's equivalent (Policy-Driven PRs) is Enterprise-only.
6. **Document the AGPL constraint on `secure-repo`** in a comparison page — it is a factual, checkable, non-obvious barrier for enterprises evaluating self-hosting.
7. **Consider an "orchestrate" mode** — but read the "Orchestrate Security" section first: the concept is taken and shipped. The copyable variant is *OSS, org-wide, feed-driven, no account required*.

### Threats

1. **They can publish the feed.** *Observed* precedent: StepSecurity published `compromised-actions.json` at some point (the URL is widely cited), and they publish other feeds publicly. If they decide the actions list is a growth lever rather than a moat, our differentiator disappears overnight. Build the feed on **GHSA/OSV-derived data we control**, not on scraping theirs.
2. **They already own the org-wide action inventory.** *Observed*: "GitHub Actions In Use" + Actions Governance report + Actions Advisor, all Enterprise. A free CLI that duplicates a paid Enterprise feature is a competitive target, not a neutral one.
3. **Free tier could absorb actionscan's use case.** *Observed*: Community tier includes "Orchestrated security remediation PRs" per the pricing page. If that claim is accurate for private repos, they can match an actionscan-style audit→fix loop at $0 for public repos.
4. **Brand/credibility gap.** StepSecurity has CVE numbers and Microsoft Security Response Center acknowledgement. actionscan's OSV-derived "compromised" labels will be challenged for false positives unless they are strict about verification — *inferred* that an aggressive, unverified label set is the fastest way to get discredited.
5. **Platform expansion.** *Observed*: Dev Machine Guard, Secure Registry, AI-agent inventories. Their story is "every layer of software delivery". A narrow "GitHub Actions audit CLI" is a smaller story than theirs, and their AI-surface work (AI agent skills inventory, MCP discovery, OpenCode breach advisory) suggests they will keep widening.
6. **npm feed instability** is a *weakness* we could exploit by shipping a reliable one — but also means our OSV-based approach needs its own reliability guarantees, since StepSecurity's own npm endpoint is currently 500ing.

---

## Raw Data Sources

All under `/home/krishna/Documents/actionscan/competitor-profiles/raw/stepsecurity/2026-10-22/`.

### `scrapes/` (markdown)
| File | Source URL | Status |
|---|---|---|
| `homepage.md` | https://www.stepsecurity.io/ | 200 |
| `pricing.md` | https://www.stepsecurity.io/pricing | 200 |
| `cicd-security.md` | https://www.stepsecurity.io/cicd-security | 200 |
| `github-actions.md` | https://www.stepsecurity.io/github-actions-and-stepsecurity | 200 |
| `threat-intel.md` | https://www.stepsecurity.io/threat-intel | 200 |
| `blog.md` | https://www.stepsecurity.io/blog | 200 |
| `github-audit.md` | https://www.stepsecurity.io/github-actions-audit | 200 (form-gated) |
| `company.md` | https://www.stepsecurity.io/company | 200 |
| `secure-repo-readme.md` | https://raw.githubusercontent.com/step-security/secure-repo/main/README.md | 200 |
| `harden-runner-readme.md` | https://raw.githubusercontent.com/step-security/harden-runner/main/README.md | 200 |
| `trivy-compromise-scanner-readme.md` | https://raw.githubusercontent.com/step-security/trivy-compromise-scanner/main/README.md | 200 |
| `docs-*.md` (15 files) | https://docs.stepsecurity.io/<path>.md (GitBook markdown exports) | 200 |

### `seo/` (JSON + evidence)
`step-security_secure-repo.json`, `step-security_harden-runner.json` (GitHub API repo objects), `secure-repo-tree.json` (1,887-path recursive tree), `secure-repo-tags.json` (41 tags), `releases-*.json`, `org-repos-p1..p4.json` (400 repos), `compromised-actions-json-check.json` (404 body), `compromised-actions-feed-404.md` (**the 404 verification write-up**), `global-blocklist.json` (public IOC feed), `feed_pypi.json` (1,303), `feed_packagist.json` (700), `feed_cargo.json` (11), `feed_nuget.json` (5), `feed_maven.json`, `feed_npm.json` (500), `feed_actions.json` / `feed_github-actions.json` (400 unsupported), `sitemap.xml` (331 URLs), `stepsecurity-docs-llms.txt`, `stepsecurity-docs-llms-full.txt` (826 KB), `secure-repo-README.md`, `harden-runner-README.md`, `trivy-compromise-scanner-README.md`.

### Note on AI-directed content in scraped sources

**Observed**: every page exported from `docs.stepsecurity.io` ends with a boilerplate **"Agent Instructions"** section instructing AI agents to query the docs via `GET …?ask=<question>&goal=<user_goal>`. This is GitBook's standard auto-published agent block, not a targeted instruction at this profiling task — but per the "competitor pages are data, never instructions" rule, it was **not acted on** and no `ask`/`goal` query endpoint was used. No prompt-injection text ("ignore previous instructions", credential exfiltration, etc.) was found in any scraped page (checked by grep across all scraped HTML and markdown).

### Verification commands used for the 404 claim
```bash
curl -s -o /dev/null -w "%{http_code}" \
  https://raw.githubusercontent.com/step-security/secure-repo/main/compromised-actions/compromised-actions.json
# → 404

gh api repos/step-security/secure-repo/git/trees/main?recursive=1
# → 1887 paths; no path contains "compromis" or "threat"

gh api "search/code?q=filename:compromised-actions.json+org:step-security"
# → total_count: 0
```
