# Harden-Runner (StepSecurity) — Quick Profile

**URL**: https://github.com/step-security/harden-runner (vendor: https://www.stepsecurity.io)
**Generated**: 2026-10-22

## At a Glance
| Metric | Value |
|--------|-------|
| Tagline | "Harden-Runner is a CI/CD security agent that works like an EDR for GitHub Actions runners. It monitors network egress, file integrity, and process activity on those runners, detecting threats in real-time." (GitHub description). README framing: "security monitoring tailored for CI/CD runners" |
| Target audience | (inferred from copy — label it) Platform-security and AppSec teams at enterprises that must evidence CI/CD runtime control for compliance, plus the OSS maintainers of major projects (Microsoft, Google, CISA, Kubernetes, Node.js, AWS). The README's stated buyer problem is an *EDR gap* on ephemeral runners, and the paid tier gates on private repos and self-hosted runners — i.e. the buyer is a mid-market/enterprise security team, not a solo maintainer |
| Language / license | TypeScript (GitHub API `language`) / Apache-2.0. **Note:** only the *Linux community-tier agent* is open source (`step-security/agent`); the Enterprise Linux agent and the Windows/macOS agents are closed-source, and the ARC daemonset is closed-source |
| GitHub stars / forks | 1,288 / 120 (GitHub API, 2026-10-22). 54 open issues, 13 watchers |
| Releases (latest) | 74 releases. Latest v2.22.2, published 2026-10-19 (GitHub API, 2026-10-22) |
| Last commit | Last push 2026-10-19 (GitHub API `pushed_at`, 2026-10-22) |
| Pricing starts at | **Community tier: Free** (public repos on GitHub-hosted runners). **Enterprise: $16 / month per contributing developer** (full platform, 14-day free trial). **Dev Machine Guard: $8 / month per device** (half the full licence) |
| Free tier/trial | Community (free): unlimited public repositories, GitHub-hosted runners on GitHub Cloud only, network + runtime monitoring, job baselines + anomaly detection, egress blocking with domain allowlist, Global Block List, source-code tamper detection. 14-day free trial on Enterprise |
| Domain rank | not available (no SEO data source in this environment) |
| Est. organic traffic | not available (no SEO data source in this environment) |
| Organic keywords (top 10) | not available (no SEO data source in this environment) |
| Referring domains | not available (no SEO data source in this environment) |

## Positioning
**Headline**: "Harden-Runner: Security Incidents Detected" / "How Harden-Runner Works"
**Subheadline**: "Corporate laptops and production servers typically have robust security monitoring in place to reduce risk and meet compliance requirements. However, CI/CD runners, which handle sensitive information like secrets for cloud environments and create production builds, often lack such security measures."
**Positioning angle**: *An EDR for the CI runner, not a scanner for the workflow file.* The argument is that traditional EDR is ineffective on ephemeral runners and lacks workflow context, so Harden-Runner brings runtime monitoring with **CI/CD-aware event correlation** — every network call, file write and process launch is attributed to the exact workflow step that produced it. The commercial wedge is a **Global Block List** of IOC domains/IPs from active supply-chain attacks, maintained centrally by StepSecurity's 24×7 SOC, applied fleet-wide with no per-workflow configuration and no action version bump.

**Critical distinction from actionscan:** Harden-Runner operates at **runtime, on the runner, during the job**. actionscan operates at **reference time, against a live feed, across an org**. They are different layers. Harden-Runner can catch a malicious action that was never in any advisory and was never pinned (it sees the outbound connection). actionscan can tell you that 40 repos across your org reference an action with a published GHSA, *before* any of them run. Neither replaces the other — and this is stated explicitly below, because conflating them is the most common error made when reading this category.

## Product & Features

### Core capabilities

**Runtime protection (from the docs site, `docs.stepsecurity.io/harden-runner`, fetched 2026-10-22):**

| Security Measure | Function | Breach example cited |
|---|---|---|
| **Network Traffic Control** | Monitor and block outbound traffic at the **DNS**, **HTTPS (Layer 7)**, and **network layers (L3/L4)** to prevent exfiltration of code and CI/CD credentials | Codecov breach |
| **Source Code Integrity Check** | Detect tampering of source code during the build to inject a backdoor | XZ Utils, SolarWinds |
| **Dependency and Workflow Monitoring** | Detect poisoned workflows and compromised dependencies exhibiting suspicious behaviour | Dependency confusion, malicious dependencies |
| **GitHub Token Permission Enforcement** | Determine minimum `GITHUB_TOKEN` permissions by monitoring HTTPS calls to GitHub APIs | Least-privilege token guidance |
| **Threat Intelligence-Driven Blocking** | StepSecurity's 24×7 SOC identifies IOC domains/IPs from active supply-chain attacks and adds them to a **Global Block List**, enforced automatically fleet-wide | pgserve npm compromise |

**File and process monitoring.** Per the docs "Data Collection and Hosting" section, the agent reports: DNS resolutions, IPs and ports contacted, the process that made each call, timestamps; HTTP request method/host/path where non-intrusive HTTPS monitoring is supported; **process name, executable path, arguments, PID, parent PID and working directory**; **file write events** (name and path of each file written to the working directory, plus the writing process); and workflow/job metadata (repo owner/name/visibility, workflow name/path, run and job IDs, branch, commit SHA, commit message, committer, trigger event, and per-step name/status/timestamps). Every event is correlated with the workflow step that produced it. **Process events and file write events are Enterprise-tier only.**
**Explicit data-handling boundaries** (good trust signals to note): the agent does **not** send source code or file contents (only names and paths), does **not** send secret values (masked preview + match location only), and does **not** send environment variable values.

**Job-level network baselines and anomaly detection.** "Harden-Runner builds a baseline for each job based on past outbound network connections. Once the baseline is created, any future outbound calls not in the baseline trigger a detection." The docs show a **Recommended Policy** tab producing a block policy from outbound calls aggregated across the current and past runs of the job. Enterprise adds **baselines at repository, organization and cluster level**.

**Egress filtering / blocking.** `egress-policy: audit` (log) vs `block` (enforce). Block mode supports **allowlist** and **denylist**. The **Global Block List** is enforced **even in `audit` mode** — "IOCs represent known-malicious infrastructure, so customers shouldn't have to re-decide whether to block each one." Allowlisting an IOC domain in your policy **does not override** the Global Block List, by design.

**Global Block List feed — confirmed public.** `GET https://agent.api.stepsecurity.io/v1/global-blocklist` — "The endpoint is public, requires no authentication, and returns the live list of indicators currently enforced across every workflow protected by Harden-Runner." **This is the closest thing in the whole landscape to a public live threat-intel feed for CI/CD, and it is open.**

**Tamper detection.** "Detect Modification of Source Code: Monitor and alert on unauthorized changes to your source code during the CI/CD pipeline." Capability matrix also lists **Agent tampering detection** (Linux only), **Runner.Worker memory-dump detection (prevents secret exfiltration)** (Linux only), **imposter commit detection**, **secrets and build-log detection**, **known C2 endpoint blocking**, and **suspicious process event detection**.

**Secret-exfiltration protection.** Achieved indirectly: egress blocking at DNS/L3/L4/L7 prevents the exfiltration; the memory-dump detection (Linux) prevents reading runner memory; secrets/build-log detection surfaces secret material in logs and artifacts; GitHub Token Permission Enforcement reduces what a stolen token can do.

**Centralized policy store.** "Manage egress policies centrally from the StepSecurity dashboard instead of editing each workflow file." Enabled with `use-policy-store: true` + `api-key`. Documented as Enterprise-tier (the Community tier still shows "Centralized Policy Store" in the README feature table but the pricing page places "Policy Store enforcement" in the Enterprise column — the two pages are inconsistent on this point; **noted as a discrepancy, not resolved**).

**StepSecurity Maintained Actions (adjacent, free for public repos).** ~500 drop-in replacement actions that are actively maintained, security-reviewed, and kept current (including Node 24 runtime migrations), with a hardened release process (manual secure code review, signed commits, mandatory peer review, tag protection). This is a *supply-chain remediation* product, not runtime protection — relevant to actionscan because it is a "what to do about the risky action" answer that is free and OSS-hosted.

**Installation model — confirmed (this is the key mechanic).**
- **GitHub-hosted runners:** add a step at the *top of every job*:
  ```yaml
  steps:
    - name: Harden Runner
      uses: step-security/harden-runner@05e31511f85b41b11d1cf0ef85d0992719546e2c # v2.21.0
      with:
        egress-policy: audit
  ```
  The action downloads and installs the StepSecurity Agent; the agent does the monitoring.
- **Self-hosted VM:** include the agent in the runner image (AMI) — no workflow change needed for audit mode.
- **Self-hosted bare metal:** install the agent as a service.
- **ARC (Kubernetes):** deploy as a DaemonSet.
- **Third-party runner providers** (BlackSmith, Depot, Namespace, Warp, Bitrise, AWS CodeBuild): use the action, same as GitHub-hosted. Version floors are documented (v2.19.0+ generally, Bitrise v2.20.0+, CodeBuild v2.20.1+, CodeBuild custom images v2.21.0+).
- **CodeBuild specifics:** requires `kernel-6 (Amazon Linux 2023)`, privileged enabled, EC2 compute only — **Lambda is explicitly unsupported**.
- **GHES:** set `customer` and `server-name` for TLS checks and policy fetching.
- Endpoints the agent needs outbound on :443: `agent.api.stepsecurity.io`, `prod.app-api.stepsecurity.io`, and `customer-transient-data-277233109775.s3.us-west-2.amazonaws.com`. All traffic is outbound-only; the agent never accepts inbound connections.

**Platform capability matrix (Linux / macOS / Windows).** All three support GitHub-hosted runners, network + DNS monitoring, process monitoring, step correlation, job summaries, imposter commit detection, secrets/build-log detection, Policy Store enforcement, and allowlist block mode. **Linux-only:** non-intrusive HTTPS monitoring, suspicious process event detection, agent tampering detection, memory-dump detection, source-code overwrite detection, file write events on GitHub-hosted and ephemeral self-hosted. **Windows has no file write events.** macOS has no file write events on persistent self-hosted runners.

**Output.**
- **Workflow logs** and a **Markdown job summary** with a link to "View security insights and recommended policy at: <URL>".
- **StepSecurity web app** (`app.stepsecurity.io`) — per-run **Summary** tab: outbound destinations contacted, HTTPS requests and actions taken, detections. Plus **Network Events** (correlated per step) and **File events** views.
- **GitHub Checks** (Enterprise): the check passes if the baseline is unchanged, fails if it changed, showing the new outbound connections.
- **Alerts/notifications** (Enterprise): email, Slack, MS Teams, SIEM integration, and **S3 / Webhook integrations** for exporting detection events to your own infrastructure (data-residency route).
- **No SARIF, no CSV, no JSON report export observed** for findings.

**Compliance/hosting.** StepSecurity is **SOC 2 Type II and ISO/IEC 27001** compliant; telemetry processed and stored in **AWS us-east-1 and us-west-2**; console reads from the same environment; transient raw process/file data goes to a dedicated S3 endpoint.

**Adoption signals.**
- "Harden-Runner secures over **25 million CI/CD workflow runs every week**, protecting thousands of pipelines, including those from popular open-source projects by **Microsoft, Google, and CISA**."
- "Harden-Runner is trusted by over **11,000 leading open-source projects and enterprises**, including Microsoft, Google, Kubernetes, and more." Named logos in the README: CISA, Microsoft, Google, DataDog, Intel, Kubernetes, Node.js, AWS.
- Documented detection case studies: **tj-actions/changed-files (CVE-2025-30066 / GHSA-mrrh-fwg8-r2c3)**, axios npm RAT, Trivy v0.69.4, Sha1-Hulud in CNCF Backstage, NX build system compromise, Google Flank, Microsoft Azure Karpenter provider, anomalous api.ipify.org traffic, unexpected Microsoft Defender install on Ubuntu runners, Docker documentation outbound call.

### Output formats
| Surface | Available? | Notes |
|---|---|---|
| Workflow log lines | ✅ | Hardened-Runner step output, link to insights |
| GitHub Actions job markdown summary | ✅ | "📄 View Full Report" + outbound connection list |
| StepSecurity web app (per-run Summary / Network Events / File events) | ✅ | SaaS dashboard |
| GitHub Checks (PR gate) | ✅ Enterprise | Baseline-unchanged → pass; baseline changed → fail |
| Alert notifications (email/Slack/Teams/SIEM) | ✅ Enterprise | |
| S3 / Webhook export of detection events | ✅ Enterprise | Data-residency route |
| Public Global Block List JSON feed | ✅ | `GET https://agent.api.stepsecurity.io/v1/global-blocklist`, no auth |
| SARIF | ❌ not observed | — |
| CSV / HTML report | ❌ not observed | — |

### Config / policy model
- **Workflow-level inputs**: `egress-policy: audit|block`, `allowed-endpoints`, `use-policy-store: true`, `api-key`, `deploy-on-self-hosted-vm`, `customer`, `server-name`, `disable-telemetry` (Community + block mode only).
- **Policy Store (central)**: centrally-managed egress policies, no per-workflow edits; **baselines at repository / organization / cluster level** (Enterprise).
- **Suppression rules** (Enterprise) to reduce alert noise.
- **Global Block List** — centrally maintained, not user-editable, enforced over user allowlists.
- **No repo-local config file** (no `.harden-runner.yml` equivalent) observed. Policy lives in the SaaS console.

### CI integration and exit codes
- Integration is a **job step**, not a repo-level workflow — so it must be added to *every job*, in *every workflow*. (`secure-repo`/StepSecurity's tooling automates this; harden-runner itself does not.)
- **Exit codes: not observed.** The behaviour is expressed as **GitHub Checks** (pass/fail on baseline change), which is a check-status contract rather than a documented process exit-code contract.
- **Important free-tier failure mode, explicitly documented by the vendor:** "**Self-hosted runners require an Enterprise subscription, even for public repositories.** Without a subscription, the Harden-Runner action is a **no-op** on self-hosted runners: the step succeeds and your workflow passes, but nothing is monitored and no insights are generated." This is a real trap for adopters and worth flagging to anyone comparing the tools.
- Windows and macOS GitHub-hosted runners are **audit mode only** (no blocking).

## Pricing Summary
| Tier | Price | Notable Inclusions |
|---|---|---|
| **Community** (public repos, GitHub-hosted runners on GitHub Cloud) | **Free** | Harden-Runner network + runtime security, every network call / process / file write correlated to the step, job-level network baselines, anomaly detection, egress blocking with domain allowlist, Global Block List, source-code tamper detection, StepSecurity Maintained Actions, orchestrated security-remediation PRs, Community support, API access. No credit card required |
| **Enterprise** (full platform) | **$16 / month per contributing developer** | + private repos, self-hosted runners (VM/bare metal/ARC), GitLab CI & Azure DevOps, workflow-run policies (block runs using compromised actions or attempting secret exfiltration), **Actions governance: inventory, security scores, approval flow for third-party actions**, centralized Threat Center + threat intelligence, API access, priority support with SLAs. 14-day free trial. Volume discounts >100 developers |
| **Dev Machine Guard** (per device) | **$8 / month** | AI coding agent / MCP / IDE extension inventory, compromised-package detection on endpoints, MDM-enforced device policy, MCP/IDE scan on every save, signed & verified loader. Includes Secure Registry |
| **Secure Registry** | Included with Dev Machine Guard / Enterprise | Cooldown periods, compromised-version blocking, typosquat protection, org-wide package/version blocklists, one policy for laptops and CI, policy evaluation logs, upstream of JFrog/Sonatype/Azure |

Volume pricing observed: 150 contributing developers on Enterprise = $2,400/mo; 850 additional devices on Dev Machine Guard = $6,800/mo; a 1,000-person company fully covered = $9,200/mo.

## Key Takeaway
Harden-Runner is the strongest brand in CI/CD security (1,288 stars, 25M workflow runs/week, 11,000+ organisations, named adoption by Microsoft, Google and CISA, SOC 2 Type II) and it solves a genuinely different problem from ours: it watches the runner *while the job runs* and can block an exfiltration that no advisory feed would ever have predicted. Its commercial moat is the **Global Block List** — a centrally-curated IOC feed that applies fleet-wide with zero configuration — and its strategic moat is that **the interesting agent code is closed-source**. Its weakness relative to actionscan is structural: it protects *one job at a time*, requires a step in *every job*, is a no-op on self-hosted runners without a paid subscription, has no reference-time inventory or advisory view, and its most relevant feature for our users ("Actions governance: inventory, security scores, approval flow") is **Enterprise-only** — the same commercial moat that already protects StepSecurity's Compromised Actions Policy.

## Competitive Implications for actionscan

**Where they're strong vs. us**
- **Brand and distribution.** "25 million workflow runs every week" and "11,000+ leading open-source projects and enterprises" is an order of magnitude more reach than any OSS CLI in this field. Where they are present, they are already installed.
- **A real-time threat feed that works.** The Global Block List is public, unauthenticated, and fleet-wide. It is the closest existing thing to the "live threat-intel feed" actionscan promises — and it is *runtime* IOC blocking, not reference-time advisory matching.
- **Detection that no static tool can match.** Runtime egress correlation catches malicious behaviour in an action that was never known-bad, was never in GHSA, and was correctly SHA-pinned.
- **Enterprise governance features we will not build**: centralized policy store, org/cluster baselines, suppression rules, SIEM/webhook/S3 export, GitHub Checks gating, minimum-`GITHUB_TOKEN`-permission inference. These are hard, and they are how StepSecurity justifies $16/dev/mo.
- **Free-tier intelligence.** The **Maintained Actions** catalogue (~500 drop-in replacements, free for public repos) is a genuinely useful, defensible answer to "this action is abandoned — use this instead".
- **Detection credibility.** Being the tool that caught tj-actions/changed-files, axios, Trivy, NX and Sha1-Hulud is the kind of proof OSS tools cannot manufacture.

**Where we're strong vs. them** (hypothesis unless evidenced)
- **Reference time vs. runtime.** Harden-Runner's value only materialises *after* a compromised action runs. actionscan's value is that it tells you, *before* the next run, that 40 repos reference an action with a published advisory — and that 12 of those repos have not been scanned since the advisory appeared.
- **Org-wide, OSS, free, and self-hosted.** The features most comparable to what actionscan does — "Actions governance: inventory, security scores, and an approval flow for third-party actions" and "Dependency intelligence: answer 'are we affected?' with one query across the org" — are **Enterprise-only** in StepSecurity's pricing table. **Observed on the pricing page, 2026-10-22.** That is the wedge.
- **Closed agent.** The Enterprise Linux agent and the Windows/macOS agents are closed-source, as is the ARC daemonset. Only the Linux community-tier agent is OSS. An OSS-org cannot audit their own runtime protection.
- **No reference-time advisory view.** No GHSA/OSV matching against `uses:` refs was observed anywhere in the Harden-Runner surface.
- **Telemetry egress.** Harden-Runner sends runtime telemetry to StepSecurity's AWS environment. An air-gapped or data-residency-constrained org cannot adopt it (the S3 export route exists but is Enterprise). actionscan is local-only by construction.
- **Deployment cost.** One step per job, in every workflow, across every repo. We need one scan.

**Opportunities**
1. **Own the "before it runs" layer explicitly.** Say plainly: Harden-Runner blocks what happens; actionscan tells you what is about to happen across the org. Position as complementary, and *recommend* harden-runner — being the tool that says "also install this" earns trust that a competitor posture would not.
2. **Leverage the public Global Block List.** `https://agent.api.stepsecurity.io/v1/global-blocklist` is free and unauthenticated. *Question: should actionscan consume it as an additional IOC source for reference-time findings (e.g. flag actions whose upstream repo hosts known-malicious infrastructure)?* It is public, no-auth and maintained by a SOC — attractive, but it is runtime IOCs, so the mapping to a static action reference would be indirect and easy to over-claim. **Do not claim it as an action-compromise feed.**
3. **Ship a public, no-auth feed of our own.** StepSecurity proved that a fleet-wide IOC feed with zero configuration is the product. If actionscan publishes its compiled findings as an open feed, it competes with the "closed Compromised Actions Policy" rather than the runtime product.
4. **Target the gap the pricing page reveals.** "Actions governance: inventory, security scores, and an approval flow for third-party actions" and "'are we affected?' with one query across the org" are Enterprise features of a $16/dev/mo product. An OSS, free, CLI-first equivalent is a direct, well-evidenced value proposition.
5. **Consider a "does my repo already run harden-runner?" check.** If a repo has `step-security/harden-runner` in a workflow, that repo already has runtime protection — our findings there could be de-prioritised or annotated as "covered at runtime". *Question: should actionscan detect existing runtime-protection steps and label findings accordingly?* This is a cheap, differentiating touch that no competitor does.
6. **Mirror the telemetry-transparency posture.** Harden-Runner's docs are unusually explicit about what it does *not* collect. Our README should make the same guarantee explicit (no source code, no secret values, no env values) — it is a real differentiator for security buyers.

**Threats**
- **StepSecurity shipping an OSS-compatible "are we affected?" CLI.** They have the Threat Center, the SOC, and the IOC feed. If they open-source a reference-time action inventory for free, our wedge closes. Watch for a `step-security/actions-audit` style repo.
- **The Global Block List could grow into a general action-compromise feed.** Today it is domains/IPs. If StepSecurity starts publishing "this action is compromised" at the action level and open-sources it, the OSS threat-intel layer becomes commoditised. **This is the most plausible competitive threat in this batch.**
- **Distribution, not capability.** They are inside Microsoft, Google and CISA workflows already. We are not.
- **Partner-or-predator dynamics.** StepSecurity's `secure-repo` already does "SHA-pin actions across all repos" and "set least-privilege GITHUB_TOKEN permissions" — the two things our pinning-hygiene check would surface. If we are seen as competing rather than complementing, we may find ourselves excluded from the ecosystem (their Marketplace actions, their docs). *Implication: make complementarity explicit and early.*
- **A shared feed standard.** If StepSecurity and another vendor agree on an open "compromised actions" schema, our own format risks being non-interoperable. *Question: should actionscan adopt or align with any existing schema?*

## Raw Data Sources
All fetched 2026-10-22.
- `raw/harden-runner/2026-10-22/scrapes/github-readme.md` — https://raw.githubusercontent.com/step-security/harden-runner/main/README.md (features, tiers, capability matrix, adoption, limitations)
- `raw/harden-runner/2026-10-22/scrapes/docs-how-it-works.md` — https://raw.githubusercontent.com/step-security/harden-runner/main/docs/how-it-works.md (**agent open-source boundaries**: Linux community agent OSS; Enterprise Linux + Windows + macOS agents closed; ARC closed; self-hosted VM agent closed)
- `raw/harden-runner/2026-10-22/scrapes/docs-harden-runner.md` — https://docs.stepsecurity.io/github-actions/harden-runner.md (threat table, Global Block List, data collection, endpoints, installation per runner type, insights access)
- `raw/harden-runner/2026-10-22/scrapes/pricing.md` — https://www.stepsecurity.io/pricing (Community/Enterprise/Dev Machine Guard, $16/dev/mo, $8/device, 14-day trial, feature matrix by tier, volume pricing)
- `raw/harden-runner/2026-10-22/seo/github-repo.json`, `github-releases.json`, `github-contributors.json`, `github-languages.json`, `github-tags.json` — GitHub REST API

**Not observed / limitations**
- **Exit codes** — not observed; gating is expressed via GitHub Checks (Enterprise) rather than a documented process exit-code contract.
- **SARIF / CSV / HTML report** — not observed.
- **The `step-security/agent` repo (the open-source Linux agent)** — not fetched; referenced by the docs. Its feature parity with the Enterprise agent was not verified.
- **`step-security/secure-repo`** — not fetched here; its pinning and token-permission features are referenced from the pricing page only.
- **Policy Store tier placement** — the harden-runner README lists "Centralized Policy Store" under Enterprise in the feature table, but the pricing page places "Policy Store enforcement" only in the Enterprise column while the README's Community section also mentions policy-derived allowlisting. **Unresolved discrepancy between the vendor's own pages.**
- **Whether the Global Block List feed was fetched and its contents inspected** — the endpoint URL and its no-auth/public nature were read from the docs; the live JSON was not retrieved, so the list size and format are unverified.
- **Windows/macOS agent capabilities in detail** — covered only by the capability matrix.
- **A dedicated `docs/limitations.md`** — referenced by the README but not fetched.
- SEO/traffic metrics — not available in this environment; never estimated.
