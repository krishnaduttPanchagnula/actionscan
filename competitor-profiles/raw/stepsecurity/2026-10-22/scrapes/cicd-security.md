<!-- Source: https://www.stepsecurity.io/cicd-security
Fetched: 2026-10-22
Method: webfetch-equivalent (curl + HTML-to-text)
Status: 200 OK
-->

CI/CD Security
# Your pipeline has production secrets.Secure everything that touches it.

Harden-Runner watches every outbound network call, file write, and process inside your CI jobs using eBPF. Around that runtime core: governance for the actions you depend on, run policies that gate what executes, and hygiene for the secrets your pipelines hold. On GitHub Actions, GitLab CI, and Azure DevOps.
Start FreeRequest a Demo

GitHub Actions GitLab CI Azure DevOps
 GitHub Actions: add one line of YAML on GitHub hosted runners, or install the agent on self hosted VMs, bare metal, and Kubernetes. Third-party runners work too: Bitrise, Blacksmith, Depot, Namespace, RunsOn, and Warp.35M+ builds secured last week15,000+open source projects use the Harden-Runner community tier3 OSLinux, macOS, and Windows runners

GitLab CI: network monitoring and runtime security controls for GitLab pipelines, self-managed and SaaS.
Azure DevOps: network monitoring, runtime controls, and artifact tracking for ADO builds.

Detection, not archaeology
## The tj-actions attack was caught here first.

When tj-actions/changed-files was compromised in March 2025, Harden-Runner flagged the anomalous outbound call in real time because it had never appeared in any baseline. The same detection caught axios, Trivy, and the Azure Karpenter attack. Below is the tj-actions detection, recreated from the actual run:
Read the detection stories
Harden-Runner docs ↗
Network Events · tj-actions incident · Mar 14, 2025
StepProcessDestinationStatus
Run actions/checkout@v4git-remote-httpgithub.com:443✓ Allowed
Get changed files · tj-actions/changed-filescurlgist.githubusercontent.com:443⚠ Anomalous
This endpoint had never appeared in the job's baseline. Harden-Runner flagged it as anomalous in real time.
The payload read secrets from Runner.Worker process memory and printed them into the build log. Published as CVE-2025-30066. Over 23,000 repositories used this action.

Not another endpoint agent

## CI/CD context that generic EDR agents don't have

An endpoint agent sees a Linux box. Harden-Runner sees a workflow. Every network call, process, and file write is correlated to the exact step that made it, so an alert points at a line of YAML instead of a haystack.
CapabilityHarden-RunnerGeneric EDR agent
Workflow contextCorrelates every event to a CI/CD step and workflow runNo job context. Events point at a host, not a build
Detection modelBaselines each job's normal behavior and flags deviationsKnown-bad lists. Exfiltration via trusted domains passes
HTTPS visibilityeBPF sees HTTPS calls, even to trusted domains like GitHubHTTPS calls typically unmonitored
Tamper detectionWatches source code and build artifact writesGeneric file changes with no CI/CD focus
EnforcementBlocks unknown egress at the DNS and network layers, and auto blocks IOC domains from StepSecurity threat intelDetect and log only
Where it runsGitHub hosted runners, VMs, bare metal, Kubernetes. Linux, macOS, and WindowsRarely deployable on GitHub hosted runners

Baseline insights

## Your baselines are a map of your CI

Harden-Runner learns the outbound destinations of every job until its behavior is stable. That map answers questions no scanner can.
Is this call normal?A job is marked stable once its network behavior stops changing across runs. From then on, a single new destination stands out immediately. That is how tj-actions was caught.Baseline docs ↗
Which jobs still call public registries?Search every baseline for registry.npmjs.org or pypi.org and get the exact list of jobs to migrate, whether you move them to Secure Registry or to the artifact manager you already run.Explore Secure Registry →
Which jobs run AI coding agents?Agents in CI call model APIs. Baselines show every job reaching endpoints like api.anthropic.com or api.openai.com, so you know where agents act before you write policy for them.

More than runtime
## Harden-Runner is the flagship.It doesn't work alone.

 Runtime catches the attack in progress. These three make sure most attacks never get that far.

 🗂
 Actions GovernanceControl the third-party actions your builds depend on.

- Inventory of every action and reusable workflow in use
- Security scores before you adopt an action
- Replace risky actions with drop-in StepSecurity Maintained Actions
- Action request & approval flow for developers
Actions governance docs ↗
⛔
Workflow Run PoliciesGate what's allowed to execute before the job runs.

- Compromised-actions policy: block runs using known-bad action versions
- Secret-exfiltration policy: stop jobs from leaking credentials
- Policy evaluations logged for every run, audit-ready
Workflow run policies docs ↗
🔐
Actions Secrets HygieneYour secrets inventory, with the risk called out.

- Secrets not rotated, with age shown
- Unused and stale secrets that are safe to remove
- Secrets replaceable by OIDC so the long-lived credential goes away entirely
Actions secrets docs ↗

StepSecurity Maintained Actions

## When a third-party action is too risky, swap it

StepSecurity maintains trusted, drop-in replacements for popular third-party actions. Every action passes a manual secure code review before onboarding, and upstream changes are incorporated within 30 days of release. When tj-actions/changed-files was compromised, StepSecurity shipped step-security/changed-files as a secure replacement as part of the incident response.
Built for the risky onesEnterprise customers ask us to onboard actions that are abandoned, have a single maintainer, score low on OpenSSF Scorecard, or require access to credentials.
Drop-in by designSwitching is a one line change in your workflow YAML. On the Enterprise tier, policy-driven PRs replace an action across thousands of repositories automatically.
Free for public reposPublic repositories use Maintained Actions at no cost. New action requests are fulfilled within 2 business days per action.

Maintained Actions docs ↗

## Prevent, detect, and respond inside the pipeline

Prevent
- Egress policies: only allowlisted endpoints leave the runner
- Workflow run policies block compromised actions and secret exfiltration
- Actions pinned to commit SHAs by automated PRs
- Risky actions replaced with StepSecurity Maintained Actions
- Security scores for third-party actions before you adopt them

Detect
- eBPF baseline of every network call, file write, process
- Anomaly alerts the moment a job deviates from its history
- Secrets-in-build-log detection
- Stale, unused, and unrotated secrets flagged, with OIDC upgrades suggested
- Imposter-commit and tag-poisoning detection

Respond
- Block mode kills C2 callbacks mid-run
- Every detection deep-links to full runtime evidence
- Which repos, which runs, which step, answered in minutes
- Guided remediation with auto-generated fixes

## Detections that made the news

Not simulations: public, verifiable catches in real projects.
March 2026axios compromised on npmC2 callback flagged in Backstage workflows. The domain had never appeared in any baseline.
Read the story →
March 2026Trivy action compromisedSecrets exfiltration to an attacker domain detected across affected open-source projects.
Read the story →
March 2025tj-actions/changed-filesThe supply chain attack that hit thousands of repos, detected by Harden-Runner in real time.
Read the story →

35,110,381builds secured last week
15,000+open source projects use the Harden-Runner community tier
3CI platforms covered

“
It's easy to get started with GitHub Actions, but using it securely has historically required manual effort and configuration which isn't as straightforward. StepSecurity solves this by automating security best practices for Workflows as well as through their harden-runner Action which provides protection against exfiltration and source code tampering throughout the lifecycle of a Workflow. Leveraging the harden-runner Action is both painless and an absolute must for any project! Evan Gibler
Staff Security Engineer, Chainguard
 From the Chainguard case study →
 “
 Before StepSecurity, detecting the origin of a suspicious outbound network connection was challenging with traditional CNAPPs or IDS solutions, as we'd only see a general alert. StepSecurity gives us complete visibility into which specific Action triggered a connection and even lets us drill down into host processes tied to that Action. Jean-Philippe Lachance
Staff Security Specialist, R&D, Coveo
From the Coveo case study →

## Start in audit mode. Watch your first baseline build today.

Start FreeRequest a Demo
