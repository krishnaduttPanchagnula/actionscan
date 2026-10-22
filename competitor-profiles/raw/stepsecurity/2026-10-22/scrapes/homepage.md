<!-- Source: https://www.stepsecurity.io/
Fetched: 2026-10-22
Method: webfetch-equivalent (curl + HTML-to-text)
Status: 200 OK
-->

## Stop malicious packages before they steal your secrets

Malicious packages get pulled in on developer machines, from registries, into code repositories, and in CI/CD pipelines. StepSecurity secures all four control points, so there is no gap for attackers to slip through.

Start Free

Product Demo

 Trusted By Enterprises Worldwide

 Case Study

 Case Study

 Case Study
 Case Study
 Case Study

 Case Study
 Case Study
 Case Study
 Case Study
 Case Study

 Case Study
 Case Study

Overlooked Attack Surfaces

## Unaddressed Software Supply Chain Security Risks Leave Companies Open to Compromise

View all CI/CD Incidents

### Breaking News -- Software Supply Attack Chains on the Rise

View All Incidents

Read the Story
March 2026

### axios Compromised on npm

Supply Chain Attack

Hijacked maintainer account used to publish poisoned axios releases injecting a hidden dependency that drops a cross-platform remote access trojan on install. attack

Read the Story

 Copy incident link

 Share incident link

Read the story
March 2026

##### Trivy Compromised

Malicious trivy-action exfiltrated CI/CD secrets to an attacker-controlled domain for 12 hours. A fake trivy binary release was also published to GitHub Releases.

Read the Story

 Copy incident link

 Share incident link

### Shai Hulud- The Second Coming

Read the Story

Nov 2025

Malware

Read the story

Read the story
March 2025

### tj-actions/changed-files action is compromised

Application Security

Learn how StepSecurity Harden-Runner detected the tj-actions/changed-files supply chain attack

Read the Story

 Copy incident link

 Share incident link

Testimonial

“StepSecurity’s cutting-edge security features are a core part of Mercari’s supply chain security strategy. Adding these isolation, monitoring and governance capabilities to our platform has enabled Mercari’s Security Engineering team to spend more time focusing on the areas that are truly unique to our enterprise.”
Allan Wirth

Manager of Platform and AI Security, Mercari

View Case Study

Testimonial

“Before StepSecurity, detecting the origin of a suspicious outbound network connection was challenging with traditional CNAPPs or IDS solutions, as we’d only see a general alert. StepSecurity gives us complete visibility into which specific Action triggered a connection and even lets us drill down into host processes tied to that Action. Now, we have a clear and actionable picture of every network connection our runners make, and we can respond with confidence.”
Jean-Philippe Lachance

Staff Security Specialist, R&D, Coveo

View Case Study

Testimonial

"StepSecurity provided an immediate large scale effect by providing a single pane-of-glass visibility into all traffic egressing from our GitHub Actions CI/CD infrastructure. This provided immediate real-world visibility and enhanced our ability to detect and respond to incidents."
Joe Blanchard

CSO/CIO Hashgraph

View Case Study

Testimonial

"It's easy to get started with GitHub Actions, but using it securely has historically required manual effort and configuration which isn't as straightforward. StepSecurity solves this by automating security best practices for Workflows as well as through their harden-runner Action which provides protection against exfiltration and source code tampering throughout the lifecycle of a Workflow. Leveraging the harden-runner Action is both painless and an absolute must for any project!"
Evan Gibler

Staff Security Engineer, Chainguard

View Case Study

Testimonial

StepSecurity has filled a critical gap in our CI/CD security stack. It gave us visibility into what our GitHub Actions runners are actually doing, not just what they’re configured to do. StepSecurity is now an integral part of how Neon secures its CI/CD pipelines.
Busra Kugler

Lead Security Engineer at Neon

View Case Study

- From Our Threat Intelligence Team
## The attacks making headlines? Our team keeps finding them first.

Every advisory ships free with affected versions, IOCs, and remediation steps. Customers get automated blocking within minutes.October 21, 2026litellm 1.107.0 Compromised on PyPI: Backdoored Wheels Drop a Credential Stealer and an Hourly Remote Code Loaderlitellm 1.107.0 shipped a credential stealer and an hourly remote code loader in all seven PyPI wheels and in the official Docker images, including the latest tags. The release was built from a lookalike GitHub repository. Full analysis, IOCs, and recovery steps for pip and container users.Read the full analysis + IOCs →October 18, 2026OpenCode Security Breach: Distillation Attack Hit Console Users With Linked AI Providers. How to Find OpenCode on Developer Machines and RespondOpenCode reported a breach affecting Console users with linked AI providers. Here is what the vendor has said, and how to find OpenCode on your developer machines.Read the full analysis + IOCs →October 9, 2026GhostAction Returns: Malicious “Security Audit” Workflows Now Mine Credentials from Entire Git HistoriesGhostAction returns: compromised maintainers push a fake security-audit.yml workflow that steals CI/CD secrets and cloud credentials from GitHub repos.Read the full analysis + IOCs →October 8, 2026Tensorlake npm Package Compromised: A Worm With a Hostage Token That Wipes Your Machine If You Revoke ItThe malicious release was built from the project's own main branch and published with an npm provenance attestation.Read the full analysis + IOCs →Browse all advisories →The Platform
## Independent defenses at every control point in software delivery.

No other platform defends every control point. Click any capability to explore it.
### CI/CD Security

→Behavioral analysis blocks compromised packages inside your build runners.
### Dev Machine Guard

→Control and governance for AI coding agents, IDE extensions, and open source packages.
### Secure Registry

→Automatically blocks compromised packages across your entire pipeline.
### Code Repo Security

→Every PR screened. Remediation pull requests opened automatically across your repos.
### Threat Intel

→First to detect tj-actions, axios, Trivy, Shai-Hulud, and other major attacks.
### Maintained Actions

→Secure, drop-in replacements for risky third-party GitHub Actions.One Platform. Every Layer.
## Attackers hit every layer of your pipeline. So do our defenses.

Independent security controls at every stage of software delivery, so an attacker who slips past one layer is caught at the next. Here is how that plays out against the supply chain attacks that actually happened.Dev MachinesDev MachineGuardCode ReposGitHubChecksCI/CDHardenRunnerCI/CDGitHubActionsEverywhereThreatCenterEverywhereSecureRegistryMiasma Worm Targets AI Coding AgentsAI coding agents · Jun 2026✓✓✓✓✓Megalodon: Mass CI/CD Secret ExfiltrationCI/CD · May 2026✓✓✓✓Nx Console VS Code Extension CompromisedDev machine · May 2026✓✓Shai-Hulud npm Worm CampaignsOSS Dependencies · 2025-26✓✓✓✓✓axios Compromised on npmOSS Dependencies · Mar 2026✓✓✓✓✓Trivy CompromisedCI/CD + Dev machine · Mar 2026✓✓✓✓✓See the full platform → Case StudyThis case study is written by Circle's Technical Operations team, based on Circle's experience using StepSecurity at scaleIndustry: EnterpriseRunners: GithubView Case Study Case Study
## StepSecurity detects the axios npm supply chain attack in real-time in Backstage GitHub Actions workflow runs!

This case study discusses how StepSecurity Harden-Runner detected the compromised axios package making anomalous outbound connections to an attacker's C2 domain during routine GitHub Actions workflow runs in the Backstage repository. Key insights are:The compromised axios release injected a hidden dependency that deployed a cross-platform remote access trojan on install
- Harden-Runner flagged the C2 callback to the attacker's domain because it had never appeared in any prior workflow run
- Detection insights are publicly verifiable, enabling the Backstage team and the broader community to confirm the finding independently

Industry:
Community

Runners:
GitHub-Hosted

View Case Study

Case Study

## StepSecurity detects the Trivy supply chain compromise across open-source GitHub Actions workflow runs in real-time!

This case study discusses how StepSecurity Harden-Runner detected the compromised trivy-action exfiltrating secrets to an attacker-controlled C2 domain across multiple open-source GitHub Actions workflow runs. Key insights are:

- The compromised action read GitHub Actions Runner memory to steal CI/CD secrets and exfiltrated them to a typosquatted domain
- Harden-Runner automatically flagged the anomalous outbound connections across affected projects including Kubernetes, Newrelic, and Grafana
- StepSecurity reported the impact to all affected community tier projects and helped the community assess and recover

Industry:
Community

Runners:
GitHub-Hosted

View Case Study

Case Study

## StepSecurity detects a CI/CD supply chain attack on Microsoft’s Azure Karpenter Provider in real-time!

This case study discusses how StepSecurity Harden-Runner detected a CI/CD supply chain attack in real-time in Microsoft’s open-source project Azure Karpenter Provider. Key insights are:

- This could have compromised the cloud environment that the project had access to
- Within an hour of the exploit, StepSecurity reported the detection to the Microsoft Security Response Center (MSRC).
- Microsoft acknowledged StepSecurity for helping detect and remediate the incident

Industry:
Community

Runners:
GitHub-Hosted

View Case Study

Case Study

## StepSecurity Detects CI/CD Supply Chain Attack in Google’s Open-Source Project Flank in real-time

This case study discusses how StepSecurity Harden-Runner detected a CI/CD supply chain attack in real-time in Google’s open-source project Flank. Key Insights are:

- This could have caused an XZ Utils and SolarWinds style software supply chain attack.
- The researcher exploited a Pwn Request Vulnerability to exfiltrate CI/CD credentials
- Harden-Runner detected this malicious outbound network call in real-time

Industry:
Community

Runners:
Harden Runner

View Case Study

- Why Step Security
## Why enterprises pick StepSecurity

### We defend every control point.

Developer machines, registries, code repos, and CI/CD.
### We deploy in an afternoon.

One line of YAML for CI, one config line for the registry, one MDM push for laptops. Nothing to host.
### We find the attacks first.

tj-actions, axios, Trivy, and Shai-Hulud were all detected here first.
## Responding to a security incident?

Protect everything that builds your software. See how StepSecurity secures your developer machines, AI coding agents, code repos, CI/CD pipelines, and open source package consumption.Start FreeRequest a Demo

 Why Step SecurityExperience the StepSecurity Difference‍
## Without StepSecurity

AI coding agents operate without security controls
- No visibility into developer machine supply chain risks
- Reactive response to OSS package compromises
- No runtime monitoring for GitHub Actions Runners
- Manual vetting of third-party actions and dependencies

## With StepSecurity

- AI agent and MCP server monitoring and control
- Complete visibility from dev environment to production
- Proactive detection of compromised OSS packages
- Real-time threat detection and response for GitHub Actions Runners
- Automated security policies and remediation
