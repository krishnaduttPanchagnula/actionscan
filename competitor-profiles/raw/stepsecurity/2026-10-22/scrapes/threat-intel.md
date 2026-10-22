<!-- Source: https://www.stepsecurity.io/threat-intel
Fetched: 2026-10-22
Method: webfetch-equivalent (curl + HTML-to-text)
Status: 200 OK
-->

Threat Intel

# Supply chain attacks, discovered first

StepSecurity's threat intelligence team is consistently among the first in the industry to discover, analyze, and report software supply chain compromises. Every advisory ships with full IOCs, affected versions, and remediation steps. And every advisory feeds automated protection into the platform within minutes.
Browse all advisoriesRequest a demo

1M+
reads of our threat research in the last 90 days

First to report
on incidents like tj-actions, axios, Trivy, and Shai-Hulud

Minutes
from confirmed compromise to automated blocking for customers

Cited by
CISA, package maintainers, and the security press

Latest alerts

## Active and recent supply chain attacks

October 21, 2026

### litellm 1.107.0 Compromised on PyPI: Backdoored Wheels Drop a Credential Stealer and an Hourly Remote Code Loader

litellm 1.107.0 shipped a credential stealer and an hourly remote code loader in all seven PyPI wheels and in the official Docker images, including the latest tags. The release was built from a lookalike GitHub repository. Full analysis, IOCs, and recovery steps for pip and container users.
Read the full analysis + IOCs

October 18, 2026
OpenCode Security Breach: Distillation Attack Hit Console Users With Linked AI Providers. How to Find OpenCode on Developer Machines and Respond
OpenCode reported a breach affecting Console users with linked AI providers. Here is what the vendor has said, and how to find OpenCode on your developer machines.

October 9, 2026
GhostAction Returns: Malicious “Security Audit” Workflows Now Mine Credentials from Entire Git Histories
GhostAction returns: compromised maintainers push a fake security-audit.yml workflow that steals CI/CD secrets and cloud credentials from GitHub repos.

October 8, 2026
Tensorlake npm Package Compromised: A Worm With a Hostage Token That Wipes Your Machine If You Revoke It
The malicious release was built from the project's own main branch and published with an npm provenance attestation.

October 5, 2026
SubQuery Ecosystem Compromise: Hidden Credential Theft and Backdoors
On October 5, 2026, StepSecurity analyzed @subql/common@5.8.3 on npm and identified a hidden payload that collects credentials and supports remote shell access. It starts during installation and when the package is imported. The code targets developer workstations and CI environments, including GitHub Actions runners and accessible cloud services.

View all Threat Intel advisories

Objective evidence

## Acknowledged by the maintainers and vendors we help

Our detections and disclosures are on the public record. Here is what that looks like.

First to notify maintainers and community
When we confirm a compromise, maintainers hear it from us first. For the axios and redhat-cloud-services npm compromises, we notified the maintainers and published the advisories that alerted the community.
See the axios disclosure

Covered by security press
Our incident research is regularly picked up and cited by security media and industry reporting, bringing major supply chain compromises to public attention.
Read the coverage

Publicly verifiable detections
Our detection insights for open-source projects are public. Anyone can independently confirm the axios C2 callback we flagged in the Backstage project's workflow runs.
See the live detection

Cited by CISA
CISA advisories reference our research alongside GitHub and Microsoft, including for the axios, tj-actions, and Shai-Hulud compromises.
Read the advisory

Not just research

## From discovery to automated protection in minutes

Threat intel that lives in a blog post does not protect anyone. Ours is wired directly into the StepSecurity platform.
1
Discover
Two signals no one else combines: AI Package Analyst continuously analyzes newly published package versions across ecosystems, and Harden Runner provides runtime insights from inside CI runners across thousands of repositories. This is how we find compromises first, and it is a key differentiator.
AI Package Analyst + Harden Runner runtime insights

2
Investigate
An on-call threat intelligence team investigates each and every alert before it is published. Humans confirm the compromise, reproduce the attack where possible, and notify maintainers. No auto-published noise, no false alarms in your feed.
Every alert human-verified

3
Publish and Protect
The advisory ships with affected versions, malicious domains, and remediation steps, free for everyone. For customers, the IOCs flow straight into the platform: Threat Center alerts your team, Compromised Actions Policy cancels affected runs, and Harden Runner blocks exfiltration.
Automatic, org-wide, in minutes

## Want these alerts in your SIEM, with automated blocking?

Threat Center pushes advisories to Slack, Splunk, and Sentinel the moment they publish, and the platform automatically blocks known-compromised actions, packages, and domains across your organization.
Request a demoStart Free
