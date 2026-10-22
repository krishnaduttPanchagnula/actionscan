<!-- Source: https://docs.stepsecurity.io/workspace_reports_actions-governance
Fetched: 2026-10-22
Method: webfetch-equivalent (curl + HTML-to-text)
Status: 200 OK (GitBook .md export)
-->

> For the complete documentation index, see [llms.txt](https://docs.stepsecurity.io/llms.txt). Markdown versions of documentation pages are available by appending `.md` to page URLs; this page is available as [Markdown](https://docs.stepsecurity.io/workspace/reports/actions-governance.md).

# Actions Governance

The Actions Governance report provides organization-wide visibility into the GitHub Actions used across your repositories.

It helps security teams and engineering leaders:

* Understand which actions are being used across workflows
* Identify risky or low-trust third-party dependencies
* Track action adoption trends over time
* Measure overall security posture using scoring and coverage metrics
* Monitor adoption of StepSecurity-maintained secure alternatives

This report is designed to support CI/CD governance and reduce exposure to supply chain threats.

## Report Overview

The Actions Governance report is organized into multiple sections that summarize:

* Total actions in use
* Risky action exposure
* Security score trends
* Usage-weighted posture
* StepSecurity-maintained adoption and coverage

Each widget provides actionable insight into the supply chain risk of workflow dependencies.

### Total Actions in Use

The Total Actions in Use widget shows the number of unique GitHub Actions currently referenced across your repositories.

#### Metrics Displayed

* Total Actions: Unique actions used across the organization
* Risky Actions: Actions with low security scores
* Standard Actions: Actions meeting acceptable security thresholds
* StepSecurity-Maintained Actions: Verified actions maintained by StepSecurity

This section helps answer how many third-party workflow dependencies does the organization rely on today?

### Actions Count History

The Actions Count History chart tracks how the number of actions used in workflows changes over time.

#### What It Shows

* Growth in action adoption
* Spikes that may indicate new dependencies introduced
* Trends in CI/CD expansion

This is useful for detecting sudden increases in external workflow dependencies.

### Risky Actions

The Risky Actions widget highlights actions with a security score ≤ 6.

These actions may introduce elevated supply chain risk due to:

* Unpinned versions
* Unverified publishers
* Abandoned maintenance
* Known vulnerabilities
* Excessive permissions

This widget helps prioritize which actions should be reviewed or replaced first.

### Risky Actions History

The Risky Actions History chart shows how risky actions change over time.

#### Why It Matters

Tracking risky action growth helps teams answer:

* Are we reducing exposure over time?
* Are risky actions being introduced faster than they are remediated?

A sharp increase may signal governance gaps or unsecured workflow growth.

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2FcoI07nKb5luyCfDK2HZ6%2FScreenshot%202026-01-28%20at%2009.44.38.png?alt=media&amp;token=8232a21c-f4a1-44ce-8727-6188fe1b4267" alt=""><figcaption></figcaption></figure>

### Average Security Score

The Average Security Score widget represents the average security score across all unique actions in use.

A higher score indicates stronger workflow dependency hygiene.

### Score History

The Score History chart tracks how the organization’s average action security posture changes over time.

#### Use Cases

This chart helps identify:

* Whether posture is improving
* Whether newly introduced actions reduce security
* Whether remediation efforts have measurable impact

Even small declines can indicate new risky dependencies.

### Weighted Average Score

The Weighted Average Score represents the action security score weighted by frequency of usage.

A strong weighted score suggests the most frequently used actions tend to be secure.

### Weighted Score History

The Weighted Score History chart shows how weighted posture changes over time.

#### Why It Matters

This view is especially important when:

* A widely used action becomes risky
* High-impact dependencies are introduced
* Secure alternatives replace common actions

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2F3n5G47yElkFzty7FTBut%2FScreenshot%202026-01-28%20at%2009.45.07.png?alt=media&amp;token=cca10af2-5891-42a5-b9c7-c27316bc2f52" alt=""><figcaption></figcaption></figure>

### StepSecurity-Maintained Actions in Use

This widget shows how many StepSecurity-maintained secure alternatives are actively adopted across workflows.

StepSecurity provides hardened, security-reviewed replacements for commonly used third-party actions.

Adopting these reduces exposure to:

* Action repository takeover
* Unknown maintainers
* Compromised upstream dependencies

### Adoption History

The Adoption History chart tracks changes in StepSecurity-maintained action adoption over time.

#### What It Shows

* Whether teams are migrating toward secure alternatives
* Adoption progress across repositories
* Long-term supply chain posture improvement

### StepSecurity-Maintained Action Coverage

Coverage represents the percentage of security-relevant workflow action usage protected by StepSecurity-maintained actions.

Higher coverage means:

* More workflows rely on verified secure actions
* Less exposure to third-party supply chain risk
* Stronger standardization and governance

### Coverage History

The Coverage History chart tracks improvement or regression in coverage over time. This helps teams measure whether governance policies are driving secure adoption.

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2Fc7mun2ppcDr4rWN6LGsW%2FScreenshot%202026-01-28%20at%2009.45.39.png?alt=media&amp;token=d9c3d807-0239-4b92-8cbd-f95e067611de" alt=""><figcaption></figcaption></figure>


---

# Agent Instructions
This documentation is published with GitBook. GitBook is the documentation platform designed so that both humans and AI agents can read, navigate, and reason over technical content effectively. Learn more at gitbook.com.

## Querying This Documentation
If you need additional information that is not directly available in this page, you can query the documentation by asking a question.

Perform an HTTP GET request on the following URL with the `ask` and `goal` query parameters:

```
GET https://docs.stepsecurity.io/workspace/reports/actions-governance.md?ask=<question>&goal=<user_goal>
```

`ask` is the immediate question: it should be specific, self-contained, and written in natural language.
`goal` is what the user is ultimately trying to achieve, the reason they need the answer. Sharing it helps GitBook give you a better, more relevant answer. A goal is most helpful when it describes the outcome the user wants rather than restating the question. For example, with `ask=how do I create an API token`, a goal like `automate deployments from our CI pipeline` lets GitBook tailor the answer to that use case.

The response will contain a direct answer to the question and relevant excerpts and sources from the documentation.

Use this mechanism when the answer is not explicitly present in the current page, you need clarification or additional context, or you want to retrieve related documentation sections.
