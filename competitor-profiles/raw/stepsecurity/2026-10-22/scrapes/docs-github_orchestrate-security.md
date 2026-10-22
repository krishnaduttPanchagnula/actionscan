<!-- Source: https://docs.stepsecurity.io/github_orchestrate-security
Fetched: 2026-10-22
Method: webfetch-equivalent (curl + HTML-to-text)
Status: 200 OK (GitBook .md export)
-->

> For the complete documentation index, see [llms.txt](https://docs.stepsecurity.io/llms.txt). Markdown versions of documentation pages are available by appending `.md` to page URLs; this page is available as [Markdown](https://docs.stepsecurity.io/github/orchestrate-security.md).

# Orchestrate Security

Orchestrate Security analyzes your GitHub Actions workflows against security best practices and automatically fixes the gaps it finds. You choose the scope (a single workflow, a full repository, or your entire organization) and StepSecurity handles the remediation.

### Tools

| Tool                                                                   | Scope                         | Description                                                                                                      |
| ---------------------------------------------------------------------- | ----------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| [Secure Workflow](/github/orchestrate-security/secure-workflow.md)     | Single workflow               | Paste a workflow file and get a hardened version back instantly                                                  |
| [Secure Repo](/github/orchestrate-security/secure-repo.md)             | All workflows in a repository | Analyze an entire repo and generate a single PR with all fixes                                                   |
| [Policy-Driven PRs](/github/orchestrate-security/policy-driven-prs.md) | Organization-wide             | Define policies centrally, get automated PRs or Issues across all selected repositories *(Enterprise Tier only)* |

### What Gets Fixed

Across all three tools, StepSecurity can apply the following security enhancements to your workflows and repositories:

* Restrict `GITHUB_TOKEN` permissions to least privilege
* Add [Harden-Runner](/github-actions/harden-runner.md) for runtime security monitoring
* Pin GitHub Actions to full-length commit SHAs
* Pin Docker image tags to immutable digests
* Update or create [Dependabot](https://docs.github.com/en/code-security/dependabot) configuration
* Add [CodeQL](https://codeql.github.com/) static analysis (SAST)
* Add [Dependency Review](https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/about-dependency-review) for PR-level vulnerability scanning
* Add [OpenSSF Scorecard](https://securityscorecards.dev/) for security posture scoring
* Update [pre-commit](https://pre-commit.com/) hook configuration

For details on each enhancement — including what the fixes look like, exemption options, and configuration — see the individual tool pages above.

{% hint style="info" %}
Not every tool applies every enhancement. [Secure Workflow](/github/orchestrate-security/secure-workflow.md) focuses on workflow-level fixes (permissions, Harden-Runner, SHA pinning), while [Secure Repo](/github/orchestrate-security/secure-repo.md) and [Policy-Driven PRs](/github/orchestrate-security/policy-driven-prs.md) cover the full set including Dependabot, CodeQL, Scorecard.
{% endhint %}


---

# Agent Instructions
This documentation is published with GitBook. GitBook is the documentation platform designed so that both humans and AI agents can read, navigate, and reason over technical content effectively. Learn more at gitbook.com.

## Querying This Documentation
If you need additional information that is not directly available in this page, you can query the documentation by asking a question.

Perform an HTTP GET request on the following URL with the `ask` and `goal` query parameters:

```
GET https://docs.stepsecurity.io/github/orchestrate-security.md?ask=<question>&goal=<user_goal>
```

`ask` is the immediate question: it should be specific, self-contained, and written in natural language.
`goal` is what the user is ultimately trying to achieve, the reason they need the answer. Sharing it helps GitBook give you a better, more relevant answer. A goal is most helpful when it describes the outcome the user wants rather than restating the question. For example, with `ask=how do I create an API token`, a goal like `automate deployments from our CI pipeline` lets GitBook tailor the answer to that use case.

The response will contain a direct answer to the question and relevant excerpts and sources from the documentation.

Use this mechanism when the answer is not explicitly present in the current page, you need clarification or additional context, or you want to retrieve related documentation sections.
