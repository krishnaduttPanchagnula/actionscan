<!-- Source: https://docs.stepsecurity.io/github_orchestrate-security_policy-driven-prs
Fetched: 2026-10-22
Method: webfetch-equivalent (curl + HTML-to-text)
Status: 200 OK (GitBook .md export)
-->

> For the complete documentation index, see [llms.txt](https://docs.stepsecurity.io/llms.txt). Markdown versions of documentation pages are available by appending `.md` to page URLs; this page is available as [Markdown](https://docs.stepsecurity.io/github/orchestrate-security/policy-driven-prs.md).

# Policy Driven PRs

{% hint style="warning" %}
**Available for Enterprise Tier only**
{% endhint %}

Policy-Driven PRs automate security remediation across your repositories. Instead of manually fixing security misconfigurations one repository at a time, you define policies centrally and StepSecurity automatically generates Pull Requests to fix issues or creates GitHub Issues to track them.

This is especially valuable for organizations managing dozens or hundreds of repositories where manual remediation does not scale.

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2FFldiZqgVCJorHqMCViEm%2FScreenshot%202025-09-09%20at%2010.05.46.png?alt=media&#x26;token=992aa258-3f4c-40dc-8239-8230441fd7a3" alt=""><figcaption><p>Policy Driven PRs page</p></figcaption></figure>

### How It Works

1. **Configure policies** — Choose which security controls to enforce (e.g., pin actions to commit SHAs, add Harden-Runner, restrict token permissions).
2. **Select repositories** — Apply policies to specific repositories or organization-wide.
3. **Choose remediation mode** — StepSecurity either opens Pull Requests with fixes or creates GitHub Issues to track vulnerabilities.
4. **Review and merge** — Your team reviews the automated PRs or triages the issues as part of normal workflow.

## Remediation Options

Choose how StepSecurity should respond when security misconfigurations or vulnerabilities are detected:

### Pull Requests

StepSecurity automatically generates PRs that fix security issues, such as hardening actions, pinning tags to commit SHAs, or restricting token permissions. Your team reviews and merges these PRs like any other code change.

{% embed url="<https://app.storylane.io/share/fqqaobdwgodp>" %}

### GitHub Issues

StepSecurity automatically creates GitHub Issues to track and discuss detected vulnerabilities. This is useful when you want human review before applying fixes, or when remediation requires context that cannot be fully automated.

## Customizing the PR Template

You can edit the PR template to match your organization's conventions. Click **Edit PR template** to customize it.

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2Fas4AVxQg1qkDmn6bsXs1%2FScreenshot%202025-10-07%20at%2017.10.54.png?alt=media&#x26;token=4c730562-006a-413c-8841-7914e075867b" alt=""><figcaption><p>Edit PR template</p></figcaption></figure>

Keep the following placeholder unchanged so that actual security fixes are displayed correctly in the PR body:

```markdown
## Security Fixes
{{STEPSECURITY_SECURITY_FIXES}}
```

## Security Controls

Each control below targets a specific category of supply chain risk. Enable the ones relevant to your organization's security posture. When enabled, StepSecurity will automatically generate PRs or Issues based on your chosen remediation mode.

### Harden GitHub-Hosted Runner

**What it does:** Automatically adds the [Harden-Runner](https://docs.stepsecurity.io/harden-runner) GitHub Action as the first step in each job on GitHub-hosted runners.

**Why it matters:** CI/CD runners handle sensitive data — cloud secrets, NPM (Node Package Manager) tokens, production build artifacts — yet they often lack the runtime monitoring that corporate laptops and production servers receive. Harden-Runner closes this gap by providing runtime security monitoring purpose-built for CI/CD.

{% hint style="info" %}
**Real-world impact:** Harden-Runner has detected multiple real-world supply chain attacks, including the [tj-actions/changed-files compromise (CVE-2025-30066)](https://www.stepsecurity.io/blog/harden-runner-detection-tj-actions-changed-files-action-is-compromised), the [Sha1-Hulud npm attack in CNCF's Backstage](https://www.stepsecurity.io/blog/how-harden-runner-detected-the-sha1-hulud-supply-chain-attack-in-cncfs-backstage-repository), and a [compromise of the NX build system](https://www.stepsecurity.io/blog/supply-chain-security-alert-popular-nx-build-system-package-compromised-with-data-stealing-malware).
{% endhint %}

**What the PR contains:** Adds `step-security/harden-runner@v2` as the first step in every job that does not already have it, configured according to your chosen settings (see below).

#### **Configuring Harden-Runner**

Click the toggle next to **Harden GitHub-Hosted Runner** to enable it and open the **Harden Runner Configuration** modal. The modal offers two modes: a default configuration for quick setup, and a custom configuration for advanced use cases.

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2FcWParXOErF8SvOttzptK%2FScreenshot%202026-09-02%20at%202.30.25%E2%80%AFPM.png?alt=media&amp;token=bc9ef689-784e-4a16-b607-27f225371a1c" alt=""><figcaption></figcaption></figure>

**Use Default Configuration**

When this toggle is enabled, StepSecurity injects the standard Harden-Runner step into your workflow files with default settings:

```yaml
- name: Harden Runner
  uses: step-security/harden-runner@v2
  with:
    egress-policy: audit
```

This is the recommended starting point for most organizations. It enables runtime visibility into outbound network calls made during your CI/CD jobs without blocking any traffic, giving you a baseline to review before moving to a stricter egress policy.

**Customize Harden Runner Action**

If your organization needs to go beyond the default setup, enable **Customize Harden Runner Action**. This lets you define a custom step YAML that will be injected into workflows instead of the default step.

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2FcWParXOErF8SvOttzptK%2FScreenshot%202026-09-02%20at%202.30.25%E2%80%AFPM.png?alt=media&amp;token=bc9ef689-784e-4a16-b607-27f225371a1c" alt=""><figcaption></figcaption></figure>

The custom YAML editor accepts any valid Harden-Runner step definition. For example, you can enable Policy Store integration and pass in your StepSecurity API key:

```yaml
- name: Harden the runner
  uses: step-security/harden-runner@v2
  with:
    use-policy-store: true
    api-key: ${{ secrets.STEP_SECURITY_API_KEY }}
```

**Update existing configuration:** When this toggle is enabled, repositories that already have a Harden-Runner step will have their configuration updated to match your custom settings. When disabled (the default), StepSecurity only adds Harden-Runner to jobs that do not already have it, leaving existing configurations untouched.

**Target Runner Labels**

By default, Harden-Runner is added to all jobs in your workflow files. Enable **Target Runner Labels** to restrict this behavior to only jobs whose `runs-on` value matches one of the labels you specify. This is useful when your organization uses a mix of GitHub-hosted and self-hosted runners and you only want to apply Harden-Runner to specific runner types.

**Exempt Runner Labels**

Enable **Exempt Runner Labels** to skip adding Harden-Runner to jobs whose `runs-on` value matches one of the labels you specify — even if they would otherwise match **Target Runner Labels**. Exempt Runner Labels takes precedence over Target Runner Labels: a job matching both is skipped.

Exemption values support path-matching wildcards:

* `runs-on/**` — a globstar pattern that matches any number of path segments under `runs-on/` (e.g. matches `runs-on/gpu/large`, `runs-on/gpu/large/spot`, etc.)
* `runs-on/*/*` — matches exactly two segments under `runs-on/` (e.g. matches `runs-on/gpu/large`, but not `runs-on/gpu` or `runs-on/gpu/large/spot`)

### Pin Actions to Full-Length Commit SHA

**What it does:** Replaces mutable tags (e.g., `actions/checkout@v4`) with full-length commit SHA references (e.g., `actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683`).

**Why it matters:** GitHub Action tags are mutable — a tag like `v4` can be moved to point at entirely different code without any notification to consumers. If an action maintainer's account is compromised, an attacker can retag a malicious commit and every workflow referencing that tag will silently execute the attacker's code. Pinning to a commit SHA ensures your workflow always runs the exact code you reviewed.

{% hint style="success" %}
**Recommended by GitHub.** GitHub's own [Security Hardening Guide](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions) recommends pinning actions to full-length commit SHAs as a best practice.
{% endhint %}

**What the PR contains:** Updates all action references in your workflow files from tags to their corresponding full-length commit SHAs, with the original tag preserved as an inline comment for readability.

{% hint style="info" %}
**Exemptions:** You can exempt specific actions using the **Exempted Actions** input.

* `actions/checkout@v3` — exempts a specific action at a specific tag
* `actions/*` — exempts all actions under a specific owner
  {% endhint %}

{% hint style="warning" %}
**Exempt your internal actions.** StepSecurity does not currently pin internal actions (actions hosted in your own organization, such as `myorg/my-action`). If a workflow references an internal action that has not been exempted, that workflow file will not be fixed.

To ensure your workflow files are pinned, add your organization's actions to the **Exempted Actions** input using an owner wildcard, for example `myorg/*`.
{% endhint %}

### Restrict GitHub Token Permissions

**What it does:** Adds explicit `permissions` blocks to your workflow files, scoping `GITHUB_TOKEN` access to only what each job actually needs.

**Why it matters:** By default, GitHub Actions workflows receive a `GITHUB_TOKEN` with broad `read/write` access to the repository. If a workflow or dependency is compromised, that token can be used to push malicious code, create releases, or modify repository settings. Restricting permissions to the minimum required (principle of least privilege) limits the blast radius of any compromise.

{% hint style="warning" %}
**Default risk:** Without explicit permissions, every job in your workflow has `read/write` access to contents, packages, issues, pull requests, and more — even if the job only needs to read code.
{% endhint %}

**What the PR contains:** Adds a top-level `permissions: read-all` (or more restrictive) block and job-level permission overrides based on the API calls each job actually makes.

### Pin Image Tags to Digests in Dockerfiles

**What it does:** Replaces mutable Docker image tags (e.g., `FROM nginx:latest`) with immutable digest references (e.g., `FROM nginx@sha256:abc123...`).

**Why it matters:** Docker tags work the same way as GitHub Action tags — they are mutable pointers. The image behind `nginx:latest` today may not be the same image tomorrow. In a supply chain attack scenario, a compromised registry account could push a malicious image under an existing tag. Pinning to digests guarantees you always pull the exact image you intended.

{% hint style="info" %}
**Exemptions:** You can exempt specific images by listing their names in the exemption input.

* `nginx:alpine` — exempts a specific image and tag
* `postgres:14` — exempts a specific version
* `ubuntu:*` — wildcard to exempt all tags for an image
  {% endhint %}

**What the PR contains:** Updates `FROM` statements in your Dockerfiles to use digest references, with the original tag preserved as a comment.

### Replace Third-Party Actions with StepSecurity-Maintained Actions

**What it does:** Swaps popular third-party GitHub Actions with secure, audited drop-in replacements maintained by StepSecurity.

**Why it matters:** Every third-party action runs inside your CI/CD environment with access to your secrets and source code. StepSecurity-maintained replacements are continuously audited, giving you the same functionality with a significantly reduced supply chain risk.

{% hint style="success" %}
**Drop-in compatible.** StepSecurity-maintained actions are designed as direct replacements, same inputs, same outputs so switching requires no workflow logic changes.
{% endhint %}

**What the PR contains:** Replaces references to supported third-party actions with their StepSecurity-maintained equivalents, according to the mode and version rules you configure.

#### **Configuring Maintained Action Replacement**

**Replace Modes**

Choose how StepSecurity decides which actions get replaced:

* **Replace selected actions** *(default)* — only actions you check in the list are replaced. Use this for gradual, opt-in rollout.
* **Replace all, except exempted** — every action with a StepSecurity-maintained equivalent is replaced, except the ones you check. Use this for maximum coverage; new actions added to the catalog are included automatically.

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2FUvmF4jiuOXlLbDVNBDtk%2FScreenshot%202026-04-22%20at%2004.14.36.png?alt=media&#x26;token=74ad25f3-580e-4025-82dc-1bf1b0a8c504" alt=""><figcaption></figcaption></figure>

**Restrict replacement to same major version**

By default, StepSecurity replaces third-party actions with the **latest** version of the StepSecurity-maintained equivalent, regardless of which major version you were using.

Enable **Restrict replacement to same major version** to only replace when the major version matches. For example:

* `aquasecurity/setup-trivy@v0.2.3` → replaced only if `step-security/setup-trivy@v0` is available
* `aquasecurity/setup-trivy@v1.0.0` → replaced only if `step-security/setup-trivy@v1` is available

Use this when workflows depend on version-specific behavior and you want to avoid unexpected breaking changes from major-version jumps.

### Replace with Runner Labels

**What it does:** Replaces specific `runs-on` labels in your workflow files with alternative runner labels you define.

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2FwWJkmaYQm2fvsrCNv5dM%2FScreenshot%202026-05-13%20at%2020.13.29.png?alt=media&#x26;token=afc06846-7f17-4257-873e-c89f69e5a846" alt=""><figcaption></figcaption></figure>

**Why it matters:** This is useful when migrating from one runner fleet to another (e.g., from GitHub-hosted to self-hosted, or from one cloud provider to another), when standardizing runner label conventions across an organization, or when routing jobs to hardened runner pools with Harden-Runner pre-installed.

**What the PR contains:** Updates `runs-on` values in your workflow files to the replacement labels you specify.

### Update Dependabot Configuration

**What it does:** Enhances or creates a `dependabot.yml` configuration file in your repositories to ensure dependencies are kept up to date.

**Why it matters:** Outdated dependencies are one of the most common attack vectors in software supply chains. [Dependabot](https://docs.github.com/en/code-security/dependabot) automatically creates PRs when new versions of your dependencies are available, but many repositories either lack a Dependabot configuration or have an incomplete one that only covers a subset of their ecosystems.

{% hint style="info" %}
**Enhanced configuration options:** Through StepSecurity, you can add support for additional ecosystems (e.g., npm, pip, Docker, GitHub Actions), edit configurations directly in the StepSecurity platform, and use `cooldown` and `group` attributes to control update frequency and organize dependency updates.
{% endhint %}

**What the PR contains:** Adds or updates the `.github/dependabot.yml` file with expanded ecosystem coverage and configuration options.

**This interactive demo walks through configuring cooldown and group attributes for a repository using Policy Driven PRs:**

{% embed url="<https://app.storylane.io/share/bcbfgosjjkfa>" %}

### Update Pre-Commit Configuration

**What it does:** Adds or updates [pre-commit](https://pre-commit.com/) hook configurations in your repositories.

**Why it matters:** Pre-commit hooks are your first line of defense — they run checks locally before code is committed, catching issues like secrets in code, formatting violations, and known vulnerability patterns before they ever reach CI/CD. Keeping these configurations up to date ensures your hooks reflect current best practices and detect the latest threat patterns.

**What the PR contains:** Adds or updates the `.pre-commit-config.yaml` file with recommended hooks and updated hook versions.

### Add GitHub Actions from Workflow Templates

**What it does:** Adds workflows from your organization's recommended workflow template set that are missing from a repository.

**Why it matters:** Organizations often define standard CI/CD workflows (e.g., security scanning, linting, release pipelines) as [reusable workflow templates](https://docs.github.com/en/actions/sharing-automations/creating-workflow-templates-for-your-organization). However, new repositories or older repositories may not have adopted all of the organization's standard workflows. This control automatically identifies missing workflows and adds them.

**What the PR contains:** Adds workflow files from your organization's template repository that are not yet present in the target repository.

## Repository Selection

You can apply policies at two levels:

#### Organization-Wide

Select **All Repositories** to apply the configuration across your entire organization. When using this option, you can optionally filter by **repository topics** so that policies only apply to repositories matching specific criteria.

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2F42AwrUrvJ5EGcxfi49Mv%2FScreenshot%202025-12-08%20at%2015.10.42.png?alt=media&#x26;token=55bf5d91-53a7-4d33-b298-fae3d129766f" alt=""><figcaption><p>Repository selection with topic filtering</p></figcaption></figure>

#### Per-Repository Overrides

Even when using organization-wide policies, you can override settings for specific repositories. This is useful when certain repositories have unique requirements that differ from the organization default.

**To set up a repository-level configuration:**

**Step 1:** Click the three dots (⋯) next to the repository you want to configure.

![](https://ajeuwbhvhr.cloudimg.io/https://colony-recorder.s3.amazonaws.com/files/2025-10-13/30845caf-f4e5-48df-b683-7ab76e3ffa30/ascreenshot.jpeg?tl_px=1058,150\&br_px=3024,1249\&force_format=jpeg\&q=100\&width=1120.0\&wat=1\&wat_opacity=1\&wat_gravity=northwest\&wat_url=https://colony-recorder.s3.amazonaws.com/images/watermarks/8B5CF6_standard.png\&wat_pad=1013,276)

**Step 2:** Click **Configure repository settings**.

![](https://ajeuwbhvhr.cloudimg.io/https://colony-recorder.s3.amazonaws.com/files/2025-10-13/24e50782-da2a-4609-98e2-4ed5952fbd35/ascreenshot.jpeg?tl_px=1058,230\&br_px=3024,1329\&force_format=jpeg\&q=100\&width=1120.0\&wat=1\&wat_opacity=1\&wat_gravity=northwest\&wat_url=https://colony-recorder.s3.amazonaws.com/images/watermarks/8B5CF6_standard.png\&wat_pad=948,276)

**Step 3:** Enable **Use repository-level configuration** and customize the settings as needed.

![](https://ajeuwbhvhr.cloudimg.io/https://colony-recorder.s3.amazonaws.com/files/2025-10-13/7c51338c-f510-4ac2-a88b-174e0a4d5deb/ascreenshot.jpeg?tl_px=272,0\&br_px=3024,1538\&force_format=jpeg\&q=100\&width=1120.0\&wat=1\&wat_opacity=1\&wat_gravity=northwest\&wat_url=https://colony-recorder.s3.amazonaws.com/images/watermarks/8B5CF6_standard.png\&wat_pad=897,17)

Repositories with custom configurations will display a **"Uses Repo Config"** tag next to their name.

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2FD9s6s13HUXmihFuQzjJl%2Fdocsss.jpg?alt=media&#x26;token=469179ba-7fd1-4564-b84b-4014738724c1" alt=""><figcaption></figcaption></figure>

## How Policy-Driven PRs Behave

This section covers how Policy-Driven PRs operate once enabled.

### One Open PR Per Repository

StepSecurity enforces a maximum of one open Policy-Driven PR per repository at a time.

If you enable an additional control while a Policy-Driven PR is already open (for example, you turn on "Replace third-party actions with StepSecurity-maintained actions" while a SHA-pinning PR is still open), StepSecurity does not open a second PR and does not modify the existing one. The new fix is queued instead.

Once the open PR is merged or closed, the next scheduled scan picks up all currently-enabled controls and generates a fresh PR containing every queued fix. Scans run automatically, with no manual trigger needed.

To bundle multiple sets of fixes into a single PR from the start, enable all the controls you want before the first scan runs. If a PR is already open and you want to add more fixes, merge or close it first so the next scan can regenerate it with the additional fixes.

### Merge Conflicts on Open PRs

StepSecurity does not automatically rebase or update an open Policy-Driven PR when new commits land on the target branch. If the target branch (for example, `main`) moves ahead while a StepSecurity-generated PR is still open, the PR remains open with merge conflicts.

To resolve this, close the conflicted PR. On the next scan, StepSecurity generates a fresh PR against the latest target branch.

## Managing Policies with Terraform

In addition to the UI, you can manage Policy-Driven PR configuration as code using the `stepsecurity_policy_driven_pr` resource in the [StepSecurity Terraform provider](https://github.com/step-security/terraform-stepsecurity-examples/tree/main/examples/gh-policy-driven-pr).

### Scoping to Repositories

Three arguments on the resource control which repositories a policy applies to:

* `selected_repos`: the repositories the policy applies to. Use an explicit list (`["repo-a", "repo-b"]`) or the wildcard `["*"]` to target all repositories.
* `excluded_repos`: repositories to opt out when `selected_repos` is set to `["*"]`.
* `selected_repos_filter`: restricts an organization-wide policy to repositories carrying specific topics, using `include_repos_only_with_topics`. This is the Terraform equivalent of the topic filtering described under Repository Selection.

The security controls themselves are configured inside the nested `auto_remediation_options` block.

**Apply to specific repositories:**

```hcl
resource "stepsecurity_policy_driven_pr" "selected" {
  owner          = "organization-name"
  selected_repos = ["test-repo-old"]

  auto_remediation_options = {
    create_pr                         = true
    harden_github_hosted_runner       = true
    pin_actions_to_sha                = true
    restrict_github_token_permissions = true
    secure_docker_file                = true
    actions_to_exempt_while_pinning   = ["actions/checkout", "actions/setup-node"]
  }
}
```

{% hint style="warning" %}
When enabling `pin_actions_to_sha`, include your organization's internal actions in `actions_to_exempt_while_pinning` using an owner wildcard (for example, `"myorg/*"`). StepSecurity does not currently pin internal actions, and workflow files that reference non-exempted internal actions will not be fixed. See the note under Pin Actions to Full-Length Commit SHA.
{% endhint %}

**Apply organization-wide with exclusions:**

```hcl
resource "stepsecurity_policy_driven_pr" "org_with_exclusions" {
  owner          = "organization-name"
  selected_repos = ["*"]
  excluded_repos = ["archived-repo", "test-repo-old"]

  auto_remediation_options = {
    create_pr                   = true
    harden_github_hosted_runner = true
    pin_actions_to_sha          = true
  }
}
```

**Apply organization-wide, filtered by repository topic:**

```hcl
resource "stepsecurity_policy_driven_pr" "org_by_topic" {
  owner          = "organization-name"
  selected_repos = ["*"]

  selected_repos_filter = {
    include_repos_only_with_topics = ["topic1", "topic2"]
  }

  auto_remediation_options = {
    create_pr                   = true
    harden_github_hosted_runner = true
    pin_actions_to_sha          = true
  }
}
```


---

# Agent Instructions
This documentation is published with GitBook. GitBook is the documentation platform designed so that both humans and AI agents can read, navigate, and reason over technical content effectively. Learn more at gitbook.com.

## Querying This Documentation
If you need additional information that is not directly available in this page, you can query the documentation by asking a question.

Perform an HTTP GET request on the following URL with the `ask` and `goal` query parameters:

```
GET https://docs.stepsecurity.io/github/orchestrate-security/policy-driven-prs.md?ask=<question>&goal=<user_goal>
```

`ask` is the immediate question: it should be specific, self-contained, and written in natural language.
`goal` is what the user is ultimately trying to achieve, the reason they need the answer. Sharing it helps GitBook give you a better, more relevant answer. A goal is most helpful when it describes the outcome the user wants rather than restating the question. For example, with `ask=how do I create an API token`, a goal like `automate deployments from our CI pipeline` lets GitBook tailor the answer to that use case.

The response will contain a direct answer to the question and relevant excerpts and sources from the documentation.

Use this mechanism when the answer is not explicitly present in the current page, you need clarification or additional context, or you want to retrieve related documentation sections.
