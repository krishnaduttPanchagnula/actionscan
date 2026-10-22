<!-- Source: https://docs.stepsecurity.io/workspace_settings_stepsecurity-api-org-access
Fetched: 2026-10-22
Method: webfetch-equivalent (curl + HTML-to-text)
Status: 200 OK (GitBook .md export)
-->

> For the complete documentation index, see [llms.txt](https://docs.stepsecurity.io/llms.txt). Markdown versions of documentation pages are available by appending `.md` to page URLs; this page is available as [Markdown](https://docs.stepsecurity.io/workspace/settings/stepsecurity-api-org-access.md).

# StepSecurity API (Org Access)

{% hint style="info" %}
In our platform, different organizations are grouped under a single tenant. This page describes API access for an individual organization. For access that applies to managing all organizations under your tenant, refer to [this page](/administration/admin-console/integrations/stepsecurity-api-tenant-access.md)
{% endhint %}

The StepSecurity API page at the organization level is where you manage credentials, federation, and API reference for calling the StepSecurity API against a specific organization. It is available under Settings > StepSecurity API in the left navigation, with three tabs:

* API keys, for managing administrative and fine-grained API keys
* OIDC (OpenID Connect) federation, for letting GitHub Actions workflows and AWS workloads mint short-lived API tokens without a stored secret
* API reference, an interactive browser for the StepSecurity API endpoints

## API keys

Three kinds of API credentials are available at the organization level:

* Organization API Key, a single administrative key for organization-level operations
* Tenant API Key, a single administrative key that also works for tenant-level operations
* Organization fine-grained API keys, scoped service credentials bound to this organization

Organization and Tenant API keys are administrative and broad. Fine-grained keys are the recommended option for service-to-service automation, because you can scope them to only the permissions and lifetime each integration needs.

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2FnNmnCceHAS9BtfjJol5H%2FScreenshot%202026-05-25%20at%2012.47.37.png?alt=media&amp;token=3a9925b9-dff0-437f-a90e-b09fa4a29792" alt=""><figcaption></figcaption></figure>

### Organization API Key

The Organization API Key is an administrative API key for organization-level operations. All organization-level APIs work with this key.

You can hold a Primary and a Secondary key at the same time and rotate between them. Use the Rotate button to mint a new value for the selected key. The Last rotated timestamp under each key shows when it was last regenerated.

This key is broad. Prefer a fine-grained API key for anything other than administrative use.

### Tenant API Key

The Tenant API Key is an administrative API key for tenant- and organization-level operations. All tenant-level and organization-level APIs work with this key, so it is broader than the Organization API Key.

The Tenant API Key is managed at the tenant level. For details on creating, rotating, and revoking it, see the tenant StepSecurity API page. It is surfaced here for reference and quick rotation.

### Organization fine-grained API keys

{% hint style="info" %}
Notifications will be sent when your fine-grained API keys are about to expire
{% endhint %}

Fine-grained API keys are long-lived service credentials bound to this organization. They are the recommended way to authenticate backend automation, CI integrations, and any other service that calls the StepSecurity API on behalf of this organization.

Each key has the following properties:

* Scoped to a single organization. The key only authenticates on `/v1/github/<organization>/*` routes and cannot be used against any other organization
* Fine-grained permissions, scoped to exactly what the integration needs
* Configurable expiration, up to 1 year
* Shown only once at creation

#### **Creating a fine-grained API key**

* On the API keys tab, in the Organization fine-grained API keys section, click New key. If you have not created any keys yet, click Create your first key

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2FW8WMGFbHH319UJDMDAnY%2FScreenshot%202026-05-25%20at%2012.49.54.png?alt=media&amp;token=31edc794-336f-4316-a940-32bf9a24eba1" alt=""><figcaption></figcaption></figure>

* Enter a Name. The name is required, helps you identify the key later, and cannot be changed after creation
* Choose an Expiration: 7 days, 30 days, 90 days, or 1 year. You can also enter a Custom (days) value. The Expires at timestamp updates to reflect your choice
* Select Permissions. Expand each category to pick specific permissions, or use the bulk controls on a category header (No access, Grant read, Clear) to set every permission in that category at once. Categories include Harden Runner, GitHub Checks, Orchestrate Security, Workflow Run Policies, Actions, Reports, Settings, and others depending on what your tenant has enabled. Each permission can be set to No access, Read-only, or Read & write
* Click Create key

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2F4gk2vWVk6n8pIiJ8Quf7%2FScreenshot%202026-05-25%20at%2012.50.32.png?alt=media&amp;token=f4f7dd49-8532-45ce-beac-d7d245aaf7b7" alt=""><figcaption></figcaption></figure>

* Copy the raw key from the confirmation screen and store it somewhere safe

The raw key is shown only once, immediately after creation. If you close the screen without copying it, you will need to create a new key.

You can only grant permissions you already have. Keys cannot escalate beyond your effective access.

**Settings permissions**

The Settings category grants access to the pages under Settings in the organization navigation. It contains four permissions:

| Permission            | Slug            | Grants access to                                                                                                                                   |
| --------------------- | --------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| Notifications         | `notifications` | Org-level notification routing and channel configuration                                                                                           |
| API Rate Limits       | `rate-limits`   | GitHub API rate-limit consumption observability (customer aggregate and per-owner views)                                                           |
| Organization API Keys | `api-keys`      | Organization-level StepSecurity API keys: the telemetry API key and the self-hosted runner VM API key. Read fetches key values, write rotates them |
| Control Evaluation    | `controls`      | Workflow security controls: summaries, exemptions, suppression, and control settings                                                               |

API Rate Limits is observability data, so it supports No access and Read-only but not Read & write.

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2FtQhXKJUYowjrXQek4pXQ%2FScreenshot%202026-07-11%20at%2000.06.38.png?alt=media&amp;token=2edcd226-3be3-47c5-9c20-7b33ff952b4e" alt=""><figcaption></figcaption></figure>

#### **Rotating and revoking**

Keys cannot be extended. To rotate, revoke the existing key and create a new one with the duration and permissions you need. Revocation takes effect immediately, and any service still using the old key will start receiving authentication errors on the next request.

To revoke a key, find it in the Organization fine-grained API keys list and remove it.

## OIDC federation

OIDC federation lets a workload mint short-lived StepSecurity API tokens by exchanging an identity token it already has, without storing a long-lived API key as a secret. Two providers are supported:

| Provider           | Who it is for                                                       | What the workload proves                                    |
| ------------------ | ------------------------------------------------------------------- | ----------------------------------------------------------- |
| **GitHub Actions** | Workflows running under your organization                           | Repository, ref, and environment, via the GitHub OIDC token |
| **AWS**            | Workloads running in your AWS account, such as EKS, EC2, and Lambda | Its IAM role, via AWS outbound identity federation          |

Each trust policy uses one provider. Pick the provider first, because it determines which identity fields the policy matches on.

A trust policy is the rule that decides which workloads are allowed to exchange their identity token, and what permissions the minted StepSecurity token gets. You add one or more policies on the OIDC federation tab.

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2Fugs7W6ZTuQnWgbDoVhDL%2FScreenshot%202026-05-25%20at%2012.52.27.png?alt=media&amp;token=511a2e4c-87fd-4def-9c96-c6f9ac8f26b4" alt=""><figcaption></figcaption></figure>

### How GitHub Actions uses the federation

Workflows must request a specific audience when minting their OIDC token, or the exchange will fail with audience-mismatch. The required audience is shown on the OIDC federation tab and follows this pattern:

```
<organization>.api.stepsecurity.io
```

For example, an organization named acme-corp would use `acme-corp.api.stepsecurity.io`.

The OIDC federation tab includes a Show ready-to-paste workflow snippet expandable that contains a complete GitHub Actions example. Copy this into your workflow as a starting point.

### How AWS workloads use the federation

AWS workloads authenticate using [AWS IAM outbound identity federation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_outbound.html), where the workload asks AWS STS for a short-lived, signed JSON Web Token that asserts its identity, then exchanges that token for a StepSecurity API token. Nothing is stored on the workload.

Three things must be in place in AWS before a policy will match:

1. **Outbound identity federation is enabled on the AWS account.** Enable it in the IAM console under **Account settings**, or with `aws iam enable-outbound-web-identity-federation`. Enabling it returns an issuer URL unique to the account, which looks like `https://<uuid>.tokens.sts.global.api.aws`. This is the value the trust policy needs. If the feature is already enabled, retrieve the issuer URL with `aws iam get-outbound-web-identity-federation-info`.
2. **The workload's IAM role can request a token.** The role needs the `sts:GetWebIdentityToken` permission.
3. **The workload requests the right audience.** As with GitHub Actions, an audience mismatch fails the exchange.

### Creating an OIDC trust policy

* On the OIDC federation tab, click New policy. If you have not created any policies yet, click Create your first policy
* Enter a Name. The name must be unique within this scope
* (Optional) Add a Description to explain what the policy is for
* Choose a **Provider**, either **GitHub Actions** or **AWS**. The identity fields below change to match the provider you pick
* **GitHub Actions provider.** Fill in the Required claims. Every non-empty field must equal the corresponding JWT (JSON Web Token) claim from the GitHub OIDC token. Empty fields are wildcards. At least one of Repo owner or Repository is required:
  * Repo owner (`repository_owner`). Locked to the current organization for org-scope policies
  * Repository (`repository`), for example `acme-corp/infra`
  * Workflow ref (`job_workflow_ref`), for example `acme-corp/infra/.github/workflows/deploy.yml@refs/heads/main`
  * Ref, for example `refs/heads/main`
  * Environment, for example `production`&#x20;
* **AWS provider.** Fill in Match AWS identity. The token is minted only for a workload whose identity matches every field you fill in. Issuer URL and AWS account ID are both required:
  * **Issuer URL**, for example `https://a1b2c3d4-....tokens.sts.global.api.aws`. Your AWS account's outbound-federation issuer, found in IAM under Account settings. This is the trust anchor used to verify tokens
  * **AWS account ID**, for example `123456789012`. The 12-digit account the workload runs in
  * **Role ARN** (optional), for example `arn:aws:iam::123456789012:role/checks-runner`. Matched against the workload's IAM role. Leave it blank to allow any role in the account. Session names and role paths are ignored

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2F0ZUNtia699kHBOoFg4jp%2FScreenshot%202026-08-24%20at%2011.58.28.png?alt=media&amp;token=d994ab7e-37f0-475f-adc4-8b556c087b5b" alt=""><figcaption></figcaption></figure>

* Set Max session duration. This caps the lifetime of tokens minted through this policy. The maximum allowed is 1 hour (3600 seconds). Set to 0 to use the server default
* Select Permissions. This is an allowlist applied to tokens minted through this policy and must be a subset of your effective permissions. Use Read all as a shortcut, or expand each category to pick specific permissions
* Click Create policy

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2FbjJIxo2x1PrPW1WulWRu%2FScreenshot%202026-05-25%20at%2012.56.39.png?alt=media&amp;token=12af2a12-47d6-4cd7-95b1-d4ac867e8325" alt=""><figcaption></figcaption></figure>

### Designing claim rules

Keep policies as narrow as the workload you are authorizing. A few patterns:

* For a deploy workflow that should only run from main on a specific repo, fill in Repository, Workflow ref, and Ref. Leave Environment empty unless you want to require it
* For a policy that covers multiple repos under the same owner, fill in Repo owner and leave Repository empty
* Prefer Workflow ref over Ref when you want to pin to a specific workflow file, because Workflow ref includes the file path

Empty fields act as wildcards, so an empty policy with only Repo owner set would match every workflow in the org. Add at least one more claim in production.

For AWS policies, the same principle applies to Role ARN. Leaving it blank trusts every role in the account, which is rarely what you want. Name the specific role the workload runs as, and give that role only the `sts:GetWebIdentityToken` permission it needs to mint a token.

## API reference

The API reference tab is an interactive browser for the StepSecurity API, rendered from the OpenAPI specification.

You can:

* Browse endpoints grouped by feature area (Overview, Harden Runner, and others)
* Download the raw OpenAPI specification using the Download OpenAPI Spec button, for use in code generators, Postman, or other tooling
* Try requests directly from the browser by clicking Authorize and pasting a valid token

The production server is `https://agent.api.stepsecurity.io/v1`.

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2FxrAXzL8N3RtGNFXb1ce0%2FScreenshot%202026-05-25%20at%2012.59.24.png?alt=media&amp;token=32f497ff-bf00-4075-b3c2-d83e38902884" alt=""><figcaption></figcaption></figure>

### Authorizing in-browser requests

Click Authorize, paste a token, and you can call endpoints directly from the reference. Any of the following token types will work, as long as they have the permissions the endpoint requires:

* A short-lived per-user token from the personal access tokens page
* A fine-grained API key from the API keys tab
* An Organization or Tenant API key

For exploratory or interactive use, a short-lived token is recommended.

## Choosing the right credential

Use this rule of thumb:

* Short-lived token, for interactive work from your own machine: MCP (Model Context Protocol) clients, scripts, CLIs, debugging. Max 12 hours, tied to your user
* OIDC federation, for GitHub Actions workflows that need to call the StepSecurity API. No stored secret, tokens are minted on demand
* Fine-grained API key, for service-to-service automation outside GitHub Actions that needs to outlive 12 hours. Up to 1 year, scoped to one organization
* Organization or Tenant API Key, only for administrative operations that need broad access. Rotate them on a schedule

## Security best practices

* Prefer OIDC federation over any stored API key when calling from GitHub Actions
* Prefer fine-grained keys over the Organization or Tenant API Key for everything else
* Pick the shortest expiration that fits the integration
* Grant only the permissions the integration actually needs. Avoid Read & write all unless required
* Store raw keys in a secure credential store (secret manager, CI secret). Do not commit them to source control
* Rotate keys before they expire to avoid downtime. Treat any key that may have been exposed as compromised and revoke it immediately
* Keep OIDC trust policies narrow. Pin Repository, Workflow ref, and Ref whenever possible


---

# Agent Instructions
This documentation is published with GitBook. GitBook is the documentation platform designed so that both humans and AI agents can read, navigate, and reason over technical content effectively. Learn more at gitbook.com.

## Querying This Documentation
If you need additional information that is not directly available in this page, you can query the documentation by asking a question.

Perform an HTTP GET request on the following URL with the `ask` and `goal` query parameters:

```
GET https://docs.stepsecurity.io/workspace/settings/stepsecurity-api-org-access.md?ask=<question>&goal=<user_goal>
```

`ask` is the immediate question: it should be specific, self-contained, and written in natural language.
`goal` is what the user is ultimately trying to achieve, the reason they need the answer. Sharing it helps GitBook give you a better, more relevant answer. A goal is most helpful when it describes the outcome the user wants rather than restating the question. For example, with `ask=how do I create an API token`, a goal like `automate deployments from our CI pipeline` lets GitBook tailor the answer to that use case.

The response will contain a direct answer to the question and relevant excerpts and sources from the documentation.

Use this mechanism when the answer is not explicitly present in the current page, you need clarification or additional context, or you want to retrieve related documentation sections.
