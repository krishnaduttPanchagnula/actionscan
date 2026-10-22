<!-- Source: https://docs.stepsecurity.io/administration_admin-console_integrations_stepsecurity-api-tenant-access
Fetched: 2026-10-22
Method: webfetch-equivalent (curl + HTML-to-text)
Status: 200 OK (GitBook .md export)
-->

> For the complete documentation index, see [llms.txt](https://docs.stepsecurity.io/llms.txt). Markdown versions of documentation pages are available by appending `.md` to page URLs; this page is available as [Markdown](https://docs.stepsecurity.io/administration/admin-console/integrations/stepsecurity-api-tenant-access.md).

# StepSecurity API (Tenant Access)

{% hint style="info" %}
This page covers API access for managing all organizations under your tenant. If you only need access for a single organization, refer to [this page](/workspace/settings/stepsecurity-api-org-access.md)
{% endhint %}

The StepSecurity API page at the tenant level is where you manage tenant-scoped credentials, federation, and API reference for calling the StepSecurity API. It is available under Admin console > Integrations > StepSecurity API, with three tabs:

* API keys, for managing administrative, read-only, registry, and fine-grained tenant API keys
* OIDC (OpenID Connect) federation, for letting GitHub Actions workflows mint short-lived API tokens at the tenant scope without a stored secret
* API reference, an interactive browser for the StepSecurity API endpoints

Tenant-level credentials are broader than organization-level ones: they can act across every organization under the tenant. For credentials scoped to a single organization, see StepSecurity API (Organization).

### API keys

Four kinds of API credentials are available at the tenant level:

* Tenant API Key, a single administrative key for tenant- and organization-level operations
* Tenant Read-Only API Key, a single read-only key for tenant- and organization-level operations
* Secure Registry API Key, a key for Secure Registry operations
* Fine-grained API keys, scoped service credentials for tenant-level automation

Fine-grained keys are the recommended option for service-to-service automation. Use the administrative keys only when you need their broader access.

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2FDf7hWx6WwyaIEQV9pv1r%2FScreenshot%202026-05-25%20at%2014.57.10.png?alt=media&amp;token=e4c7716d-bb50-40b0-8345-09ce7ec2836a" alt=""><figcaption></figcaption></figure>

#### Tenant API Key

The Tenant API Key is an administrative API key for tenant- and organization-level operations. All tenant-level and organization-level APIs work with this key.

You can hold a Primary and a Secondary key at the same time and rotate between them. Use the Rotate button to mint a new value for the selected key. The Last rotated timestamp under each key shows when it was last regenerated.

This key is broad. Prefer a fine-grained API key for anything other than administrative use.

#### Tenant Read-Only API Key

The Tenant Read-Only API Key is a read-only API key for tenant- and organization-level operations. Only read operations will work with this key, which makes it a safer default for reporting, dashboards, and any integration that does not need to modify state.

Primary and Secondary slots are available for rotation, just like the Tenant API Key.

#### Secure Registry API Key

The Secure Registry API Key authenticates calls to Secure Registry operations. Use it from registry clients and any tooling that interacts with the Secure Registry. Primary and Secondary slots are available for rotation.

#### Fine-grained API keys

Fine-grained API keys are long-lived service credentials for tenant-level automation. They are the recommended way to authenticate backend services that call the StepSecurity API across the tenant.

Each key has the following properties:

* Scoped to the tenant. The key can act across organizations under the tenant, subject to the permissions you grant
* Fine-grained permissions, scoped to exactly what the integration needs
* Configurable expiration, up to 1 year
* Shown only once at creation

**Creating a fine-grained API key**

* On the API keys tab, in the Fine-grained API keys section, click New key. If you have not created any keys yet, click Create your first key
* Enter a Name. The name is required, helps you identify the key later, and cannot be changed after creation
* Choose an Expiration: 7 days, 30 days, 90 days, or 1 year. You can also enter a Custom (days) value. The Expires at timestamp updates to reflect your choice
* Select Permissions. Expand each category to pick specific permissions, or use the bulk controls on a category header (No access, Grant read, Clear) to set every permission in that category at once. Once permissions are granted in a category, its header shows a granted count (for example, 1 of 8 granted). Tenant-level categories include Apps & PATs, Action Secrets, Actions, Reports, Dev Machine Guard, Settings, Admin Console, and Supply Chain, with the exact list depending on what your tenant has enabled. Each permission can be set to No access, Read-only, or Read & write
* Click Create key

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2FFoBvnKisOwiWeCDI6IN4%2FScreenshot%202026-05-25%20at%2014.58.51.png?alt=media&amp;token=71d3fefd-a6d9-4739-86dc-8b1d5ab8156f" alt=""><figcaption></figcaption></figure>

* Copy the raw key from the confirmation screen and store it somewhere safe

The raw key is shown only once, immediately after creation. If you close the screen without copying it, you will need to create a new key.

You can only grant permissions you already have. Keys cannot escalate beyond your effective access.

**Admin Console permissions**

The Admin Console category grants API access to tenant administration itself, matching the sections of the Admin Console. Because these permissions control who can manage credentials, members, and access control, grant them sparingly. The category contains eight permissions:

| Permission      | Slug                | Grants access to                                                                                                                                                                 |
| --------------- | ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Resources       | `resources`         | GitHub Cloud, GHES, GitLab, and Azure DevOps server and organization management                                                                                                  |
| Integrations    | `integrations`      | S3, webhook, Slack, and other external integrations                                                                                                                              |
| Tenant API Keys | `tenant-api-keys`   | Tenant-level StepSecurity API keys: Tenant, Tenant Read-Only, Secure Registry, Broker, ARC, and tenant-wide self-hosted VM API keys. Read fetches key values, write rotates them |
| Members         | `users`             | Customer member (user) provisioning and lifecycle                                                                                                                                |
| Security & Auth | `security-auth`     | SSO configuration and authentication options                                                                                                                                     |
| Audit Logs      | `audit-logs`        | Customer activity audit trail                                                                                                                                                    |
| Roles           | `roles`             | Custom role definitions and the permission catalog                                                                                                                               |
| Settings        | `customer-settings` | Customer-level admin settings                                                                                                                                                    |

Audit Logs is an append-only trail, so it supports No access and Read-only but not Read & write.

A key with write access to Tenant API Keys, Members, Security & Auth, or Roles can change who and what can access your tenant. Treat such keys like the Tenant API Key itself: shortest workable expiration, tight storage, and rotation on any suspicion of exposure.

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2FgKuBIk0ie0nITTMxXi5t%2FScreenshot%202026-07-11%20at%2001.20.05.png?alt=media&amp;token=bb0c5bbb-2513-4a4b-94b1-a0e5974688b4" alt=""><figcaption></figcaption></figure>

**Rotating and revoking**

Keys cannot be extended. To rotate, revoke the existing key and create a new one with the duration and permissions you need. Revocation takes effect immediately, and any service still using the old key will start receiving authentication errors on the next request.

To revoke a key, find it in the Fine-grained API keys list and remove it.

### OIDC federation

OIDC federation lets GitHub Actions workflows mint short-lived StepSecurity API tokens at the tenant scope by exchanging their GitHub OIDC token, without storing a long-lived API key as a secret.

A trust policy is the rule that decides which workflow runs are allowed to exchange their OIDC token, and what permissions the minted StepSecurity token gets. You add one or more policies on the OIDC federation tab.

Tenant-scope policies differ from organization-scope policies in two important ways:

* They are not pinned to a single organization. You can match any `repository_owner` under your tenant
* The minted token operates at the tenant scope, so it can act across organizations subject to the permissions you allow

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2Fht4XyspzF7PmZQAS7EEl%2FScreenshot%202026-05-25%20at%2014.59.34.png?alt=media&amp;token=3ce51004-eaa9-4fcb-9b2c-592254875407" alt=""><figcaption></figcaption></figure>

#### How GitHub Actions uses the federation

Workflows must request a specific audience when minting their OIDC token, or the exchange will fail with audience-mismatch. The required audience is shown on the OIDC federation tab and follows this pattern:

```
<tenant>.api.stepsecurity.io
```

For example, a tenant named acme-corp would use `acme-corp.api.stepsecurity.io`.

The OIDC federation tab includes a Show ready-to-paste workflow snippet expandable that contains a complete GitHub Actions example. Copy this into your workflow as a starting point.

#### Creating an OIDC trust policy

* On the OIDC federation tab, click New policy. If you have not created any policies yet, click Create your first policy
* Enter a Name. The name must be unique within this scope
* (Optional) Add a Description to explain what the policy is for
* Fill in the Required claims. Every non-empty field must equal the corresponding JWT (JSON Web Token) claim from the GitHub OIDC token. Empty fields are wildcards. At least one of Repo owner or Repository is required:
  * Repo owner (`repository_owner`), for example `acme`. Free text at the tenant level, so you can match any owner under your tenant
  * Repository (`repository`), for example `acme/infra`
  * Workflow ref (`job_workflow_ref`), for example `acme/infra/.github/workflows/deploy.yml@refs/heads/main`
  * Ref, for example `refs/heads/main`
  * Environment, for example `production`
* Set Max session duration. This caps the lifetime of tokens minted through this policy. The maximum allowed is 1 hour (3600 seconds). Set to 0 to use the server default
* Select Permissions. This is an allowlist applied to tokens minted through this policy and must be a subset of your effective permissions. Use Read all as a shortcut, or expand each category to pick specific permissions
* Click Create policy

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2Fiy9Y4Sj7dIdM7YrKOoah%2FScreenshot%202026-05-25%20at%2015.01.35.png?alt=media&amp;token=6a2d0616-7e6f-4457-a47c-9616034996ed" alt=""><figcaption></figcaption></figure>

#### Designing claim rules

Tenant policies can match across organizations, which makes narrow claim rules even more important. A few patterns:

* For a workflow that should only run from main on a specific repo, fill in Repository, Workflow ref, and Ref. Leave Repo owner empty if the repository value already pins the owner
* For a policy that covers multiple repos under the same owner, fill in Repo owner and leave Repository empty
* For a policy that should match any workflow under your tenant, leave Repo owner empty. Combine this with a specific Workflow ref or Environment so the match still has at least one strong constraint
* Prefer Workflow ref over Ref when you want to pin to a specific workflow file, because Workflow ref includes the file path

Empty fields act as wildcards. A policy with only a permissive permission set and no specific claim values would match almost any workflow in any org. Add at least one strong claim in production.

### API reference

The API reference tab is an interactive browser for the StepSecurity API, rendered from the OpenAPI specification.

You can:

* Browse endpoints grouped by feature area (Overview, Harden Runner, and others)
* Download the raw OpenAPI specification using the Download OpenAPI Spec button, for use in code generators, Postman, or other tooling
* Try requests directly from the browser by clicking Authorize and pasting a valid token

The production server is `https://agent.api.stepsecurity.io/v1`.

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2FDbGAnpWAmOdteTxJXAp4%2FScreenshot%202026-05-25%20at%2015.02.49.png?alt=media&amp;token=85696427-6e1c-4b20-ba1f-5cab4eb2d03f" alt=""><figcaption></figcaption></figure>

#### Authorizing in-browser requests

Click Authorize, paste a token, and you can call endpoints directly from the reference. Any of the following token types will work, as long as they have the permissions the endpoint requires:

* A short-lived per-user token from the personal access tokens page
* A fine-grained API key from any API keys tab
* A Tenant, Tenant Read-Only, Secure Registry, or Organization API key

For exploratory or interactive use, a short-lived token is recommended.

### Choosing the right credential

Use this rule of thumb:

* Short-lived token, for interactive work from your own machine: MCP (Model Context Protocol) clients, scripts, CLIs, debugging. Max 12 hours, tied to your user
* OIDC federation, for GitHub Actions workflows that need to call the StepSecurity API. No stored secret, tokens are minted on demand
* Fine-grained API key, for service-to-service automation outside GitHub Actions that needs to outlive 12 hours. Up to 1 year. Choose the tenant-level page when the integration needs to act across organizations, and the organization-level page when it should be pinned to one
* Tenant Read-Only API Key, for reporting and dashboards that only need read access
* Secure Registry API Key, only for Secure Registry operations
* Tenant API Key, only for administrative operations that need broad access. Rotate it on a schedule

### Security best practices

* Prefer OIDC federation over any stored API key when calling from GitHub Actions
* Prefer fine-grained keys over the Tenant API Key for everything else, and use the Tenant Read-Only API Key when write access is not needed
* Pin tenant fine-grained keys and OIDC policies as narrowly as possible. Tenant-scope credentials can act across organizations, so loose configuration has a larger blast radius than at the org level
* Pick the shortest expiration that fits the integration
* Grant only the permissions the integration actually needs. Avoid Read & write all unless required
* Store raw keys in a secure credential store (secret manager, CI secret). Do not commit them to source control
* Rotate keys before they expire to avoid downtime. Treat any key that may have been exposed as compromised and revoke it immediately


---

# Agent Instructions
This documentation is published with GitBook. GitBook is the documentation platform designed so that both humans and AI agents can read, navigate, and reason over technical content effectively. Learn more at gitbook.com.

## Querying This Documentation
If you need additional information that is not directly available in this page, you can query the documentation by asking a question.

Perform an HTTP GET request on the following URL with the `ask` and `goal` query parameters:

```
GET https://docs.stepsecurity.io/administration/admin-console/integrations/stepsecurity-api-tenant-access.md?ask=<question>&goal=<user_goal>
```

`ask` is the immediate question: it should be specific, self-contained, and written in natural language.
`goal` is what the user is ultimately trying to achieve, the reason they need the answer. Sharing it helps GitBook give you a better, more relevant answer. A goal is most helpful when it describes the outcome the user wants rather than restating the question. For example, with `ask=how do I create an API token`, a goal like `automate deployments from our CI pipeline` lets GitBook tailor the answer to that use case.

The response will contain a direct answer to the question and relevant excerpts and sources from the documentation.

Use this mechanism when the answer is not explicitly present in the current page, you need clarification or additional context, or you want to retrieve related documentation sections.
