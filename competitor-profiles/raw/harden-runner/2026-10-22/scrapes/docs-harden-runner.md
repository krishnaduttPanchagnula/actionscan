> For the complete documentation index, see [llms.txt](https://docs.stepsecurity.io/llms.txt). Markdown versions of documentation pages are available by appending `.md` to page URLs; this page is available as [Markdown](https://docs.stepsecurity.io/github-actions/harden-runner.md).

# Harden-Runner

Corporate laptops and production servers have strong security monitoring for compliance and risk reduction. However, CI/CD runners, which handle sensitive data like cloud secrets and production builds, often lack such protections, making them targets for supply chain attacks like SolarWinds and Codecov.

Traditional security tools struggle with CI/CD runners due to their short-lived nature and lack of workflow context.

Harden-Runner fills this gap by providing tailored security monitoring, ensuring CI/CD runners receive the same protection as other critical systems.

**Community Tier Availability**

* **Public repositories only:** The Community Tier does not support private repositories. To enable Harden-Runner on private repositories, upgrade to the Enterprise Tier, which includes a 14-day free trial.

For teams with higher usage needs or private repository support, the Enterprise Tier provides expanded capacity and advanced features.

## Security Incidents Detected

* [Harden-Runner Detected the tj-actions/changed-files compromise](https://www.stepsecurity.io/blog/harden-runner-detection-tj-actions-changed-files-action-is-compromised) ([CVE-2025-30066](https://github.com/advisories/GHSA-mrrh-fwg8-r2c3))
* [Harden Runner Detected the Sha1-Hulud Supply Chain Attack in CNCF's Backstage Repository](https://www.stepsecurity.io/blog/how-harden-runner-detected-the-sha1-hulud-supply-chain-attack-in-cncfs-backstage-repository)
* [Harden-Runner Detected the NX Build System compromise](https://www.stepsecurity.io/blog/supply-chain-security-alert-popular-nx-build-system-package-compromised-with-data-stealing-malware)
* [Harden-Runner Detected a CI/CD Supply Chain Attack in Google’s Open-Source Project Flank](https://www.stepsecurity.io/case-studies/flank)
* [Harden-Runner Detected a CI/CD Supply Chain Attack in Microsoft’s Open-Source Project Azure Karpenter Provider in Real-Time](https://www.stepsecurity.io/case-studies/azure-karpenter-provider)
* [Harden-Runner Detected Anomalous Traffic to api.ipify.org Across Multiple Customers](https://www.stepsecurity.io/blog/harden-runner-detects-anomalous-traffic-to-api-ipify-org-across-multiple-customers)
* [Harden-Runner Detected an Unexpected Microsoft Defender Installation on GitHub-Hosted Ubuntu Runners](https://www.stepsecurity.io/blog/how-stepsecurity-harden-runner-detected-unexpected-microsoft-defender-installation-on-github-hosted-ubuntu-runners)

**Follow this interactive demo to see a real detection:**

{% embed url="<https://app.storylane.io/share/679y2zgzljov>" %}

## Threats in a CI/CD Environment

Compromised workflows, dependencies, and build tools pose several major threats:

1. Exfiltration of CI/CD credentials and source code
2. Tampering of source code, dependencies, or artifacts during the build process to inject backdoors
3. Exploitation of third party GitHub Actions
4. Dependency based supply chain attacks

To mitigate these risks, Harden-Runner provides key security measures. The table below outlines its core functionalities and the threats they help prevent:

| Security Measure                    | Function                                                                                                                                                                                     | Past Breach Example                                                                                                                                                                                                                                                                                                                                           |
| ----------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Network Traffic Control             | Monitor and block outbound network traffic at the DNS, HTTPS (Layer 7), and network layers (Layers 3 and 4) to prevent exfiltration of code and CI/CD credentials                            | To prevent the [Codecov breach](https://github.com/step-security/github-actions-goat/blob/main/docs/Vulnerabilities/ExfiltratingCICDSecrets.md#codecov-breach) scenario                                                                                                                                                                                       |
| Source Code Integrity Check         | Detect if source code is being tampered during the build process to inject a backdoor                                                                                                        | To detect the [XZ Utils](https://www.stepsecurity.io/blog/analysis-of-backdoored-xz-utils-build-process-with-harden-runner) and [SolarWinds incident ](https://github.com/step-security/github-actions-goat/blob/main/docs/Vulnerabilities/TamperingDuringBuild.md#sunspot-an-implant-in-the-build-process)scenarios                                          |
| Dependency and Workflow Monitoring  | Detect poisoned workflows and compromised dependencies that exhibit suspicious behavior                                                                                                      | To detect [Dependency confusion](https://github.com/step-security/github-actions-goat/blob/main/docs/Vulnerabilities/ExfiltratingCICDSecrets.md#dependency-confusion-attacks) and [Malicious dependencies](https://github.com/step-security/github-actions-goat/blob/main/docs/Vulnerabilities/ExfiltratingCICDSecrets.md#compromised-dependencies) scenarios |
| GitHub Token Permission Enforcement | Determine minimum GITHUB\_TOKEN permissions by monitoring HTTPS calls to GitHub APIs                                                                                                         | To set [minimum GITHUB\_TOKEN permissions](https://www.stepsecurity.io/blog/determine-minimum-github-token-permissions-using-ebpf-with-stepsecurity-harden-runner) to reduce the impact of exfiltration                                                                                                                                                       |
| Threat Intelligence-Driven Blocking | StepSecurity's 24×7 SOC identifies IOC domains and IPs from active supply-chain attacks and adds them to a Global Block List that is enforced automatically across every protected workflow. | To block exfiltration from the [pgserve npm compromise](https://www.stepsecurity.io/blog/pgserve-compromised-on-npm-malicious-versions-harvest-credentials) in real time                                                                                                                                                                                      |

## Global Block List

Harden-Runner enforces a **Global Block List** of domains and IP addresses associated with active supply-chain attacks. The list is maintained by StepSecurity's 24×7 Security Operations Center (SOC), which continuously tracks emerging threats across the CI/CD ecosystem and the npm, PyPI, and GitHub Actions registries.

**Automatic, zero-config enforcement:** When our SOC identifies a new indicator of compromise (IOC), it's added to the Global Block List and takes effect immediately across every workflow using Harden-Runner — no configuration change, no action version bump, no workflow edit required.

**Enforced regardless of egress policy:** The Global Block List is enforced even when a workflow is running in `egress-policy: audit` mode. IOCs represent known-malicious infrastructure, so customers shouldn't have to re-decide whether to block each one.

Allowlisting an IOC domain in your policy does **not** override the Global Block List. This is intentional — it prevents a compromised action or misconfigured workflow from granting itself access to known-malicious infrastructure.

**When an entry fires,** the blocked request appears on the workflow's Network Events and Detections views, labeled **Attack Blocked** so you can distinguish it from regular policy blocks.

{% hint style="info" %}
You don't manage the Global Block List directly — it's maintained centrally by StepSecurity so every customer benefits from threat intelligence gathered across the entire fleet. If you believe a domain has been blocked in error, contact StepSecurity support.
{% endhint %}

### Inspecting the Global Block List

The current contents of the Global Block List are available as a read-only JSON feed:

```
GET https://agent.api.stepsecurity.io/v1/global-blocklist
```

The endpoint is public, requires no authentication, and returns the live list of indicators currently enforced across every workflow protected by Harden-Runner. It is provided so security teams can audit what is being blocked on their behalf, integrate the list into their own threat-intelligence tooling, or confirm that a specific domain or IP is on the list.

## Enabling Runtime Security with Harden-Runner

Securing your CI/CD pipelines starts with protecting your runners. StepSecurity’s Harden-Runner provides comprehensive monitoring and protection across different runner environments. Because these runners handle sensitive build processes, dependencies, and secrets, runtime protection is essential to prevent supply chain attacks.

Harden-Runner supports multiple CI/CD runner types:

<table><thead><tr><th>Environment Type</th><th>Compatibility</th><th>Audit Mode Deployment</th><th width="141">Workflow Changes for Audit Mode</th></tr></thead><tbody><tr><td><a href="#github-hosted-runners">GitHub-Hosted runners</a> (Linux, macOS, Windows)</td><td>✅ Full support</td><td>Add Harden-Runner Action to workflow</td><td>Yes</td></tr><tr><td><a href="#github-hosted-custom-vm">GitHub-Hosted Custom VM</a></td><td>✅ Full support</td><td>Include agent in runner image</td><td>No</td></tr><tr><td><a href="#self-hosted-vm-runners">Self-hosted VM runners</a></td><td>✅ Full support</td><td>Include agent in runner image</td><td>No</td></tr><tr><td><a href="#self-hosted-bare-metal-runners">Self-hosted bare-metal runners</a></td><td>✅ Full support</td><td>Install agent as a service</td><td>No</td></tr><tr><td><a href="#actions-runner-controller-arc-runners">Actions Runner Controller (ARC)</a></td><td>✅ Full support</td><td>Deploy as DaemonSet</td><td>No</td></tr><tr><td><a href="/resources/partnerships/runson.md">RunsOn Runners</a></td><td>✅ Full support</td><td>Pre-integrated</td><td>No</td></tr><tr><td><a href="#blacksmith">BlackSmith</a></td><td>✅ Full support</td><td>Add Harden-Runner Action to workflow</td><td>Yes</td></tr><tr><td><a href="#namespace">Namespace</a></td><td>✅ Full support</td><td>Add Harden-Runner Action to workflow</td><td>Yes</td></tr><tr><td><a href="#warp">Warp</a></td><td>✅ Full support</td><td>Add Harden-Runner Action to workflow</td><td>Yes</td></tr><tr><td><a href="#depot">Depot</a></td><td>✅ Full support</td><td>Add Harden-Runner Action to workflow</td><td>Yes</td></tr><tr><td><a href="#bitrise">Bitrise (macOS)</a></td><td>✅ Full support</td><td>Add Harden-Runner Action to workflow</td><td>Yes</td></tr><tr><td><a href="#aws-codebuild">AWS CodeBuild</a></td><td>✅ Full support</td><td>Add Harden-Runner Action to workflow</td><td>Yes</td></tr></tbody></table>

**Follow this interactive demo to see how it works:**

{% embed url="<https://app.storylane.io/share/xhizsh7scdwr>" %}

### Platform Capability Matrix

Harden-Runner's capabilities vary by runner operating system. The matrix below shows which features are currently supported on Linux, macOS, and Windows.

<table><thead><tr><th width="420.81512451171875">Capability</th><th align="center">Linux</th><th align="center">macOS</th><th align="center">Windows</th></tr></thead><tbody><tr><td>GitHub-hosted runner support</td><td align="center">✅</td><td align="center">✅</td><td align="center">✅</td></tr><tr><td>Self-hosted VM (ephemeral)</td><td align="center">✅</td><td align="center">✅</td><td align="center">✅</td></tr><tr><td>Self-hosted VM (persistent)</td><td align="center">✅</td><td align="center">✅</td><td align="center">✅</td></tr><tr><td>Network + DNS monitoring</td><td align="center">✅</td><td align="center">✅</td><td align="center">✅</td></tr><tr><td>Process monitoring</td><td align="center">✅</td><td align="center">✅</td><td align="center">✅</td></tr><tr><td>Correlation of events with the exact workflow step</td><td align="center">✅</td><td align="center">✅</td><td align="center">✅</td></tr><tr><td>Job summaries in workflow logs</td><td align="center">✅</td><td align="center">✅</td><td align="center">✅</td></tr><tr><td>Imposter commit detection</td><td align="center">✅</td><td align="center">✅</td><td align="center">✅</td></tr><tr><td>Secrets and build-log detection</td><td align="center">✅</td><td align="center">✅</td><td align="center">✅</td></tr><tr><td>Source code overwrite detection</td><td align="center">✅</td><td align="center">✅</td><td align="center">❌</td></tr><tr><td>File write events (GitHub-Hosted)</td><td align="center">✅</td><td align="center">✅</td><td align="center">❌</td></tr><tr><td>File write events (Self-Hosted, ephemeral)</td><td align="center">✅</td><td align="center">✅</td><td align="center">❌</td></tr><tr><td>File write events (Self-Hosted, persistent)</td><td align="center">❌</td><td align="center">✅</td><td align="center">❌</td></tr><tr><td>Custom VM image baking</td><td align="center">✅</td><td align="center">❌</td><td align="center">✅</td></tr><tr><td>Non-intrusive HTTPS monitoring</td><td align="center">✅</td><td align="center">❌</td><td align="center">❌</td></tr><tr><td>Suspicious process event detection</td><td align="center">✅</td><td align="center">❌</td><td align="center">❌</td></tr><tr><td>Known C2 endpoint blocking</td><td align="center">✅</td><td align="center">✅</td><td align="center">❌</td></tr><tr><td>Agent tampering detection</td><td align="center">✅</td><td align="center">❌</td><td align="center">❌</td></tr><tr><td>Runner.Worker memory-dump detection (prevents secret exfiltration)</td><td align="center">✅</td><td align="center">❌</td><td align="center">❌</td></tr><tr><td>Policy Store enforcement</td><td align="center">✅</td><td align="center">✅</td><td align="center">✅</td></tr><tr><td>Block mode (GitHub-hosted, supported for Allow list)</td><td align="center">✅</td><td align="center">✅</td><td align="center">✅</td></tr><tr><td>Block mode (Self-hosted, supported for Allow list)</td><td align="center">✅</td><td align="center">✅</td><td align="center">✅</td></tr><tr><td>Block mode (GitHub-hosted, supported for Deny list)</td><td align="center">✅</td><td align="center">✅</td><td align="center">❌</td></tr><tr><td>Block mode (Self-hosted, supported for Deny list)</td><td align="center">✅</td><td align="center">✅</td><td align="center">✅</td></tr></tbody></table>

{% hint style="info" %}
File write events are not currently supported for Linux persistent runners.
{% endhint %}

### Harden-Runner Endpoints

The Harden-Runner agent requires outbound access to the following endpoints on port 443 (HTTPS). If your runner environment uses a firewall, proxy, or network allowlist, ensure these endpoints are permitted.

| Endpoint                                                              | Purpose                                          |
| --------------------------------------------------------------------- | ------------------------------------------------ |
| `agent.api.stepsecurity.io:443`                                       | Agent communication and policy retrieval         |
| `prod.app-api.stepsecurity.io:443`                                    | Telemetry                                        |
| `customer-transient-data-277233109775.s3.us-west-2.amazonaws.com:443` | Transient data storage for runtime event uploads |

All communication is encrypted over TLS. These endpoints are automatically allowed by Harden-Runner and do not need to be added to your allowed endpoints list. However, if your organization has configured firewalls at the infrastructure level (e.g., network firewalls, proxy servers, or cloud security groups), these endpoints must be permitted for Harden-Runner to function correctly.

### Data Collection and Hosting

Harden-Runner sends runtime telemetry from the runner to StepSecurity. This telemetry is what powers the [security insights page](#how-to-access-harden-runner-security-insights), runtime detections, and notifications. This section covers what the agent sends, where that data is stored, and what it does not collect.

#### **What the agent sends**

The agent reports metadata about the job and about the runtime activity it observes on the runner.

<table><thead><tr><th width="240">Category</th><th>What is included</th></tr></thead><tbody><tr><td>Network and DNS events</td><td>Domain names resolved, IP addresses and ports contacted, the process that made each call, and a timestamp</td></tr><tr><td>HTTPS request metadata</td><td>Where non-intrusive HTTPS monitoring is supported: the request method, host, and path of outbound HTTPS calls</td></tr><tr><td>Process events</td><td>Process name and executable path, process arguments, process ID and parent process ID, and working directory</td></tr><tr><td>File write events</td><td>Name and path of each file written to the working directory, and the process that wrote it</td></tr><tr><td>Workflow and job metadata</td><td>Repository owner and name, repository visibility, workflow name and path, run and job IDs, branch, commit SHA and commit message, committer, trigger event, and the name, status, and start and end times of each step</td></tr><tr><td>Runner details</td><td>Runner name, machine name, runner group, runner labels, environment type (for example GitHub-hosted, self-hosted, or ARC), and for ARC deployments the cluster name</td></tr><tr><td>Harden-Runner configuration</td><td>The egress policy in effect for the job, and whether telemetry or file monitoring were disabled for that job</td></tr></tbody></table>

Every event is correlated with the workflow step that produced it. That correlation is what allows the insights page to attribute a network call or a process launch to a specific step rather than to the job as a whole.

Process events and file write events are available on the **Enterprise Tier** only. See [Workflow Runs](/github-actions/harden-runner/workflow-runs.md) for the full list of features and their tier requirements.

Raw process and file event data is uploaded through the transient data endpoint listed under [Harden-Runner Endpoints](#harden-runner-endpoints). All uploads are outbound only and encrypted over TLS.

For the exact shape of the data StepSecurity stores per workflow run, see the **Insights Response** example on the [Sample Detection Events](/administration/admin-console/integrations/sample-detection-events.md) page.

#### **Where the data is hosted**

Harden-Runner telemetry is processed and stored in StepSecurity's own AWS environment. That environment runs in two AWS regions, both in the United States:

* **us-east-1** (N. Virginia)
* **us-west-2** (Oregon)

The StepSecurity console reads from the same environment, so the insights, detections, and reports you see in the app are served from these regions.

**How the data flows**

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2FhXwkdjvsa4wuDz7MeZgi%2FScreenshot%202026-09-03%20at%2020.04.32.png?alt=media&amp;token=0db8b258-0811-4d73-851d-4aa3977c4eff" alt=""><figcaption></figcaption></figure>

Three kinds of traffic cross the boundary between your environment and StepSecurity:

* **Runtime events**, sent outbound from the Harden-Runner agent on the runner to the StepSecurity backend. This is the telemetry described above.
* **Console access**, from your authorized users to the StepSecurity frontend, which in turn calls the backend API.
* **GitHub API calls**, made by the StepSecurity backend to your GitHub organization, for example to post GitHub Checks, open pull requests, and read workflow run metadata. These calls are authorized by the StepSecurity GitHub App you install.

On the StepSecurity side, the platform runs entirely on managed AWS services within the two regions listed above:

<table><thead><tr><th width="220">Component</th><th>Service</th><th>Role</th></tr></thead><tbody><tr><td>Frontend app</td><td>AWS Amplify</td><td>Serves the StepSecurity console to authorized users</td></tr><tr><td>Backend API</td><td>Amazon API Gateway</td><td>Entry point for agent telemetry and console API calls</td></tr><tr><td>Backend</td><td>AWS Lambda</td><td>Processes runtime events, evaluates detections, and calls the GitHub API</td></tr><tr><td>Object storage</td><td>Amazon S3</td><td>Stores raw process and file event data and generated report artifacts</td></tr><tr><td>Structured storage</td><td>Amazon DynamoDB</td><td>Stores workflow run records, detections, policies, and organization configuration</td></tr></tbody></table>

All agent traffic is outbound only. The Harden-Runner agent never accepts inbound connections, and StepSecurity does not require any inbound network access into your runner environment.

StepSecurity is SOC 2 Type II and ISO/IEC 27001 compliant, and compliance and penetration test reports are available on request. See [Enterprise Readiness](/resources/enterprise-readiness.md) for details.

If your organization needs telemetry or detection events in storage you control, for example to satisfy an internal retention or residency requirement, StepSecurity can export them to your own infrastructure through the [S3 Integration](/administration/admin-console/integrations/s3-integration.md) or the [Webhook Integration](/administration/admin-console/integrations/webhook-integration.md).

{% hint style="info" %}
If you have a data residency requirement that these two regions do not meet, contact <support@stepsecurity.io> to discuss options.
{% endhint %}

#### **What the agent does not collect**

The Harden-Runner agent collects only the metadata required for runtime visibility and enforcement. It does not send:

* **Source code or file contents.** File write events record file names and paths, never the contents of those files.
* **Secret values.** When StepSecurity detects a secret in a build log or a build artifact, the detection event records a masked preview and the location of the match, not the secret itself.
* **Environment variable values.**

#### **Turning telemetry off**

On the **Community Tier**, workflows running in block mode can stop sending telemetry with the `disable-telemetry` input. This is not recommended on the Enterprise Tier, because detections and notifications depend on the telemetry. See [Disable telemetry in block mode](/github-actions/harden-runner/workflow-runs.md#disable-telemetry-in-block-mode).

### GitHub-Hosted Runners

**Step 1:** Add the `step-security/harden-runner` GitHub Action to your GitHub Actions workflow file as the first step in each job. You can automate adding Harden-Runner Action to your workflow file by using [Secure Workflow](https://app.stepsecurity.io/secure-workflow).

```
steps:
  - uses: step-security/harden-runner@v2 # v2.10.3
    with:
      egress-policy: audit
```

**Step 2:** You will see a link to security insights and recommendations in the workflow logs and the job markdown summary.

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2FYX3MKpKbexghqI93BZLC%2Fbuildlog1.png?alt=media&amp;token=213269fe-b65a-4e04-9d5e-68a2499966f1" alt="build log showing link to StepSecurity insights page"><figcaption><p>build log</p></figcaption></figure>

**Step 3:** Click on the link ([example link](https://app.stepsecurity.io/github/step-security/github-actions-goat/actions/runs/7704454287)). You will see a process monitor view of network and file events correlated with each step of the job.

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2FmlcKX29uvnA71IuBq9io%2FScreenshot%202025-02-01%20at%2009.50.49.png?alt=media&amp;token=f1cefd7d-eac0-4985-863c-9186e1eb6526" alt="StepSecurity Insights page showing Network Events"><figcaption><p>StepSecurity Insights Page showing Network Events</p></figcaption></figure>

**Step 4:** In the `Recommended Policy` tab, you'll find a recommended block policy based on outbound calls aggregated from the current and past runs of the job. You can update your workflow file with this policy or use the Policy Store to apply the policy without modifying the workflow file. From now on, any outbound calls not on the allowed list will be blocked.

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2F70pp06pSLIFl8c6bT7Sr%2FScreenshot%202025-02-01%20at%2009.52.20.png?alt=media&amp;token=82f39bf4-8e4f-4875-8f61-1a54aa9b0aa1" alt="StepSecurity Insights Page showing Recommendations"><figcaption><p>StepSecurity Insights Page showing Recommendations</p></figcaption></figure>

### GitHub-Hosted Custom VM

GitHub-hosted custom VM runners combine the flexibility of self-managed environments with the convenience of GitHub’s hosted infrastructure.

Harden-Runner enables runtime security for GitHub-hosted custom VM runners by providing continuous monitoring and policy enforcement directly on the VM image. Unlike the standard GitHub-hosted environment, which requires adding the Harden-Runner GitHub Action in each workflow, custom VM environments can be preconfigured with the Harden-Runner agent for persistent protection.

{% hint style="info" %}
Instructions for installing the Harden-Runner agent on your runner image are available under [**Harden-Runner Installations**](/github-actions/harden-runner/harden-runner-installation.md)
{% endhint %}

### Self-Hosted VM Runners

To enable runtime security for self-hosted runners on Cloud VMs (e.g. EC2 instances), you can add the Harden-Runner agent to your runner image.

Instead of adding the Harden-Runner GitHub Action in each job, you'll need to install the Harden-Runner agent on your runner image (e.g., AMI). This is typically done using a packer or as a post-install step when using the [https://github.com/philips-labs/terraform-aws-github-runner](https://github.com/github-aws-runners/terraform-aws-github-runner) project to set up runners.

The Harden-Runner agent monitors all jobs run on the VM; both ephemeral and persistent runners are supported; you do NOT need to add the Harden-Runner GitHub Action to each job for `audit` mode

For jobs where you want to enable `block` mode, there are two options:

* Attach a [policy](/github-actions/harden-runner/policy-store.md#for-self-hosted-runners) to enforce blocking behavior.
* Add the Harden-Runner GitHub Action directly to those specific jobs.

{% hint style="info" %}
Both ephemeral and persistent VM runners are supported.
{% endhint %}

You can access security insights and runtime detections under the `Harden-Runner` section in your dashboard.

{% hint style="info" %}
Instructions for installing the Harden-Runner agent on your runner image are available under [**Harden-Runner Installations**](/github-actions/harden-runner/harden-runner-installation.md)

This agent is different from the one used for GitHub-hosted runners.
{% endhint %}

### Self-Hosted bare-metal Runners

Self-hosted bare-metal runners are set up by installing the harden-runner agent as a service. This setup closely resembles the self-hosted cloud VM scenario but runs directly on physical hardware instead of virtualized environments.

#### Actions Runner Controller (ARC) Runners

Actions Runner Controller (ARC) is a Kubernetes operator that orchestrates and scales self-hosted runners for GitHub Actions.

Rather than incorporating the Harden Runner GitHub Action into each individual workflow, you'll need to install the ARC-Harden-Runner daemonset on your Kubernetes cluster.

Upon installation, the ARC Harden-Runner daemonset monitors all jobs run on the cluster; you do NOT need to add the Harden-Runner GitHub Action to each job for `audit` mode.

For jobs where you want to enable `block` mode, there are two options:

* Attach a [policy](/github-actions/harden-runner/policy-store.md#for-self-hosted-runners) to enforce blocking behavior.
* Add the Harden-Runner GitHub Action directly to those specific jobs.

You can access security insights and runtime detections under the Runtime Security tab in your dashboard.

{% hint style="info" %}
Installation instructions for the ARC-Harden-Runner daemonset are available under the [**Harden-Runner Installations**](/github-actions/harden-runner/harden-runner-installation.md)
{% endhint %}

### Third-Party GitHub Actions Runners

Harden-Runner supports third-party GitHub Actions runner providers that offer faster, cheaper, or region-specific alternatives to GitHub-hosted runners. Integration works the same way as with GitHub-hosted runners: add the `step-security/harden-runner` action as the first step of each job. Only the `runs-on` value changes.

The following providers are supported:

* [Bitrise](https://bitrise.io/platform/build-hub)
* [Blacksmith](https://www.blacksmith.sh/)
* [Depot](https://depot.dev/)
* [Namespace](https://namespace.so/)
* [Warp Build](https://warpbuild.com/)
* [AWS CodeBuild](https://docs.aws.amazon.com/codebuild/latest/userguide/action-runner-overview.html)

{% hint style="info" %}
Harden-Runner action **v2.19.0 or later** is required for third-party runner support. Bitrise runners require **v2.20.0 or later.** AWS CodeBuild runners require **v2.20.1 or later**, and CodeBuild custom images require **v2.21.0 or later**.
{% endhint %}

#### **Bitrise**

Harden-Runner supports Bitrise Build Hub macOS runners for GitHub Actions. Bitrise runners are targeted using the labels you define when creating a Build Hub machine pool, so your `runs-on` value depends on your pool configuration. Use your pool's label in `runs-on` and add Harden-Runner as the first step:

```yaml
jobs:
  build:
    runs-on: bitrise-m4-pro # replace with your Build Hub machine pool label
    steps:
      - uses: step-security/harden-runner@v2.20.0
        with:
          egress-policy: audit
      - uses: actions/checkout@v4
      # ... rest of your job
```

{% hint style="info" %}
Bitrise support requires Harden-Runner action **v2.20.0 or later**. Bitrise machine pool labels are user-defined; see [Configuring Build Hub for GitHub Actions](https://docs.bitrise.io/en/bitrise-build-hub/build-hub-for-github-actions/configuring-build-hub-for-github-actions) for how to create and target pool labels.
{% endhint %}

#### **Blacksmith**

Use a Blacksmith runner label in `runs-on` and add Harden-Runner as the first step:

```yaml
jobs:
  build:
    runs-on: blacksmith-4vcpu-ubuntu-2404
    steps:
      - uses: step-security/harden-runner@v2.19.0
        with:
          use-policy-store: true
          api-key: ${{ secrets.STEP_SECURITY_API_KEY }}
      - uses: actions/checkout@v4
```

#### **Depot**

Use a Depot runner label in `runs-on` and add Harden-Runner as the first step.

```yaml
jobs:
  build:
    runs-on: depot-ubuntu-24.04
    steps:
      - uses: step-security/harden-runner@v2.19.0
        with:
          use-policy-store: true
          api-key: ${{ secrets.STEP_SECURITY_API_KEY }}
      - uses: actions/checkout@v4
```

#### **Namespace**

Use a Namespace profile label in `runs-on` and add Harden-Runner as the first step:

```yaml
jobs:
  build:
    runs-on: namespace-profile-default
    steps:
      - uses: step-security/harden-runner@v2.19.0
        with:
          use-policy-store: true
          api-key: ${{ secrets.STEP_SECURITY_API_KEY }}
      - uses: actions/checkout@v4
      # ... rest of your job
```

#### **Warp**

Use a Warp runner label in `runs-on` and add Harden-Runner as the first step:

```yaml
jobs:
  build:
    runs-on: warp-ubuntu-latest-x64-4x
    steps:
      - uses: step-security/harden-runner@v2.19.0
        with:
          use-policy-store: true
          api-key: ${{ secrets.STEP_SECURITY_API_KEY }}
      - uses: actions/checkout@v4
      # ... rest of your job
```

#### **AWS CodeBuild**

Harden-Runner supports GitHub Actions runners hosted on [AWS CodeBuild](https://docs.aws.amazon.com/codebuild/latest/userguide/action-runner-overview.html) on EC2 compute. CodeBuild registers a just-in-time self-hosted runner for each queued job, so the job runs on your AWS compute, in your VPC, under your CodeBuild project's IAM service role.

**CodeBuild project requirements**

Unlike the other providers on this page, CodeBuild requires specific settings on the CodeBuild project itself. The agent relies on kernel-level features, so a project that does not meet these requirements will not be monitored.

| Setting                | Required value                                                                                                                 |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| **Compute**            | `EC2`. Lambda compute is **not supported**.                                                                                    |
| **Host kernel**        | `kernel-6 (Amazon Linux 2023)`                                                                                                 |
| **Privileged**         | Enabled                                                                                                                        |
| **Provisioning model** | `On-demand` or `Reserved capacity`. Both are supported.                                                                        |
| **Environment image**  | `Managed image` with **Running mode** set to `Instance`, or `Custom image` with **Environment type** set to `Linux Container`. |

{% hint style="warning" %}
**Host kernel** must be set to `kernel-6 (Amazon Linux 2023)`. This is a comparatively new CodeBuild setting, and it is the most common reason a correctly-configured workflow produces no monitoring data.
{% endhint %}

{% hint style="danger" %}
CodeBuild-hosted runners on **AWS Lambda compute are not supported**. AWS offers CodeBuild-hosted GitHub Actions runners on both EC2 and Lambda compute, but the Harden-Runner agent requires elevated privileges and kernel-level features that Lambda compute does not provide. Jobs on Lambda compute are not monitored.
{% endhint %}

**Workflow configuration**

Target CodeBuild runners with the standard CodeBuild runner label and add Harden-Runner as the first step:

```yaml
jobs:
  build:
    runs-on: codebuild-my-project-${{ github.run_id }}-${{ github.run_attempt }}
    steps:
      - uses: step-security/harden-runner@v2.21.0
        with:
          egress-policy: audit
      - uses: actions/checkout@v4
      # ... rest of your job
```

Replace `my-project` with the name of the CodeBuild project whose webhook is configured for `WORKFLOW_JOB_QUEUED` events. The project name must match the project name in the AWS console exactly.

No buildspec or webhook changes are needed. If you use CodeBuild [label overrides](https://docs.aws.amazon.com/codebuild/latest/userguide/sample-github-action-runners-update-labels.html) to select an image, instance size, or fleet per job, those continue to apply, as long as the resulting environment still meets the requirements above.

**Custom images**

CodeBuild runners that run Linux containers on EC2 compute with a custom image are supported from Harden-Runner **v2.21.0**. Set **Environment image** to `Custom image` and **Environment type** to `Linux Container`. Images hosted in Amazon ECR and in external Docker registries are both supported. You can also select a custom image per job with the `image:custom-<environment-type>-<custom-image-identifier>` label override.

{% hint style="info" %}
AWS CodeBuild support requires Harden-Runner action **v2.20.1 or later**. Custom images require **v2.21.0 or later**. For how to configure a CodeBuild project as a GitHub Actions runner, see [Self-hosted GitHub Actions runners in AWS CodeBuild](https://docs.aws.amazon.com/codebuild/latest/userguide/action-runner-overview.html).
{% endhint %}

#### **What works the same as GitHub-hosted runners**

All standard Harden-Runner features are available on these providers:

* **Audit mode** (`egress-policy: audit`) — logs outbound traffic without blocking
* **Block mode** (`egress-policy: block`) with `allowed-endpoints`
* **Policy Store** integration (`use-policy-store: true` with an `api-key`) — centrally manage egress policies without modifying each workflow
* **Security insights link** in the job log and the Markdown job summary
* All detections surface in the StepSecurity dashboard the same way as for GitHub-hosted runners

## How to access Harden-Runner security insights

For each GitHub Actions workflow run, Harden-Runner monitors the run-time network, file, and process events and makes runtime insights available via the StepSecurity Web App.

There are **four** ways to find the insights link:

* [**BuildLog**](#buildlog)
* [**Workflow Runs**](#latest-workflow-runs)
* [**Markdown Job Summary**](#markdown-job-summary)
* [**GitHub Checks**](#github-checks)

### BuildLog

**Step 1:** Navigate to build log of your workflow file in Github Actions.

**Step 2:** Look for the Harden-Runner step in the log and click on the Insights link which appears in the logs as `View security insights and recommended policy at:` followed by a clickable URL (this is an [example link](https://app.stepsecurity.io/github/ossf/scorecard/actions/runs/2265028928)).

<figure><img src="https://ajeuwbhvhr.cloudimg.io/colony-recorder.s3.amazonaws.com/files/2025-02-05/4089ae82-00f6-4fe3-80b2-41bacd79612f/user_cropped_screenshot.jpeg?tl_px=0,175&#x26;br_px=2266,1714&#x26;force_format=jpeg&#x26;q=100&#x26;width=1120.0&#x26;wat=1&#x26;wat_opacity=1&#x26;wat_gravity=northwest&#x26;wat_url=https://colony-recorder.s3.amazonaws.com/images/watermarks/8B5CF6_standard.png&#x26;wat_pad=519,369" alt="build log showing StepSecurity insights link"><figcaption><p>build log</p></figcaption></figure>

**Step 3:** Once you click on the Insights link, you will be redirected to the `Summary` tab in the StepSecurity Web App. The `Summary` Page provides an overview of:

* Outbound destinations contacted during the job execution.
* HTTPS requests and the number of actions taken.
* Detections (if any security risks were found).

<figure><img src="https://ajeuwbhvhr.cloudimg.io/colony-recorder.s3.amazonaws.com/files/2025-02-05/d1e9d4c2-2dd9-43db-ae1f-dd708a3481e6/ascreenshot.jpeg?tl_px=0,0&#x26;br_px=2266,1538&#x26;force_format=jpeg&#x26;q=100&#x26;width=1120.0&#x26;wat=1&#x26;wat_opacity=1&#x26;wat_gravity=northwest&#x26;wat_url=https://colony-recorder.s3.amazonaws.com/images/watermarks/8B5CF6_standard.png&#x26;wat_pad=254,86" alt="StepSecurity Insights Summary Page"><figcaption><p>StepSecurity Insights Summary Page</p></figcaption></figure>

### Workflow runs

StepSecurity provides a dashboard where you can view the latest GitHub Actions workflow runs monitored by Harden-Runner. This guide will help you navigate the dashboard and access insights for specific workflow runs.

**Step 1:** Navigate to `https://app.stepsecurity.io/github/<GITHUB_ORG_NAME>/actions/dashboard`

**Step 2:** In the left-hand menu, under Harden-Runner, click Workflow Runs

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2FggIOML5BaGZTVm0BXoUn%2FScreenshot%202026-05-13%20at%2015.21.40.png?alt=media&amp;token=5c95d6e7-9321-412a-a827-9f3d9108dc2f" alt=""><figcaption></figcaption></figure>

**Step 3:** After opening the Workflow Runs page, locate the workflow you want to inspect and click on it.

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2FU9e7lCBITD9tBKw2K04m%2FReview%20Recommendations%20for%20Python%20Workflow%20on%20GitHub%20-%20Step%203.png?alt=media&amp;token=31eede9c-22e7-4486-9380-235b8fabae87" alt="StepSecurity Workflow Runs page showing different workflow runs"><figcaption><p>StepSecurity Workflow Runs page showing different workflow runs</p></figcaption></figure>

**Step 4:** Once inside the workflow details page, navigate to the `Summary` tab.

Here, you can review:

* Outbound destinations contacted during the workflow.
* Security detections (if any were found).
* Actions performed by the workflow.

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2FoK2ABv5lc6hVE2fcrHjI%2FReview%20Recommendations%20for%20Python%20Workflow%20on%20GitHub%20-%20Step%204.png?alt=media&amp;token=efb771ce-46d4-4568-bf5a-de0d39a0a790" alt="StepSecurity Insights summary page"><figcaption><p>StepSecurity Insights summary page</p></figcaption></figure>

### Markdown Job Summary

**Step 1:** Navigate to the workflow run page

**Step 2:** Click "📄 View Full Report"

<figure><img src="https://ajeuwbhvhr.cloudimg.io/colony-recorder.s3.amazonaws.com/files/2025-02-11/89576757-4949-479b-bc9a-f7e9f3ffad50/ascreenshot.jpeg?tl_px=0,175&#x26;br_px=2266,1714&#x26;force_format=jpeg&#x26;q=100&#x26;width=1120.0&#x26;wat=1&#x26;wat_opacity=1&#x26;wat_gravity=northwest&#x26;wat_url=https://colony-recorder.s3.amazonaws.com/images/watermarks/8B5CF6_standard.png&#x26;wat_pad=447,590" alt="StepSecurity markdown report"><figcaption><p>StepSecurity markdown report</p></figcaption></figure>

**Step 3:** Review the outbound connections allowed during the workflow execution.

<figure><img src="https://ajeuwbhvhr.cloudimg.io/colony-recorder.s3.amazonaws.com/files/2025-02-11/0535747d-46e6-42c6-8018-77176eb7ff0f/user_cropped_screenshot.jpeg?tl_px=0,175&#x26;br_px=2266,1714&#x26;force_format=jpeg&#x26;q=100&#x26;width=1120.0&#x26;wat=1&#x26;wat_opacity=1&#x26;wat_gravity=northwest&#x26;wat_url=https://colony-recorder.s3.amazonaws.com/images/watermarks/8B5CF6_standard.png&#x26;wat_pad=531,538" alt="StepSecurity Insights summary page"><figcaption><p>StepSecurity Insights summary page</p></figcaption></figure>

### GitHub Checks

To enable GitHub Checks, check out this [guide](broken://pages/Gl1Qm7ei5iANGikFhSYk#how-to-enable-the-github-checks-feature).

**Step 1:** Navigate to the Pull Request

**Step 2:** View Check Details

* Look at the checks summary under your pull request.
* Identify any failed or successful checks.
* Click on the “Details” link next to the StepSecurity Harden-Runner check.

<figure><img src="https://ajeuwbhvhr.cloudimg.io/colony-recorder.s3.amazonaws.com/files/2025-02-11/bed6dbb8-9073-403b-ad1c-db333f002cf0/ascreenshot.jpeg?tl_px=0,179&#x26;br_px=2236,1718&#x26;force_format=jpeg&#x26;q=100&#x26;width=1120.0&#x26;wat=1&#x26;wat_opacity=1&#x26;wat_gravity=northwest&#x26;wat_url=https://colony-recorder.s3.amazonaws.com/images/watermarks/8B5CF6_standard.png&#x26;wat_pad=706,376" alt="List of GitHub Checks including StepSecurity Harden-Runner check"><figcaption><p>List of GitHub Checks including StepSecurity Harden-Runner check</p></figcaption></figure>

**Step 3:** Access Insights URL

* On the new page, select StepSecurity Harden-Runner from the list of workflow checks.
* Find the Insights URL under the Workflow Run Insights section.
* Click the Insights URL to proceed.

<figure><img src="https://ajeuwbhvhr.cloudimg.io/colony-recorder.s3.amazonaws.com/files/2025-02-11/e61a4995-af92-4c0b-9632-9ae80bc86736/ascreenshot.jpeg?tl_px=0,179&#x26;br_px=2236,1718&#x26;force_format=jpeg&#x26;q=100&#x26;width=1120.0&#x26;wat=1&#x26;wat_opacity=1&#x26;wat_gravity=northwest&#x26;wat_url=https://colony-recorder.s3.amazonaws.com/images/watermarks/8B5CF6_standard.png&#x26;wat_pad=731,575" alt="StepSecurity Harden-Runner Check"><figcaption><p>StepSecurity Harden-Runner Check</p></figcaption></figure>

**Step 4:** Review Security Insights

* The Insights page will display outbound traffic details, network events, and security findings.
* Verify if any unauthorized outbound connections were detected.
* Review the All Outbound Destinations and All Detections sections for further analysis.

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2FhbxIVAqSlnwrChwJhjkQ%2FScreenshot%202026-05-13%20at%2015.22.39.png?alt=media&amp;token=2eb7f402-d3d9-41a9-aae0-b10ec673836b" alt=""><figcaption></figcaption></figure>


---

# Agent Instructions
This documentation is published with GitBook. GitBook is the documentation platform designed so that both humans and AI agents can read, navigate, and reason over technical content effectively. Learn more at gitbook.com.

## Querying This Documentation
If you need additional information that is not directly available in this page, you can query the documentation by asking a question.

Perform an HTTP GET request on the following URL with the `ask` and `goal` query parameters:

```
GET https://docs.stepsecurity.io/github-actions/harden-runner.md?ask=<question>&goal=<user_goal>
```

`ask` is the immediate question: it should be specific, self-contained, and written in natural language.
`goal` is what the user is ultimately trying to achieve, the reason they need the answer. Sharing it helps GitBook give you a better, more relevant answer. A goal is most helpful when it describes the outcome the user wants rather than restating the question. For example, with `ask=how do I create an API token`, a goal like `automate deployments from our CI pipeline` lets GitBook tailor the answer to that use case.

The response will contain a direct answer to the question and relevant excerpts and sources from the documentation.

Use this mechanism when the answer is not explicitly present in the current page, you need clarification or additional context, or you want to retrieve related documentation sections.
