<!-- Source: https://docs.stepsecurity.io/workspace_threat-center
Fetched: 2026-10-22
Method: webfetch-equivalent (curl + HTML-to-text)
Status: 200 OK (GitBook .md export)
-->

> For the complete documentation index, see [llms.txt](https://docs.stepsecurity.io/llms.txt). Markdown versions of documentation pages are available by appending `.md` to page URLs; this page is available as [Markdown](https://docs.stepsecurity.io/workspace/threat-center.md).

# Threat Center

{% hint style="warning" %}
Available for **Enterprise** Tier only
{% endhint %}

The Threat Center in StepSecurity is your central view into all supply chain compromises detected by StepSecurity. It provides a real-time feed of active incidents alongside historical records, making it easier to track, investigate, and respond.

For background on the intelligence powering the Threat Center, [see our blog post](https://www.stepsecurity.io/blog/introducing-stepsecurity-threat-intelligence-real-time-supply-chain-attack-alerts-for-your-siem).

### Accessing the Threat Center

#### Step 1: Open the StepSecurity Dashboard

* From the left-hand menu, click Threat Center. The page displays a list of active threats, marked with a red Active badge, along with historical incidents that include their start and close times.

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2FWWYDEqUjjTZEmDmoSMjw%2FScreenshot%202026-08-18%20at%2008.53.58.png?alt=media&amp;token=9ffb4e74-0903-4aca-83d1-bce45c79f94f" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
You can also open the Threat Center directly by clicking the 🔔 New Threat notification in the dashboard header
{% endhint %}

#### Step 2: Expand Threat Details

* Click Show Details on any incident to see:
  * A description of the compromise
  * Affected packages or Actions
  * Recommended remediation steps you can take directly within StepSecurity

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2FW2SSsEaH7odeJAvbE9Z3%2FScreenshot%202026-05-13%20at%2014.29.36.png?alt=media&amp;token=7b585c9c-4942-4dea-80fc-915346bc911d" alt=""><figcaption></figcaption></figure>

### Identifying threats that affect you

Not every incident in the Threat Center touches your organization. StepSecurity evaluates each incident against your environment and flags the ones you are exposed to, so you can focus remediation on what actually applies to you. An incident is treated as affecting you when StepSecurity finds either of the following:

* A **matched component**: a compromised package from the incident is present in one of your repositories, either in an open pull request or on the default branch.
* A **matched IOC**: an indicator of compromise from the incident, such as a malicious network endpoint, was observed in your Harden-Runner runtime data.

#### **Filter by exposure**

At the top of the Threat Center, two tabs control which incidents are shown:

* **All** lists every incident StepSecurity has published, with a count of the total.
* **Affecting You** lists only the incidents that affect your organization, with a count of how many currently apply to you.

Incidents that affect you also carry a red **You are affected** badge next to the title, in both views.

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2FNxWUCtPZZswupXhF9Snl%2FScreenshot%202026-08-18%20at%2009.02.16.png?alt=media&amp;token=8e8ac9ca-df3b-4f31-8f96-e0c042ee7c20" alt=""><figcaption></figcaption></figure>

#### **Reviewing an affected incident**

Open an affected incident to see exactly where and how you are exposed. A summary banner at the top reports the scope of your exposure, for example "Your tenant is affected across 1 organization," together with a count of matched components and matched IOCs.

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2FXCyynRVh2M7SxZEdA3DK%2FScreenshot%202026-08-18%20at%2009.03.07.png?alt=media&amp;token=12611624-d1b2-40ac-879c-0133e141ff21" alt=""><figcaption></figcaption></figure>

#### **Matched components**

For each affected organization, the **Matched components** section lists every compromised package found in your repositories, tagged with its ecosystem (for example, npm). Under each package, StepSecurity shows where the compromised version was found:

* **Pull request** matches show the pull request number and title, who opened it, the date, the matched version, the head commit, and the affected files (for example, `package-lock.json`).
* **Default branch** matches indicate that the compromised version is present on the repository's default branch, such as `main`, and not only proposed in a pull request.

#### **Matched IOCs**

The **Matched IOCs** section lists indicators of compromise from the incident that were observed in your Harden-Runner runtime data. For a network endpoint IOC, StepSecurity shows the endpoint, when it was first and last seen, the total number of calls, and a per-run breakdown under **Endpoint observations** listing the repository, workflow, job, and run for each observed call. This lets you trace an IOC back to the exact workflow run that contacted it.

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2Fud2qjEnkHS99x6Uzph6u%2FScreenshot%202026-08-18%20at%2009.04.23.png?alt=media&amp;token=58c3948a-5d83-437c-b1ed-5b77343455f0" alt=""><figcaption></figcaption></figure>

### Notifications and Integrations

Threat Center incidents are delivered through your existing StepSecurity notification channels, so your team is informed immediately:

* Slack
* Email
* AWS S3
* Webhook

Whether you are notified about every incident or only about incidents that affect your organization is controlled by your **threat intel notification granularity**:

* **All threat intel incidents:** every incident, whether or not you are affected.
* **Affected packages:** only incidents where a compromised package matches your dependencies by name.
* **Exact version only:** only incidents where you use the exact compromised version.

Configure granularity and channels at the organization level in Notifications, or tenant-wide in Admin Console Notifications.

Because alerts are integrated with your existing systems, you can automate the response process. For example, you can configure your SIEM so that when a new Threat Center event is raised, an on-call engineer is automatically paged.

See an example detection event [here](/administration/admin-console/integrations/sample-detection-events.md#threat-intelligence)

### Querying Threat Intelligence via API

StepSecurity exposes threat intelligence in two ways: per incident, scoped to your organization, and as a full per-ecosystem feed of every compromised package StepSecurity is tracking.

#### **Compromised components for a single incident**

You can retrieve the compromised Open Source Software (OSS) components for a specific Threat Center incident programmatically through the StepSecurity API. This is useful for feeding incident data into your own tooling, automating triage, or correlating compromised packages against your dependency inventory.

The endpoint returns all compromised components tied to an incident, including the package ecosystem, affected version, severity, verification status, and a description of the threat.

```
GET /github/{owner}/threat-intel/incidents/{incidentId}/compromised-components
```

The request takes your GitHub organization (`owner`) and the unique incident identifier (`incidentId`) as path parameters, and requires a valid StepSecurity API token.

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2F7v7FJg7Kbv2o2b89HVvt%2FScreenshot%202026-06-05%20at%2018.31.53.png?alt=media&amp;token=f8964b1c-e59c-4ea3-944a-ffa427a20fd1" alt=""><figcaption></figcaption></figure>

**Example Response**

```json
{
  "compromised_components": [
    {
      "type": "npm",
      "component_name": "malicious-pkg",
      "version": "1.2.3",
      "incident_group_id": "ig-001",
      "description": "Package contains malicious code that exfiltrates credentials",
      "severity": "critical",
      "verified": true,
      "added_at": "2024-01-15T10:00:00Z",
      "threat_intel_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479"
    }
  ]
}
```

{% hint style="info" %}
The per-incident endpoint returns only the components attached to that one incident. To export every compromised package StepSecurity is tracking, including packages that are not linked to a Threat Center incident, use the per-ecosystem feed below.
{% endhint %}

#### **Full list of compromised packages per ecosystem**

To export everything StepSecurity is tracking, rather than the components of one incident, use the per-ecosystem compromised packages feed. Each endpoint returns the complete list of compromised package versions for one ecosystem, combining Threat Center incidents with compromises reported by external advisory sources such as OSV. The feed is refreshed about every 15 minutes. This is the feed to use when you want to load StepSecurity threat intelligence into your own SIEM, artifact registry policy, or dependency scanner.

```
GET https://agent.api.stepsecurity.io/v1/application/packages/{ecosystem}/compromised
```

Supported values for `{ecosystem}`:

| `npm`       | npm                  |
| ----------- | -------------------- |
| `pypi`      | PyPI                 |
| `cargo`     | crates.io            |
| `packagist` | Packagist (Composer) |
| `go`        | Go modules           |
| `maven`     | Maven Central        |
| `nuget`     | NuGet                |

Some ecosystems were added to tracking recently and may return an empty `packages` array until compromises are recorded.

Requesting an unsupported ecosystem returns HTTP 400 with `{"error": "unsupported ecosystem: <value>"}`.

Responses can be large (the PyPI feed is several hundred kilobytes, and npm is larger). Send `Accept-Encoding: gzip` so the response is compressed in transit. Standard HTTP clients decompress it automatically.

```bash
curl -sS --compressed \
  https://agent.api.stepsecurity.io/v1/application/packages/pypi/compromised
```

**Example Response**

```json
{
  "packages": [
    {
      "type": "pypi",
      "component_name_version": "aiassistcore#0.1.2",
      "component_name": "aiassistcore",
      "version": "0.1.2",
      "description": "Malicious code in aiassistcore (PyPI)",
      "added_at": "2026-08-25T09:48:44Z",
      "threat_intel_id": "oss-compromised-uncategorized"
    }
  ]
}
```

| Field                    | Description                                                                                                                                                        |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `type`                   | Ecosystem of the package, matching the `{ecosystem}` value in the request.                                                                                         |
| `component_name`         | Package name as published in the registry.                                                                                                                         |
| `version`                | Compromised version. A value of `*` means all published versions are compromised.                                                                                  |
| `component_name_version` | `component_name` and `version` joined with `#`, useful as a stable lookup key.                                                                                     |
| `description`            | Summary of the compromise.                                                                                                                                         |
| `added_at`               | When the entry was added to the feed (UTC).                                                                                                                        |
| `threat_intel_id`        | Identifier of the Threat Center incident the package is linked to. Packages that are not linked to a Threat Center incident carry `oss-compromised-uncategorized`. |

The response may include additional fields that are used internally and are subject to change. Build integrations on the fields listed above.

Entries are appended as new compromises are confirmed. Poll the feed on a schedule and diff on `component_name_version` to pick up new entries.


---

# Agent Instructions
This documentation is published with GitBook. GitBook is the documentation platform designed so that both humans and AI agents can read, navigate, and reason over technical content effectively. Learn more at gitbook.com.

## Querying This Documentation
If you need additional information that is not directly available in this page, you can query the documentation by asking a question.

Perform an HTTP GET request on the following URL with the `ask` and `goal` query parameters:

```
GET https://docs.stepsecurity.io/workspace/threat-center.md?ask=<question>&goal=<user_goal>
```

`ask` is the immediate question: it should be specific, self-contained, and written in natural language.
`goal` is what the user is ultimately trying to achieve, the reason they need the answer. Sharing it helps GitBook give you a better, more relevant answer. A goal is most helpful when it describes the outcome the user wants rather than restating the question. For example, with `ask=how do I create an API token`, a goal like `automate deployments from our CI pipeline` lets GitBook tailor the answer to that use case.

The response will contain a direct answer to the question and relevant excerpts and sources from the documentation.

Use this mechanism when the answer is not explicitly present in the current page, you need clarification or additional context, or you want to retrieve related documentation sections.
