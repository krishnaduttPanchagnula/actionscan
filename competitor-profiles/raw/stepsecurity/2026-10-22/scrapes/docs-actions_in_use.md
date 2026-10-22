<!-- Source: https://docs.stepsecurity.io/actions_in_use
Fetched: 2026-10-22
Method: webfetch-equivalent (curl + HTML-to-text)
Status: 200 OK (GitBook .md export)
-->

> For the complete documentation index, see [llms.txt](https://docs.stepsecurity.io/llms.txt). Markdown versions of documentation pages are available by appending `.md` to page URLs; this page is available as [Markdown](https://docs.stepsecurity.io/github-actions/actions/github-actions-in-use.md).

# GitHub Actions In Use

{% hint style="warning" %}
Available for **Enterprise** Tier only
{% endhint %}

To get insights into the GitHub Actions used in your repositories, navigate to the `Actions` section in the StepSecurity dashboard. Here, you can find:

* The name of each Action.
* The Action Security Score.
* The Repositories using that particular Action.

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2FmF1Lg6HKZl6yD9udDObf%2FScreenshot%202026-05-13%20at%2019.36.07.png?alt=media&amp;token=2cd45c96-c61f-40bc-affd-e1a7865d0ba9" alt=""><figcaption></figcaption></figure>

## Exploring GitHub Actions Insights

* [Viewing Action Details](#viewing-action-details)
* [How Action Scores are Calculated](#how-action-scores-are-calculated)
* [Managing Low Scoring Actions](#managing-low-scoring-actions)
* [Requesting a Maintained Action](#requesting-a-maintained-action)

### Viewing Action Details

Click on a specific Action (e.g., actions/checkout) to open its details page. You will see four tabs:

#### Repositories Tab

* Displays the repositories using the selected Action.
* Lists associated workflows.
* Shows the SHA and tag used in each repository.
* Displays the age of the last used tag or SHA.
  * If a tag has not been updated recently, it’s recommended to upgrade it.
  * You can automate this process using Dependabot.

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2FDQ6AcRexNjo5AMWYXL5V%2FScreenshot%202026-02-13%20at%2008.22.37.png?alt=media&amp;token=6129231f-79d8-43f2-81a2-1deee1268de9" alt=""><figcaption></figcaption></figure>

#### Security Score Tab

* Displays the Security Score of the Action.
* The score is calculated using industry best practices, including OpenSSF Scorecard checks and the Secure Software Publishing Guide.

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2FlFLF1o68BxUFK5yosJcs%2FScreenshot%202026-02-13%20at%2008.24.22.png?alt=media&amp;token=8892bf23-343c-42fe-950e-67fcc3ef02b1" alt=""><figcaption></figcaption></figure>

#### AI Analysis

* Displays the AI-powered security assessment of the selected Action.
* The AI Analysis evaluates the Action’s source code, workflow configuration, token usage, and supply chain risk patterns to identify potential security issues.\
  This analysis is powered by StepSecurity’s vertical supply chain security AI agent, which is trained on past real-world supply chain incidents and common CI/CD attack patterns. By leveraging historical breach data and known exploitation techniques, the AI agent is able to detect subtle risk indicators that traditional rule-based scanners may miss.
* It generates the AI Security Score and provides detailed security findings with severity levels and remediation guidance.

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2FbRW6KbDf76EQ0PJ1CHxo%2FScreenshot%202026-02-13%20at%2008.34.44.png?alt=media&amp;token=a95d2473-7673-4a8f-a8d9-8b87c7d3bcf3" alt=""><figcaption></figcaption></figure>

* For Actions that do not yet have AI Analysis available, you can request an analysis directly from the Action details page.

{% hint style="info" %}
**Note**: Each user is limited to 10 AI Analysis requests per day.
{% endhint %}

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2FSQ72hseUifoks7UXGgpL%2FScreenshot%202026-02-13%20at%2008.39.06.png?alt=media&amp;token=10fb28b7-4619-43c8-8ca0-9b82f1bf0df3" alt=""><figcaption></figcaption></figure>

#### Network Behavior Tab

* Shows all outbound network calls made by the Action during execution.

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2FXEViSnV9No6oq5a8xb4X%2FScreenshot%202026-02-13%20at%2008.35.21.png?alt=media&amp;token=cf4ddd3f-9b1f-4a08-aedd-fd568091987b" alt=""><figcaption></figcaption></figure>

### How Action Scores are Calculated

Each GitHub Action is assigned a Security Score on a 0–10 scale. The score reflects how closely the Action aligns with industry best practices for secure software development and maintenance.

Scores are derived from multiple components, each normalized to a 0–10 range, and combined into a final score depending on whether the Action is public or private.

#### Score Components

Each component contributes a score between 0 and 10.

| Component         | Source                        | Description                                                                                                                       |
| ----------------- | ----------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| License           | GitHub API                    | 10 for permissive OSS licenses like MIT or Apache 2.0, lower for restrictive licenses like AGPL, and 0 if no license is specified |
| Popularity        | GitHub Code Search            | Based on how many open-source projects use the action                                                                             |
| Branch Protection | Scorecard                     | Measures repository branch protection settings                                                                                    |
| Maintained        | Scorecard (or internal check) | How recently the action was updated                                                                                               |
| Security Policy   | Scorecard                     | Whether repo has a security policy                                                                                                |
| Vulnerabilities   | Scorecard (or OSV scan)       | Known vulnerabilities in dependencies                                                                                             |

**Popularity Score**

| More than 1000 | 10 |
| -------------- | -- |
| More than 500  | 7  |
| More than 200  | 5  |
| 200 or fewer   | 0  |

**Maintained Score (for internal/private actions)**

* Node.js Runtime Check
  * If the Action uses Node.js 16 or lower, the score is 0.<br>
* Commit Recency

| 30 days or less    | 10 |
| ------------------ | -- |
| 90 days or less    | 8  |
| 180 days or less   | 6  |
| 365 days or less   | 4  |
| 730 days or less   | 2  |
| More than 730 days | 0  |

***

**Vulnerabilities Score (for internal/private actions)**

The score is calculated using an OSV scan of the Action’s dependencies.

| 0           | 10 |
| ----------- | -- |
| 1–2         | 7  |
| 3–5         | 4  |
| More than 5 | 0  |

If no dependencies are found to scan, the score defaults to 10.

**Branch Protection Score**

Derived from OpenSSF Scorecard results and reflects whether the Action’s repository enforces recommended branch protection settings.

**Final Score Calculation**

* Public Actions (6 components)

{% code overflow="wrap" %}

```
(License + Popularity + BranchProtection + Maintained + SecurityPolicy + Vulnerabilities) / 6
```

{% endcode %}

* Private or Internal Actions (3 components)

```
(Maintained + Vulnerabilities + BranchProtection) / 3
```

The final score is rounded to the nearest whole number, resulting in a value between 0 and 10.

### Managing Low-Scoring Actions

* Actions with low security scores should be replaced or updated.
* If there is no suitable alternative and you accept an Action's risk after review, you can exempt it from the high-score control under [Settings > Control Evaluation](/workspace/settings/control-evaluation.md).
* StepSecurity provides maintained alternatives for some actions.
* If an action has a maintained version, you will see a `Maintained action available` label.

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2FK0JJrkB2BV6SXHnastNj%2FRequesting%20Maintained%20Action%20in%20GitHub%20Actions%20-%20Step%2012.png?alt=media&amp;token=7cb6b341-7466-4eee-baf3-343850db03ef" alt=""><figcaption><p>StepSecurity Actions page showing GitHub Actions in Use</p></figcaption></figure>

* Clicking on the `Maintained action available` label will take you to the StepSecurity-maintained action, where you can see the difference between the StepSecurity-maintained action and the low-scoring action.

### Requesting a Maintained Action

* Click on an action with a **low score**.

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2FFsF0GDjQDHvFPaPOFXUq%2Fdoc.jpg?alt=media&amp;token=89356ee4-48b2-430e-9900-ecfff0e84ae0" alt=""><figcaption></figcaption></figure>

* If it does not have a maintained version, you can request one.
* Click on `Request maintained action` .<br>

![GitHub Actions Advisor](https://ajeuwbhvhr.cloudimg.io/colony-recorder.s3.amazonaws.com/files/2025-03-03/4df01b00-116c-4320-9a48-1df15530d28f/ascreenshot.jpeg?tl_px=255,0\&br_px=3008,1538\&force_format=jpeg\&q=100\&width=1120.0\&wat=1\&wat_opacity=1\&wat_gravity=northwest\&wat_url=https://colony-recorder.s3.amazonaws.com/images/watermarks/8B5CF6_standard.png\&wat_pad=922,241)

* Enter your email and submit the request.

![GitHub Actions Advisor](https://ajeuwbhvhr.cloudimg.io/colony-recorder.s3.amazonaws.com/files/2025-03-03/cfdf34d9-6f5e-412b-9ccb-890e6218b508/ascreenshot.jpeg?tl_px=255,179\&br_px=3008,1718\&force_format=jpeg\&q=100\&width=1120.0\&wat=1\&wat_opacity=1\&wat_gravity=northwest\&wat_url=https://colony-recorder.s3.amazonaws.com/images/watermarks/8B5CF6_standard.png\&wat_pad=629,299)


---

# Agent Instructions
This documentation is published with GitBook. GitBook is the documentation platform designed so that both humans and AI agents can read, navigate, and reason over technical content effectively. Learn more at gitbook.com.

## Querying This Documentation
If you need additional information that is not directly available in this page, you can query the documentation by asking a question.

Perform an HTTP GET request on the following URL with the `ask` and `goal` query parameters:

```
GET https://docs.stepsecurity.io/github-actions/actions/github-actions-in-use.md?ask=<question>&goal=<user_goal>
```

`ask` is the immediate question: it should be specific, self-contained, and written in natural language.
`goal` is what the user is ultimately trying to achieve, the reason they need the answer. Sharing it helps GitBook give you a better, more relevant answer. A goal is most helpful when it describes the outcome the user wants rather than restating the question. For example, with `ask=how do I create an API token`, a goal like `automate deployments from our CI pipeline` lets GitBook tailor the answer to that use case.

The response will contain a direct answer to the question and relevant excerpts and sources from the documentation.

Use this mechanism when the answer is not explicitly present in the current page, you need clarification or additional context, or you want to retrieve related documentation sections.
