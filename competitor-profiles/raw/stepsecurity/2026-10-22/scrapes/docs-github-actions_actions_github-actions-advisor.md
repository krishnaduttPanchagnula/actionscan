<!-- Source: https://docs.stepsecurity.io/github-actions_actions_github-actions-advisor
Fetched: 2026-10-22
Method: webfetch-equivalent (curl + HTML-to-text)
Status: 200 OK (GitBook .md export)
-->

> For the complete documentation index, see [llms.txt](https://docs.stepsecurity.io/llms.txt). Markdown versions of documentation pages are available by appending `.md` to page URLs; this page is available as [Markdown](https://docs.stepsecurity.io/github-actions/actions/github-actions-advisor.md).

# GitHub Actions Advisor

{% hint style="warning" %}
Available for **Enterprise** Tier only
{% endhint %}

We perform a holistic evaluation of Actions using Static Analysis, AI Analysis, and Runtime Analysis to provide a complete view of their risk profile

{% hint style="info" %}
Note: GitHub Actions security scores are graded by **OpenSSF ScoreCard**
{% endhint %}

### How to Check an Actions Security Score

* Navigate to the Actions section and select `GitHub Actions Advisor`
* Enter the name of an action (e.g., TimonVS/pr-labeler-action) to view its security score.
* You can also browse a list of Actions maintained by StepSecurity

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2FdZuRwtu56MwQHyNAHTAV%2FScreenshot%202026-05-13%20at%2019.42.38.png?alt=media&amp;token=a4ccf73a-47b6-4afc-adbf-f6ea32a0a819" alt=""><figcaption></figcaption></figure>

* This will open the GitHub Actions Advisor, which provides a breakdown of the GitHub Actions security score. The scores are calculated using Static Analysis

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2FgjSsjM4FZq3007jFwdHU%2FScreenshot%202026-02-13%20at%2008.47.35.png?alt=media&amp;token=98487d8e-00fb-4627-80e7-2b02ed21c0d8" alt=""><figcaption></figcaption></figure>

* The following details are displayed for each Action:

| Security Score Details   | Remarks                                                                                                                                                                                                       |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Score                    | The actions security score. The highest rating is 10.                                                                                                                                                         |
| License                  | Verifies the presence of a published license in standard locations. A clear license is crucial for security reviews, audits, and mitigating legal risks for users.                                            |
| Maintained               | Project activity is assessed based on recent commits and issue engagement. Active maintenance is crucial for ongoing security and functionality.                                                              |
| Vulnerabilities          | Dependencies are monitored for vulnerabilities and updated periodically to address identified issues promptly.                                                                                                |
| Branch protection        | Checks if default and release branches are protected using GitHub’s branch protection or repository rules. Ensures defined workflows, such as required reviews or status checks, are enforced before merging. |
| Manual code review       | Verifies that code changes are reviewed by at least one person other than the author. This practice enhances code quality and security through additional oversight.                                          |
| Secure publishinng       | Verifies that secure deployment practices are in place, including deployment review, reproducible builds, and generation of SBOM and provenance.                                                              |
| Signed commits           | All code contributions are made with signed commits, enforced through branch protection to ensure code authenticity and integrity.                                                                            |
| Automated security tools | Verifies the use of automated tools like SAST, SCA, and security scorecards on each change and periodically. Checks if responses are triaged promptly to maintain security standards.                         |
| Popular                  | Checks if the action is widely used by other open source projects. Higher usage can indicate community trust and more thorough vetting.                                                                       |
| Security policy          | Verifies the presence of a SECURITY.md file in standard locations. This policy provides secure reporting methods, ensuring responsible disclosure.                                                            |

* Scroll down in the GitHub Actions Advisor to see all outbound network calls made by the action. This section displays the results of the Action’s runtime analysis

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2FY54peuxh6oLlaF6cOK0p%2FScreenshot%202026-02-13%20at%2008.48.18.png?alt=media&amp;token=c41df5a5-1689-46b9-8d4b-459e65d2c3bd" alt=""><figcaption></figcaption></figure>

* On the second tab, you can view the AI Analysis of the Action, including the Action Summary, AI Security Score, security findings, and recommendations

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2Fj3siAoKZHBpacZTd8PS5%2FScreenshot%202026-02-13%20at%2008.49.16.png?alt=media&amp;token=25b43d03-ac42-4ffd-b267-f24025ef4815" alt=""><figcaption></figcaption></figure>

### Composite Actions

Some GitHub Actions act as composite (parent) actions, meaning they include other GitHub Actions within their own action.yml. These composite actions make it easier to reuse complex logic but also introduce additional dependencies that can affect overall security.

When you open a composite action in the GitHub Actions Advisor, you’ll see a Composite Action Details section like this:

* **Effective Score** — Displays the combined score that factors in both the composite action and all internal actions it uses
* **Pinnable** — Indicates whether the composite action can be pinned, based on whether all internal actions are pinned to specific SHAs
* **Action Scores** — Lists each GitHub Action used inside the composite action, along with its individual security score

<figure><img src="https://754495266-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQJRZY4cfEeY3I7DXTOCp%2Fuploads%2FEXw7hW5lh5DjCTVmho1x%2FScreenshot%202025-10-11%20at%2012.32.56.png?alt=media&amp;token=e8144e25-f11b-43a4-8fe0-2bcd6377f3cf" alt=""><figcaption><p>GitHub Actions Advisor</p></figcaption></figure>


---

# Agent Instructions
This documentation is published with GitBook. GitBook is the documentation platform designed so that both humans and AI agents can read, navigate, and reason over technical content effectively. Learn more at gitbook.com.

## Querying This Documentation
If you need additional information that is not directly available in this page, you can query the documentation by asking a question.

Perform an HTTP GET request on the following URL with the `ask` and `goal` query parameters:

```
GET https://docs.stepsecurity.io/github-actions/actions/github-actions-advisor.md?ask=<question>&goal=<user_goal>
```

`ask` is the immediate question: it should be specific, self-contained, and written in natural language.
`goal` is what the user is ultimately trying to achieve, the reason they need the answer. Sharing it helps GitBook give you a better, more relevant answer. A goal is most helpful when it describes the outcome the user wants rather than restating the question. For example, with `ask=how do I create an API token`, a goal like `automate deployments from our CI pipeline` lets GitBook tailor the answer to that use case.

The response will contain a direct answer to the question and relevant excerpts and sources from the documentation.

Use this mechanism when the answer is not explicitly present in the current page, you need clarification or additional context, or you want to retrieve related documentation sections.
