# Checkov — Quick Profile

**URL**: https://www.checkov.io/
**Generated**: 2026-10-22

## At a Glance
| Metric | Value |
|--------|-------|
| Tagline | "Policy-as-code for everyone" (observed, checkov.io homepage) |
| Target audience | Cloud/IaC engineers & platform teams wanting misconfiguration gates in CI; Prisma Cloud enterprise buyers (inferred from homepage copy: "Checkov scans cloud infrastructure configurations to find misconfigurations before they're deployed.") |
| Language / license | Python (>=3.9, <=3.12) / Apache-2.0 |
| GitHub stars / forks | 9,092 / 1,446 (GitHub API, 2026-10-22) |
| Releases (latest) | 100 fetched on first page of releases API (repo has 100+); latest 3.3.30, published 2026-10-20 (GitHub API) |
| Install / download volume | PyPI `checkov`: **3,968,190/month** (pypistats `/recent`, last_month); 4,730,760 over the trailing 30 days without mirrors; 205,424 last day; 1,191,459 last week (computed from `pypistats.org/api/packages/checkov/overall`). Homebrew: 2,860 installs/30d, 8,380/90d, 33,835/365d. |
| Pricing starts at | Checkov CLI: free, Apache-2.0. Commercial: Prisma Cloud — **pricing not observable** from the pages scraped (checkov.io homepage links to prismacloud.io; no price table was retrieved) |
| Free tier/trial | Yes — CLI fully free; Prisma Cloud offers a "request a trial" path (link present on checkov.io) |
| Domain rank | not available (no SEO data source) |
| Est. organic traffic | not available (no SEO data source) |
| Organic keywords (top 10) | not available (no SEO data source) |
| Referring domains | not available (no SEO data source) |

## Positioning
**Headline**: "Policy-as-code for everyone"
**Subheadline**: "Checkov scans cloud infrastructure configurations to find misconfigurations before they're deployed. Checkov uses a common command line interface to manage and analyze infrastructure as code (IaC) scan results across platforms such as Terraform, CloudFormation, Kubernetes, Helm, ARM Templates and Serverless framework."
**Positioning angle**: *Observed* — breadth of IaC frameworks + "extensible policy management interfaces" (Python policies, graph-based YAML policies, custom providers/suppressions) + CI integration. *Inferred* — Checkov's identity is "the enterprise-grade IaC policy engine you can run yourself", with Prisma Cloud as the upsell for central policy enforcement.

## Product & Features
### Core capabilities
*Observed (README + docs, 2026-10-22)*:
- **Over 1000 built-in policies** across AWS/Azure/GCP; also Argo Workflows, Azure Pipelines, Bitbucket Pipelines, CircleCI Pipelines, **GitHub Actions**, GitLab CI.
- Three policy styles: Python attribute policies, YAML attribute policies, and **graph-based YAML policies** (context/resource relationships).
- Additional frameworks: `sca_package` (dependency scanning), `sca_image` (container images), `secrets` (regex + keyword + entropy), `github_configuration` (GitHub repo settings via API).
- **Live Terminal Execution** — "Execute, test, and modify runner parameters in the context of a subject repository CI/CD and version control integrations" (observed on homepage).
- Platform integration: `--bc-api-key` / `--repo-id` to push results and fetch central **enforcement rules** to Prisma Cloud; `--use-enforcement-rules`.
- Suppressions: inline, by check ID, severity-based; `--skip-check`, `--skip-framework`.
- SCA scanning of dependencies (packages) — this is the closest Checkov comes to "known-vulnerable software", and it is package-based (pip/npm/maven), **not action-reference-based**.

### GitHub Actions coverage — what it does and does not do
**Core finding (verified at source level, 2026-10-22): Checkov's `github_actions` framework is 8 checks, all structural/pattern checks on the workflow YAML. None resolve `uses:` to a package or consult an advisory feed.**

*Observed* — `checkov/github_actions/checks/` contains exactly 7 Python checks + 1 graph check:
| ID | Policy text (verbatim from checkov.io Policy Index) | Source file |
|---|---|---|
| CKV_GHA_1 | "Ensure ACTIONS_ALLOW_UNSECURE_COMMANDS isn't true on environment variables" | `AllowUnsecureCommandsOnJob.py` |
| CKV_GHA_2 | "Ensure run commands are not vulnerable to shell injection" | `ShellInjection.py` |
| CKV_GHA_3 | "Suspicious use of curl with secrets" | `SuspectCurlInScript.py` |
| CKV_GHA_4 | "Suspicious use of netcat with IP address" | `ReverseShellNetcat.py` |
| CKV_GHA_5 | "Found artifact build without evidence of cosign sign execution in pipeline" | `CosignArtifacts.py` |
| CKV_GHA_6 | "Found artifact build without evidence of cosign sbom attestation in pipeline" | `CosignSBOM.py` |
| CKV_GHA_7 | "The build output cannot be affected by user parameters other than the build entry point and the top-level source location. GitHub Actions workflow_dispatch inputs MUST be empty." | `EmptyWorkflowDispatch.py` |
| CKV2_GHA_1 | "Ensure top-level permissions are not set to write-all" (graph check on `permissions`) | `ReadOnlyTopLevelPermissions.yaml` |

*Observed*:
- The checkov.io Policy Index page for `github_actions` lists exactly these 8 checks (11 table rows, because several checks are registered against two entity scopes: `jobs` and `jobs.*.steps[]`).
- `checkov/github_actions/utils.py` and `schemas.py` reference `uses` only as a **string field to pattern-match**, never to resolve.
- GitHub code search in the repo for `action.yml` / `action.yaml` returns **0 results** — Checkov never parses an action's own definition.
- There is **no "GitHub Actions" page in the checkov.io "7.Scan Examples" section** (which covers Terraform, Helm, Kustomize, SAM, Ansible, Argo, Azure ARM/Pipelines/Bicep, Bitbucket, CDK, CloudFormation, Dockerfile, GitHub, GitLab, Kubernetes, OpenAPI, SCA, Serverless). GitHub Actions is listed in the README's framework list but has no dedicated scan walkthrough.
- The checkov.io "4.Integrations/GitHub Actions" page is about **running Checkov inside GitHub Actions** (via `bridgecrewio/checkov-action`) on Terraform, not about scanning workflows.

*Consequence — the core question*: Checkov **does not resolve GitHub Action references against any advisory feed**. Its GitHub Actions checks are equivalent to what a YAML-linter does. Notably, Checkov's `github_actions` framework has **no pinning check** — nothing flags `uses: owner/repo@v1` vs a SHA.

### Output formats
*Observed* (docs/2.Basics/CLI Command Reference.md, `--output` enum): `cli`, `csv`, `cyclonedx`, `cyclonedx_json`, `spdx`, `json`, `junitxml`, `github_failed_only`, `gitlab_sast`, `sarif`.
- **SARIF**: yes (`-o sarif`), with a documented sample and a "GitHub code scanning" framing; `github_action_resources/checkov-problem-matcher.json` exists for GitHub problem matchers.
- **HTML**: **no native HTML report in the OSS CLI.** Dashboards are a Prisma Cloud platform feature ("Visualizing Checkov output" → send results to Prisma Cloud).
- Multiple outputs can be produced in one run; `--output-file-path` maps output type → file.

### CI integration and exit codes
*Observed*:
- Official `bridgecrewio/checkov-action`; docs show the action failing the build on findings; pre-commit hook; Jenkins, GitLab CI, Bitbucket, CircleCI, Azure Pipelines, Kubernetes, Docker integrations.
- **Exit codes (documented in docs/2.Basics/Hard and soft fail.md, 2026-10-22)**:
  - `0` — passing (all checks passed or skipped), or a "soft fail" where findings were reported but demoted.
  - `1` — failure (any hard-failed check).
  - Granularity comes from `--soft-fail` (always exit 0), `--soft-fail-on <IDs|SEVERITY>` and `--hard-fail-on <IDs|SEVERITY>`, with a documented precedence order (check-ID match → severity threshold → `--soft-fail` fallback). Platform enforcement rules can set a hard-fail severity threshold centrally.
- *Note*: there is no separate "error" exit code — Checkov uses 0/1 only.

### Org-wide scan capability
*Observed*: **Not in the OSS CLI.** The CLI scans a local directory (`-d`), a file (`-f`), a docker image, or a remote repo via the platform. Org-wide enforcement is a **Prisma Cloud** feature: `--bc-api-key` + `--repo-id` uploads results, and `--use-enforcement-rules` pulls centrally-configured hard-fail thresholds back down. The `github_configuration` framework can query GitHub repo settings, but it is per-repository.
*Inferred*: the OSS path to "scan our whole org" is a loop over repos driven by the user, or a paid platform — which is precisely the segment actionscan targets for free.

## Pricing Summary
| Tier | Price | Notable Inclusions |
|------|-------|--------------------|
| Checkov CLI (OSS) | Free, Apache-2.0 | 1000+ built-in policies, Python+YAML+graph policies, 24 frameworks incl. `github_actions`, SCA + secrets, SARIF/JUnit/CSV/CycloneDX/SPDX output |
| Prisma Cloud Code Security (commercial) | Not observable from the pages scraped (no price table retrieved; "request a Prisma Cloud trial" link present) | Central enforcement rules, multi-repo/org management, dashboards, "Live Terminal Execution" |

## Key Takeaway
Checkov has by far the largest measured install base in this set (≈4.0M PyPI downloads/month, ~3.97M by pypistats `/recent`), an enterprise-grade policy engine, and real GitHub Actions awareness — but its GitHub Actions support is 8 workflow-YAML pattern checks, with no pinning check and no advisory lookup of any `uses:` reference. It is a CI-gating IaC scanner that happens to also parse workflow files, and it is the distribution threat most likely to be mistaken for actionscan by a platform/security buyer.

## Competitive Implications for actionscan
**Where they're strong vs. us** | **Where we're strong vs. them** (hypothesis unless evidenced) | **Opportunities** | **Threats**
---|---|---|---|
| **Observed:** ~4.0M PyPI downloads/month, 1,446 forks (highest fork ratio of the four → high enterprise derivative use), Apache-2.0, 1000+ policies, first-class SARIF + JUnit + CSV, "hard/soft fail" CI gating documented in depth, Prisma Cloud enterprise backing with central enforcement rules. | **Observed:** `github_actions` = 8 checks, all structural; **no pinning check**; **no `uses:` resolution**; **no advisory feed for actions**; **no org sweep in OSS**; **no HTML report**. **Inferred:** a Checkov user gets zero signal on "is the action I depend on compromised/vulnerable/outdated". | Lead with the checks Checkov structurally lacks: pinning hygiene, compromised-action detection, GHSA/OSV matching on action versions, and outdated-version reporting. Provide a **drop-in CI step** (SARIF + same exit-code semantics) so a Checkov shop can add us next to Checkov without changing gate logic. Consider a `checkov`-style YAML output so results can be merged into an existing gate. | *Inferred:* Checkov already has the Python policy language, the platform, the enterprise sales motion and the install base — if Bridgecrew/Prisma wanted action-reference auditing, adding it to `github_actions` (plus a pinning check) is a small increment on top of an existing SCA engine, and it would arrive pre-installed in millions of CI jobs. |
| **Observed:** live-org workflows are the natural entry point: PyPI install is one command; `--soft-fail-on`/`--hard-fail-on` severity gating is a UX we can copy. | **Observed:** exit codes are 0/1 only, with severity thresholds handled by flags — simple to adopt. | Adopt a documented exit-code ladder that is *more* expressive than 0/1 (severity-based, like zizmor) and publish it, so CI integrators can choose. Differentiate on the *unit of analysis* (an org-wide inventory of action dependencies) rather than on per-file rules. | *Inferred:* the "just run checkov" answer is credible for a buyer who wants "one scanner for everything" — we lose those deals unless we make the action-reference layer obviously a different job. |

## Raw Data Sources
| Source | URL / path | Saved to |
|---|---|---|
| Checkov homepage | https://www.checkov.io/ | `raw/checkov/2026-10-22/scrapes/checkov_homepage.md` |
| GitHub Actions integration page | https://www.checkov.io/4.Integrations/GitHub Actions.html | `raw/checkov/2026-10-22/scrapes/checkov_github_actions_integration.md` |
| Policy Index — github_actions | https://www.checkov.io/5.Policy Index/github_actions.html | `raw/checkov/2026-10-22/scrapes/checkov_policy_index_github_actions.md` |
| Checkov README | https://raw.githubusercontent.com/bridgecrewio/checkov/main/README.md | `raw/checkov/2026-10-22/scrapes/checkov_readme.md` |
| Docs: CLI Command Reference (output/framework enums) | `docs/2.Basics/CLI Command Reference.md` | `raw/checkov/2026-10-22/scrapes/checkov_cli_reference.md` |
| Docs: Hard and soft fail (exit codes) | `docs/2.Basics/Hard and soft fail.md` | `raw/checkov/2026-10-22/scrapes/checkov_hard_soft_fail.md` |
| Docs: Outputs — SARIF | `docs/8.Outputs/SARIF.md` | `raw/checkov/2026-10-22/scrapes/checkov_output_sarif.md` |
| Docs: Outputs — CSV / Reviewing results / Visualizing | `docs/8.Outputs/CSV.md`, `docs/2.Basics/*.md` | `raw/checkov/2026-10-22/scrapes/checkov_output_csv.md`, `checkov_reviewing_scan_results.md`, `checkov_visualizing_output.md` |
| Source: GitHub Actions checks (7 py + 1 graph) | `checkov/github_actions/checks/{job,graph_checks}/` | verified live via GitHub API + raw fetch |
| Source: no action-definition parsing | GitHub code search `repo:bridgecrewio/checkov "action.yml"` → 0 results | verified live |
| GitHub repo + releases API | `bridgecrewio/checkov` | `raw/checkov/2026-10-22/seo/github-repo.json`, `github-releases.json` |
| PyPI download stats | https://pypistats.org/api/packages/checkov/recent + /overall | `raw/checkov/2026-10-22/seo/pypistats-checkov.json`, `pypistats-checkov-overall.json` |
| Homebrew formula + analytics | https://formulae.brew.sh/api/formula/checkov.json | `raw/checkov/2026-10-22/seo/brew-checkov.json` |
| Academic benchmark (Checkov **not** included in the study) | arXiv 2601.14455v2 | `raw/semgrep/2026-10-22/scrapes/arxiv_2601.14455_v2.txt` |
