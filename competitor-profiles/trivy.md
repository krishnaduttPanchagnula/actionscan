# Trivy — Quick Profile

**URL**: https://trivy.dev/
**Generated**: 2026-10-22

## At a Glance
| Metric | Value |
|--------|-------|
| Tagline | "The All-in-One Security Scanner" (observed, trivy.dev homepage) |
| Target audience | DevOps / cloud-native platform & security engineers, container + IaC users (inferred from homepage copy: "Use Trivy to find vulnerabilities (CVE) & misconfigurations (IaC) across code repositories, binary artifacts, container images, and Kubernetes clusters.") |
| Language / license | Go / Apache-2.0 |
| GitHub stars / forks | 38,608 / 790 (GitHub API, 2026-10-22) |
| Releases (latest) | 95 fetched on first page of releases API; latest v0.76.1, published 2026-10-21 (GitHub API) |
| Install / download volume | Homebrew: 13,806 installs/30d, 33,813/90d, 138,808/365d (formulae.brew.sh API, 2026-10-22). Docker/GitHub-release download counts not fetched. |
| Pricing starts at | Trivy CLI: free, Apache-2.0. Commercial: Aqua Security — pricing page scraped but prices are JS-rendered and **not observable** from the fetched HTML (aquasec.com/pricing, 2026-10-22) |
| Free tier/trial | Yes — the CLI is fully free and self-hosted; the checks bundle and vuln DB are published as OCI artifacts on GHCR/mirror.gcr.io |
| Domain rank | not available (no SEO data source) |
| Est. organic traffic | not available (no SEO data source) |
| Organic keywords (top 10) | not available (no SEO data source) |
| Referring domains | not available (no SEO data source) |

## Positioning
**Headline**: "The All-in-One Security Scanner"
**Subheadline**: "Use Trivy to find vulnerabilities (CVE) & misconfigurations (IaC) across code repositories, binary artifacts, container images, and Kubernetes clusters."
**Positioning angle**: *Observed* — one binary, many targets (image, filesystem, git repo, rootfs, VM, Kubernetes, SBOM) and many scanners (vuln, misconfig, secret, license, crypto). *Inferred* — Trivy's value proposition is breadth and zero-config adoption ("brew install trivy", `docker run aquasec/trivy`), not depth in any one workflow-security niche.

## Product & Features
### Core capabilities
*Observed (README + docs, 2026-10-22)*:
- **Targets**: Container Image, Filesystem, Rootfs, Git Repository (remote), Virtual Machine Image, Kubernetes, SBOM (`trivy image|fs|rootfs|repo|vm|kubernetes|sbom|config|vex|server`).
- **Scanners**: OS packages & dependency vulns (CVE), IaC misconfigurations (OPA/Rego), secrets, software licenses, cryptographic assets.
- **Misconfiguration engine**: Rego checks distributed as an OPA bundle on `ghcr.io/aquasecurity/trivy-checks`, auto-updated every 24h, with an embedded fallback bundle for air-gapped use.
- **Vuln DB**: OCI artifacts `mirror.gcr.io/aquasec/trivy-db:2` / `ghcr.io/aquasecurity/trivy-db:2`; supports SBOM/attestation/VEX, `--skip-update`, self-hosted DBs.
- **Self-hosting**: `--db-repository`, `--checks-bundle-repository`, air-gap docs, `trivy server` client/server mode, usage telemetry opt-out.

### GitHub Actions coverage — what it does and does not do
**Core finding (verified at source level, 2026-10-22): Trivy has no GitHub Actions scanner at all.**

*Observed*:
- The IaC coverage table (docs/guide/coverage/iac/index.md) lists exactly: Kubernetes, Docker, Terraform, Terraform Plan, CloudFormation, Azure ARM Template, Helm, generic YAML, generic JSON, Ansible. **No GitHub Actions / workflow entry.**
- The misconfiguration check bundle (`aquasecurity/trivy-checks`) contains exactly three check families: `checks/cloud`, `checks/docker`, `checks/kubernetes`. There is no `checks/github-actions`.
- The single GitHub-named check — `checks/cloud/github/actions/no_plain_text_action_secrets.rego` (AVD-GIT-0002) — is a **Terraform-provider** check on `github_environmentsecrets`; it does not parse `.github/workflows/*.yml`.
- Trivy's dependency analyzers (`pkg/fanal/analyzer/language/`) cover c, conda, dart, dotnet, elixir, golang, java, julia, nodejs, php, python, ruby, rust, swift. There is **no GitHub Actions language analyzer**, so `uses: owner/repo@ref` is never resolved to a package.
- The docs **CI/CD ecosystem page is live and correct at `https://trivy.dev/latest/docs/ecosystem/cicd/`** (the earlier 404 in our notes does not reproduce as of 2026-10-22; it lists Azure DevOps, trivy-action, Buildkite, Dagger, Semaphore, CircleCI, Woodpecker, Concourse, SecObserve). It is a list of **integrations for running Trivy inside CI/CD**, not a scanner of CI/CD configuration.

*Consequence — the core question*: Trivy **does not resolve GitHub Action references against any advisory feed**. There is no GHSA/OSV lookup for `uses:` references, no compromised-action feed, no "is this action version known-bad" logic anywhere in the codebase or check bundle.

*Inferred*: a workflow file passed to `trivy fs .` would be treated as generic YAML — eligible only for the secret scanner, and for misconfiguration only if it happens to match a Kubernetes/CloudFormation schema. `actions/checkout@v4` would be scanned as an arbitrary string, not as a software reference.

### Output formats
*Observed (docs/guide/configuration/reporting.md)*: Table (default, with table modes), JSON, **SARIF** (2.1.0, `--format sarif`), GitHub dependency snapshot (`--format github`), Template (custom Go templates, incl. built-in `contrib/junit.tpl`, `contrib/html.tpl`, `contrib/gitlab.tpl`, ASFF for Security Hub), SBOM/CycloneDX/SPDX via `trivy convert`.
- **HTML**: available only via the template mechanism (`--format template --template "@contrib/html.tpl"`) — not a first-class `--format html`.
- **CSV**: not offered.
- `trivy convert` can convert a JSON report into other formats (CycloneDX, etc.).

### CI integration and exit codes
*Observed*:
- Official `aquasecurity/trivy-action` GitHub Action; SARIF upload to **GitHub code scanning** via `github/codeql-action/upload-sarif` is documented in the action README (SARIF 2.1.0 compliance).
- Community integrations for CircleCI, Buildkite, Dagger, Semaphore, Woodpecker, Concourse, Azure DevOps, SecObserve.
- **Exit codes (verified in source, `pkg/commands/operation/operation.go` + `cmd/trivy/main.go` + `pkg/log/logger.go`, 2026-10-22)**:
  - `0` — clean / no findings (also the default for `--exit-code`, i.e. **Trivy does not fail the build by default**).
  - `1` — fatal error: `log.Fatal` → `os.Exit(1)` for user errors and unexpected failures.
  - `N` — findings present, where `N` is whatever the user set via `--exit-code N` (the flag default is `0`; `trivy-action` docs show `exit-code: '1'` as a typical setting).
  - `N` — EOL OS detected, via `--exit-on-eol N`.
  - **There is no built-in "2 = findings" convention.** The premise that Trivy uses `0/1/2` is *not* what the code does: the findings exit code is user-configurable and defaults to 0.
  - *Inferred*: because `--exit-code` is a free integer, Trivy's convention is "0 = pass, non-zero = fail, code chosen by the caller", not a severity ladder.

### Org-wide scan capability
*Observed*: **None in the OSS CLI.** There is no `trivy org`/organization subcommand; the full command list is `clean, config, convert, filesystem, image, kubernetes, module, plugin, registry, repository, rootfs, sbom, server, version, vex, vm` (docs/guide/references/configuration/cli/trivy.md). `trivy repo` scans **one** repository (remote URL + optional `--branch`/`--commit`).
*Inferred*: org-wide coverage would have to be orchestrated by the caller (a loop over repos) or delegated to the commercial Aqua platform. This is exactly the gap actionscan targets.

## Pricing Summary
| Tier | Price | Notable Inclusions |
|------|-------|--------------------|
| Trivy CLI (OSS) | Free, Apache-2.0 | All scanners, all targets, local vuln DB + checks bundle, self-hostable/air-gappable |
| Aqua Security (commercial) | Not observable — pricing page is JS-rendered (aquasec.com/pricing scraped 2026-10-22) | Enterprise platform, CSPM/CWPP, CI/CD pipeline security (per site navigation) |

## Key Takeaway
Trivy is the distribution leader of this set by GitHub stars (38.6k) and by Homebrew installs (13.8k/30d), and it is genuinely excellent at its actual job — scanning containers, filesystems and lockfiles for known CVEs. But its architecture makes GitHub Actions structurally invisible: there is no workflow schema, no `uses:` parser, no advisory feed for action references, and no organization sweep. Its "CI/CD" story is entirely about *running Trivy in* CI, not about *scanning* CI definitions.

## Competitive Implications for actionscan
**Where they're strong vs. us** | **Where we're strong vs. them** (hypothesis unless evidenced) | **Opportunities** | **Threats**
---|---|---|---|
| **Observed:** unmatched brand, 38.6k stars, 13.8k brew installs/30d, 138.8k/365d; one-binary install (`brew install trivy`); official GitHub Action with SARIF→code-scanning already solved; free & permissive license; vendor (Aqua) sells an enterprise tier that could one day bolt on supply-chain features. | **Observed:** Trivy has zero GitHub Actions coverage — no workflow parser, no `uses:` resolution, no GHSA/OSV lookup for actions, no compromised-action feed, no org sweep. **Inferred:** an org that runs Trivy today gets no visibility into which actions it depends on. | Ship the "Trivy for Actions" gap: a Trivy-plugin-style or standalone scanner that resolves every `uses:` to a package and checks it against GHSA/OSV/compromised feeds. Position explicitly as "the Trivy of Actions supply chain" for users who already trust Trivy's DB. Consider emitting Trivy-compatible JSON so Trivy users can pipe results in. | *Inferred:* Aqua could add a GitHub Actions dependency scanner to Trivy's DB (it already ships GHSA/OSV-derived data) and would inherit 38.6k stars + the whole Docker install base for free. Conversely, Trivy's ubiquity means "we're the GitHub-Actions scanner" will always be compared against "the Trivy of GitHub Actions" in search. |
| **Observed:** SARIF + code-scanning integration is solved and copyable. | **Observed:** Trivy's exit-code convention (0 pass / 1 fatal / user-set code for findings) is simpler than zizmor's severity ladder — we can copy the "user picks the code" model or deliberately differentiate with a documented severity ladder. | Match Trivy's SARIF + GitHub code-scanning upload UX so a Trivy user can adopt us with one workflow step. Adopt a documented exit-code contract and publish it (Trivy's is only inferable from source). | *Inferred:* Trivy's install-base default (`brew install trivy`) means a user may pick Trivy reflexively; if Trivy ever ships a `trivy actions` subcommand, the "just use Trivy" objection becomes strong. |

## Raw Data Sources
| Source | URL / path | Saved to |
|---|---|---|
| Trivy homepage | https://trivy.dev/ | `raw/trivy/2026-10-22/scrapes/trivy_homepage.md` |
| Trivy CI/CD ecosystem | https://trivy.dev/latest/docs/ecosystem/cicd/ | `raw/trivy/2026-10-22/scrapes/trivy_ecosystem_cicd.md` |
| Trivy IaC coverage table | https://trivy.dev/latest/docs/guide/coverage/iac/ | `raw/trivy/2026-10-22/scrapes/trivy_coverage_iac.md` |
| Trivy reporting / formats | https://trivy.dev/latest/docs/guide/configuration/reporting/ | `raw/trivy/2026-10-22/scrapes/trivy_reporting.md` |
| Trivy docs (raw markdown) | ecosystem/cicd.md, guide/coverage/iac/index.md, guide/configuration/reporting.md, guide/references/modes/standalone.md, guide/scanner/misconfiguration/check/builtin.md, CLI refs | `raw/trivy/2026-10-22/scrapes/trivy_*.md` |
| Trivy README | https://raw.githubusercontent.com/aquasecurity/trivy/main/README.md | `raw/trivy/2026-10-22/scrapes/trivy_readme.md` |
| trivy-action README (exit-code + code-scanning SARIF) | https://raw.githubusercontent.com/aquasecurity/trivy-action/master/README.md | `raw/trivy/2026-10-22/scrapes/trivy_action_readme.md` |
| trivy-checks bundle contents (no github-actions family) | GitHub API `aquasecurity/trivy-checks/contents/checks` | (API, verified live) |
| trivy-checks github/actions check (Terraform provider, not workflows) | `checks/cloud/github/actions/no_plain_text_action_secrets.rego` | `raw/trivy/2026-10-22/scrapes/trivy_chk_gh_actions.rego` |
| Trivy exit-code logic (source) | `pkg/commands/operation/operation.go`, `cmd/trivy/main.go`, `pkg/types/error.go`, `pkg/log/logger.go` | verified live at tag v0.76.1-era main |
| GitHub repo + releases API | `aquasecurity/trivy` | `raw/trivy/2026-10-22/seo/github-repo.json`, `github-releases.json` |
| Homebrew formula + analytics | https://formulae.brew.sh/api/formula/trivy.json | `raw/trivy/2026-10-22/seo/brew-trivy.json` |
| Aqua pricing (JS-rendered, prices not observable) | https://www.aquasec.com/pricing | `raw/trivy/2026-10-22/scrapes/aquasec_pricing.md` |
| Academic benchmark (Trivy **excluded** from study) | arXiv 2601.14455v2 | `raw/semgrep/2026-10-22/scrapes/arxiv_2601.14455_v2.txt` |
