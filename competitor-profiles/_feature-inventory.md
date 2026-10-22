# Competitor Capability Matrix — actionscan

**Generated**: 2026-10-22  
**Sources**: 14 competitor profiles in `competitor-profiles/` (all fetched 2026-10-22)  
**Raw data**: `competitor-profiles/raw/<slug>/2026-10-22/`

Mechanical extraction of what each profile states. `Y` = observed in the profile (qualifier in parentheses). `—` = not observed in the profile. `n/a` = category does not apply to that tool's model (used only for Harden-Runner, a runtime agent, on file/repo-input rows).

> **Column-count note**: the brief names 15 competitors, but only 14 competitor profile files exist (`zizmor`, `stepsecurity`, `osv-scanner`, `poutine`, `actionlint`, `scorecard`, `scharf`, `frizbee`, `pinny`, `harden-runner`, `trivy`, `checkov`, `semgrep`, `kics`). Snyk and Raven appear in `_prioritized-list.md` but were never profiled (`raw/raven/2026-10-22/` is empty), so they are excluded rather than guessed. The matrix therefore has 14 columns.

**Rules applied**: extract only what the profiles state; where two documents in the profile set conflict, the more specific/sourced statement is used and flagged with `⚠` in that section's evidence line. No ranking, no recommendation, no scoring.

## Scope & target

| Capability | zizmor | StepSecurity | osv-scanner | poutine | actionlint | Scorecard | scharf | frizbee | pinny | Harden-Runner | Trivy | Checkov | Semgrep | KICS |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Single file / explicit path input | Y (individual files) | Y (Secure Workflow paste) | Y (custom lockfile) | Y (analyze_manifest content) | Y (explicit paths) | Y (--repo) | Y (local path or URL) | Y (single ref or dir) | Y (workflows dir) | n/a | Y (fs, file, repo) | Y (-f file) | Y (local paths) | Y (scan -p paths) |
| Local directory / checkout input | Y | Y (repository via platform) | Y | Y | Y | Y | Y | Y | Y | n/a | Y | Y | Y | Y |
| Remote repository scan | Y (owner/repo[@ref]) | Y (repo via platform) | — | Y (analyze_repo) | — | Y (--repo) | Y (URL auto-cloned) | — | — | n/a | Y (trivy repo) | Y (remote repo via platform) | — | — |
| Org-wide / user-wide sweep | — | Y (Enterprise only) | — | Y (analyze_org, clones) | — | Y (--org) | — | — | — | — | — | Y (Prisma Cloud, paid) | Y (paid; 10-repo cap) | — |
| Explicit multi-repo list | — | Y (trivy-compromise-scanner --repo) | — | — | — | Y (--repos) | Y (find --root workspace) | — | — | n/a | — | — | — | — |
| Standard-input input | Y (-) | — | — | — | Y (-) | — | — | — | — | n/a | — | — | — | — |
| GitLab CI support | — | Y (runner security) | — | Y (gitlab parser) | — | — | — | — | — | Y (Enterprise) | — | Y (GitLab CI framework) | — | — |
| Azure DevOps / Tekton support | — | Y (ADO runners) | — | Y (azure + tekton) | — | — | — | — | — | Y (ADO) | — | Y (Azure Pipelines) | — | — |
| Container image target | — | — | Y (scan image) | — | — | — | — | Y (tag→digest) | Y (Dockerfile pin) | n/a | Y (image, rootfs, k8s) | Y (sca_image) | — | — |
| Lockfile / manifest target | — | — | Y (19+ lockfiles) | — | — | Y (OSV deps check) | — | — | — | n/a | Y (dependency CVEs) | Y (sca_package) | Y (SCA 20+ ecosystems) | — |
| SBOM ingest | — | — | Y (SPDX + CycloneDX) | — | — | — | — | — | — | n/a | Y (sbom target, VEX) | — | — | — |
| Runtime runner monitoring | — | Y (Harden-Runner) | — | — | — | — | — | — | — | Y (eBPF agent) | — | — | — | — |
| Repo-level posture score output | — | — | — | — | — | Y (0-10 + aggregate) | — | — | — | — | — | — | — | — |
| Action definition (action.yml) parsing | Y | — | — | — | Y (input/output validation) | — | — | — | — | n/a | — | — | — | — |
| Dependabot config parsing | Y | — | — | — | — | — | — | — | — | n/a | — | — | — | — |
| Pre-commit config parsing | Y | — | — | — | — | — | — | — | — | n/a | — | — | — | — |
| Workflow run-log scanning | — | Y (trivy-compromise-scanner) | — | — | — | — | — | — | — | n/a | — | — | — | — |
| Cross-repo action-reference inventory | — | Y (Actions In Use, Enterprise) | — | — | — | — | — | — | — | — | — | — | — | — |
| Fork / archived repo exclusion in sweeps | — | — | — | Y (--ignore-forks, archived skipped) | — | Y (non-archived only) | — | — | — | — | — | — | — | — |
| Non-default / stale branch scanning | — | — | — | Y (analyze_repo_stale_branches) | — | — | Y (remote-tracking branches) | — | — | — | — | — | — | — |

> Evidence: zizmor.md §Product & Features (Input collection, Operating modes, Audit catalogue); stepsecurity.md §Product & Features (Actions Governance, trivy-compromise-scanner flags); osv-scanner.md §Product & Features (Supported Artifacts, Ecosystem support); poutine.md §Product & Features (Subcommands, analyze_org, Multi-CI support); actionlint.md §Product & Features (What it checks, Scope / non-features); scorecard.md §Product & Features (Unit of analysis, `--org`/`--repos`); scharf.md §Product & Features (Command surface); frizbee.md §Product & Features (Commands); pinny.md §Product & Features (Command surface); harden-runner.md §Product & Features (Installation model, capability matrix); trivy.md §Product & Features (Targets, GitHub Actions coverage); checkov.md §Product & Features (Frameworks, GitHub Actions coverage); semgrep.md §Product & Features (p/github-actions ruleset); kics.md §Product & Features (Query platforms, 4 CI/CD queries).

## Detection rules

| Capability | zizmor | StepSecurity | osv-scanner | poutine | actionlint | Scorecard | scharf | frizbee | pinny | Harden-Runner | Trivy | Checkov | Semgrep | KICS |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Rule / audit catalogue size | Y (41 audits) | — | — | Y (13 Rego rules) | Y (39 checks) | Y (20 checks, 48 probes) | Y (1 SHA-pin rule) | — | — | — | — | Y (8 GHA checks) | Y (12 GHA rules) | Y (4 CI/CD queries) |
| Static workflow-file rule analysis | Y | Y (secure-repo audits workflows) | — | Y | Y | Y (Dangerous-Workflow, Pinned-Dependencies) | Y (structure-aware spans) | Y (uses: scan only) | Y (regex line scan) | — | — | Y | Y | Y |
| uses: resolved against advisory DB | Y (GHSA only, first-level) | Y (closed Threat Center) | — | Y (19 static, semver only) | — | — | — | — | — | — | — | — | — | — |
| Workflow expression / type linting | — | — | — | — | Y (full type system) | — | — | — | — | — | — | — | — | — |
| Secret / credential exposure detection | Y (overprovisioned, redaction, container creds) | — | — | — | Y (hardcoded credentials check) | — | — | — | — | Y (runtime build-log secrets) | Y (secret scanner) | Y (secrets framework) | Y (semantic secrets detection) | Y (secret scanner) |
| Injection detection | Y | — | — | Y (injection rule) | Y (script injection) | Y (Dangerous-Workflow) | — | — | — | — | — | Y (CKV_GHA_2) | Y (2 rules) | Y (2 rules) |
| Token permission least-privilege analysis | Y | Y (secure-repo) | — | Y (job_all_secrets) | — | Y (Token-Permissions check) | — | — | — | Y (runtime inference) | — | — | — | — |
| Supply-chain compromise detection | — | Y (compromised-actions policy) | — | — | — | — | — | — | — | Y (runtime tamper, imposter) | — | — | Y (one Shai-Hulud signature) | — |
| Transitive uses: graph traversal | — | — | — | — | — | — | Y (composite + reusable workflows) | — | — | — | — | — | — | — |
| Embedded transitive-unpinnable knowledge | — | — | — | Y (6,123-purl list) | — | — | — | — | — | — | — | — | — | — |
| Advisory / CVE database | Y (GHSA) | Y (Threat Center) | Y (OSV.dev) | Y (19 OSV + 705 CVE) | — | Y (OSV check) | — | — | — | — | Y (trivy-db) | Y (SCA packages only) | Y (SCA ecosystems) | — |
| Live feed vs static snapshot | Y (live GHSA API) | Y (SOC-maintained) | Y (live API) | — | — | Y (live OSV) | — | — | — | Y (live IOC blocklist) | Y (auto-updated DB) | — | — | — |
| Feed freshness / TTL | — | Y (24x7 SOC, per-eval snapshot) | — | — | — | — | — | — | — | Y (24x7 SOC) | Y (24h bundle refresh) | — | — | — |
| Version-range matching on action refs | Y (GHSA range query) | Y (SHA-scoped entries) | — | Y (semver regex only) | — | — | — | — | — | — | — | — | — | — |
| Outdated / newer-version exists check | — | Y (stale tag/SHA age) | — | — | — | — | — | — | — | — | — | — | — | — |
| Unverified creator / typosquat detection | Y (typosquat-uses) | — | — | Y (verified-creator allowlist) | — | — | — | — | — | — | — | — | — | — |
| Impostor-commit detection | Y (impostor-commit audit) | — | — | — | — | — | Y (upstream branch proof) | — | — | Y (runtime imposter detection) | — | — | — | — |
| Archived / unmaintained repo detection | Y (archived-uses) | — | — | — | — | Y (Maintained check) | — | — | — | — | — | — | — | — |
| SHA vs tag version mismatch | Y (ref-version-mismatch) | — | — | — | — | — | — | — | — | — | — | — | — | — |
| Self-hosted runner detection | Y | — | — | Y (pr_runs_on_self_hosted) | — | — | — | — | — | — | — | — | — | — |
| Dangerous trigger detection | Y | — | — | Y (risky events, auto-merge) | — | Y (Dangerous-Workflow) | — | — | — | — | — | — | Y (2 rules) | — |
| Cache poisoning detection | Y | — | — | — | — | — | — | — | — | — | — | — | — | — |
| Unpinned container image detection | Y (unpinned-images) | — | — | — | — | — | — | — | — | — | — | — | — | — |
| Signing / attestation presence in pipeline | — | — | — | — | — | Y (Signed-Releases check) | — | — | — | — | — | Y (CKV_GHA_5/6 cosign) | — | — |
| Risk-weighted aggregate score | — | Y (per-action 0-10) | — | — | — | Y (weights 10/7.5/5/2.5) | — | — | — | — | — | — | — | — |
| Tiered per-check remediation steps | — | — | — | — | — | Y (numbered tiers) | — | — | — | — | — | — | — | — |
| Structured results / probe facts | — | — | — | — | — | Y (48 probes, v5) | — | — | — | — | — | — | — | — |
| License scanning | — | — | Y (--licenses allowlist) | — | — | Y (License check) | — | — | — | — | Y | — | — | — |
| Deprecated / yanked package flagging | — | — | Y (--x-flag-deprecated-packages) | — | — | — | — | — | — | — | — | — | — | — |
| Call-graph reachability FP filter | — | — | Y (--call-analysis) | — | — | — | — | — | — | — | — | — | — | — |
| Custom rule authoring | — | — | Y (Scalibr plugins) | Y (Rego include:) | — | — | — | — | — | — | Y (Rego bundle) | Y (Python/YAML/graph) | Y (registry, YAML rules) | Y (Rego, --queries-path) |
| Shell linter integration | — | — | — | — | Y (shellcheck + pyflakes) | — | — | — | — | — | — | — | — | — |
| Action metadata input/output validation | — | — | — | — | Y (219 popular actions) | — | — | — | — | — | — | — | — | — |
| SBOM presence check | — | — | — | — | — | Y (SBOM check) | — | — | — | — | — | — | — | — |

> Evidence: zizmor.md §Product & Features (41-audit catalogue, network-required audits); stepsecurity.md §Product & Features (Threat Center, Actions Advisor rubric), §Is the Threat-Intel Feed Publicly Consumable?; osv-scanner.md §Product & Features (Ecosystem support — GitHub Actions gap, Level 1-4 evidence ladder); poutine.md §Product & Features (Rego rules, advisory data, threat-intel/reputation data); actionlint.md §Product & Features (39 checks, Action metadata checking, Nuance on outdated); scorecard.md §Product & Features (check catalogue, probes, risk rating); scharf.md §Product & Features (transitive dependency audit, What scharf does NOT do); frizbee.md §Product & Features (What frizbee does NOT do); pinny.md §Product & Features (How it finds dependencies); harden-runner.md §Product & Features (Runtime protection, File and process monitoring, Tamper detection); trivy.md §Product & Features (Scanners, GitHub Actions coverage); checkov.md §Product & Features (8 GHA checks, SCA, Live Terminal Execution); semgrep.md §Product & Features (12 p/github-actions rules, benchmark); kics.md §Product & Features (4 CI/CD queries, Rego verbatim).
>
> ⚠ **Advisory data for poutine** — `_prioritized-list.md` §4 poutine states "No advisory/CVE feed for actions"; `poutine.md` §Rego rules documents an embedded 19-entry OSV table plus a 705-entry CI-platform CVE snapshot. The latter is the more specific, source-verified statement and is used in this matrix.
>
> ⚠ **Compromise detection for Semgrep** — `semgrep.md` records one hard-coded Shai-Hulud signature rule; that is a static signature of a single 2025 incident, not a live feed, and is qualified as such in the cell.

## Ref resolution & pinning

| Capability | zizmor | StepSecurity | osv-scanner | poutine | actionlint | Scorecard | scharf | frizbee | pinny | Harden-Runner | Trivy | Checkov | Semgrep | KICS |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| SHA-pinning guidance / policy | Y (default requires SHA) | Y (pin org-wide) | — | Y (unpinnable_action) | — | Y (Pinned-Dependencies) | Y (SCHARF001) | Y | Y | — | — | — | Y (1 rule) | Y (1 query) |
| Mutable tag detection | Y | Y | — | Y | — | Y | Y | Y (rewrites; list subcommand) | Y (rewrites all refs) | — | — | — | Y | Y |
| Short-SHA detection | — | — | — | — | — | — | Y (40-hex required) | — | Y (shortened hashes) | — | — | — | Y (40-hex required) | Y (40-hex required) |
| Unpinned / no-ref detection | Y | — | — | — | — | — | Y | — | — | — | — | — | Y | Y |
| Rewrites refs to immutable SHAs | Y (--fix) | Y (remediation PRs) | — | — | — | — | Y (autofix) | Y | Y | — | — | — | — | — |
| Generic auto-remediation (non-ref) | — | — | — | — | — | — | — | — | — | — | — | — | — | Y (kics remediate) |
| Provenance verification (upstream branch) | — | — | — | — | — | — | Y (--verify-provenance) | — | — | — | — | — | — | — |
| Ref to version resolution (tag to SHA) | Y (resolves SHA for fixes) | Y (secure-repo resolves) | — | — | — | — | Y (lookup, list) | Y | Y (actions digest) | — | — | — | — | — |
| Floating tag handling | Y (unpinned-uses policies) | — | — | — | — | — | Y (major-tag movement reported) | Y (main/master excluded) | — | — | — | — | — | — |
| Container tag to digest resolution | — | — | — | — | — | — | — | Y | Y | — | — | — | — | — |
| Branch-ref warning | — | — | — | — | — | — | — | Y (excludes main/master) | Y (WARN on branch refs) | — | — | — | — | — |
| Exact-tag-over-branch resolution precedence | — | — | — | — | — | — | — | — | Y (ListMatchingRefs) | — | — | — | — | — |

> Evidence: zizmor.md §Product & Features (Audit catalogue `unpinned-uses`, `unpinned-images`; Auto-fix; Configuration model); stepsecurity.md §Orchestrate Security (secure-repo 8 fix categories, tag→SHA resolution); osv-scanner.md §Product & Features (no pinning model); poutine.md §Product & Features (`unpinnable_action`, `unpinnable_actions.txt`); actionlint.md §Product & Features (Nuance on pinning — mutable tag accepted); scorecard.md §Product & Features (`Pinned-Dependencies` check); scharf.md §Product & Features (SCHARF001, `--verify-provenance`, `autofix`, `lookup`, `upgrade`); frizbee.md §Product & Features (rewrites, `--dry-run`/`--error`, config defaults); pinny.md §Product & Features (pin, digest, ListMatchingRefs precedence, branch WARN); harden-runner.md §Product & Features (no pinning layer); trivy.md §Product & Features (no Actions analyzer); checkov.md §Product & Features ("no pinning check"); semgrep.md §Product & Features (`github-actions-mutable-action-tag`); kics.md §Product & Features (`unpinned_actions_full_length_commit_sha` Rego).

## Output formats

| Capability | zizmor | StepSecurity | osv-scanner | poutine | actionlint | Scorecard | scharf | frizbee | pinny | Harden-Runner | Trivy | Checkov | Semgrep | KICS |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Console / plain text | Y (plain) | Y (workflow logs, PR comments) | Y (table, vertical) | Y (pretty) | Y | Y | Y (human) | Y | Y | Y (workflow logs) | Y (table) | Y (cli) | Y (text) | Y |
| JSON | Y (json, json-v1) | Y (trivy-compromise-scanner) | Y | Y | Y (Go template) | Y | Y | Y (list only) | — | — | Y | Y | Y | Y |
| SARIF | Y | — | Y (2.1.0) | Y (2.1.0) | Y (shipped template) | Y (via action) | Y (2.1.0) | — | — | — | Y (2.1.0) | Y | Y | Y (2.1.0) |
| CSV | — | Y (trivy-compromise-scanner) | — | — | — | — | Y (find only) | — | — | — | — | Y | — | Y |
| HTML report | — | — | Y (--serve interactive) | — | — | — | — | — | — | — | Y (template only) | — | — | Y |
| PDF report | — | — | — | — | — | — | — | — | — | — | — | — | — | Y |
| Dashboard / web app | — | Y (app.stepsecurity.io) | — | — | — | — | — | — | — | Y (per-run console) | — | Y (Prisma Cloud, paid) | Y (AppSec Platform, paid) | — |
| SPDX | — | — | Y (2.3) | — | — | — | — | — | — | — | Y (via convert) | Y | — | — |
| CycloneDX | — | — | Y (1.4-1.7) | — | — | — | — | — | — | — | Y (via convert) | Y | — | Y |
| Markdown | — | — | Y | — | — | — | — | — | — | Y (job summary) | — | — | — | — |
| JUnit | — | — | — | — | — | — | — | — | — | — | Y (contrib/junit.tpl) | Y (junitxml) | — | Y |
| Custom templates | — | — | — | — | Y (Go templates) | — | — | — | — | — | Y (Go templates) | — | — | — |
| GitHub dependency snapshot | — | — | — | — | — | — | — | — | — | — | Y (--format github) | — | — | — |
| ASFF (AWS Security Hub) | — | — | — | — | — | — | — | — | — | — | Y | — | — | Y |
| CodeClimate / SonarQube / GitLab SAST | — | — | — | — | — | — | — | — | — | — | — | Y (gitlab_sast) | Y (gitlab-sast) | Y |
| in-toto attestation | — | — | — | — | — | Y (intoto results_format) | — | — | — | — | — | — | — | — |
| Versioned JSON / compatibility policy | Y (json-v1 deprecation policy) | — | Y (v1 to v2 migration) | — | — | — | — | — | — | — | — | — | — | — |

> Evidence: zizmor.md §Product & Features (Output formats, JSON versioning policy); stepsecurity.md §Product & Features (Outputs, trivy-compromise-scanner `--format json|csv`); osv-scanner.md §Output formats (`--format` list, no CSV, `--serve`); poutine.md §Product & Features (Output formats & SARIF upload — no HTML, no SARIF upload); actionlint.md §Product & Features (Format error messages — Go templates, SARIF template); scorecard.md §Output formats (text, JSON, SARIF via action, in-toto, not-observed list); scharf.md §Output formats; frizbee.md §Output formats; pinny.md §Product & Features (Output format, no JSON/SARIF/HTML); harden-runner.md §Output formats (table of surfaces); trivy.md §Output formats; checkov.md §Output formats; semgrep.md §Output formats; kics.md §Output formats.
>
> ⚠ **actionlint is not console-only** — `_prioritized-list.md` §5 lists "actionlint is console-only" as a corrected error, and `actionlint.md` §Product & Features carries the same correction: it has `-format` with Go templates and ships a SARIF template. The corrected statement is used here.

## CI integration & gating

| Capability | zizmor | StepSecurity | osv-scanner | poutine | actionlint | Scorecard | scharf | frizbee | pinny | Harden-Runner | Trivy | Checkov | Semgrep | KICS |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Documented exit-code contract | Y (0/1/2/3/11-14) | — | Y (0/1/127/128) | Y (0/1/2/10) | Y (0/1/2/3) | — | Y (semantics only, no numbering) | Y (--error opt-in) | — | — | Y (0/1/user-set) | Y (0/1, soft-fail) | Y (0/1/2/3/4/5/7/8/13/99) | Y (0/20-60/70/126/130) |
| Severity-band exit codes | Y | — | — | — | — | — | — | — | — | — | — | — | — | Y (20/30/40/50/60) |
| GitHub Actions annotations | Y (--format=github, 10/step) | — | Y (gh-annotations) | — | Y (problem matchers) | — | Y (github format) | — | — | — | Y (github format) | Y (github_failed_only) | — | — |
| $GITHUB_STEP_SUMMARY output | — | — | — | — | — | — | — | — | — | Y (post-job hook appends) | — | — | — | — |
| GitHub code-scanning upload | Y | — | Y | — | — | Y | Y | — | — | — | Y | Y | Y | Y |
| PR / build gate on findings | Y | Y (cancels runs) | Y | Y (--fail-on-violation) | Y | — | Y (--raise-error) | Y (--error) | — | Y (GitHub Checks) | Y (opt-in) | Y | Y (--error) | Y (--fail-on) |
| Pre-commit hook | Y | — | Y | Y | Y | — | — | — | — | — | — | Y | — | Y |
| Editor / LSP integration | Y (LSP experimental, Zed, VS Code) | — | — | — | Y (VS Code, Emacs, Vim) | — | — | — | — | — | — | — | Y (semgrep lsp) | Y (VS Code) |
| MCP server | — | Y (stepsecurity-mcp) | — | Y (5 tools) | — | — | — | — | — | — | — | — | Y (semgrep mcp) | — |
| Official GitHub Action wrapper | Y | Y (harden-runner) | Y (osv-scanner-action) | — | — | Y (scorecard-action) | Y (scharf-action) | Y (frizbee-action) | — | Y (step-security/harden-runner) | Y (trivy-action) | Y (checkov-action) | Y | Y |
| Third-party CI / linter integrations | Y (super-linter, megalinter) | Y (GitLab, ADO, CodeBuild) | — | — | Y (reviewdog) | — | — | — | — | Y (GitLab, ADO) | Y (8 CI systems) | Y (7 CI systems) | Y (GitLab CI) | Y (10 CI systems) |
| Pre-execution run cancellation | — | Y (cancels run via API) | — | — | — | — | — | — | — | — | — | — | — | — |
| Public posture badge / results API | — | — | Y (Scorecard badge) | — | — | Y (badge + REST API) | — | — | — | — | — | — | — | — |

> Evidence: zizmor.md §Product & Features (Exit-code contract, Integrations table); stepsecurity.md §Product & Features (Integrations, Workflow Run Policies), §Pricing (tier gating); osv-scanner.md §Output formats (return codes), §Integrations (osv-scanner-action, pre-commit); poutine.md §Product & Features (exit codes 0/1/2/10, SARIF upload, MCP server); actionlint.md §Product & Features (Exit statuses, Editor / platform integrations); scorecard.md §CI integration and exit codes (exit codes not observed, scorecard-action); scharf.md §CI integration and exit codes; frizbee.md §CI integration and exit codes; pinny.md §Product & Features (CI integration and exit codes); harden-runner.md §CI integration and exit codes, §Output formats (job summary); trivy.md §CI integration and exit codes; checkov.md §CI integration and exit codes (hard/soft fail); semgrep.md §CI integration and exit codes; kics.md §CI integration and exit codes.
>
> ⚠ **StepSecurity org-wide policy-driven PRs tier** — `stepsecurity.md` §Pricing records that the `/pricing` feature matrix marks "Orchestrate Security / policy-driven PRs" as available on Community, while the docs banner says "Available for Enterprise Tier only". Both statements are live; the matrix records the feature as present with the tier unresolved, and the profile flags it as unresolved.
>
> ⚠ **Trivy `$GITHUB_STEP_SUMMARY`** — `trivy.md` does not record a built-in step summary. The only occurrence in the raw source is a user-authored snippet in the `trivy-action` README (`raw/trivy/2026-10-22/scrapes/trivy_action_readme.md:850`), so the cell is recorded as not observed.

## Configuration & suppression

| Capability | zizmor | StepSecurity | osv-scanner | poutine | actionlint | Scorecard | scharf | frizbee | pinny | Harden-Runner | Trivy | Checkov | Semgrep | KICS |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Config file name | Y (zizmor.yml) | — | Y (TOML) | Y (.poutine.yml) | Y (actionlint.yaml) | — | Y (.scharf-policy.yml) | Y (.frizbee.yml) | — | — | Y (trivy.yaml) | Y (config.yml) | — | — |
| Inline ignore comment syntax | Y (# zizmor: ignore[rule]) | — | — | — | — | — | — | — | — | — | — | Y (#checkov:skip=ID:reason) | — | — |
| Allow / deny / skip lists | Y | — | Y (PackageOverrides) | Y (allowedRules, skip) | Y (-ignore regex) | — | Y (--ignore exact/regex) | Y (exclude lists) | — | Y (egress allow/denylist) | — | Y (--check/--skip-check) | — | Y (--include-queries) |
| Per-repo / per-path scoping | Y (repo patterns, path:line:col) | — | Y (per-path overrides) | Y (skip.path) | Y (paths.<glob>) | — | Y (rules.paths, exceptions.paths) | Y (exclude paths) | — | — | — | — | — | — |
| Policy-as-code | Y | — | Y | Y (Rego policies) | Y | — | Y (versioned, strict) | Y | — | — | Y | Y | — | — |
| Severity remapping | Y (rules.<id>.remap.severity) | — | — | — | — | — | — | — | — | — | — | — | — | — |
| Personas / sensitivity profiles | Y (regular, pedantic, auditor) | — | — | — | — | — | — | — | — | — | — | — | — | — |
| No-ignores mode | Y (--no-ignores) | — | — | — | — | — | — | — | — | — | — | — | — | — |
| Accountable expiring exceptions | — | — | — | — | — | — | Y (owner, approver, expiry) | — | — | — | — | — | — | — |
| Trusted-ref policy loading | — | — | — | — | — | — | Y (--policy-from-ref) | — | — | — | — | — | — | — |
| Severity threshold gating | Y (--min-severity) | — | — | — | — | — | — | — | — | — | — | Y (--soft-fail-on/--hard-fail-on) | — | Y (--fail-on) |
| JSON Schema published | Y (SchemaStore) | — | — | — | — | — | — | — | — | — | — | — | — | — |

> Evidence: zizmor.md §Product & Features (Ignore model, Configuration model, JSON Schema on SchemaStore); stepsecurity.md §Product & Features (Policy Store, suppression rules); osv-scanner.md §Product & Features (Config, TOML, PackageOverrides); poutine.md §Product & Features (Config `.poutine.yml`, six `skip:` keys, `allowedRules`); actionlint.md §Configuration (`actionlint.yaml`, `paths.<glob>.ignore`); scorecard.md §Config / policy model (`--policy` not supported yet); scharf.md §Config / policy model (`.scharf-policy.yml`, exceptions, `--policy-from-ref`); frizbee.md §Config / policy model (`.frizbee.yml` excludes); pinny.md §Product & Features (Configuration — none observed); harden-runner.md §Config / policy model (no repo-local config file); trivy.md §Product & Features (trivy config file, `--exit-code`); checkov.md §Product & Features (suppressions, `--skip-check`); semgrep.md §Product & Features (no suppression config recorded); kics.md §Product & Features (`--exclude-results`, `--exclude-severities`, `--include-queries`, `--fail-on`).
>
> ⚠ **Harden-Runner Policy Store tier** — `harden-runner.md` §Config / policy model records the README's feature table and the pricing page disagree on whether Policy Store enforcement is Community or Enterprise. Unresolved; recorded as not a repo-local config in either case.

## Delta & history

| Capability | zizmor | StepSecurity | osv-scanner | poutine | actionlint | Scorecard | scharf | frizbee | pinny | Harden-Runner | Trivy | Checkov | Semgrep | KICS |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Baseline comparison mode | — | — | — | — | — | — | Y (baseline.ref, mode new) | — | — | — | — | — | — | — |
| Merge-base diff | — | — | — | — | — | — | Y (HEAD vs merge base) | — | — | — | — | — | — | — |
| Changed-lines mode | — | — | Y (reusable-pr diff) | — | — | — | Y (--changed-lines) | — | — | — | — | — | Y (semgrep ci) | — |
| Finding fingerprints / dedup | — | — | — | — | — | — | Y (multiset ref comparison) | — | — | — | — | — | — | — |
| Trend / history charts | — | Y (actions-count history) | — | — | — | — | — | — | — | — | — | — | — | — |
| Previous-scan comparison | — | — | Y (osv-reporter diffs two scans) | — | — | — | — | — | — | — | — | — | — | — |
| Last-used version age tracking | — | Y (age of last-used tag/SHA) | — | — | — | — | — | — | — | — | — | — | — | — |
| Adoption / usage trends | — | Y (usage-weighted posture) | — | — | — | — | — | — | — | — | — | — | — | — |

> Evidence: scharf.md §Product & Features (Baseline / changed lines, merge-base multiset comparison, rename detection); osv-scanner.md §Product & Features (osv-reporter diffing two scan JSONs, `osv-scanner-reusable-pr.yml` diff vs target branch); semgrep.md §Product & Features (`semgrep ci` runs on a git diff); stepsecurity.md §Product & Features (Actions Governance history, age of last-used tag/SHA, adoption trends); poutine.md §Product & Features (analyze_repo_stale_branches); actionlint.md §Product & Features (no baseline/delta); zizmor.md §Product & Features (no baseline); frizbee.md §Product & Features (no baseline/delta mode); pinny.md §Product & Features (no baseline); scorecard.md §Product & Features (per-repo reports only, no cross-repo roll-up); harden-runner.md §Product & Features (per-job baselines, no scan-to-scan delta); trivy.md, checkov.md, kics.md §Product & Features (no delta mode recorded).

## Scale & operations

| Capability | zizmor | StepSecurity | osv-scanner | poutine | actionlint | Scorecard | scharf | frizbee | pinny | Harden-Runner | Trivy | Checkov | Semgrep | KICS |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Concurrency / threading control | — | — | — | Y (--threads, default 2) | — | — | — | — | — | — | — | — | — | Y (--parallel) |
| Rate-limit handling | Y (token + HTTP cache) | Y (AI 10/user/day) | — | — | — | Y (multi-token round-robin) | Y (500-request budget) | Y (GITHUB_TOKEN advised) | Y (GITHUB_TOKEN escape hatch) | — | — | — | Y (10-repo free cap) | — |
| Retry / backoff | Y (precise retry handling) | — | — | — | — | Y (action retries 4xx once) | — | — | — | — | — | — | — | — |
| Offline / air-gapped mode | Y (default without token) | — | Y (--offline + local DBs) | — | Y (no network by design) | — | Y (plain audit offline-capable) | — | — | — | Y (--skip-update, air-gap) | — | — | — |
| Persistent caching | Y (--cache-dir) | — | Y (local DB cache dir) | — | — | — | — | — | Y (in-process ref cache) | — | — | — | — | — |
| Incremental / resume | — | — | — | — | — | — | — | — | — | — | — | — | — | — |
| Proxy support | — | — | — | — | — | — | — | — | — | — | — | — | Y (HTTP_PROXY, HTTPS_PROXY) | — |
| GitHub Enterprise support | Y (--gh-hostname, best-effort) | Y (GHES, Enterprise) | — | — | — | — | — | — | — | Y (customer, server-name) | — | — | — | — |
| Private repository support | Y (token, private repos) | Y (Enterprise) | — | — | — | — | — | — | — | — | — | — | — | — |
| Token requirements | Y (GH_TOKEN for online audits) | Y (read:org, repo) | — | Y (read-level token) | — | Y (PAT/GITHUB_TOKEN/App) | Y (GITHUB_TOKEN) | Y (GITHUB_TOKEN optional) | Y (GITHUB_TOKEN) | Y (api-key, policy store) | — | Y (bc-api-key) | Y (login, API key) | — |
| Self-hostable data source | — | — | Y (gs:// OSV mirror) | Y (make update-vulndb) | — | — | — | — | — | — | Y (trivy server, --db-repository) | — | — | — |
| API enumeration without full clone | — | — | — | — | — | Y (ListOrgRepos) | — | — | — | — | — | — | — | — |
| Telemetry opt-out | — | — | — | Y (--disable-version-check) | — | — | — | — | — | Y (disable-telemetry input) | Y (usage telemetry opt-out) | — | — | — |
| Traversal budgets / hard limits | — | — | — | — | — | — | Y (depth 12, 5k nodes, 8 MiB) | — | — | — | — | — | — | — |
| Data residency / event export | — | Y (S3, webhook, AWS regions) | — | — | — | — | — | — | — | Y (S3 transient endpoint) | — | — | — | — |

> Evidence: zizmor.md §Product & Features (Caching & enterprise, Operating modes, release-notes retry handling); stepsecurity.md §Product & Features (Integrations, AI analysis rate limit); osv-scanner.md §Product & Features (offline mode, OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY, GCS mirror); poutine.md §Product & Features (analyze_org `--threads`, telemetry, `make update-vulndb`); actionlint.md §Product & Features (no network access); scorecard.md §Product & Features (token scoping, `--org` via ListOrgRepos, action retry behaviour); scharf.md §Product & Features (hard budgets, `--verify-provenance` bounds); frizbee.md §Product & Features (GITHUB_TOKEN, `--error`); pinny.md §Product & Features (GITHUB_TOKEN, actionRefCache); harden-runner.md §Product & Features (endpoints, data residency, disable-telemetry, GHES); trivy.md §Product & Features (self-hosting, `--skip-update`, telemetry opt-out); checkov.md §Product & Features (`--bc-api-key`); semgrep.md §Product & Features (proxy env vars, Free Edition 10-repo cap); kics.md §Product & Features (`--parallel` worker auto-detection).

## UX & reporting

| Capability | zizmor | StepSecurity | osv-scanner | poutine | actionlint | Scorecard | scharf | frizbee | pinny | Harden-Runner | Trivy | Checkov | Semgrep | KICS |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Verdict / triage framing | Y (personas, signal-to-noise) | Y (Action Security Score) | Y (called vs uncalled) | — | — | Y (risk-weighted score) | — | — | — | Y (baseline pass/fail) | — | Y (passed/failed/suppressed) | — | — |
| Severity model | Y (info/low/medium/high) | — | Y | Y (note/warning/error) | — | Y (Critical to Low) | Y (error/warning/note) | — | — | — | Y | Y | Y (ERROR/WARNING) | Y |
| Group-by / blast-radius view | — | Y (repos per action) | — | — | — | — | — | — | — | — | — | — | — | — |
| Filters | Y (min-severity, min-confidence) | — | Y | Y (skip filters) | Y (-ignore regex) | — | Y (--ignore) | Y (exclude lists) | — | — | Y (--severity) | Y | — | Y |
| Search / filterable feed UI | — | Y (OSS Security Feed) | Y (HTML filters) | — | — | — | — | — | — | — | — | — | — | — |
| Sorting | — | — | — | — | — | — | — | — | — | — | — | — | — | Y (severity-sorted SARIF) |
| Shareable URLs | Y (OSC 8 doc links) | Y (insights URL) | — | Y (rule doc + line link) | Y (playground links) | Y (badge, API URL) | — | — | — | Y (insights URL) | — | — | — | — |
| Remediation guidance | Y (per-audit docs) | Y (trusted alternatives) | Y (SARIF help text) | — | — | Y (tiered steps) | Y (replacement SHA) | — | — | — | — | — | — | Y (remediate) |
| Copy-paste fix | Y (--fix rewrites file) | Y (Secure Workflow YAML) | — | — | — | — | Y (exact SHA in output) | Y (rewrites uses:) | Y (rewrites + comment) | — | — | — | — | Y (remediate) |
| Per-finding context | Y (span, confidence, audit URL) | Y (score rubric) | Y (full advisory entries) | Y (rule, severity, doc link) | Y (example per check) | Y (REASON column) | Y (chain, commit, status) | — | — | Y (per-step correlation) | Y (layer, package detail) | Y (resource, code block) | — | — |
| Print / color control | Y (--color, NO_COLOR) | — | — | — | — | — | — | — | — | — | — | — | — | — |
| Accessibility | — | — | — | — | — | — | — | — | — | — | — | — | — | — |
| Interactive HTML report | — | — | Y (--serve, severity breakdown) | — | — | — | — | — | — | — | — | — | — | — |
| Web playground | — | — | — | — | Y (WASM playground) | — | — | — | — | — | — | — | — | — |

> Evidence: zizmor.md §Product & Features (Personas, Filtering, per-audit docs, OSC 8 links); stepsecurity.md §Product & Features (Actions Advisor score rubric, actions-in-use per-repo SHA/tag, PR comment with alternatives, Secure Workflow); osv-scanner.md §Output formats (interactive HTML, severity breakdown, filters, call analysis); poutine.md §Product & Features (pretty output with rule table, docs deep link, GitHub line-link); actionlint.md §Product & Features (checks.md examples, playground deep links, `-ignore`); scorecard.md §Product & Features (risk rating, tiered remediation, CLI text REASON column, badge/API); scharf.md §Product & Features (github/human output with exact replacement SHA, chain, status); frizbee.md §Product & Features (rewrites `uses:` field); pinny.md §Product & Features (rewrites with trailing comment); harden-runner.md §Output formats (per-step correlation, GitHub Checks, insights URL); trivy.md §Output formats (table, template output); checkov.md §Output formats (cli output with passed/failed/suppressed counts, CSV, resource + code block); semgrep.md §Output formats (text, json, sarif); kics.md §Output formats (severity-sorted SARIF, report formats).
>
> ⚠ **StepSecurity free audit report format** — `stepsecurity.md` §SEO & Content Strategy states the free GitHub Actions Audit is a lead-capture form whose report is emailed, and that the report's file format (PDF / HTML / CSV) was **not observed**. The matrix therefore records the dashboard/web app and the trivy-compromise-scanner JSON/CSV surfaces, and does not claim a native audit-report format for StepSecurity.

## Trust & transparency

| Capability | zizmor | StepSecurity | osv-scanner | poutine | actionlint | Scorecard | scharf | frizbee | pinny | Harden-Runner | Trivy | Checkov | Semgrep | KICS |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Data sources disclosure | — | — | Y (Data Sources and Privacy) | — | — | — | — | — | — | Y (data-collection boundaries) | — | — | — | — |
| Degraded / failed-feed signalling | — | — | Y (error if local DB absent) | — | — | — | — | — | — | Y (no-op without subscription) | — | — | — | — |
| Incomplete-vs-clean semantics | — | — | — | — | — | — | Y (complete-clean/with-findings/incomplete) | — | — | — | — | — | — | — |
| Audit log | — | Y (policy evaluation logs) | — | — | — | — | — | — | — | — | — | — | — | — |
| Open-source license | Y (MIT) | Y (AGPL-3.0 secure-repo) | Y (Apache-2.0) | Y (Apache-2.0) | Y (MIT) | Y (Apache-2.0) | Y (Apache-2.0) | Y (Apache-2.0) | Y (Apache-2.0) | Y (Apache-2.0, agents closed) | Y (Apache-2.0) | Y (Apache-2.0) | Y (LGPL-2.1-or-later) | Y (Apache-2.0) |
| Signed releases / verifiable provenance | — | — | Y (SLSA L3) | Y (SLSA L3, signed releases) | — | — | — | — | — | — | Y (OCI digest-pinned artifacts) | — | — | — |
| Public machine-readable threat feed | — | Y (blocklist + package feed) | — | — | — | — | — | — | — | Y (global blocklist JSON) | — | — | — | — |
| Telemetry payload disclosure | — | — | Y (endpoints, payload fields) | — | — | — | — | — | Y (version + instance id only) | Y (no source/secret/env) | — | — | — | — |
| SOC 2 / ISO certification | — | Y (SOC 2 Type II, ISO 27001) | — | — | — | — | — | — | — | Y (SOC 2 Type II, ISO/IEC 27001) | — | — | — | — |
| Self-published security advisory | Y (GHSA-f42p-wjw5-97qh) | — | — | — | — | — | — | — | — | — | — | — | — | — |
| OpenSSF Scorecard badge | — | — | Y | — | — | — | — | — | — | — | — | — | — | — |

> Evidence: zizmor.md §Product & Features (MIT, GHSA-f42p-wjw5-97qh, JSON Schema, limitations page); stepsecurity.md §Is the Threat-Intel Feed Publicly Consumable? (public unauthenticated feeds, 404 verification), §Product & Features (Threat Center, Secure Registry policy evaluation logs, Pricing tiers); osv-scanner.md §Pricing ("Data Sources and Privacy", SLSA L3, offline limitation, offline error); poutine.md §Product & Features (badges, SLSA L3, signed releases, telemetry payload); actionlint.md §Product & Features (MIT, no network); scorecard.md §Product & Features (OpenSSF governance, REST API, BigQuery dataset retired); scharf.md §Product & Features (complete-clean / complete-with-findings / incomplete, `executionSuccessful=false`); frizbee.md §Product & Features (Apache-2.0); pinny.md §Product & Features (Apache-2.0); harden-runner.md §Product & Features (data-collection boundaries, endpoints, SOC 2 / ISO, Global Block List, no-op failure mode); trivy.md §Product & Features (OCI DB/checks bundle, air-gap, telemetry opt-out); checkov.md §Product & Features (Apache-2.0, Prisma Cloud); semgrep.md §Product & Features (LGPL-2.1-or-later, rules under Semgrep Rules License); kics.md §Product & Features (Apache-2.0, Checkmarx backing).

## Capability counts per competitor

Raw density count of `Y` cells per column across all 156 capability rows. A density count only — not a quality or coverage judgment.

| Competitor | Y cells | Rows |
|---|---|---|
| zizmor | 70 | 156 |
| StepSecurity | 52 | 156 |
| osv-scanner | 48 | 156 |
| poutine | 43 | 156 |
| actionlint | 31 | 156 |
| Scorecard | 41 | 156 |
| scharf | 47 | 156 |
| frizbee | 25 | 156 |
| pinny | 19 | 156 |
| Harden-Runner | 30 | 156 |
| Trivy | 38 | 156 |
| Checkov | 42 | 156 |
| Semgrep | 34 | 156 |
| KICS | 39 | 156 |

## Capabilities exactly one competitor has

52 of 156 rows have exactly one `Y` cell. Listed in matrix order.

| # | Area | Capability | Sole holder | Qualifier |
|---|---|---|---|---|
| 1 | Scope & target | Repo-level posture score output | Scorecard | Y (0-10 + aggregate) |
| 2 | Scope & target | Dependabot config parsing | zizmor | Y |
| 3 | Scope & target | Pre-commit config parsing | zizmor | Y |
| 4 | Scope & target | Workflow run-log scanning | StepSecurity | Y (trivy-compromise-scanner) |
| 5 | Scope & target | Cross-repo action-reference inventory | StepSecurity | Y (Actions In Use, Enterprise) |
| 6 | Detection rules | Workflow expression / type linting | actionlint | Y (full type system) |
| 7 | Detection rules | Transitive uses: graph traversal | scharf | Y (composite + reusable workflows) |
| 8 | Detection rules | Embedded transitive-unpinnable knowledge | poutine | Y (6,123-purl list) |
| 9 | Detection rules | Outdated / newer-version exists check | StepSecurity | Y (stale tag/SHA age) |
| 10 | Detection rules | SHA vs tag version mismatch | zizmor | Y (ref-version-mismatch) |
| 11 | Detection rules | Cache poisoning detection | zizmor | Y |
| 12 | Detection rules | Unpinned container image detection | zizmor | Y (unpinned-images) |
| 13 | Detection rules | Tiered per-check remediation steps | Scorecard | Y (numbered tiers) |
| 14 | Detection rules | Structured results / probe facts | Scorecard | Y (48 probes, v5) |
| 15 | Detection rules | Deprecated / yanked package flagging | osv-scanner | Y (--x-flag-deprecated-packages) |
| 16 | Detection rules | Call-graph reachability FP filter | osv-scanner | Y (--call-analysis) |
| 17 | Detection rules | Shell linter integration | actionlint | Y (shellcheck + pyflakes) |
| 18 | Detection rules | Action metadata input/output validation | actionlint | Y (219 popular actions) |
| 19 | Detection rules | SBOM presence check | Scorecard | Y (SBOM check) |
| 20 | Ref resolution & pinning | Generic auto-remediation (non-ref) | KICS | Y (kics remediate) |
| 21 | Ref resolution & pinning | Provenance verification (upstream branch) | scharf | Y (--verify-provenance) |
| 22 | Ref resolution & pinning | Exact-tag-over-branch resolution precedence | pinny | Y (ListMatchingRefs) |
| 23 | Output formats | PDF report | KICS | Y |
| 24 | Output formats | GitHub dependency snapshot | Trivy | Y (--format github) |
| 25 | Output formats | in-toto attestation | Scorecard | Y (intoto results_format) |
| 26 | CI integration & gating | $GITHUB_STEP_SUMMARY output | Harden-Runner | Y (post-job hook appends) |
| 27 | CI integration & gating | Pre-execution run cancellation | StepSecurity | Y (cancels run via API) |
| 28 | Configuration & suppression | Severity remapping | zizmor | Y (rules.<id>.remap.severity) |
| 29 | Configuration & suppression | Personas / sensitivity profiles | zizmor | Y (regular, pedantic, auditor) |
| 30 | Configuration & suppression | No-ignores mode | zizmor | Y (--no-ignores) |
| 31 | Configuration & suppression | Accountable expiring exceptions | scharf | Y (owner, approver, expiry) |
| 32 | Configuration & suppression | Trusted-ref policy loading | scharf | Y (--policy-from-ref) |
| 33 | Configuration & suppression | JSON Schema published | zizmor | Y (SchemaStore) |
| 34 | Delta & history | Baseline comparison mode | scharf | Y (baseline.ref, mode new) |
| 35 | Delta & history | Merge-base diff | scharf | Y (HEAD vs merge base) |
| 36 | Delta & history | Finding fingerprints / dedup | scharf | Y (multiset ref comparison) |
| 37 | Delta & history | Trend / history charts | StepSecurity | Y (actions-count history) |
| 38 | Delta & history | Previous-scan comparison | osv-scanner | Y (osv-reporter diffs two scans) |
| 39 | Delta & history | Last-used version age tracking | StepSecurity | Y (age of last-used tag/SHA) |
| 40 | Delta & history | Adoption / usage trends | StepSecurity | Y (usage-weighted posture) |
| 41 | Scale & operations | Proxy support | Semgrep | Y (HTTP_PROXY, HTTPS_PROXY) |
| 42 | Scale & operations | API enumeration without full clone | Scorecard | Y (ListOrgRepos) |
| 43 | Scale & operations | Traversal budgets / hard limits | scharf | Y (depth 12, 5k nodes, 8 MiB) |
| 44 | UX & reporting | Group-by / blast-radius view | StepSecurity | Y (repos per action) |
| 45 | UX & reporting | Sorting | KICS | Y (severity-sorted SARIF) |
| 46 | UX & reporting | Print / color control | zizmor | Y (--color, NO_COLOR) |
| 47 | UX & reporting | Interactive HTML report | osv-scanner | Y (--serve, severity breakdown) |
| 48 | UX & reporting | Web playground | actionlint | Y (WASM playground) |
| 49 | Trust & transparency | Incomplete-vs-clean semantics | scharf | Y (complete-clean/with-findings/incomplete) |
| 50 | Trust & transparency | Audit log | StepSecurity | Y (policy evaluation logs) |
| 51 | Trust & transparency | Self-published security advisory | zizmor | Y (GHSA-f42p-wjw5-97qh) |
| 52 | Trust & transparency | OpenSSF Scorecard badge | osv-scanner | Y |
