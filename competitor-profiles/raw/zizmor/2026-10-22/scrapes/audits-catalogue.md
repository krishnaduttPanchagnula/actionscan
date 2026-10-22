# zizmor audit catalogue — 41 audits

Extracted from https://raw.githubusercontent.com/zizmorcore/zizmor/main/docs/audits.md (main branch), fetched 2026-10-22.

| Audit | Type | Introduced | Works offline | Auto-fix | Configurable | One-line description (from docs) |
|---|---|---|---|---|---|---|
| `adhoc-packages` | Workflow, Action | v1.26.0 | ✅ | ❌ | ❌ | Detects `#!yaml run:` steps that install or manipulate packages in an ad-hoc |
| `anonymous-definition` | Workflow, Action | v1.10.0 | ✅ | ❌ | ❌ | Detects workflows or action definitions that lack a `name:` field. |
| `archived-uses` | Workflow, Action | v1.19.0 | ✅ | ❌ | ❌ | Detects `#!yaml uses:` clauses that reference [archived repositories]. |
| `artipacked` | Workflow | v0.1.0 | ✅ | ⚠️ | ❌ | Detects local filesystem `git` credential storage on GitHub Actions, as well as |
| `bot-conditions` | Workflow | v1.2.0 | ✅ | ✅ | ❌ | Detects potentially spoofable bot conditions. |
| `cache-poisoning` | Workflow | v0.10.0 | ✅ | ⚠️ | ❌ | Detects two common cache-poisoning primitives in GitHub Actions: |
| `concurrency-limits` | Workflow | v1.16.0 | ✅ | ❌ | ❌ | Detects insufficient concurrency limits in workflows. |
| `dangerous-triggers` | Workflow | v0.1.0 | ✅ | ❌ | ❌ | Detects fundamentally dangerous GitHub Actions workflow triggers. |
| `dependabot-cooldown` | Dependabot | v1.15.0 | ✅ | ✅ | ✅ | Detects missing or insufficient `cooldown` settings in Dependabot configuration |
| `dependabot-execution` | Dependabot | v1.15.0 | ✅ | ⚠️ | ❌ | Detects usages of `insecure-external-code-execution` in Dependabot configuration |
| `excessive-permissions` | Workflow | v0.1.0 | ✅ | ❌ | ❌ | Detects excessive permissions in workflows, both at the workflow level and |
| `forbidden-uses` | Workflow, Action | v1.6.0 | ✅ | ❌ | ✅ | An *opt-in* audit for denylisting/allowlisting specific `#!yaml uses:` clauses. |
| `github-app` | Workflow, Action | v1.25.0 | ✅ | ❌ | ❌ | Detects dangerous usages of GitHub App installation tokens. |
| `github-env` | Workflow, Action | v0.6.0 | ✅ | ❌ | ❌ | Detects dangerous writes to the `GITHUB_ENV` and `GITHUB_PATH` environment variables. |
| `hardcoded-container-credentials` | Workflow | v0.1.0 | ✅ | ❌ | ❌ | Detects Docker credentials (usernames and passwords) hardcoded in various places |
| `impostor-commit` | Workflow, Action, pre-commit | v0.1.0 | ❌ | ✅ | ❌ | Detects commits within a repository Git's network that are not present on |
| `insecure-commands` | Workflow, Action | v0.5.0 | ✅ | ⚠️ | ❌ | Detects opt-in for executing insecure workflow commands. |
| `insecure-url-scheme` | pre-commit | v1.29.0 | ✅ | ❌ | ❌ | Detects uses of insecure schemes in URLs. |
| `known-vulnerable-actions` | Workflow, Action | v0.1.0 | ❌ | ⚠️ | ❌ | Detects actions with known, publicly disclosed vulnerabilities that are tracked |
| `misfeature` | Workflow, Action | v1.21.0 | ✅ | ❌ | ❌ | Checks for usages of GitHub Actions features that are considered "misfeatures." |
| `obfuscation` | Workflow, Action | v1.7.0 | ✅ | ⚠️ | ❌ | Checks for obfuscated usages of GitHub Actions features. |
| `overprovisioned-secrets` | Workflow, Action | v1.3.0 | ✅ | ❌ | ❌ | Detects excessive sharing of the `secrets` context. |
| `ref-confusion` | Workflow, Action | v0.1.0 | ❌ | ❌ | ❌ | Detects actions that are pinned to confusable symbolic refs (i.e. branches |
| `ref-version-mismatch` | Workflow, Action | v1.14.0 | ✅ | ⚠️ | ❌ | Detects `#!yaml uses:` clauses where a hash-pinned action's version comment |
| `secrets-inherit` | Workflow | v1.1.0 | ✅ | ❌ | ❌ | Detects excessive secret inheritance between calling workflows and reusable |
| `secrets-outside-env` | Workflow | v1.23.0 | ✅ | ❌ | ❌ | Detects usage of the `secrets` context in jobs without a dedicated environment. |
| `self-hosted-runner` | Workflow | v0.1.0 | ✅ | ❌ | ❌ | Detects self-hosted runner usage within workflows. |
| `self-repository` | Workflow, Action | v1.30.0 | ✅ | ⚠️ | ❌ | Detects uses of in-repo actions or reusable workflows that don't use GitHub's |
| `stale-action-refs` | Workflow, Action | v1.7.0 | ❌ | ❌ | ❌ | Checks for `#!yaml uses:` clauses which pin an action using a SHA reference, |
| `superfluous-actions` | Workflow, Action | v1.23.0 | ✅ | ❌ | ❌ | Detects actions that are known to be "superfluous," i.e. perform an operation already provided by GitHub's own runner images. |
| `template-injection` | Workflow, Action | v0.1.0 | ✅ | ⚠️ | ❌ | Detects potential sources of code injection via template expansion. |
| `typosquat-uses` | Workflow, Action, pre-commit | v1.26.0 | ✅ | ❌ | ❌ | Detects `#!yaml uses:` clauses and pre-commit `#!yaml repo:` URLs whose |
| `undocumented-permissions` | Workflow | v1.13.0 | ✅ | ❌ | ❌ | Detects explicit permissions blocks that lack explanatory comments. |
| `unpinned-images` | Workflow, Action | v1.7.0 | ✅ | ❌ | ❌ | Checks for `container.image` values where the image is not pinned by either a tag (other than `latest`) or SHA256. |
| `unpinned-tools` | Workflow, Action | v1.25.0 | ✅ | ❌ | ❌ | Detects certain `#!yaml uses:` steps where the referenced action may use an unpinned external |
| `unpinned-uses` | Workflow, Action | v0.4.0 | ✅ | ⚠️ | ✅ | Detects "unpinned" `#!yaml uses:` clauses. |
| `unredacted-secrets` | Workflow, Action | v1.4.0 | ✅ | ❌ | ❌ | Detects potential secret leakage via redaction failures. |
| `unsound-condition` | Workflow, Action | v1.12.0 | ✅ | ✅ | ❌ | Detects conditions that are inadvertently always true despite containing |
| `unsound-contains` | Workflow | v1.7.0 | ✅ | ❌ | ❌ | Detects conditions that use the `contains()` function in a way that can be bypassed. |
| `unsound-ternary` | Workflow, Action | v1.26.0 | ✅ | ❌ | ❌ | Detects GitHub Actions expressions that use `&&` and `||` as a pseudo-ternary |
| `use-trusted-publishing` | Workflow | v0.1.0 | ✅ | ❌ | ❌ | Detects packaging workflows that could use [Trusted Publishing]. |
