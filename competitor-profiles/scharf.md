# Scharf — Quick Profile

**URL**: https://github.com/cybrota/scharf (site: https://cybrota.github.io/scharf/)
**Generated**: 2026-10-22

## At a Glance
| Metric | Value |
|--------|-------|
| Tagline | "Static analysis tool to Identify and Fix GitHub Actions prone to Supply‑Chain Risks" (GitHub description). Site/README: "Secure your CI/CD pipeline against supply-chain attacks on third-party GitHub Actions." |
| Target audience | (inferred from copy — label it) Platform/security engineers who own CI workflows and want third-party actions SHA-pinned in CI, with policy-as-code enforcement and PR/CI-native feedback. The README's "Further Reading" cites CISA's tj-actions advisory, alexwlchan.net and GHSA-mrrh-fwg8-r2c3 — an audience already burned by the March 2025 tj-actions/changed-files compromise |
| Language / license | Go / Apache-2.0 (GitHub API reports `NOASSERTION` because the repo also carries a `LICENSE-3P` third-party notice file alongside the Apache `LICENSE`; the `LICENSE` file itself is verbatim Apache-2.0, "Copyright (c) 2025 Naren Yellavula & Cybrota contributors") |
| GitHub stars / forks | **15 / 0** (GitHub API, 2026-10-22). 6 open issues, 1 watcher. Companion repo `cybrota/scharf-action`: 1 star, MIT, created 2025-04-13, last push 2025-04-14 |
| Releases (latest) | 22 releases. Latest v1.4.2, published 2026-10-08 (GitHub API, 2026-10-22) |
| Last commit | Last push 2026-10-10 (GitHub API `pushed_at`, 2026-10-22) |
| Pricing starts at | Free, open source. No paid tier observed on the pages checked |
| Free tier/trial | N/A — free OSS CLI (Apache-2.0). Distributed via Homebrew (`brew tap cybrota/cybrota`), prebuilt binaries, and `install.sh` |
| Domain rank | not available (no SEO data source in this environment) |
| Est. organic traffic | not available (no SEO data source in this environment) |
| Organic keywords (top 10) | not available (no SEO data source in this environment) |
| Referring domains | not available (no SEO data source in this environment) |

## Positioning
**Headline**: "Scharf"
**Subheadline**: "Secure your CI/CD pipeline against supply-chain attacks on third-party GitHub Actions."
**Positioning angle**: *Pinning is the control, and policy is the enforcement mechanism.* Scharf's argument is that the tj-actions/changed-files class of breach is prevented by SHA-pinning third-party actions, and that pinning must be **governed** — versioned policy files, accountable and expiring exceptions, baseline/delta mode for gradual rollout, trusted-policy loading from a git ref so a checkout cannot relax enforcement, and CI-native output (GitHub annotations + SARIF). The `find` command scans a *workspace of cloned repos*; `audit` handles one repo or a remote URL.

**The 15-star caveat, stated plainly:** scharf has 15 stars, 0 forks, and 1 watcher as of 2026-10-22. It is effectively unknown. Its `scharf-action` wrapper has 1 star and was last pushed in April 2025. That is a real, measurable weakness and it is not disputed here.

**Why it is still the best prior art in the field for pinning + transitive resolution:** the engineering density per user is the highest observed in this batch by a wide margin. The repo ships **six ADRs** (`001` SHA-upgrade design, `002` structure-aware workflow scanning, `003` policy & PR feedback, `004` declarative dependency traversal, `005` upstream SHA provenance, `006` reviewed release pipeline) that specify, in writing, the exact trust boundaries, budget constants, failure semantics and adversarial limits of each feature. The transitive dependency audit (`--dependencies`) is the only read-only, budgeted, cycle-aware `uses:` graph traversal found in *any* tool in this landscape — and it exists in a tool with 15 stars, which is precisely why it has not been copied. Anyone building this capability should read `docs/adr/004-declarative-dependency-traversal.md` before designing their own.

## Product & Features

### Core capabilities

**Command surface — confirmed, all seven commands present in `main.go` (cobra) and the README.**

| Command | Purpose | Key flags (from `main.go`) |
|---|---|---|
| `scharf audit <repo\|url>` | Audit one repo (local path or remote URL; remote is auto-cloned to `/tmp` with a `scharf-*` prefix) for mutable references | `--raise-error` (persistent), `--policy`, `--policy-from-ref`, `--ignore` (repeatable, `StringArray`), `--baseline-ref`, `--changed-lines`, `--verify-provenance`, `--out human\|github\|sarif\|json`, `--output <path>`, `--dependencies` |
| `scharf autofix <repo\|url>` | Rewrite mutable refs to full commit SHAs | `--dry-run` (persistent), `--verify-provenance` |
| `scharf find --root <dir>` | Scan a workspace of cloned repos; `--out json\|csv` (default json), `--head-only` | `--root` (default `.`), `--out`, `--head-only` |
| `scharf list owner/repo` | Table of available refs → commit SHAs for an action | — |
| `scharf lookup owner/repo@version` | Resolve one ref to its immutable SHA | — |
| `scharf upgrade owner/repo@version` | Move a pinned SHA to the next version | `--from-version` (when input is already a SHA), `--cooldown-hours` (default 24), `--dry-run`, `--verify-provenance` |
| `scharf upgrade-all-sha .` | Upgrade every Scharf-formatted pin (`owner/repo@<sha> # <version>`) in workflows. Does **not** touch mutable refs — that is `autofix`'s job | `--cooldown-hours`, `--dry-run`, `--verify-provenance` |

Plus `scharf version` / `-V`.

**`--out` formats.** `audit` accepts **`human`, `github`, `sarif`, `json`** (validated in `main.go`: "invalid --out value %q: valid values are human, github, sarif, and json"). The README's example lists `--out json|csv|sarif|github|human` but `csv` is a **`find`-only** format in the code — `find` accepts `json|csv`. **Correction worth noting:** the brief listed `csv` as an audit format; the code shows csv belongs to `find`. The dependency-graph mode accepts `human`, `json`, `sarif` only ("dependency output must be human, json, or sarif").

**`--ignore` semantics** (from `docs/policy.md`): repeatable, two forms — plain `owner/repo[/subpath][@ref]` exact match, or `regex:<RE2>` which must match the *complete canonical reference*. `allow_cli_ignores: false` in the policy rejects CLI ignores entirely.

**`--verify-provenance` — confirmed.** Available on `audit`, `autofix`, `upgrade`, `upgrade-all-sha`. Default behaviour remains immutability-only. Per `docs/provenance.md` and ADR 005: verification requires **fresh GitHub API responses** and proof that the commit is equal to or an ancestor of at least one *current branch tip* from the upstream repo's branches API, with GitHub compare metadata showing `ahead` or `identical` and the candidate as merge base. It records the **canonical repo name and stable numeric repository ID**, check time, SHA and the exact supporting `refs/heads/*` tip. Before accepting evidence it re-checks the requested path and any distinct canonical path against the starting identity; a changed numeric ID blocks the result. A commit merely *addressable* through `/repos/owner/repo/commits/<sha>` is explicitly **not sufficient** — fork-network commit addressability is called out as the attack this defends against. First observation is stored in `~/.scharf/provenance.json` as a trust-on-first-use record. Forward movement of a branch or major tag (`v4`) is reported as `moved-reference` with `requires_review: false`; a moved patch tag, non-forward change, tag/branch namespace change or uncheckable prior ancestry requires review. Autofix/upgrade **refuse to write** on unknown or review-required evidence. Explicit caveat repeated in the docs: **"Verified" does not mean benign code.** Bounds: 128 API calls, five branch-list pages of 100, 2 MiB per response, eight annotated-tag objects, 15 s per request, 45 s overall, max three same-host HTTPS redirects.

**`.scharf-policy.yml` schema — confirmed from `docs/policy.md`.** The repo's own file is minimal (`version: 1` / `allow_cli_ignores: false`); the full documented schema is:

```yaml
version: 1                    # must be "1"
allow_cli_ignores: false

rules:
  - id: SCHARF001
    requirement: full-commit-sha
    severity: error           # error | warning | note
    repositories: ["actions/*", "github/*"]
    paths: [".github/workflows/*.yml", ".github/workflows/*.yaml"]

baseline:
  ref: origin/main
  mode: new

exceptions:
  - id: SEC-1234
    match:
      repository: example/internal-action
      subpath: deploy
      ref: main
      paths: [".github/workflows/release.yml"]
    owner: team-platform
    rationale: Migration to an immutable release is in progress
    approved_by: security-team
    approval: https://github.com/example/project/issues/1234
    expires: 2026-10-01
```

Semantics worth copying:
- **Rules use ordered, first-match precedence.** Empty `repositories`/`paths` match all. Patterns use Go path-match syntax (`*` does not cross `/`). Repository matching is case-insensitive; path/subpath/ref matching is case-sensitive.
- **Absent `rules`** ⇒ default `SCHARF001` / `full-commit-sha` / `severity: error` on every parsed external reference.
- **Exceptions are accountable and expiring.** Required: `id`, `match.repository`, `owner`, `rationale`, `approved_by`, `approval`, `expires`. Optional: `subpath`, `ref`, `paths`. `expires` is `YYYY-MM-DD` and remains active *through* that UTC date, expiring at the start of the next UTC date.
- **Malformed exceptions invalidate the entire policy** — "Scharf never skips an invalid exception and continues scanning."
- **Application order** (explicitly documented): (1) reject invalid policy/CLI matchers → (2) select first matching rule → (3) apply matching *active* exception → (4) a matching *expired* exception is treated as a **violation** (a CLI ignore cannot revive it) → (5) apply a permitted matching CLI ignore → (6) apply baseline + changed-line rollout filters. When multiple durable exceptions match, any active renewal wins over expired records.
- **Trust model for CI:** in `--raise-error` mode scharf does **not** trust the policy from the checkout — it applies the secure default unless `--policy <path>` or `--policy-from-ref <revision>` is given. `--policy-from-ref origin/main` reads the *committed* policy from that revision so checkout changes cannot relax enforcement. `--policy` and `--policy-from-ref` are mutually exclusive. Docs advise protecting `.scharf-policy.yml` with branch protection and CODEOWNERS.

**Baseline / changed lines — confirmed.** `baseline.ref` with `mode: new`, or `--baseline-ref <ref>` (which overrides the policy baseline and selects `new` mode). Scharf compares `HEAD` with **its merge base** against the selected ref, detects workflow renames, scans **both** revision trees, and compares duplicate references as a **multiset**: a pure rename stays an existing finding; a changed ref or an *additional* duplicate becomes new. `--changed-lines` restricts enforcement to findings whose right-side workflow line changed since the merge base; it **requires** a baseline ref and **rejects uncommitted workflow changes** (the git diff would not describe the bytes being audited). Missing refs, malformed baseline workflows and diff failures make the scan **incomplete** — never clean.

**The read-only transitive dependency audit (`--dependencies`) — the most important prior-art artifact in this batch.**

*Invocation:* `scharf audit ./repository --dependencies --out json` (also `human`, `sarif`).

*Semantics (README + ADR 004):* it follows declarative `uses:` edges **through composite actions and reusable workflows at resolved commits**. Each remote ref is resolved **once per invocation**; the action metadata or reusable workflow is then read *at that full commit*. Successful immutable content is cached; **every caller chain is retained**. The graph includes original references, resolved commits, and each caller chain. API access uses `GITHUB_TOKEN` when available. **It never executes downloaded actions** and normal audit behaviour is unchanged.

*Hard budgets (ADR 004, exact constants — corroborated in source):*
- **depth 12** (checked *before* resolving or fetching a child)
- **5,000 visited YAML structures / aliases / mapping keys** (including repeated caller paths and invalid documents)
- **8 MiB of unique decoded metadata**
- **500 HTTP requests**
- **2 MiB per API response**
- **1 MiB per remote metadata file**
- **15 seconds per request**

Source corroboration: `scanner/dependencies.go` → `DefaultDependencyLimits() DependencyLimits{12, 5000, 8 << 20}`; `network/dependencies.go` → `MaxRequests: 500`, `Timeout: 15 * time.Second`, `CheckRedirect` returns `ErrUseLastResponse` (redirects refused), `io.LimitReader(resp.Body, (2<<20)+1)` → "dependency API response exceeds 2 MiB", and "metadata exceeds 1 MiB".

*How it signals incompleteness — the key semantic.* The report is **never clean when it could not see everything**. ADR 004 states: "YAML merge keys, cycles, invalid references, inaccessible metadata and exhausted budgets produce incomplete reports. Structural work is charged even for run-only or malformed aliases; global node/byte exhaustion stops all remaining traversal." The report carries a top-level `complete` boolean and a `status`; per-edge `status` strings observed in `scanner/dependencies.go` include: `resolved`, `container-not-traversed`, `workspace-context-unknown`, `invalid-self-reference`, `unresolved-reference`, `resolution-unavailable`, `depth-budget-exhausted`, `metadata-unavailable`, `invalid-workflow-path`. The JSON shape (`scanner/dependencies_report.go`): `DependencyReport{Status, Complete, Edges[], Errors[], Scope}`; `DependencyEdge{Chain[], Repository, Ref, Commit, Metadata, Mutable, Status}`; `DependencyLocation{File, Line, Column, Uses}`. SARIF sets `invocations[].executionSuccessful = report.Complete`, emits `SCHARF_SCAN_INCOMPLETE` notifications and results, retains successful findings, and returns a non-zero status. **Incomplete scans always return an error**, regardless of `--raise-error`.

*Scope limits, stated by the tool itself:*
- **Graph mode rejects** `--policy`, `--ignore` and baseline flags outright — "rather than silently pretending those decisions cover transitive edges". Normal policy audit must be run separately.
- **No transitive autofix.**
- `$/` uses **defining-repository** semantics (requires runner 2.336.0+; scharf reports the semantics without claiming the runner supports it). `./` inside a remote composite action needs workspace context and is **left unresolved** (status `workspace-context-unknown`). Local workflow calls retain their defining repository/commit.
- **Docker image references are explicitly marked not traversed** (`container-not-traversed`) — "image auditing is separate work".
- **It excludes shell/JavaScript downloads, package and container contents.** ADR 004: "Parsing declarative edges cannot discover runtime downloads, generated workflows, dependencies inside JS or Docker images, or establish source trust."
- **"A clean result means only that the traversed GitHub repository references were pinned."** and **"a pinned graph is not a trust assessment."**
- API resolution uses GitHub.com content/commit endpoints and **does not prove upstream reachability**. Repository rename redirects intentionally remain unavailable. Conservative YAML merge handling may require manual review.
- **No recursive cloning, no execution** of third-party actions.
- Hardening (ADR 004): rooted file access keeps local symlinks inside the scanned repository including concurrent symlink replacement; Unix opens reject FIFOs without blocking; remote symlink objects are rejected; redirects refused including for injected HTTP clients.

**Structure-aware scanning (ADR 002).** Scharf parses workflows with `go.yaml.in/yaml/v3` and inspects **only job-level `uses:` values and step-level `uses:` values** — not every line. It derives half-open byte spans from YAML scalar node locations rather than re-serialising, so quoting, formatting, action subpaths, reusable-workflow paths and existing comments survive autofix. Mutable references are "all syntactically valid external references except full 40-character hexadecimal commit SHAs"; local actions, Docker references, malformed references and dynamic expressions are not candidates. It scans local and remote-tracking branches **directly from their git commit trees without checking them out**, labelling results `remote:<remote>/<branch>` and skipping symbolic remote HEAD refs. Scan state is explicit: **`complete-clean`, `complete-with-findings`, or `incomplete`** — file-level errors are retained beside successful findings and an aggregate error is returned so exit status cannot imply a clean result. Mutable references expressed through YAML aliases, anchors or block scalars are findings in an **incomplete** scan (their spans are not safe to edit).

**What scharf does NOT do (observed):** no advisory/threat-intel feed, no CVE lookup, no "is this action compromised" check, no org-wide API-driven sweep (its multi-repo mode, `find`, requires repos **already cloned to a local workspace**), no HTML report, no dashboard, no CSV for `audit`.

### Output formats
- `audit`: `human` (default), `github` (GitHub Actions workflow commands with escaped output: rule ID, source location, current reference, exception state, remediation, and the exact replacement SHA when one resolves safely), `sarif` (SARIF 2.1.0 with stable rule IDs, Unicode code-point columns, baseline state, accepted suppressions, directly applicable replacements; `invocations[].executionSuccessful=false` + `SCHARF_SCAN_INCOMPLETE` on incomplete scans), `json`. `--output <path>` writes any format to a file.
- `find`: `json` (default), `csv`.
- Dependency graph: `human`, `json`, `sarif` (rule id `SCHARF_DEPENDENCY`, level `warning`).
- SARIF upload path documented: `github/codeql-action/upload-sarif` with `sarif_file: scharf.sarif`.

### Config / policy model
- `.scharf-policy.yml` at the scanned repo root, auto-discovered for advisory audits; `--policy <path>` to trust an explicit file; `--policy-from-ref <rev>` to load from a trusted git revision.
- Parser is **strict**: rejects unknown fields, unsupported versions, duplicate IDs, invalid patterns, malformed exceptions. Malformed exceptions invalidate the whole policy.
- Plus `--ignore` CLI exceptions (exact or `regex:`), `baseline`/`baseline-ref` rollout mode, `allow_cli_ignores` toggle.
- **Dependency-graph mode deliberately does not accept policy/baseline/ignore flags** (it errors rather than pretending coverage).
- Provenance observations in `~/.scharf/provenance.json` (versioned, atomic writes, private, fails closed on corrupt/unknown-version/locked state).

### CI integration and exit codes
- `cybrota/scharf-action` (1 star, MIT) — `uses: cybrota/scharf-action@<sha>` with `with: raise-error: true`. The action prints a table of `MATCH | FILEPATH | REPLACE WITH SHA` and "No mutable references found. Good job!" when clean.
- `--raise-error` fails **only** for blocking (`severity: error`) policy findings. **Incomplete scans always fail**, regardless of `--raise-error`, after writing available human/github/sarif output.
- Dependency-graph mode: `--raise-error` rejects mutable graph edges; incomplete scans always error.
- Auth: `GITHUB_TOKEN` for dependency-graph API access and provenance verification. Network required for dependency-graph and provenance modes; **not** required for plain local audit (except resolving refs for autofix).
- Platforms: Linux, macOS (README "Supported Platforms"). Windows **not observed** as supported.

## Pricing Summary
| Tier | Price | Notable Inclusions |
|---|---|---|
| Scharf CLI (all seven commands) | Free (Apache-2.0) | Audit + autofix + find + list + lookup + upgrade + upgrade-all-sha, transitive dependency graph, provenance verification, policy file, SARIF/GitHub annotations/JSON output |
| scharf-action | Free (MIT) | One-step CI wrapper with `raise-error` input |
| Commercial support / hosted offering | Not observed on the pages checked | — |

## Key Takeaway
Scharf has 15 stars and 0 forks, and that is the honest headline. But it is the most rigorously *specified* pinning tool in existence: six ADRs specify trust boundaries, budget constants, failure semantics and adversarial limits in prose that a reviewer can audit; the transitive dependency graph is budgeted (depth 12 / 5k structures / 8 MiB / 500 requests), cycle-aware, never-executes-anything, and reports **incomplete ≠ clean** rather than lying; and the policy model handles the hard cases (trusted-ref policy loading so a checkout can't relax enforcement, accountable expiring exceptions, expired exceptions reverting to violations, baseline/merge-base diffing as a multiset so renames don't hide new pins). Its weaknesses are equally clear: it has no advisory feed at all, no org-level API sweep (its multi-repo mode needs repos pre-cloned locally), no HTML/dashboard, and effectively no distribution.

## Competitive Implications for actionscan

**Where they're strong vs. us**
- **Transitive dependency resolution — done, documented, and copyable.** If we build this, scharf has already answered most of the design questions (budgets, incompleteness semantics, cycle handling, symlink/redirect hardening). That is a gift to us and a warning: it is a 15-star project, so nobody has noticed it yet, and the moment it is noticed the barrier to entry rises.
- **Policy model depth.** Accountable exceptions with owner/approver/rationale/expiry; trusted-ref policy loading; expired-exception-reverts-to-violation; `allow_cli_ignores` toggle. This is more rigorous than zizmor's inline ignores and than anything we have.
- **Incompleteness as a first-class output state** (`complete-clean` / `complete-with-findings` / `incomplete`, with `executionSuccessful=false` and non-zero exit). Our org sweep will hit partial failures (rate limits, deleted repos, private repos we can't read). scharf shows how to represent that honestly.
- **Baseline/delta mode done properly** — merge-base comparison, both trees scanned, multiset comparison of duplicate references, rename detection. This is the feature our prior list calls "the #1 user complaint" and "unclaimed". **It is not unclaimed — scharf has it.** *Correction to our own positioning document.*
- **Provenance verification** (branch-membership proof, not just immutability) is a genuinely novel control that none of the popular tools have. It also correctly refuses to over-claim ("verified" ≠ benign).

**Where we're strong vs. them**
- **Live threat-intel feeds.** scharf has zero advisory capability. It answers "is this ref mutable?" and "is this SHA still on an upstream branch?" — never "is this action in a GHSA/OSV advisory range or a known-compromised list?". **Observed:** no advisory or CVE code path on the pages checked; the README's threat framing is entirely about mutable tags.
- **Org-wide sweep via API.** scharf's `find` requires repos **already cloned** into a local workspace (`--root /path/to/workspace`). We enumerate an org via the GitHub API and scan without cloning. That is a large operational difference for a 500-repo org.
- **Dashboard/HTML output.** scharf is console/SARIF/JSON only. Our HTML dashboard is a distribution advantage we should keep.
- **Audiences.** 15 stars vs. our need to reach platform-security teams. scharf will not out-distribute us.
- **Fixable-SHA remediation for advisories.** scharf resolves mutable refs to SHAs; we would resolve *vulnerable* refs to safe SHAs. The mechanism is the same, the intelligence is ours.

**Opportunities**
1. **Adopt scharf's incompleteness contract verbatim.** Adopt `complete-clean` / `complete-with-findings` / `incomplete` as our scan status, set SARIF `invocations[].executionSuccessful=false` on partial scans, and **always exit non-zero on an incomplete org sweep**. This is a cheap, high-trust differentiator for a tool that touches 500 repos and will hit rate limits.
2. **Port the budget model.** depth 12 / 5,000 structures / 8 MiB / 500 requests / 2 MiB per response / 1 MiB per metadata file / 15 s per request, with the *same* explicit constants and the same refusal to execute anything. Also port the hardening: refuse redirects, reject remote symlink objects, keep local symlinks inside the repo, reject FIFOs without blocking.
3. **Port the "reject policy flags in graph mode" behaviour.** Our transitive graph mode should *reject* `--ignore`/baseline flags rather than silently pretending they cover transitive edges. Same honesty, same trust.
4. **Port the baseline/merge-base multiset algorithm** for our delta mode — it is already written and specified; reinventing it would be strictly worse.
5. **Port the trusted-ref policy loading** (`--policy-from-ref origin/main`) so a PR cannot relax our enforcement in CI.
6. **Adopt the "clean means only what we traversed" wording.** Our reports should say precisely what was and was not covered — scharf's phrasing ("a pinned graph is not a trust assessment") is the right register for a tool that could otherwise be over-trusted.
7. **Consider porting the provenance-verification idea** — but as a *separate* opt-in layer over our findings, with the same refusal to over-claim.

**Threats**
- **A finding, not a market threat, but a real one:** scharf could add an advisory feed — it already has the GitHub API client, the graph traversal and the SHA resolution. If it does, the most technically complete pinning tool in the field gets a threat-intel layer, and the "most advanced pinning engineering" argument transfers to it wholesale. **Watch `cybrota/scharf` releases.**
- **Low incumbent risk.** 15 stars, 0 forks, no distribution, no team behind it visible. It is unlikely to out-ship us on features. The realistic threat is *acquisition of its ideas* by someone else.
- **The risk of us copying blindly.** ADR 004 and ADR 005 are unusually honest documents, but they encode *scharf's* threat model (mutable tags, upstream identity). If we copy the mechanism without adapting the semantics to advisories, we may build the wrong graph. **Implication: read ADR 004 as a design constraint list, not a spec to transcribe.**

## Raw Data Sources
All fetched 2026-10-22.
- `raw/scharf/2026-10-22/scrapes/github-readme.md` — https://raw.githubusercontent.com/cybrota/scharf/main/README.md
- `raw/scharf/2026-10-22/scrapes/website-homepage.md` — https://cybrota.github.io/scharf/ (rendered README)
- `raw/scharf/2026-10-22/scrapes/docs-policy.md` — https://raw.githubusercontent.com/cybrota/scharf/main/docs/policy.md (full policy schema, precedence, exceptions, baselines, output formats)
- `raw/scharf/2026-10-22/scrapes/docs-provenance.md` — https://raw.githubusercontent.com/cybrota/scharf/main/docs/provenance.md
- `raw/scharf/2026-10-22/scrapes/adr-002-structure-aware-workflow-scanning.md`
- `raw/scharf/2026-10-22/scrapes/adr-003-policy-and-pr-feedback.md`
- `raw/scharf/2026-10-22/scrapes/adr-004-declarative-dependency-traversal.md` — **the key artifact: budgets, limits, incompleteness semantics**
- `raw/scharf/2026-10-22/scrapes/adr-005-upstream-sha-provenance.md`
- `raw/scharf/2026-10-22/scrapes/scharf-main.go` — `main.go` (all cobra commands and flags)
- `raw/scharf/2026-10-22/scrapes/scharf-scanner-dependencies.go` — `scanner/dependencies.go` (`DefaultDependencyLimits(){12, 5000, 8<<20}`, edge status strings)
- `raw/scharf/2026-10-22/scrapes/scharf-dependencies-report.go` — `scanner/dependencies_report.go` (report JSON/SARIF shape)
- `raw/scharf/2026-10-22/scrapes/scharf-network-dependencies.go` — `network/dependencies.go` (`MaxRequests: 500`, 15 s timeout, redirect refusal, 2 MiB / 1 MiB limits)
- `raw/scharf/2026-10-22/scrapes/scharf-policy.yml` — the repo's own `.scharf-policy.yml`
- `raw/scharf/2026-10-22/scrapes/scharf-action-readme.md` — https://raw.githubusercontent.com/cybrota/scharf-action/main/README.md
- `raw/scharf/2026-10-22/scrapes/scharf-LICENSE.txt`, `scharf-LICENSE-3P.txt` — license situation
- `raw/scharf/2026-10-22/seo/github-repo.json`, `github-releases.json`, `github-contributors.json`, `github-languages.json`, `github-tags.json`, `github-repo-scharf-action.json` — GitHub REST API
- GitHub API repo tree for `cybrota/scharf` (full file listing, used to confirm all six ADRs exist)

**Not observed / limitations**
- **No advisory/CVE/threat-intel capability** on the pages checked — confirmed absent from the README, all docs, all ADRs and the command surface, but the repo was not exhaustively grepped for feed clients.
- **No HTML report, no dashboard** — not observed.
- **No org-wide API sweep.** `find` operates on a local workspace of already-cloned repos. Not observed to have a GitHub-API org enumerator.
- **Windows support** — not observed; README lists Linux and macOS only.
- **`--out csv` for `audit`** — the brief listed it; the code shows csv is a `find`-only format. `audit` accepts human/github/sarif/json.
- **Exit-code numbering** — not observed. Only the semantics (`--raise-error` blocks on `severity: error`; incomplete always fails) are documented.
- **`docs/usage.md`** — fetch returned `404: Not Found`; saved as `raw/scharf/2026-10-22/scrapes/docs-usage.md`.
- No pricing page, no commercial offering observed.
