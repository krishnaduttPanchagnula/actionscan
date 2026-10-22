# Pinny — Quick Profile

**URL**: https://github.com/koalalab-inc/pinny (vendor: https://www.koalalab.com/)
**Generated**: 2026-10-22

## At a Glance
| Metric | Value |
|--------|-------|
| Tagline | "Pin your 3rd Party Github Actions and Docker Images dependencies." (GitHub description). README: "Hash-pinning for your OSS dependencies to protect against repojacking and imposter commits." |
| Target audience | (inferred from copy — label it) Small teams and individual maintainers worried about **repojacking** and **imposter commits** specifically — the README leads with the Linux Foundation's "742% increase in new-age supply chain attacks from 2019-2022" and links two of its own long-form explainer docs (`docs/Secure-by-design-OSS.md`, `docs/impostorcommits.md`). The demo GIFs are of pinning the **Akto** repo's workflows and **Metabase**'s Dockerfile — i.e. a normal OSS maintainer, not a security team. Distribution is Docker-image-first, which suggests a developer audience without Go on the box |
| Language / license | Go / Apache-2.0 |
| GitHub stars / forks | 17 / 2 (GitHub API, 2026-10-22). 1 open issue, 2 watchers |
| Releases (latest) | **5 releases only**. Latest v0.0.9, published **2024-04-11** (GitHub API, 2026-10-22) — over two years old |
| Last commit | Last push **2025-03-15** (GitHub API `pushed_at`, 2026-10-22) — ~19 months stale. Repo `updated_at` is 2026-09-03 (likely issue/star activity, not code) |
| Pricing starts at | Free, open source (Apache-2.0) |
| Free tier/trial | N/A — free OSS CLI. Shipped primarily as a **Docker image** (`ghcr.io/koalalab-inc/pinny:0.0.9`) or as a precompiled binary from GitHub Releases |
| Domain rank | not available (no SEO data source in this environment) |
| Est. organic traffic | not available (no SEO data source in this environment) |
| Organic keywords (top 10) | not available (no SEO data source in this environment) |
| Referring domains | not available (no SEO data source in this environment) |

## Positioning
**Headline**: "Pinny"
**Subheadline**: "Hash-pinning for your OSS dependencies to protect against repojacking and imposter commits."
**Positioning angle**: *Pinning as self-defence against repository takeover.* pinny frames pinning narrowly around two threats — **repojacking** (a maintainer's GitHub handle is freed and re-registered, so a mutable `owner/repo` reference now resolves to an attacker's repo) and **imposter commits** (a legitimate-looking commit authored under a similar identity). The interesting differentiator versus frizbee/scharf is the **lockfile workflow for Docker images**: `pinny docker lock` generates a committed `pinny-lock.json`, and `pinny docker transform` applies that lockfile in CI — a two-phase commit-then-apply model that frizbee does not have.

## Product & Features

### Core capabilities

**Command surface (cobra; confirmed in `cmd/`):**
- `pinny actions pin` — "Pin all third party Github Actions used in your workflows." Rewrites every `uses:` in `.github/workflows/*.yml|*.yaml` to the action's commit digest, appending the original ref as a trailing comment: `actions/checkout@93ea575cb5d8a053eaa0ac8fa3b40d7e05a33cc8 # actions/checkout@v3.1.0`. When multiple other ref names resolve to the same digest, they are appended: `# actions/setup-go@v2 | v2.2.0`.
- `pinny actions digest` — a digest-resolution subcommand (`cmd/actions/digest.go`).
- `pinny docker pin` — pins the base images in a `Dockerfile`, writing `Dockerfile.pinned` by default; `--inplace`/`-i` overwrites the original; `--file`/`-f` selects a different filename.
- `pinny docker lock` — generates a `pinny-lock.json` with the pinned versions of all base images; `--file`/`-f` selects the Dockerfile.
- `pinny docker transform` — applies the committed `pinny-lock.json` to transform Dockerfiles in CI; `--file`/`-f`, `--inplace`/`-i`.
- `pinny docker digest` — digest resolution subcommand.
- `pinny version` (`rootCmd` sets `Version: version`, template `Pinny v{{.Version}}`).

**How it finds dependencies — confirmed from `pkg/actions/actions.go`.**
- It is a **line-based regex scanner**, not a YAML parser. Two regexes are applied per line: `^(?P<pre>.*uses\s*:\s*)(?P<actionString>docker://\S+)(?P<post>.*)$` for Docker references and `^(?P<pre>.*uses\s*:\s*)(?P<actionString>\S+@\S+)(?P<post>.*)$` for action references. Any line containing `uses:` is a candidate.
- Action references are parsed with `(?P<owner>[^/]+)/(?P<repo>[^@/]+)(/(?P<path>[^@]+))?@(?P<ref>.+)` into a `GithubActionRef{Owner, Repo, Path, Ref, OtherRefNames, Digest}`.
- Digest resolution goes through the **Git refs API**: it lists matching refs (`Git.ListMatchingRefs`) and prefers an **exact tag match** (`refs/tags/<ref>`) over a branch match, then falls back to detecting **shortened hashes**. Branch references produce an explicit warning: `WARN:: Branch references are being used for third party Github Action: <owner>/<repo>@<ref>`.
- Results are cached in a package-level `actionRefCache map[string]*GithubActionRef`.
- **Important caveat for readers:** because it is line-and-regex based, pinny will match `uses:` inside comments and will treat `owner/repo` substrings loosely — a materially weaker parsing model than scharf's structure-aware YAML span extraction (ADR 002) or zizmor's. **Observed from source.**

**Output format — confirmed.**
- The rewritten workflow file itself, with the original ref preserved as a trailing `#` comment.
- `pinny actions pin` prints `Pinned <path>` per file and, under `--dry-run`, prints the full rewritten file content to stdout.
- `--dry-run`/`-d` is declared in `cmd/actions/pin.go`: "Print the changes without updating the workflow files".
- `pinny docker lock` prints `Generated pinny-lock.json:` with the lockfile contents.
- **No JSON, no CSV, no SARIF, no HTML output.** The "output" is the rewritten file plus human stdout. The Docker path's machine-readable artifact is `pinny-lock.json`.
- **No audit-only / report mode.** pinny rewrites. There is no "tell me what's unpinned and exit non-zero without touching files" mode equivalent to frizbee's `--dry-run --error` combination — `--dry-run` prints the changes but the exit behaviour was **not observed** to gate on findings.

**Atomicity / error handling — observed.** `PinWorkflows` writes each rewritten workflow to `<file>.tmp` first, and only renames the `.tmp` over the original if **no** file in the batch errored; on error it removes the `.tmp` and breaks. So a failed batch does not partially apply. The rename is not atomic across the *set* of files, but it is atomic per file and all-or-nothing in the common path.

**Configuration.** **None observed.** There is no config file, no exclude list, no allowlist, no policy file, no baseline/delta mode. The only knobs are the CLI flags above. This is a notable gap relative to every other competitor in this batch.

**CI integration and exit codes.**
- The Docker-image-first distribution (`docker run -v "$(pwd):/app" -w /app -u $(id -u):$(id -g) ghcr.io/koalalab-inc/pinny:0.0.9 ...`) is the intended invocation; the README documents aliasing it to `pinny`.
- Precompiled binaries are published per-OS via GitHub Releases (`pinny_Darwin_x86_64.tar.gz`), with a macOS Gatekeeper note (`sudo xattr -d com.apple.quarantine /usr/local/bin/pinny`).
- **Exit codes: not observed.** The code uses `cobra.CheckErr(err)` for errors, which exits non-zero, but no explicit finding-based exit-code contract was found.
- `GITHUB_TOKEN=<your_token> pinny actions pin` is the documented rate-limit escape hatch ("If you are being rate limited by Github's API").

**Dormancy — stated plainly.**
- **5 releases ever**, latest **v0.0.9 from 2024-04-11**.
- **Last code push 2025-03-15** — roughly 19 months before this profile date (2026-10-22).
- 1 open issue, 2 watchers, 17 stars, 2 forks.
- The README still points users at `0.0.9` in the install instructions, and the release assets on GitHub are named for v0.0.9.
- **This is effectively a dormant project.** It is not abandoned — the repo is not archived and `updated_at` shows recent activity — but there is no development trajectory.

## Pricing Summary
| Tier | Price | Notable Inclusions |
|---|---|---|
| Pinny CLI + Docker image | Free (Apache-2.0) | `actions pin`, `actions digest`, `docker pin`, `docker lock`, `docker transform`, `docker digest` |
| Commercial support / hosted offering | Not observed on the pages checked | — |

## Key Takeaway
pinny is a small, cleanly-scoped pinning tool whose real differentiator is a **lockfile workflow for container images** (`pinny docker lock` → commit `pinny-lock.json` → `pinny docker transform` in CI) and a Docker-image-first distribution model aimed at maintainers without Go installed. But it is **effectively dormant** — 5 releases, latest from April 2024, last code push March 2025, 17 stars — it uses **line-regex scanning rather than YAML parsing** (so it will match `uses:` inside comments), and it has **no config file, no allowlist, no report mode, and no JSON/SARIF output**. It is a useful reference for the commit-then-apply lockfile pattern and nothing more.

## Competitive Implications for actionscan

**Where they're strong vs. us**
- **The Docker lockfile pattern.** `pinny-lock.json` committed to the repo, applied by CI. For container references in workflows, this is a legitimately good model: it makes the pinning decision reviewable in a PR and reproducible in CI, rather than resolved live at scan time. If we ever add container-image coverage, this is the pattern to copy.
- **Docker-first distribution.** `docker run -v "$(pwd):/app"` with host-UID passthrough is a genuinely low-friction install for a Go tool that many security teams won't `go install`. Worth copying for actionscan's own distribution.
- **Non-destructive batch semantics.** All-or-nothing `.tmp` + rename across a workflow directory is a correct pattern that prevents half-applied rewrites.
- **Warning on branch refs.** `WARN:: Branch references are being used for third party Github Action` surfaces a real risk (branch refs are the repojacking vector) — a cheap, high-signal touch.

**Where we're strong vs. them** (hypothesis unless evidenced)
- **Everything past "find the ref".** pinny stops at resolution. We go on to answer "is this action vulnerable, compromised, unmaintained, or outdated?", across an entire org, with severity, evidence and remediation.
- **Parsing quality.** Their regex approach matches `uses:` in comments and non-`uses:` strings. Our extractor should be AST/YAML-based (as scharf's ADR 002 argues at length).
- **Reporting.** No JSON, no SARIF, no HTML, no severity model, no evidence trail.
- **Policy.** No exclude list at all. Ours will have one.
- **Activity.** We can out-ship a project with no release since April 2024.

**Opportunities**
1. **Consider a lockfile mode for actionscan.** A committed `actionscan.lock` recording resolved SHAs for every action reference, plus a `--check-lock` mode that fails when a workflow reference no longer matches the lock — that is pinny's best idea, and it composes naturally with our org-wide inventory (one lock per repo, generated centrally).
2. **Copy the Docker-first install ergonomics.** `docker run -v "$(pwd):/app" -w /app -u $(id -u):$(id -g) ghcr.io/<org>/actionscan:<version>` with a documented alias. Our users are the same people.
3. **Adopt the "warn loudly on branch refs" behaviour** as a distinct finding class. Branch references are the repojacking primitive; pinny is right that they deserve their own signal, separate from "tag instead of SHA".
4. **Do not copy the regex scanner.** If we extract `uses:` values, parse the YAML.

**Threats**
- **Very low.** 17 stars, dormant since March 2025, no config, no reporting, no org sweep, and no advisory layer. It cannot out-ship us and does not compete for the same job.
- **The only realistic "threat" is opportunity-cost:** pinny is the tool a user will find when they search "pin github actions sha", and it is simpler than anything we will build. If our tool is not obviously more valuable to a security team, a simple rewriter wins on perceived effort. *Implication: the free-tier story must be that actionscan finds things pinning tools cannot — compromised and vulnerable actions across the org — not that it pins better.*
- **Its "lockfile" concept could be independently reinvented** by a larger project; if a big player ships an action lockfile standard, our lockfile idea loses its novelty.

## Raw Data Sources
All fetched 2026-10-22.
- `raw/pinny/2026-10-22/scrapes/github-readme.md` — https://raw.githubusercontent.com/koalalab-inc/pinny/main/README.md
- `raw/pinny/2026-10-22/scrapes/cmd-root.go` — `cmd/root.go` (root command, version template)
- `raw/pinny/2026-10-22/scrapes/cmd-actions-actions.go` — `cmd/actions/actions.go` (`actions` group: `pin`, `digest`)
- `raw/pinny/2026-10-22/scrapes/cmd-actions-pin.go` — `cmd/actions/pin.go` (**regexes**, `.tmp`+rename batch semantics, `--dry-run/-d`, `Pinned <path>` output)
- `raw/pinny/2026-10-22/scrapes/cmd-actions-digest.go` — `cmd/actions/digest.go`
- `raw/pinny/2026-10-22/scrapes/pkg-actions.go` — `pkg/actions/actions.go` (**digest resolution via `ListMatchingRefs`, exact-tag-over-branch precedence, shortened-hash handling, branch WARN, `actionRefCache`**)
- `raw/pinny/2026-10-22/scrapes/cmd-docker-lock.go` — `cmd/docker/lock.go` (`Generated pinny-lock.json:`)
- `raw/pinny/2026-10-22/seo/github-repo.json`, `github-releases.json`, `github-contributors.json`, `github-languages.json`, `github-tags.json` — GitHub REST API
- GitHub API repo tree for `koalalab-inc/pinny` (file listing; confirms the small surface area)

**Not observed / limitations**
- **Exit codes** — not observed; only `cobra.CheckErr` error propagation is visible.
- **No config file, no exclude list** — not observed anywhere in the repo tree or README.
- **No JSON/SARIF/HTML output** — not observed.
- **No advisory/threat-intel feed** — not observed in README or source.
- **Whether `pinny actions pin` gates on findings in CI** — not observed; `--dry-run` prints but no documented non-zero-on-findings contract.
- **The `pinny-lock.json` schema** — only the file name and the "Generated pinny-lock.json:" output were observed; the exact JSON structure was not read in full.
- **Windows support** — not observed; README documents only Darwin binaries.
- Pricing / commercial offering — none found.
