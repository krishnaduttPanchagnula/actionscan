# Frizbee — Quick Profile

**URL**: https://github.com/stacklok/frizbee
**Generated**: 2026-10-22

## At a Glance
| Metric | Value |
|--------|-------|
| Tagline | "Throw a tag at it and it comes back with a checksum." (GitHub description). README: "Frizbee is a tool you may throw a tag at and it comes back with a checksum." |
| Target audience | (inferred from copy — label it) Platform engineers and supply-chain-conscious OSS maintainers who want a mechanical tag→SHA/digest rewriter for both GitHub Actions and container images. The tagline-first README and the "useful for verifying that the contents have not changed" framing reads like a developer utility, not a security posture product. Backed by Stacklok (Minder company), and shipped as a GitHub Action in the Marketplace |
| Language / license | Go / Apache-2.0 |
| GitHub stars / forks | 186 / 24 (GitHub API, 2026-10-22). 18 open issues, 9 watchers |
| Releases (latest) | 30 releases. Latest v0.1.11, published 2026-08-14 (GitHub API, 2026-10-22). Still on a `v0.x` line |
| Last commit | Last push 2026-10-21 (GitHub API `pushed_at`, 2026-10-22) — actively developed, but **no release since 2026-08-14** (≈2.5 months) |
| Pricing starts at | Free, open source (Apache-2.0) |
| Free tier/trial | N/A — free OSS CLI + library. Install via `go install`, Homebrew (`brew install frizbee`), or `winget install stacklok.frizbee` |
| Domain rank | not available (no SEO data source in this environment) |
| Est. organic traffic | not available (no SEO data source in this environment) |
| Organic keywords (top 10) | not available (no SEO data source in this environment) |
| Referring domains | not available (no SEO data source in this environment) |

## Positioning
**Headline**: "Frizbee"
**Subheadline**: "It's a command-line tool designed to provide checksums for GitHub Actions and container images based on tags."
**Positioning angle**: *A mechanical resolver, deliberately narrow.* frizbee does exactly one thing: given a mutable tag, produce the immutable commit SHA (for actions) or image digest (for containers), and optionally rewrite the reference in place. It is a **library first** — the README documents `replacer.NewGitHubActionsReplacer` / `NewContainerImagesReplacer` with `ParseString`, `ParsePath`, `ParsePathInFS`, `ParseFile`, `ListPath`, `ListPathInFS`, `ListFile` — so other tools can embed it. It is also one of the very few tools in this field that handles **container image digests** alongside action SHAs.

## Product & Features

### Core capabilities

**Commands (cobra; confirmed in `cmd/`):**
- `frizbee actions <path-to-workflows-dir | owner/repo@ref>` (alias `ghactions`) — rewrites the `uses:` field of GitHub Action references to full commit SHAs. Defaults to `.github/workflows` when no argument is given. Also accepts a **single reference** to print the replacement without touching files.
- `frizbee actions list <dir>` (alias `ls`) — lists the actions referenced in a directory; `--output json|table` (default `table`).
- `frizbee image <path-to-yaml-dir | ghcr.io/org/img:tag>` (aliases `containerimage`, `dockercompose`, `compose`) — rewrites container image tags to digests. "This works for all yaml/yml and Dockerfile files in the directory provided by the `-d` flag." Exact one argument required.
- `frizbee image list` — subcommand present (`cmd/image/list.go`).
- `frizbee version`.

**`--dry-run`** — "this command supports dry-run mode, which will print the replacements to stdout instead of writing them to the files." Flag is `-n/--dry-run`, declared as "don't modify files". Implemented in `internal/cli/cli.go` `ProcessOutput`: under dry-run the content is written to stdout; otherwise to the file.

**Exits non-zero if replacements found — confirmed.** The `internal/cli/cli.go` helper declares:
```
cmd.Flags().BoolP("error", "e", false, "exit with error code if any file is modified")
```
and `CheckModified(modified)` returns `errors.New("files were modified")` when `len(modified) > 0 && ErrOnModified`. So the exit-non-zero behaviour is **opt-in via `--error`**, not the default. The README describes it as "It also supports exiting with a non-zero exit code if any replacements are found. This is handy for CI/CD pipelines." — i.e. a CI-gating mode, not default behaviour. **This is a correction to the brief's framing:** the flag exists and is the CI mechanism, but the tool does not fail by default.

**Other flags** (`cli.DeclareFrizbeeFlags`): `--dry-run/-n`, `--quiet/-q` ("don't print anything"), `--error/-e`, `--regex/-r` ("regex to match artifact references"), `--platform/-p` ("platform to match artifact references, e.g. linux/amd64"), and `--output/-o` (json|table) on the `list` subcommands only. `GITHUB_TOKEN` env var is read for the GitHub client; the tool prints a note that it's recommended given GitHub's tighter anonymous rate limits.

**`.frizbee.yml` configuration — confirmed.** Schema read from `pkg/utils/config/config.go`:

```yaml
ghactions:
  exclude:                          # list of action/workflow paths to skip
    - slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml
  exclude_branches:                 # refs to skip
    - main
    - master
images:
  exclude_images:                   # regex that must match for the image to be excluded
    - busybox
  exclude_tags:                     # tags to skip
    - devel
```

**Defaults confirmed in source (`pkg/utils/config/config.go`):**
- `ExcludeBranches: []string{"main", "master"}` — "By default, Frizbee will exclude all actions that are referencing `main` or `master`." ✅ confirmed.
- `ExcludeImages: []string{"scratch"}` — the `scratch` image is always excluded ("mostly making sure that we don't try to pin the scratch image"); note the code *appends* `scratch` even if the user removed it, so `scratch` is forced.
- `ExcludeTags: []string{"latest"}` — the `latest` image tag is excluded by default.

**Docker tags → digests — confirmed.** `frizbee image` resolves a tag to a digest via the container registry and rewrites the reference; `frizbee image ghcr.io/stacklok/minder/server:latest` prints the digest reference. It operates on yaml/yml and Dockerfile files in a directory.

**Reference replacement semantics:** the `actions` command "will only replace the `uses` field of the GitHub Action references" (README) — it is scoped to the `uses:` key rather than doing free-text replacement.

**What frizbee does NOT do (observed):** no advisory/threat-intel feed, no CVE or GHSA lookup, no "is this action compromised" check, no org-wide sweep (single-directory scope), no HTML report, no policy/allowlist beyond the exclude lists, no baseline/delta mode, no transitive dependency traversal, no audit-only mode that reports without rewriting (the `list` subcommand is the closest thing). It also does **not** appear to support the `--out json|sarif` reporting style of scharf — its JSON output is the `list` subcommand's entity dump, and there is **no SARIF output** on the pages checked.

### Output formats
- **Human/stdout text** for the rewrite commands: logs `Processed: <path>` / `Modified: <path>` to stderr; under `--dry-run` prints the rewritten file content to stdout.
- **Single-reference mode** prints `name@sha` (e.g. `actions/checkout@<sha>`) to stdout.
- **`list` subcommand**: `--output json` (JSON array of entities, `json.MarshalIndent`) or `--output table` (default).
- **No SARIF, no HTML, no CSV** observed.

### Config / policy model
- Single `.frizbee.yml` at the working directory, with `ghactions.exclude`, `ghactions.exclude_branches`, `images.exclude_images`, `images.exclude_tags`.
- Excludes are **path/ref/regex-based skips**, not finding suppressions with rationale or expiry.
- No policy versioning, no accountability metadata, no baseline.

### CI integration and exit codes
- Shipped as a GitHub Action: **frizbee-action** (https://github.com/marketplace/actions/frizbee-action).
- Exit codes: `--error` (`-e`) makes the command exit non-zero when any file was modified. Errors from the underlying resolver also surface as non-zero exits. **The exact numeric exit code was not observed** in the code reviewed (Go `error` return → cobra → exit 1 is the normal convention).
- `--dry-run` + `--error` is the canonical "gate CI on unpinned refs" combination: detect without rewriting, fail if anything is unpinned.
- Auth: `GITHUB_TOKEN` for GitHub API calls (higher rate limits).

## Pricing Summary
| Tier | Price | Notable Inclusions |
|---|---|---|
| Frizbee CLI | Free (Apache-2.0) | `actions`/`image` rewrite, `list` subcommands, `--dry-run`, `--error`, `.frizbee.yml` excludes, library API |
| Frizbee Go library | Free (Apache-2.0) | `pkg/replacer` — `ParseString`, `ParsePath`, `ParsePathInFS`, `ParseFile`, `ListPath`, `ListPathInFS`, `ListFile` |
| frizbee-action | Free | Marketplace action wrapper |
| Commercial support / hosted offering | Not observed on the pages checked | — |

## Key Takeaway
frizbee is the cleanest, most focused tag→checksum resolver in the field, and unusual in covering **container images** as well as actions — it is the only tool in this batch that pins Docker tags to digests. Its engineering is solid (Go, Apache-2.0, Stacklok-backed, actively maintained) and its API is genuinely embeddable. But its scope is deliberately narrow: it resolves and rewrites, it does not judge, and it has no advisory layer, no org-wide enumeration, no reporting beyond text/JSON, and it is still shipping `v0.1.x` with a ~2.5-month gap since its last release.

## Competitive Implications for actionscan

**Where they're strong vs. us**
- **Action *and* container image pinning in one tool.** If actionscan ever wants to report unpinned container references alongside unpinned actions, frizbee's `pkg/replacer` is a directly usable library rather than something to rebuild.
- **Embeddable API.** A Go library with a stable `replacer`/`config` surface is easy to consume. If we implement pinning remediation, frizbee is a legitimate dependency candidate — its Apache-2.0 licence and Stacklok stewardship lower the risk.
- **Active maintenance** (last push 2026-10-21) despite the release gap.
- **Sensible default-safety**: excluding `main`/`master`/`latest`/`scratch` by default prevents it from "pinning" things that were never meant to be pinned.

**Where we're strong vs. them** (hypothesis unless evidenced)
- **They answer "what SHA is this tag?"; we answer "is this action safe to use at all?"** frizbee has zero threat-intel, zero advisory lookup, zero notion of a compromised action. A pinned-but-compromised action passes frizbee cleanly. **Observed** absence of any feed.
- **Org-wide.** frizbee operates on one directory. We sweep an org via the API without cloning.
- **Findings, not rewrites.** frizbee's primary verb is *mutate the file*. Ours is *report a finding with a location, a severity, and a reason*. For a security report you want the second.
- **Reporting.** No HTML dashboard, no CSV, no SARIF observed. Our dashboard and SARIF output are a clear lead.

**Opportunities**
1. **Use frizbee as a dependency rather than reimplementing SHA resolution**, if we add pinning remediation. *Question: do we want a remediation path at all, or stay report-only and let scharf/frizbee own the rewrite?* Staying report-only keeps our scope tight and avoids duplicating a solved problem.
2. **Adopt the `--dry-run` + `--error` split.** "Detect without writing, exit non-zero if anything needs changing" is exactly our CI-gating shape and is cleaner than a single `--fix` flag. Worth mirroring in our exit-code design.
3. **Borrow the exclude-config shape.** `.frizbee.yml`'s `exclude` / `exclude_branches` / `exclude_images` / `exclude_tags` is a clean, flat, four-key config. Our ignore/allowlist config should be at least this easy to write. Note this is *easier* than scharf's policy schema — a real trade-off to weigh.
4. **Consider container images.** frizbee's `image` command and `images.*` config keys are a ready-made model if we extend actionscan to container references (a natural extension of "everything my CI pulls from outside").

**Threats**
- **Low direct threat.** frizbee does not audit, does not report risk, and does not sweep orgs. It is a complementary utility, not a competitor for the actionscan job.
- **Medium "table stakes" threat.** If a user asks "how do I pin my actions?", frizbee (186 stars, Marketplace action, brew/winget/go-install) is the answer they find. We must be visibly better at *finding and explaining* problems, not merely better at pinning.
- **The `v0.1.x` + release gap is a distribution opening, not a threat.** If frizbee's maintainers slow down, a better-maintained pinning tool could take the slot — but scharf already occupies the more sophisticated slot.

## Raw Data Sources
All fetched 2026-10-22.
- `raw/frizbee/2026-10-22/scrapes/github-readme.md` — https://raw.githubusercontent.com/stacklok/frizbee/main/README.md
- `raw/frizbee/2026-10-22/scrapes/cmd-actions.go` — `cmd/actions/actions.go` (command surface, `ParsePath`/`ParseString`, `CheckModified` call)
- `raw/frizbee/2026-10-22/scrapes/cmd-actions-list.go` — `cmd/actions/list.go` (`--output json|table`, list behaviour)
- `raw/frizbee/2026-10-22/scrapes/cmd-image.go` — `cmd/image/image.go` (image/digest command)
- `raw/frizbee/2026-10-22/scrapes/internal-cli.go` — `internal/cli/cli.go` (**`--dry-run/-n`, `--quiet/-q`, `--error/-e`, `--regex/-r`, `--platform/-p`, `--output/-o`**; `CheckModified` → `errors.New("files were modified")`; `ProcessOutput` dry-run behaviour)
- `raw/frizbee/2026-10-22/scrapes/pkg-config.go` — `pkg/utils/config/config.go` (**defaults: `main`/`master` branches excluded, `scratch` image excluded, `latest` tag excluded**; `.frizbee.yml` schema)
- `raw/frizbee/2026-10-22/seo/github-repo.json`, `github-releases.json`, `github-contributors.json`, `github-languages.json`, `github-tags.json` — GitHub REST API
- GitHub API repo tree for `stacklok/frizbee` (file listing)

**Not observed / limitations**
- **Exit code numbers** — not observed; only the `--error` semantics are confirmed from source.
- **No SARIF / HTML / CSV output** — not observed on the pages checked.
- **No org-wide sweep** — not observed; scope is a local path.
- **No advisory/threat-intel feed** — not observed in README, config, command surface, or the CLI/cmd sources reviewed. The repo was not exhaustively grepped for feed clients.
- **frizbee-action README** — not fetched; the Marketplace link is referenced from the frizbee README.
- **Pricing / commercial offering** — none found.
