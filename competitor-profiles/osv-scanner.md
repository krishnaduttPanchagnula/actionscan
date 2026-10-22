# osv-scanner (Google) — Competitor Profile

**URL**: https://google.github.io/osv-scanner/
**Generated**: 2026-10-22
**Depth**: deep profile

> All facts below are labelled **[Observed]** (with source + date), **[Inferred]**, or **[Implication]**.
> "Not observed" is used where a check was made and found nothing — it does not mean the thing is absent.
> SEO metrics (domain authority, backlinks, organic traffic, referring domains, organic keywords) were **not
> obtainable** in this environment; GitHub stars/releases + registry downloads are used as the honest substitute.

---

## At a Glance

| Metric | Value |
|---|---|
| Tagline | "Use OSV-Scanner to find existing vulnerabilities affecting your project's dependencies." **[Observed]** — docs homepage, 2026-10-22 |
| One-liner (their framing) | "an officially supported frontend to the OSV database that connects a project's list of dependencies with the vulnerabilities that affect them" **[Observed]** — docs homepage |
| Founded | Repo created 2022-11-14; publicly launched 2022-12-13 via Google Online Security Blog (authored by Rex Pan, Google Open Source Security Team) **[Observed]** — GitHub API + blog post |
| Backing | Google (Google Open Source Security Team). OpenSSF Scorecard badge in README; OSV-Scanner is the engine behind the **OpenSSF Scorecard "Vulnerabilities" check** (~1.2M projects evaluated, per the launch post). The OSV schema itself lives at `ossf/osv-schema` under OpenSSF. **[Observed]** — README badges, blog post, `ossf/osv-schema` repo |
| Language / License | Go / Apache-2.0 **[Observed]** — GitHub API |
| GitHub stars | **11,233** **[Observed]** — GitHub API, 2026-10-22 |
| Forks / watchers | 818 forks / 77 watchers **[Observed]** — GitHub API |
| Open issues | 98 via `open_issues_count` **[Observed]** — GitHub API. Broken out: **86 open issues + 12 open PRs** **[Observed]** — GitHub search API |
| Releases | **56** total; latest **v2.7.0** published 2026-10-12 **[Observed]** — GitHub API |
| Downloads | Homebrew: **3,535** installs/30d, 7,755/90d, 24,822/365d **[Observed]** — formulae.brew.sh API, 2026-10-22. Also distributed via Scoop, WinGet, Arch, Alpine, FreeBSD, NetBSD, OpenBSD, `go install`, and `ghcr.io/google/osv-scanner` **[Observed]** — docs Installation page |
| Related repos | `google/osv-scalibr` (SCA library, 648 stars) — the extraction engine; `google/osv-scanner-action` (99 stars) — reusable CI workflows; `google/osv-scanner-v1` — frozen v1 line **[Observed]** |
| Domain rank | not available (no SEO data source in this environment) |
| Organic traffic | not available (no SEO data source in this environment) |
| Referring domains | not available (no SEO data source in this environment) |
| Organic keywords | not available (no SEO data source in this environment) |
| OSV.dev "GitHub Actions" ecosystem size | **55 advisories** (of 2,544,922 total across all OSV ecosystems) **[Observed]** — https://osv.dev/list?ecosystem=GitHub+Actions, 2026-10-22 |
| **Can it find a vulnerable GitHub Action?** | **No — empirically verified on v2.7.0. See "the GitHub Actions gap" below.** |

---

## Positioning & Messaging

**[Observed]** The homepage sells two things: the *scanner* and the *database*.

- **The database as the moat.** "Since the OSV.dev database is open source and distributed, it has several benefits in comparison with closed source advisory databases and scanners" — then three bullets: each advisory comes from an open and authoritative source (e.g. RustSec), anyone can suggest improvements, and the OSV format "unambiguously stores information about affected versions in a machine-readable format that precisely maps onto a developer's list of packages". The stated payoff: "fewer, more actionable vulnerability notifications, which reduces the time needed to resolve them."
- **Explicit anti-false-positive messaging.** The 2022 launch post: "The above all results in accurate and actionable vulnerability notifications." This is the axis they compete on.
- **Two consumption modes.** "As a CLI tool: Run directly in a terminal or CI/CD pipeline to scan projects" / "As a Go library: Import the Go package to integrate vulnerability scanning logic into Go applications."
- **Point-and-scan, per project.** The mental model throughout the docs is: give it a directory, a lockfile, or a container image; it returns vulnerabilities *for that target*.

**[Inferred]** The positioning is **"high-precision, low-noise, per-project dependency vulnerability matching against the authoritative open database."** Nothing in the docs, README, nav, or release notes positions osv-scanner as an organisation-level, cross-repository, or CI-workflow-configuration auditing tool. The noun they own is *dependency*, not *action reference*.

**[Observed]** Roadmap language from the launch post ("our plan for OSV-Scanner is not just to build a simple vulnerability scanner; we want to build the best vulnerability management tool") has largely been delivered: standalone CI actions ✅, call-graph analysis ✅ (`--call-analysis`), minimal version bumps / auto-remediation ✅ (`fix` / guided remediation), C/C++ commit-level data ✅, VEX ⚠️ (not found in the current docs).

**[Implication]** actionscan should not try to win a "database depth" argument — OSV.dev ingests GitHub Security Advisories directly, so the *advisory sources* overlap. Our differentiation must be **scope** (which artifacts we read, across how many repos) and **adjacent signals** (compromised-action-specific feeds, pinning hygiene, release-freshness), not "we also read GHSA".

---

## Product & Features

### Core capabilities

**[Observed]** v2 CLI surface: three commands — `scan source` (default), `scan image`, `fix` — plus the experimental `osv-reporter` binary.

| Capability | Detail | Source |
|---|---|---|
| Source scanning | Recursive scan of a directory for supported lockfiles/manifests | docs Usage |
| Container scanning | Layer-aware image scanning; Alpine APK, Debian/Ubuntu dpkg, Ubuntu chiseled, Go binaries, cargo-auditable Rust binaries, Java jars, node_modules, Python wheels | docs Supported Artifacts |
| SBOM scanning | SPDX JSON + CycloneDX via Package URLs; `--sbom` now relies on filename spec (`*.spdx.json`) | docs, v1→v2 Migration Guide |
| C/C++ commit-level scanning | Vendored and submoduled C/C++ deps via commit hashes; `determineversion` API for vendored copies | docs Supported Artifacts |
| Transitive dependency resolution | Maven `pom.xml` only; uses deps.dev resolver; `--no-resolve` to disable; `--data-source=native` for Maven Central / private registries | docs Supported Artifacts |
| Call analysis | `--call-analysis=<lang>` splits findings into "affects code called by your project" vs "uncalled" — a false-positive reducer | docs Output |
| License scanning | `--licenses` / `--licenses="MIT,Apache-2.0"` allowlist check via deps.dev | docs Usage |
| Deprecation flagging | `--x-flag-deprecated-packages` — reports deprecated/yanked packages | docs Experimental |
| Custom lockfile input | Hand-written `osv-scanner.json` (or `osv-scanner-custom.json`) in the scanner's own JSON output format | docs Supported Artifacts |
| Config | TOML config; per-path package ignore rules (`PackageOverrides`) | docs Configuration |

**[Observed]** Supported lockfiles/manifests (docs "Supported Artifacts and Manifests"): C/C++ (`conan.lock`), Dart, Elixir, Go (`go.mod`), Haskell, Java (Gradle locks, `pom.xml`), JavaScript (`bun.lock`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`), .NET, PHP, Python (`Pipfile.lock`, `poetry.lock`, `requirements.txt`, `pdm.lock`, `pylock.toml`, `uv.lock`), R, Ruby, Rust (`Cargo.lock`).

**[Observed]** README claims "11+ language ecosystems and 19+ lockfile types."

### Ecosystem support — and the GitHub Actions gap

This is the section that matters most for actionscan, so it is documented as an evidence ladder.

#### Level 1 — Documented support: no workflow parsing

**[Observed]** The canonical gate is the docs page *Supported Artifacts and Manifests* (https://google.github.io/osv-scanner/supported-languages-and-lockfiles/, scraped 2026-10-22). Its "Supported lockfiles/manifests" table lists 13 languages and their lockfiles. **There is no CI-workflow, no `.github/`, no `uses:` row anywhere in the table.** A grep of the scraped page for `workflow`, `.github`, and `action` returns only two incidental prose hits — no table entries.

**[Observed]** The "Supported Artifacts" table (container scanning) is likewise OS-package/binary oriented, with no workflow entry.

#### Level 2 — Empirical verification on the shipped binary

**[Observed]** Ran the released `osv-scanner_linux_amd64` **v2.7.0** (built 2026-10-12, `osv-scalibr version: 0.5.3`) against a fixture repo containing:

```yaml
# .github/workflows/ci.yml
steps:
  - uses: tj-actions/changed-files@v45.0.7
  - uses: actions/checkout@v4
```

Result of `osv-scanner scan source -r . --format json`:
- Packages reported: `('PyPI', 'requests', '2.0.0')` — from a control `requirements.txt` (13 findings).
- `tj-actions` present in output: **false**. `GitHub Actions` ecosystem present in output: **false**.
- The workflow file was not parsed at all.

#### Level 3 — The documented workaround also returns nothing

**[Observed]** The docs' escape hatch for unsupported lockfiles is a hand-written `osv-scanner.json`. Tested with the GitHub Actions ecosystem:

```
$ osv-scanner scan source -L osv-scanner:./osv-scanner.json --verbosity info
{"package":{"name":"tj-actions/changed-files","version":"45.0.7","ecosystem":"GitHub Actions"}}
→ Scanned .../osv-scanner.json file and found 1 package
→ No issues found
```
The package is **not** filtered as unscannable (no "Filtered N unscannable package/s" line) — it is queried and comes back empty. Control: the identical path with `{"name":"lodash","version":"4.17.15","ecosystem":"npm"}` returns **6 findings**, so the pipeline works; the GitHub Actions ecosystem specifically yields nothing.

#### Level 4 — Why: the OSV API's version matching does not work for this ecosystem

**[Observed]** Verified directly against `api.osv.dev` (2026-10-22):

| Request | Result |
|---|---|
| `POST /v1/query` `{"package":{"name":"tj-actions/changed-files","ecosystem":"GitHub Actions"}}` (no version) | **2 vulns** — `GHSA-mcph-m25j-8j63`, `GHSA-mrrh-fwg8-r2c3` |
| `POST /v1/query` same package **+ `"version":"45.0.7"`** | **`{}`** |
| Version sweep in this ecosystem: `45.0.7`, `v45.0.7`, `45.0.8`, `v45.0.8`, `40`, `v40`, `41`, `45`, `v45`, `0`, `v0`, `46.0.1`, `v46.0.1` | **`{}` for every one** |
| Control: `POST /v1/query` `{"package":{"name":"lodash","ecosystem":"npm"},"version":"4.17.15"}` | **6 vulns** |
| `POST /v1/querybatch` without version | 2 vulns |
| `POST /v1/querybatch` **with** version `45.0.7` | `{"results":[{}]}` |
| `POST /v1/query` with `"ecosystem":"GitHubActions"` (no space) | **HTTP 400** `{"code":3,"message":"invalid ecosystem"}` |

**[Observed]** The advisory data itself is correct and machine-readable:
`GET /v1/vulns/GHSA-mrrh-fwg8-r2c3` → `affected[0].package = {"name":"tj-actions/changed-files","ecosystem":"GitHub Actions"}`, `ranges = [{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"46.0.1"}]}]`, `aliases = ["CVE-2025-30066"]`, summary "tj-actions changed-files through 45.0.7 allows remote attackers to discover secrets by reading actions logs."
The second advisory `GHSA-mcph-m25j-8j63` has `introduced: 0 / fixed: 41`.

**[Inferred]** Version-scoped queries against the "GitHub Actions" ecosystem do not match at the OSV API level, even for versions demonstrably inside the affected range, while the same code path works for npm. This is an ecosystem-specific behaviour in the OSV service's version comparator, not a data problem.

**[Observed]** osv-scanner's Go client uses `QueryBatch` (symbols in the v2.7.0 binary: `osv.dev/bindings/go/osvdev.(*OSVClient).QueryBatch`), so it inherits this behaviour.

> **This is the technical reason actionscan must query by package name and match version ranges locally** rather than by exact version. It is not an implementation preference.

#### Level 5 — Upstream status: the feature was asked for and auto-closed; the extractor exists but is off by default and still finds nothing

**[Observed]** `google/osv-scanner#2821` — **"Feature Request: Scan GitHub Actions Workflows"**, opened 2026-05-19 by a community member, closed 2026-08-17 with labels `stale`, `autoclosed`. The body proposes exactly the actionscan approach: "**Parser** — Implement a parser for `.github/*.yml` files to extract `uses:` references (e.g., `actions/checkout@v3`); **API Integration** — Query the OSV API for these references using the `GitHub Actions` ecosystem; **CLI Update** — Update `osv-scanner scan source` to include these files during recursive scans." One maintainer reply (2026-06-04): "https://github.com/google/osv-scalibr/pull/2032 added this to osv-scalibr, so hopefully this will come soon."

**[Observed]** `google/osv-scalibr#2032` — **"Add extractor for GitHub Actions workflow dependencies"**, **merged 2026-05-06**. It parses `.github/workflows/*.yml|yaml`, extracts `uses:` refs as `name=owner/repo`, `version=ref`, `ecosystem=GitHub Actions`, normalises sub-paths to `owner/repo`, skips local actions and `docker://` refs, tracks line numbers, and captures the commit hash when the ref is a pinned 40-char SHA. The extractor is listed in Scalibr's `docs/supported_inventory_types.md` as plugin **`github/actions`**.

**[Observed]** But osv-scanner v2.7.0 does **not** enable it by default, and the docs page for supported artifacts does not mention it. The docs note: "OSV-Scanner has access to the full list of OSV-Scalibr plugins, though only a well tested subset of them are enabled by default in OSV-Scanner," and the escape hatch is the experimental `--x-plugins` flag.

**[Observed]** Enabling it experimentally still does not produce findings, and breaks offline mode:
```
$ osv-scanner scan source -r . --x-no-default-plugins --x-plugins github/actions --format json
→ Scanned .../.github/workflows/ci.yml file and found 2 packages
→ "results": []          ← zero vulnerabilities, for tj-actions/changed-files@v45.0.7
```
```
$ osv-scanner scan source -r . --x-no-default-plugins --x-plugins github/actions \
    --offline-vulnerabilities --download-offline-databases
→ Loaded GitHub Actions local db from ~/.cache/osv-scalibr/GitHub Actions/all.zip
→ panic: unsupported ecosystem GitHub Actions
→ panic: runtime error: invalid memory address or nil pointer dereference  [SIGSEGV]
→ exit code 2
   github.com/google/osv-scalibr/semantic.MustParse(...)  semantic/parse.go:36
   .../enricher/vulnmatch/osvlocal/internal/vulns.rangeContainsVersion(...)
```
**[Observed]** The panic is the same class of bug as `google/osv-scanner#2831` ("Offline scan panics with 'unsupported ecosystem GitHub Actions' on SBOMs containing actions that have OSV advisories", filed 2026-05-21, closed 2026-05-28). That issue's own text states the online-mode behaviour we reproduced: "The same SBOM in **online** mode returns successfully — but silently reports **no findings** for any GitHub Actions component, which is a separate false-negative issue." The 2026-05-28 fix covered osv-scanner's internal matcher (`internal/utility/vulns.rangeContainsVersion`); the Scalibr local-matcher path still panics in v2.7.0.

#### The scope boundary, stated fairly

**[Observed]** The GitHub Actions gap is a **structural scope boundary, not a quality defect**. osv-scanner is a *dependency vulnerability matcher*: it resolves packages from lockfiles/manifests/containers/SBOMs and matches them against OSV. CI workflow configuration is not a dependency manifest, so it is out of the tool's declared scope. The same boundary explains why the tool also has no notion of "which of my repositories use X".

**[Implication]** The consequence for actionscan is precise and worth stating in our own docs: **osv-scanner can never answer "which of my org's repos use a vulnerable action"** — not "answers it badly", but "cannot answer it", because it (a) never enumerates an org's repos and (b) never reads a `uses:` line on the default path, and (c) even when forced to read one via the experimental flag, the version-matching path that would have to produce a finding returns empty. **This is a scope boundary we should describe factually, not as a criticism of their engineering.**

### Output formats

**[Observed]** `--format` values, from `osv-scanner scan --help` on v2.7.0:
`table` (default), `html`, `vertical`, `json`, `markdown`, `sarif`, `gh-annotations`, `cyclonedx-1-4`, `cyclonedx-1-5`, `cyclonedx-1-6`, `cyclonedx-1-7`, `spdx-2-3`.

- **SARIF** is SARIF v2.1.0; each vulnerability (grouped by aliases) is a rule, each vulnerable package a rule violation, with remediation instructions in the help text.
- **HTML** is interactive: severity breakdown, package and ID filtering, vulnerability-importance filtering, full advisory entries; for containers, layer filtering and base-image identification. `osv-scanner scan --serve <dir>` hosts it on `localhost:8000` (`--port` to change).
- **Call analysis** adds a split between "affects code called by your project" and "Uncalled vulnerabilities" in table output.
- **Exit codes**: `0` = packages found, no vulnerabilities; `1` = vulnerabilities/findings; `1-126` = vulnerability-result errors; `127` = general error; `128` = no packages found; `129-255` = non-result errors.
- **[Observed] There is no CSV format.** Grep for `csv` in the Output docs page: 0 hits.

### Integrations

| Integration | Detail | Status |
|---|---|---|
| **OpenSSF Scorecard** | osv-scanner is the engine behind Scorecard's "Vulnerabilities" check; ~1.2M projects evaluated (per launch post) | **[Observed]** 2022 launch post |
| **GitHub Code Scanning** | SARIF upload via `security-events: write`; findings also appear as GitHub PR annotations | **[Observed]** docs |
| **`google/osv-scanner-action`** | Two reusable workflows: `osv-scanner-reusable-pr.yml` (diff vs target branch, fails on new vulns) and `osv-scanner-reusable.yml` (scheduled/push/release full scan). 99 stars, last pushed 2026-10-12 | **[Observed]** GitHub API + docs |
| **deps.dev API** | Dependency resolution, container image metadata, license info, deprecation checks | **[Observed]** README |
| **OSV.dev API** | Primary vulnerability source; sends package names, versions, ecosystems, file hashes | **[Observed]** README |
| **Package registries** | Maven Central, npm registry, PyPI (only with `--data-source=native`) | **[Observed]** README |
| **Docker** | `ghcr.io/google/osv-scanner` | **[Observed]** docs |
| **pre-commit** | Official `osv-scanner` and `osv-scanner-docker` hooks | **[Observed]** docs |
| **SLSA** | Level 3 provenance (`multiple.intoto.jsonl`), verifiable with `slsa-verifier` | **[Observed]** README + Installation |
| **Go library** | Importable Go package | **[Observed]** README |

### Product direction signals

**[Observed]** Direction over the last ~19 months is toward **more machine-consumable output and more automation**, away from new scanning surfaces:

- v2.0.0 (2025-03-17) was a large CLI/JSON-output breaking change; v1 was forked to `google/osv-scanner-v1` with its own docs site (`google.github.io/osv-scanner-v1`). **[Observed]** README + Migration Guide.
- The experimental surface has grown: `--x-plugins`, `--x-no-default-plugins`, `--x-disable-plugins`, `--x-flag-deprecated-packages`, `osv-reporter` (diffing two scan JSONs, multi-format emission). **[Observed]** docs Experimental.
- Guided remediation now covers npm lockfiles (in-place), npm manifests (relock), Maven `pom.xml` (override) — all package-ecosystem, none CI. **[Observed]** README + docs.
- Release cadence: 8 minor releases since v2.0.0 (2025-03-17 → 2026-10-12), roughly every 2–6 weeks; plus patch releases (v2.3.5, v2.3.6, v2.3.8, v2.5.1, v2.0.1–.3). **[Observed]** GitHub releases API.
- **[Observed]** Deprecation of the experimental flag prefix is explicitly documented: "features prefixed with `x` … are experimental and might be changed or removed with only a Minor version change." **[Inferred]** They intend to graduate selected `--x-*` features into stable, which is where the `github/actions` extractor could land.

---

## Pricing

**[Observed]** No pricing page. The project is **Apache-2.0** and free. The launch post explicitly calls it "a free tool". Nothing in the docs, README, or repo mentions a paid tier, a hosted commercial product, or a support contract.

**What is free:** the CLI, the Go library, the container image, the reusable GitHub Actions workflows, the offline database, and the OSV.dev API.

**What the "Data Sources and Privacy" section commits to** (README section titled *"Data Sources and Privacy"*, quoted/paraphrased — a genuinely good transparency model worth imitating):
1. **Enumerate every external service**: OSV.dev API, deps.dev API, and package registries (Maven Central, npm registry, PyPI).
2. **State exactly what data is sent**:
   - OSV.dev: "package names, versions, ecosystems, and file hashes."
   - deps.dev: "package names, versions, and ecosystems. **No source code is transmitted.**"
3. **Offer a hard network-off switch**: `--offline` "will not download or update the local database, nor will it send any project or dependency information anywhere. When a local database is not present, you will get an error message. No network connection is required when using this flag."
4. **Publish the offline database location and format** (`gs://osv-vulnerabilities`, per-ecosystem `all.zip`), so an operator can mirror it themselves.
5. **Document the offline limitation** honestly: "Commit level scanning is not supported."

**[Implication]** actionscan should adopt the same three-part shape (enumerate endpoints / state payload fields / offer a no-network mode). Our equivalent payload disclosure is: GitHub API reads (repo metadata, workflow file contents), OSV/GHSA/feed reads (package names + versions only, never workflow file contents), and no source-code transmission.

---

## Customers & Social Proof

**[Observed]** There is no customer logo wall, no case-study page, no testimonial page, no named-enterprise reference list, and no pricing-to-enterprise-sales motion (checked: docs site nav, README, repo, release notes). The repo's `topics` are `scanner, security-audit, security-tools, vulnerability-scanner`.

**[Observed]** The social proof that does exist is ecosystem-level:
- **Google Open Source Security Team** authorship and maintenance.
- **OpenSSF Scorecard integration** — the Vulnerabilities check, which the launch post says extends analysis to "the 1.2M projects regularly evaluated by Scorecard."
- **11,233 stars / 818 forks / 77 watchers** — a very large public constituency.
- **24,822 Homebrew installs in 365 days**; first-party formulae in Scoop, WinGet, Arch, Alpine, FreeBSD, NetBSD, OpenBSD.
- **56 releases** over ~3 years, including a major v1→v2 migration with a dedicated docs site.
- **Secondary press coverage** at launch: InfoQ, Dark Reading, Help Net Security — a useful indicator that the tool has *mindshare* even where it has no named customers.
- **[Observed]** 98 open issues (86 issues + 12 PRs) and a live `Discussions` tab — an active community surface.

**[Inferred]** The audience is **individual OSS maintainers and security engineers**, reached via CI pipelines and the Scorecard badge. There is no observed enterprise-org buying centre, which is the segment actionscan addresses.

---

## SEO & Content Strategy

**[Observed]** Site: `google.github.io/osv-scanner` — GitHub Pages, Jekyll + **just-the-docs** theme, just-the-docs search (Lunr). Analytics: **Google gtag `G-60SWD6J0TM`** on the docs site.

**[Observed]** Title tag: *"OSV-Scanner | Use OSV-Scanner to find existing vulnerabilities affecting your project's dependencies."* Meta description is the same string. Both are keyword-stuffed product-name-first — classic OSS-project SEO hygiene rather than a content strategy.

**[Observed]** Content inventory (~15 pages, all task-oriented, none promotional):
Home · Supported Artifacts and Manifests · Installation · Usage (+ Container Image Scanning, Project Source Scanning, License Scanning, Offline Mode) · Configuration · Output · GitHub Action · Experimental (Guided Remediation, OSV-Reporter, Flag Deprecated Packages, Manual OSV-Scalibr Plugin Selection) · Contribute · Migrating from osv-scalibr · Migration Guide (v1→v2) · plus external links to osv.dev, OSV API docs, OSV Schema.

**[Observed]** Content gaps relevant to us:
- **No page about GitHub Actions / CI workflow scanning.** Confirmed by the nav listing above and by the supported-artifacts table. The docs never say "we don't scan workflows" either — it is simply absent.
- No comparison pages, no "osv-scanner vs X" pages, no competitor-alternative guides, no use-case landing pages, no blog on the docs site, no pricing page, no FAQ (the FAQ lives on osv.dev, not here).
- The two "migration" pages are internal-migration guides (v1→v2, scalibr→scanner), not competitive-displacement content.

**[Observed]** Their organic surface is not the docs site — it is: the **GitHub repo** (11.2k stars, badge-driven), **osv.dev** (a separate, much larger site), the **Google Online Security Blog** launch post, and press coverage.

**[Observed]** Not available in this environment: domain authority, backlinks, referring domains, organic traffic, organic keywords for `google.github.io` or `osv.dev`. Not estimated.

**[Implication]** Their content moat is *documentation completeness of the supported-artifact table* — that table is the de-facto contract for "what can this tool scan?", and it is where a would-be Actions user lands. Our content should answer the question their table cannot, and should not pretend to have their SEO footprint.

---

## Strengths & Weaknesses

### Strengths

**[Observed]** Brand and institutional trust (Google, OpenSSF Scorecard integration, SLSA 3 provenance, Apache-2.0).
**[Observed]** Unmatched adoption surface for an OSS scanner: 11.2k stars, 24.8k annual Homebrew installs, eight OS package managers, a Docker image, a Go library, pre-commit hooks, and a first-party reusable GitHub Action.
**[Observed]** Output breadth exceeds ours: SARIF 2.1.0, SPDX 2.3, CycloneDX 1.4–1.7, HTML, Markdown, vertical, `gh-annotations`, JSON, table. **We have no SPDX or CycloneDX.**
**[Observed]** False-positive reduction machinery: call analysis, VEX-adjacent filtering, "Fixed Version" column.
**[Observed]** Remediation, not just detection: guided remediation (`fix`) with in-place / relock / override strategies and an interactive mode.
**[Observed]** Air-gap story: `--offline` + `--download-offline-databases` + documented GCS mirror.
**[Observed]** Adjacent features we don't have: license scanning, deprecation flagging, Maven transitive resolution via deps.dev, C/C++ commit-level scanning, SBOM ingest.

### Weaknesses / scope boundaries

**[Observed]** **Cannot report a vulnerable GitHub Action reference by any documented route**, and crashes in offline mode if the experimental extractor is force-enabled (v2.7.0).
**[Observed]** **No organisation- or repository-enumeration mode.** Every invocation targets one directory, one lockfile, one image, or one SBOM. There is no "scan all repos in this org" concept anywhere in the docs or CLI.
**[Observed]** **No cross-repo rollup.** Output is per-target; there is no dashboard aggregating many projects, and no CSV export.
**[Observed]** **Version matching for the "GitHub Actions" OSV ecosystem is broken at the API level**, producing false negatives for any consumer that queries by version — including osv-scanner itself.
**[Observed]** **Documentation does not disclose the Actions gap.** The supported-artifacts table simply omits workflows; there is no "CI workflows are not scanned" note, so a user looking for Actions coverage will not find an answer either way.
**[Observed]** **Experimental-flag sprawl** (`--x-plugins`, `--x-no-default-plugins`, `--x-disable-plugins`, `--x-flag-deprecated-packages`) and a separate `osv-reporter` binary installed from source only.
**[Observed]** **v1/v2 split-repo confusion** — two repos, two doc sites, and a README still referring to "the latest OSV-Scanner V2 beta".
**[Observed]** The `github/actions` extractor shipped in Scalibr in May 2026 but is still off by default in osv-scanner five months later — a slow integration path from library to CLI.

**[Inferred]** The structural reason for the whole gap: osv-scanner's model is *package manifest → package → advisory*. A GitHub Action reference is a *CI configuration token*, resolved by a different mechanism (tag → commit → release), with a different versioning discipline (tags, branches, SHAs, sub-paths) and a different blast radius (it executes in CI with repository secrets). Supporting it well is a different product, not a feature flag.

---

## Competitive Implications for actionscan

### Where they're strong vs. us

**[Observed]** Installed base, brand, and CI mindshare. Anyone who has already put osv-scanner in their pipeline will not switch for Actions coverage alone — they would **add** a tool.
**[Observed]** Output-format parity-plus: SPDX and CycloneDX, which we lack. If a buyer has an SBOM-compliance requirement, osv-scanner is the incumbent answer.
**[Observed]** Remediation and reduced-noise features (`fix`, call analysis) that we do not offer and that are the natural next questions from a sophisticated buyer.
**[Observed]** Google/OpenSSF credibility, which moves procurement checklists.
**[Imferred]** Because OSV.dev already ingests GitHub Security Advisories, the "we read GHSA too" claim is not a differentiator against them — the differentiator is *what we point it at*.

### Where we're strong vs. them

**[Observed]** **Action-reference auditing.** osv-scanner v2.7.0 has no documented, working path to report a vulnerable GitHub Action — verified by execution, not inference. We can cite their own issue #2821 (auto-closed as stale) and #2831 (panic + documented online false-negative).
**[Observed]** **Org-wide enumeration.** We scan every repo for a user/org and extract every `uses:` reference; they scan one target per invocation.
**[Observed]** **Cross-repo rollup.** Their outputs are per-target; there is no dashboard and no CSV. We emit an HTML dashboard + CSV + JSON + SARIF.
**[Observed]** **Feeds beyond OSV.** Compromised-action-specific feeds and release-freshness/outdated-release checks are outside their data sources (OSV + deps.dev + registries); pinning-hygiene (SHA-pinned vs. tag) is outside their model entirely.
**[Observed]** **CSV** is a genuine small gap in their format list.
**[Hypothesis — needs our own verification]** That an org-level owner wants a single answer ("which of my repos use a vulnerable action?") rather than per-project CI gates. This is a positioning claim about our buyers that we have not independently validated in this profile.

**[Observed parity — do not claim as differentiation]** They already have an **interactive HTML report** (`--serve`, severity breakdown, filters, full advisory entries) and **SARIF** output. Our HTML dashboard and SARIF are *parity*, not wins. Our differentiators must be the *data* (org-wide action references, extra feeds) and the *unit of analysis* (the organisation, not the repository), not the file format.

### Opportunities

1. **[Implication]** Publish the empirical proof as content — a reproducible 30-line fixture showing osv-scanner v2.7.0 returning `results: []` on a workflow referencing a CVSS-critical Action, with the upstream issue links. This is defensible, verifiable content in a space where their docs are silent.
2. **[Implication]** Emit an **osv-scanner-compatible `osv-scanner.json`** so users can hand our findings to osv-scanner (or to their CI) and keep one pipeline. Their custom-lockfile format is documented and stable enough to target.
3. **[Implication]** Ship a **"what osv-scanner can't tell you"** comparison page — factual, scope-boundary framed, no criticism of quality. Their own #2821 is the citation.
4. **[Implication]** Add a **no-network mode + explicit payload disclosure** in our README, mirroring their "Data Sources and Privacy" model. It is a cheap credibility transfer and we have the same class of payload (repo metadata, workflow contents, package names/versions).
5. **[Implication]** Since their offline mode *panics* on GitHub Actions SBOMs, an **air-gapped Actions auditor** is a defensible niche they cannot serve.

### Threats

1. **[Observed → real threat]** The `github/actions` extractor is already merged in `osv-scalibr` (#2032, 2026-05-06) and documented in Scalibr's inventory-types doc. **[Inferred]** If osv-scanner graduates it to a default plugin, the headline "no Actions support" claim narrows to "no *working* Actions support" — still true today because the OSV API version matching returns empty, but a much weaker headline.
2. **[Observed → real threat]** The OSV API's GitHub Actions version matching is a service-side bug. If it is fixed, osv-scanner + the existing extractor would immediately start reporting Action vulnerabilities for anyone who opts into `--x-plugins github/actions`. Our lead could shrink substantially.
3. **[Inferred]** Google could add an org-wide / multi-repo mode to close the enumeration gap — the "scan source" model is easy to extend, and Google has the GitHub API access and the CI Action distribution to do it.
4. **[Observed]** The v1→v2 precedent shows they will make breaking changes freely and will fork a v1 repo for compatibility. A future v3 could reorganise the CLI surface, potentially making an Actions mode easier to introduce.
5. **[Inferred]** If a large org standardises on osv-scanner for SBOM/SPDX/CycloneDX compliance, "we already have Google tooling" becomes the default answer and our tool is a niche add-on. The mitigation is to be the tool that answers a question the incumbent *cannot answer at all*, not a better version of the same question.

---

## Raw Data Sources

All raw artefacts saved under `competitor-profiles/raw/osv-scanner/2026-10-22/`.

### `scrapes/` (markdown + original HTML)

| File | Source URL | Notes |
|---|---|---|
| `homepage.md` / `.html` | https://google.github.io/osv-scanner/ | Positioning, two consumption modes, OSV.dev benefits |
| `supported-languages-and-lockfiles.md` / `.html` | https://google.github.io/osv-scanner/supported-languages-and-lockfiles/ | **Primary gap evidence.** Supported artifacts + lockfiles tables; Custom Lockfiles section; Known limitations |
| `usage.md` / `.html` | https://google.github.io/osv-scanner/usage/ | Subcommands, flags, `--serve`, offline-vulnerabilities, `--all-packages`, pre-commit, Docker |
| `output.md` / `.html` | https://google.github.io/osv-scanner/output/ | All output formats with samples; call analysis; **return codes** |
| `installation.md` / `.html` | https://google.github.io/osv-scanner/installation/ | 8 package managers, `go install`, SLSA verification, SemVer/`x` prefix policy |
| `scan-image.md` / `.html` | https://google.github.io/osv-scanner/usage/scan-image | Container scanning |
| `scan-source.md` / `.html` | https://google.github.io/osv-scanner/usage/scan-source | Source scanning |
| `license-scanning.md` / `.html` | https://google.github.io/osv-scanner/usage/license-scanning/ | License allowlist scanning |
| `offline-mode.md` / `.html` | https://google.github.io/osv-scanner/usage/offline-mode/ | Air-gapped mode, `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY`, `gs://osv-vulnerabilities`, limitations |
| `configuration.md` / `.html` | https://google.github.io/osv-scanner/configuration/ | TOML config, package ignore rules |
| `github-action.md` / `.html` | https://google.github.io/osv-scanner/github-action/ | Reusable PR / scheduled / release workflows, SARIF upload |
| `guided-remediation.md` / `.html` | https://google.github.io/osv-scanner/experimental/guided-remediation/ | `fix` strategies (in-place / relock / override) |
| `osv-reporter.md` / `.html` | https://google.github.io/osv-scanner/experimental/osv-reporter/ | Diffing scans, multi-format emission |
| `flag-deprecated.md` / `.html` | https://google.github.io/osv-scanner/experimental/flag-deprecated-packages/ | Deprecation flagging via deps.dev |
| `contribute.md` / `.html` | https://google.github.io/osv-scanner/contribute/ | Contribution flow |
| `migration-guide.md` / `.html` | https://google.github.io/osv-scanner/migration-guide.html | v1→v2 CLI and JSON changes |
| `migrating-from-scalibr.md` / `.html` | https://google.github.io/osv-scanner/migrating-from-scalibr.html | **States that only a subset of Scalibr plugins is enabled by default**; `--x-plugins` escape hatch |
| `osv-dev-list-github-actions.md` / `.html` | https://osv.dev/list?ecosystem=GitHub+Actions | **GitHub Actions = 55 advisories**; all-ecosystem totals; first-page advisory list |
| `google-blog-announcement.md` / `.html` | https://security.googleblog.com/2022/12/announcing-osv-scanner-vulnerability.html | 2022-12-13 launch post (Rex Pan, Google Open Source Security Team); roadmap; Scorecard integration |

### `seo/` (verified API responses + notes)

| File | What it is |
|---|---|
| `osv-api-verification-notes.md` | **The verification record.** Every OSV API call made, with results, plus the 13-value version-format sweep, the npm control, the `querybatch` results, the HTTP 400 invalid-ecosystem case, and the ecosystem counts. |
| `osv-vuln-GHSA-mrrh-fwg8-r2c3.json` | `GET /v1/vulns/GHSA-mrrh-fwg8-r2c3` — confirms `affected[].package = {"name":"tj-actions/changed-files","ecosystem":"GitHub Actions"}` and range `introduced 0 / fixed 46.0.1` |
| `osv-query-tj-actions-no-version.json` | `POST /v1/query` with package only → 2 advisories (`GHSA-mcph-m25j-8j63`, `GHSA-mrrh-fwg8-r2c3`) |
| `osv-query-tj-actions-version-45.0.7.json` | `POST /v1/query` with `"version":"45.0.7"` → `{}` |
| `osv-scanner-scan-workflow-repo.json` | Full `osv-scanner scan source -r . --format json` output on the fixture repo — contains only the PyPI control finding, no Actions finding |
| `osv-scanner-custom-lockfile-github-actions.json` | `osv-scanner scan source -L osv-scanner:./osv-scanner.json` output for the hand-written GitHub Actions entry → `"results": []` |
| `osv-scanner-github-actions-empirical-test.md` | **Full write-up of the four-part experiment** (default scan / `--x-plugins` / custom lockfile / offline panic), with fixture and commands |
| `osv-scanner-offline-github-actions-panic.txt` | Verbatim panic trace: `panic: unsupported ecosystem GitHub Actions` → SIGSEGV, exit 2, in `osv-scalibr@v0.5.4-.../enricher/vulnmatch/osvlocal/internal/vulns/vulnerability.go` |
| `github-api-repo-stats.json` | GitHub REST API snapshot (stars, forks, issues, watchers, dates, topics, releases count, osv-scanner-action, osv-scalibr, Homebrew analytics) |
| `releases.json` | Full release list (56 entries, v1.0.0 2022-12-13 → v2.7.0 2026-10-12) with publish timestamps — cadence evidence |

### Upstream artifacts cited (fetched via GitHub API / raw.githubusercontent.com)

| Artifact | Relevance |
|---|---|
| `google/osv-scanner#2821` "Feature Request: Scan GitHub Actions Workflows" (2026-05-19 → 2026-08-17, labels `stale`, `autoclosed`) | The feature was requested upstream and auto-closed. Body proposes exactly the actionscan approach. |
| `google/osv-scanner#2831` "Offline scan panics with 'unsupported ecosystem GitHub Actions'…" (2026-05-21 → 2026-05-28) | Documents the online-mode false negative in their own words. |
| `google/osv-scalibr#2032` "Add extractor for GitHub Actions workflow dependencies" (merged 2026-05-06) | The extractor exists in the library; not enabled by default in the CLI. |
| `ossf/osv-schema` `bindings/go/osvconstants/constants.go` | `EcosystemGitHubActions Ecosystem = "GitHub Actions"` — the ecosystem is schema-valid, so osv-scanner does not reject it; it is queried and returns empty. |
| `google/osv-scalibr` `docs/supported_inventory_types.md` | Lists plugin `github/actions` under "Misc". |

### Environment notes

- No Firecrawl / no SEO MCP available; all scraping via `webfetch` / `curl` + a local HTML→markdown converter.
- GitHub data via the GitHub REST API using `gh auth token`.
- **SEO metrics (domain authority, backlinks, organic traffic, referring domains, organic keywords) are not available in this environment and are not estimated anywhere in this profile.**
- The osv-scanner v2.7.0 binary was downloaded from the official GitHub release and executed locally against a purpose-built fixture repo. All four experiments are reproducible from `osv-scanner-github-actions-empirical-test.md`.
