# 🔍 actionscan

**actionscan** scans all GitHub repositories for a user or organization, extracts every
GitHub Action referenced in CI workflows, and audits them against **live threat intel feeds**:

- 🚨 **Compromised actions** — supply-chain compromises from GitHub Security Advisories
  (CWE-506: embedded malicious code) plus a community compromised-action feed
- 🐛 **Vulnerable actions** — GitHub Security Advisories (`ecosystem=actions`) with the
  advisory's own severity and patched version
- 🌐 **OSV.dev** — package queries matched against the affected ranges
- 📦 **Outdated actions** — latest-release tag lookups per action repo
- 📌 **Pinning hygiene** — missing refs and short SHAs

Reports are generated as **HTML** (a triage dashboard), **CSV**, **JSON**, and **SARIF**.

---

## Features

| | |
|---|---|
| 🔴 CRITICAL | Known compromised actions (supply-chain compromise) |
| 🟠 HIGH+ | Versions matching GHSA advisory ranges (the advisory's own severity is used) |
| 🟠 HIGH+ | OSV.dev hits for the exact action version |
| 🟡 MEDIUM | Unpinned or short-SHA action refs |
| 🟢 LOW | Major version behind latest release |

- ✅ **Live data** — feeds fetched at scan time; a small built-in list is used only
  when the advisory feed is unreachable, and the report says so
- ✅ **Disk cache with TTL** (`~/.actionscan/rules-cache.json`, default 12h); a degraded
  load is **never** cached, so one outage cannot silently blind the scanner for 12h
- ✅ **No cloning** — reads workflow files via the GitHub API (git tree + contents)
- ✅ **Concurrent scanning** with configurable worker count
- ✅ **Rate-limit aware** — waits out GitHub's limits instead of dropping repos
- ✅ **CI gating** — `--fail-on critical|high|medium|low` exits non-zero
- ✅ **SARIF output** — upload findings to GitHub code scanning
- ✅ **Honest reports** — the dashboard states what was scanned, which feeds answered,
  which repos could not be read, and when the rules were fetched
- ✅ **Triage dashboard** — verdict banner, blast radius, filters, shareable URLs
- ✅ **Real workflow parsing** — YAML-aware, so local actions, `docker://` refs,
  `$/` self-references and `uses:` inside shell scripts are not reported as findings
- ✅ **Transitive graph layer** — resolves composite actions and reusable workflows
  (`--transitive`); reports actions that run in your CI but are outside the
  top-level scan
- ✅ **Provenance checks** — verifies pinned SHAs are still published by the
  upstream repo (`--provenance`; imposter commits that were force-pushed away
  are flagged)
- ✅ **Policy file** (`actionscan.yml`) — suppression rules, severity remaps,
  personas (`regular`/`pedantic`/`auditor`), and inline `# actionscan: ignore`
- ✅ **Baseline + delta** — scan now, scan later, see what's *new* vs *resolved*
  (`--baseline`), with regressed findings flagged as NEW in the HTML
- ✅ **`--repo` and `--no-ignores`** — single-repo scans and CI-respecting
  inline ignores
- ✅ **GitHub Actions annotations** — findings are emitted as `::warning::`/
  `::error::` with a Markdown step summary when run under `GITHUB_ACTIONS=true`
- ✅ **Threat-intel feed** — `actionscan feed` builds a supply-chain feed
  (JSON/Atom) of compromised actions from GHSA, ready to publish on GitHub Pages

actionscan is a **static supply-chain scanner**: it audits the actions your
workflows *reference*. It is **not** a linter for workflow YAML, a runtime
defence, a dependency/package scanner, or a secret scanner — those have their
own tools and are out of scope.

---

## How it works

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────┐
│ GitHub API  │────▶│  Extract actions │────▶│  Check against  │
│ (repo list, │     │  from workflows  │     │  live ruleset   │
│ workflows)  │     │  (YAML `uses:`)  │     │  (5 layers)     │
└─────────────┘     └──────────────────┘     └────────┬────────┘
                                                      │
                                              ┌───────▼────────┐
                                              │ HTML / CSV /   │
                                              │ JSON / SARIF   │
                                              └────────────────┘
```

**Check priority** (short-circuits on a compromised action):

1. **Compromised** (supply-chain compromise) → CRITICAL, stops further checks
2. **Vulnerable** (GHSA ranges) → the advisory's own severity
3. **OSV.dev** (package query, ranges matched locally) → the advisory's severity;
   an advisory already reported by GHSA is not reported twice
4. **Outdated** (latest major behind) → LOW
5. **Unpinned / short SHA** → MEDIUM

---

## Installation

```bash
git clone https://github.com/krishnaduttPanchagnula/actionscan.git
cd actionscan
go build -o actionscan .
```

Requires **Go 1.22+**. The dashboard template is embedded in the binary, so the
released artifact works from any directory.

---

## Configuration

Create a `config.yaml` (optional — flags and env vars override it):

```yaml
server:
  port: "8080"
  host: "127.0.0.1"
  mode: release

github:
  token: ""          # or use env/flag
  org: ""
  user: ""

scan:
  concurrency: 8
  report_dir: ./reports

rules:
  cache_ttl_hours: 12
  cache_dir: ""              # empty = ~/.actionscan
  fetch_latest_tags: true
  use_osv: true              # OSV.dev per-action queries
  malicious_feed_url: ""     # extra compromised-action feed; empty = default
```

**Precedence:** flags > env vars (`ACTIONSCAN_*`) > `config.yaml` > defaults

---

## Usage

### Scan

```bash
# Scan repos of the authenticated user
./actionscan scan

# Scan an org
./actionscan scan --org my-org

# Scan a user
./actionscan scan --user someuser

# Tune it
./actionscan scan --org my-org --concurrency 16 --out ./reports

# Skip network layers (faster)
./actionscan scan --org my-org --no-osv --no-latest

# Gate a CI pipeline on critical findings
./actionscan scan --org my-org --fail-on critical
```

Output:

```
Loading vulnerability rules (GHSA + OSV + compromised-action feeds)…
Rules loaded from: [ghsa compromised-feed] (cached 2026-10-22T10:30:00Z)
Found 42 repos. Scanning with 8 workers…

Done. 17 findings in 12 of 42 repos (2410 action usages evaluated):
  CRITICAL: 1  HIGH: 4  MEDIUM: 8  LOW: 4
Reports:
  HTML:  reports/report.html
  CSV:   reports/report.csv
  JSON:  reports/report.json
  SARIF: reports/report.sarif
```

Progress goes to **stderr**, so `actionscan scan > out.txt` only captures stdout.

### Serve the report

```bash
./actionscan serve --port 8080
# → http://127.0.0.1:8080
```

The dashboard provides:

- a **verdict banner** (how bad is it, right now)
- a **blast radius** panel: which action, in how many repos — the #1 triage question
- **filters** by severity, category, and repository, plus free-text search
- **sortable columns** and **shareable URLs** (filter state is in the URL)
- a **Recommended fix** column with copy-to-clipboard for paste-ready fixes only
- **dark mode**, **print styles**, and a responsive layout
- explicit **warnings** when a threat feed was degraded or a repo could not be read

Download endpoints: `/report.csv`, `/report.json`, `/report.sarif`.
JSON API: `GET /api/status`, `GET /api/findings`.

### All flags

| Flag | Default | Description |
|---|---|---|
| `--config` | `./config.yaml` | config file path |
| `--token` | env | GitHub token |
| `--org` / `--user` | — | target org or user |
| `--concurrency` | `8` | parallel repo workers |
| `--out` | `./reports` | report output dir |
| `--cache-ttl` | `12` | rules cache TTL (hours; `0` disables the cache) |
| `--no-latest` | `false` | skip latest-tag lookups |
| `--no-osv` | `false` | skip OSV.dev queries |
| `--fail-on` | `none` | exit non-zero at this severity: `none\|critical\|high\|medium\|low` |
| `--repo` | — | scan a single repository (`owner/name`) |
| `--policy` | `./actionscan.yml` | path to the policy file (directory is fine) |
| `--persona` | — | sensitivity profile: `regular` / `pedantic` / `auditor` |
| `--no-ignores` | `false` | ignore inline `# actionscan: ignore` comments |
| `--baseline` | — | compare against a previous `report.json`; report only what is new |
| `--transitive` | `false` | also resolve the transitive dependency graph |
| `--provenance` | `false` | also verify that pinned SHAs are still published upstream |
| `--port` / `--host` | `8080` / `127.0.0.1` | serve bind address |

**Exit codes**

| Code | Meaning |
|---|---|
| `0` | scan completed, no findings at or above the `--fail-on` threshold |
| `1` | findings at or above the threshold |
| `2` | the scan could not be completed reliably (a threat feed was unreachable, `--fail-on` is not a valid value, or an incomplete transitive graph) — a degraded/incomplete scan never passes a gate |

---

## Project structure

```
actionscan/
├── main.go                  # entrypoint
├── config.yaml              # default config
├── cmd/
│   ├── root.go              # cobra root + viper config init
│   ├── scan.go              # scan command + CI exit codes
│   ├── serve.go             # Gin web server for reports
│   └── version.go           # build-time version stamping
├── internal/
│   ├── config/config.go     # typed config
│   ├── github/client.go     # repo listing, workflow fetch, latest tags
│   ├── rules/
│   │   ├── feeds.go         # GHSA + compromised-action fetchers + fallbacks
│   │   ├── osv.go           # OSV.dev client + range matching
│   │   └── ruleset.go       # merged RuleSet, disk cache, semver matching
│   ├── scanner/scanner.go   # YAML workflow parsing + 5-layer checks
│   └── report/report.go     # HTML/CSV/JSON/SARIF generation
└── web/
    ├── embed.go             # embeds the dashboard in the binary
    └── template.html        # triage dashboard
```

---

## Data sources & caching

| Source | Endpoint | Cached | TTL |
|---|---|---|---|
| GitHub Security Advisories | `api.github.com/advisories?type=reviewed&ecosystem=actions` | disk | 12h (config) |
| Compromised-action feed | `raw.githubusercontent.com/TreRB/gh-actions-pwn-hunter/.../compromised-actions.json` | disk | 12h (config) |
| OSV.dev | `api.osv.dev/v1/query` | memory (per run) | — |
| Latest tags | GitHub Releases API | memory (per run) | — |

A feed that fails is reported as **degraded** in the CLI output and in the
dashboard banner, and the fallback rule set is **not** cached. The compromised-action
feed URL is configurable (`rules.malicious_feed_url`); any feed in the same shape
works.

The "outdated" layer only works for actions that publish GitHub **Releases** — an
action without a release is simply not checked.

Rate limits: use a token for GHSA (60→5000 req/hr). OSV is unauthenticated and generous.
Rate-limited calls are retried automatically.

---

## Example finding (JSON)

```json
{
  "repo": "my-org/my-service",
  "workflow": ".github/workflows/ci.yml",
  "job": "build",
  "action": "tj-actions/changed-files@v41",
  "ref": "v41",
  "severity": "CRITICAL",
  "category": "malicious",
  "reason": "GHSA-mrrh-fwg8-r2c3: tj-actions changed-files through 45.0.7 allows remote attackers to discover secrets (supply-chain compromise)",
  "fix": "Upgrade tj-actions/changed-files to v46.0.1; rotate any secrets/tokens it could have accessed and audit recent workflow runs; see GHSA-mrrh-fwg8-r2c3",
  "advisory_id": "GHSA-mrrh-fwg8-r2c3",
  "advisory_url": "https://github.com/advisories/GHSA-mrrh-fwg8-r2c3"
}
```

## Policy: ignore and prioritise (`actionscan.yml`)

Create an `actionscan.yml` (or point at one with `--policy`) to suppress noise and
prioritise what actually matters:

```yaml
persona: regular                 # regular | pedantic | auditor
severity_remap:                  # override the severity of a category/advisory
  outdated: low
ignore_actions:                  # glob-style against "owner/repo" (no ref)
  - actions/checkout
  - my-org/legacy-*             # suite of actions you own and can verify
deny_ignore:                     # these must NEVER be suppressed, even by personas
  - tj-actions/changed-files
respect_inline_ignores: true      # honour `# actionscan: ignore` comments
```

- **Personas**: `regular` (default) reports the five layers. `pedantic` adds
  mutable-tag findings ("this pin is a branch or a floating tag"). `auditor`
  adds *every* check at its highest sensitivity — for compliance runs.
- **Inline ignores**: end a workflow line with `# actionscan: ignore` (or
  `# actionscan: ignore[category]`) to drop a finding on that line, without
  silencing the whole repo. `--no-ignores` disables inline ignores.
- The policy file is reported in `PolicyFile` of the JSON summary so scans are
  reproducible.

## Baseline and delta (regressions vs. new vs. resolved)

```bash
# First scan — save the report as your baseline
./actionscan scan --org my-org --out ./base

# Later scan — only what changed since the baseline
./actionscan scan --org my-org --out ./now --baseline ./base/report.json
# → "Baseline ./base/report.json: 3 new, 2 resolved"
```

- `--baseline` compares fingerprints and prints `new`, `resolved`, and the
  baseline timestamp. `baseline-diff.json` is written next to the reports.
- Findings that were **not** in the baseline are tagged `NEW` as a badge in
  the HTML dashboard, so regressions stand out.
- Fingerprints are deterministic (sorted, no timestamps), so the same inputs
  always produce the same diff.

## Transitive layer (`--transitive`)

By default actionscan reads top-level `uses:`. With `--transitive` it also
resolves composite actions and reusable workflows to depth 12, and applies the
same five checks to every action they pull in — including ones never mentioned in
your repositories.

```bash
./actionscan scan --org my-org --transitive
# Transitive graph: 28 nodes, depth 2, complete-with-findings
```

- An **incomplete** graph (a file that cannot be parsed, a fetch error, or a
  budget being exceeded) exits with code **2** — a gate never passes on a scan
  that did not examine all the code. Only the gate is affected; the report
  still contains what was found.
- Budgets: depth 12, 5 000 YAML structures per document, 8 MiB of metadata,
  500 HTTP requests.

## Provenance checks (`--provenance`)

Pinning to a SHA is only safe while the upstream project still carries that
commit. With `--provenance` each pinned action is checked against *every*
published branch and tag; a commit reachable from no branch or tag is an
**imposter commit** (force-pushed away, or pushed by someone with write
access) and is reported.

```bash
./actionscan scan --org my-org --provenance
```

## Supply-chain feed (`actionscan feed`)

`actionscan feed` writes two files from the live feeds: `feed.json` (the
OSV-style schema, one entry per compromised action, each with a "became
compromised / patched" window) and `feed.atom`. They are meant to be published
on GitHub Pages so other tools — or your own CI — can subscribe.

```bash
./actionscan feed --out ./feed
```

---

## Limitations

- Semver matching only applies to version-pinned refs (`v4.1.1`); branch/SHA refs can't be range-checked
- Floating tags (`v4`) are evaluated at their nominal major version, not the resolved commit — this is the largest source of both false positives and false negatives
- Transitive dependencies **opt-in** via `--transitive` (composite actions,
  reusable workflows). Default off because it is more API-heavy and an incomplete
  graph now fails the gate (exit 2) rather than silently passing
- `docker://` actions and `container:` images are out of scope
- Only non-fork repos are scanned
- A repo whose git tree is too large for the API to return, or whose workflow
  files cannot be read, is reported as unreadable — never as clean
- The provenance check needs read access to the upstream action repo's branches
  and tags; private or deleted action repos come back as "could not check"

---

## License

MIT
