# 🔍 actionscan

**actionscan** scans all GitHub repositories for a user or organization, extracts every
GitHub Action referenced in CI workflows, and audits them against **live threat intel feeds**:

- 🚨 **Malicious actions** — StepSecurity compromised-actions feed
- 🐛 **Vulnerable actions** — GitHub Security Advisories (`ecosystem=actions`)
- 🌐 **OSV.dev** — exact-version vulnerability queries as an extra layer
- 📦 **Outdated actions** — latest-release tag lookups per action repo
- 📌 **Pinning hygiene** — missing refs and short SHAs

Reports are generated as **HTML** (with 4 themes), **CSV**, and **JSON**.

---

## Features

| | |
|---|---|
| 🔴 CRITICAL | Known compromised actions (StepSecurity feed, ref-aware) |
| 🟠 HIGH | Versions matching GHSA advisory ranges |
| 🟠 HIGH | OSV.dev hits for exact action versions |
| 🟡 MEDIUM | Unpinned or short-SHA action refs |
| 🟢 LOW | Major version behind latest release |

- ✅ **Live data** — no hardcoded lists; feeds fetched at scan time
- ✅ **Disk cache with TTL** (`~/.actionscan/rules-cache.json`, default 12h)
- ✅ **Graceful offline fallback** — built-in default rules when feeds unreachable
- ✅ **No cloning** — reads workflow files via the GitHub API (git tree + contents)
- ✅ **Concurrent scanning** with configurable worker count
- ✅ **Themed HTML report** — Dark / Aurora / Light / Sand with localStorage persistence

---

## How it works

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────┐
│ GitHub API  │────▶│  Extract actions │────▶│  Check against  │
│ (repo list, │     │  from workflows  │     │  live ruleset   │
│ workflows)  │     │  (uses: lines)   │     │  (4 layers)     │
└─────────────┘     └──────────────────┘     └────────┬────────┘
                                                      │
                                              ┌───────▼────────┐
                                              │ HTML / CSV /   │
                                              │ JSON reports   │
                                              └────────────────┘
```

**Check priority** (short-circuits on malicious match):

1. **Malicious** (StepSecurity) → CRITICAL, stops further checks
2. **Vulnerable** (GHSA ranges) → HIGH
3. **OSV.dev** (exact version, cached per `repo@version`) → HIGH
4. **Outdated** (latest major behind) → LOW
5. **Unpinned / short SHA** → MEDIUM

---

## Installation

```bash
git clone https://github.com/krishnaduttPanchagnula/actionscan.git
cd actionscan
go mod tidy
go build -o actionscan .
```

Requires **Go 1.22+**.

---

## Configuration

Create a `config.yaml` (optional — flags and env vars override it):

```yaml
server:
  port: "8080"
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
  use_osv: true
```

**Precedence:** flags > env vars (`ACTIONSCAN_*`) > `config.yaml` > defaults

A GitHub token is **required**. Provide it via:

```bash
export ACTIONSCAN_TOKEN=ghp_xxx    # or GITHUB_TOKEN
# or: ./actionscan scan --token ghp_xxx
```

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

# Skip network layers (faster, uses cached/builtin rules)
./actionscan scan --org my-org --no-osv --no-latest
```

Output:

```
Loading vulnerability rules (StepSecurity + GHSA + OSV)…
Rules loaded from: [stepsecurity ghsa] (cached 2025-01-15T10:30:00Z)
Found 42 repos. Scanning with 8 workers…

Done. 17 findings across 42 repos:
  CRITICAL: 1  HIGH: 4  MEDIUM: 8  LOW: 4
Reports:
  HTML: reports/report.html
  CSV:  reports/report.csv
  JSON: reports/report.json
```

### Serve the report

```bash
./actionscan serve --port 8080
# → http://localhost:8080
```

- Themed HTML report with theme switcher (Dark / Aurora / Light / Sand)
- CSV + JSON download buttons
- JSON API: `GET /api/status`, `GET /api/findings`

### All flags

| Flag | Default | Description |
|---|---|---|
| `--config` | `./config.yaml` | config file path |
| `--token` | env | GitHub token |
| `--org` / `--user` | — | target org or user |
| `--concurrency` | `8` | parallel repo workers |
| `--out` | `./reports` | report output dir |
| `--cache-ttl` | `12` | rules cache TTL (hours) |
| `--no-latest` | `false` | skip latest-tag lookups |
| `--no-osv` | `false` | skip OSV.dev queries |

---

## Project structure

```
actionscan/
├── main.go                  # entrypoint
├── config.yaml              # default config
├── cmd/
│   ├── root.go              # cobra root + viper config init
│   ├── scan.go              # scan command
│   └── serve.go             # Gin web server for reports
├── internal/
│   ├── config/config.go     # typed config
│   ├── github/client.go     # repo listing, workflow fetch, latest tags
│   ├── rules/
│   │   ├── feeds.go         # StepSecurity + GHSA fetchers + fallbacks
│   │   ├── osv.go           # OSV.dev query client
│   │   └── ruleset.go       # merged RuleSet, disk cache, semver matching
│   ├── scanner/scanner.go   # workflow parsing + 4-layer checks
│   └── report/report.go     # HTML/CSV/JSON generation
└── web/template.html        # themed HTML report template
```

---

## Data sources & caching

| Source | Endpoint | Cached | TTL |
|---|---|---|---|
| StepSecurity compromised actions | `step-security/secure-repo` (raw GitHub) | disk | 12h (config) |
| GitHub Security Advisories | `api.github.com/advisories` | disk | 12h (config) |
| OSV.dev | `api.osv.dev/v1/query` | memory (per run) | — |
| Latest tags | GitHub Releases API | memory (per run) | — |

Rate limits: use a token for GHSA (60→5000 req/hr). OSV is unauthenticated and generous.

---

## Example finding (JSON)

```json
{
  "repo": "my-org/my-service",
  "workflow": "ci.yml",
  "action": "tj-actions/changed-files@v41",
  "ref": "v41",
  "severity": "CRITICAL",
  "category": "malicious",
  "reason": "Compromised Mar 2025 (CVE-2025-30066) — dumped runner memory to attacker C2"
}
```

---

## Limitations

- Semver matching only applies to version-pinned refs (`v4.1.1`); branch/SHA refs can't be range-checked
- OSV's `GitHubActions` ecosystem coverage is still growing — it's a best-effort extra layer
- The StepSecurity feed URL/schema may drift; a built-in fallback list kicks in if unreachable
- Only non-fork repos are scanned

---

## License

MIT
