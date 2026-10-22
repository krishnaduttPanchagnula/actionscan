# zizmor — releases summary (GitHub API)

- Source: https://api.github.com/repos/zizmorcore/zizmor/releases?per_page=100
- Fetched: 2026-10-22
- Raw JSON: ../seo/github-releases.json

## Counts

- Total releases returned by API (per_page=100): **94**
- First release: `v0.1.0` — 2024-10-27
- Latest release: `v1.31.1` — 2026-10-15
- Second latest: `v1.31.0` — 2026-10-15 (same day as the patch release)
- Repo created: 2024-08-19 (GitHub API) → first release ~2 months later
- Last push to default branch: 2026-10-22

## Release list (newest first)

| Tag | Published | Prerelease |
|---|---|---|
| v1.31.1 | 2026-10-15 | no |
| v1.31.0 | 2026-10-15 | no |
| v1.30.1 | 2026-09-09 | no |
| v1.30.0 | 2026-08-30 | no |
| v1.30.0-rc2 | 2026-10-15 | yes |
| v1.30.0-rc1 | 2026-08-13 | yes |
| v1.29.0 | 2026-08-01 | no |
| v1.28.0 | 2026-07-21 | no |
| v1.27.0 | 2026-07-14 | no |
| v1.26.1 | 2026-06-21 | no |
| v1.26.0 | 2026-06-21 | no |
| v1.25.2 | 2026-05-16 | no |
| v1.25.1 | 2026-05-16 | no |
| v1.25.0 | 2026-05-14 | no |
| v1.24.1 | 2026-04-13 | no |
| v1.24.0 | 2026-04-13 | no |
| v1.24.0-rc3 | 2026-04-13 | yes |
| v1.24.0-rc2 | 2026-04-13 | yes |
| v1.23.1 | 2026-03-08 | no |
| v1.23.0 | 2026-03-08 | no |
| v1.22.0 | 2026-02-06 | no |
| v1.21.0 | 2026-01-15 | no |
| ... | ... | ... |
| v0.1.4 | 2024-10-31 | no |
| v0.1.3 | 2024-10-29 | no |
| v0.1.2 | 2024-10-29 | no |
| v0.1.1 | 2024-10-28 | no |
| v0.1.0 | 2024-10-27 | no |

## Cadence (derived)

Roughly one minor release every 3–6 weeks, with patch releases often shipped same-day
or within days of a minor. 94 releases over ~24 months ≈ 3.9 releases/month including
patch/RC builds.

## Notable release-note content (see ../scrapes/release-notes.md for full text)

- **1.31.0** (2026-10-15): `typosquat-uses` extended to pre-commit; more precise
  `self-hosted-runner`; `dangerous-triggers` now treats `issue_comment` as fundamentally
  dangerous; awareness of GitHub's `cache-mode:` setting (suppresses cache-poisoning
  findings when `cache-mode: none`); new PowerShell tree-sitter grammar.
- **1.30.0** (2026-08-30): new audit `self-repository`; most audits extended to
  pre-commit config inputs.
- **1.29.0** (2026-08-01): experimental pre-commit support; new audit
  `insecure-url-scheme`; support for GitHub's "self-repository" reference syntax.
- **1.28.0** (2026-07-21): **security release** — v1.27.0 printed configured GitHub
  credentials in cleartext logs (GHSA-f42p-wjw5-97qh).
- **Next (UNRELEASED)**: "root-aware" input collection (only collect inputs GitHub
  Actions would actually use); LSP `didChangeWorkspaceFolders` support.

**Direction signal (inferred):** expansion of *input surface* (pre-commit → parallel
steps → root-aware collection), steady precision work on existing audits, and continued
GitHub-platform-syntax awareness (`cache-mode`, `image_version`, self-repository refs).
No org-level / fleet-level scanning feature appears in release notes or docs.
