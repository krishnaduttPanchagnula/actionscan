# OSV API verification notes — 2026-10-22

All requests issued from this environment against `https://api.osv.dev`.

## 1. `GET /v1/vulns/GHSA-mrrh-fwg8-r2c3`
File: `osv-vuln-GHSA-mrrh-fwg8-r2c3.json` (HTTP 200)
- `id`: `GHSA-mrrh-fwg8-r2c3`
- `aliases`: `["CVE-2025-30066"]`
- `summary`: "tj-actions changed-files through 45.0.7 allows remote attackers to discover secrets by reading actions logs."
- `published`: 2025-03-15, `modified`: 2025-10-22
- `affected[0].package` = `{"name":"tj-actions/changed-files","ecosystem":"GitHub Actions"}`  <-- CONFIRMED
- `affected[0].ranges` = `{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"46.0.1"}]}`  <-- CONFIRMED
  (introduced 0 / fixed 46.0.1)

## 2. `POST /v1/query` — package only (no version)
File: `osv-query-tj-actions-no-version.json` (HTTP 200)
Body: `{"package":{"name":"tj-actions/changed-files","ecosystem":"GitHub Actions"}}`
Result: 2 vulns -> `GHSA-mcph-m25j-8j63`, `GHSA-mrrh-fwg8-r2c3`
- `GHSA-mcph-m25j-8j63` range: introduced `0`, fixed `41`
- `GHSA-mrrh-fwg8-r2c3` range: introduced `0`, fixed `46.0.1`
=> **CONFIRMED**: package-only queries DO return GitHub Actions advisories.

## 3. `POST /v1/query` — with version
File: `osv-query-tj-actions-version-45.0.7.json` (HTTP 200)
Body: `{"package":{"name":"tj-actions/changed-files","ecosystem":"GitHub Actions"},"version":"45.0.7"}`
Result: `{}`  <-- CONFIRMED empty.

### 3b. Exhaustive version-format sweep (not saved as files; results here)
Every version tested against the GitHub Actions ecosystem returned `{}`:
`45.0.7`, `v45.0.7`, `45.0.8`, `v45.0.8`, `40`, `v40`, `41`, `45`, `v45`, `0`, `v0`, `46.0.1`, `v46.0.1`.
Control (npm): `{"package":{"name":"lodash","ecosystem":"npm"},"version":"4.17.15"}` -> **6 vulns**.
=> **Version-scoped queries against the "GitHub Actions" ecosystem do not match at the OSV API level
   as of 2026-10-22**, even for versions that are demonstrably inside the affected range.
   This is the technical reason actionscan must query by package name and match version ranges locally.

### 3c. `POST /v1/querybatch`
- Without version: `{"results":[{"vulns":[{"id":"GHSA-mcph-m25j-8j63",...},{"id":"GHSA-mrrh-fwg8-r2c3",...}]}]}` (HTTP 200)
- With version `45.0.7`: `{"results":[{}]}` (HTTP 200) — empty result for that query.
osv-scanner's Go client uses `QueryBatch` (see strings in the v2.7.0 binary:
`osv.dev/bindings/go/osvdev.(*OSVClient).QueryBatch`), which is why it inherits the same behaviour.

## 4. Invalid ecosystem
`POST /v1/query` with `"ecosystem":"GitHubActions"` (no space):
HTTP **400** `{"code":3,"message":"invalid ecosystem"}`  <-- CONFIRMED.
The ecosystem name is **"GitHub Actions" with a space**.

## 5. Ecosystem index
`GET https://api.osv.dev/v1/ecosystems` -> HTTP 404 `{"code":404,"message":"The current request is not defined by this API."}`
(not a supported endpoint; do not cite it as an ecosystem list).

Live ecosystem counts from https://osv.dev/list?ecosystem=GitHub+Actions (scraped 2026-10-22):
- **GitHub Actions: 55** advisories
- All ecosystems total: 2,544,922
- Neighbouring ecosystems for context: GIT 114,862 / npm 229,905 / Go 9,586 / PyPI 25,896 /
  crates.io 2,834 / Maven 7,085 / NuGet 1,924 / RubyGems 5,397 / Packagist 7,182
=> The GitHub Actions ecosystem is **small** relative to OSV's total: 55 / 2,544,922 (~0.002%).
   actionscan's value is not in the size of this ecosystem but in *where* those refs live
   (across a whole org's workflows) and in the non-OSV feeds (GitHub Security Advisories,
   compromised-action feeds, outdated-release and pinning-hygiene checks).

## 6. osv-schema ecosystem constant
`ossf/osv-schema` `bindings/go/osvconstants/constants.go` contains
`EcosystemGitHubActions Ecosystem = "GitHub Actions"` — so the ecosystem IS in the schema's
known-ecosystem list, and osv-scanner's filter annotator does NOT reject it as an unknown
ecosystem. It is queried and simply returns nothing (see empirical test).

## 7. `GET /v1/vulns?ecosystem=GitHub+Actions` -> HTTP 404. Not a supported endpoint.
