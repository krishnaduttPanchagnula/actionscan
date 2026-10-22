# Empirical test: osv-scanner v2.7.0 vs. GitHub Actions workflows

Date: 2026-10-22. Binary: `osv-scanner_linux_amd64` from release v2.7.0 (built 2026-10-12).
Version banner: `osv-scanner version: 2.7.0` / `osv-scalibr version: 0.5.3`.

## Test fixture
`testrepo/.github/workflows/ci.yml`:
```yaml
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: tj-actions/changed-files@v45.0.7
      - uses: actions/checkout@v4
```
Also `testrepo/requirements.txt` containing `requests==2.0.0` (control: a known-vulnerable PyPI package).

## Result 1 — default scan (documented path)
```
$ osv-scanner scan source -r . --format json
```
- Packages reported: `('PyPI', 'requests', '2.0.0')` with 13 vulnerabilities.
- `tj-actions` present in output: **False**.
- `GitHub Actions` ecosystem present in output: **False**.
=> The workflow file was not parsed at all. The documented lockfile/manifest table has no Actions support.

## Result 2 — experimental plugin flag
```
$ osv-scanner scan source -r . --x-no-default-plugins --x-plugins github/actions --format json
```
Output (stderr):
```
Scanned /tmp/.../testrepo/.github/workflows/ci.yml file and found 2 packages
...
"results": [],
```
=> The Scalibr `github/actions` extractor (merged in google/osv-scalibr#2032, 2026-05-06) IS reachable
   via the experimental `--x-plugins` flag and DOES parse `.github/workflows/*.yml`.
   BUT it reports **zero vulnerabilities** for `tj-actions/changed-files@v45.0.7`, which is covered by
   GHSA-mrrh-fwg8-r2c3 (introduced 0 / fixed 46.0.1) and GHSA-mcph-m25j-8j63 (introduced 0 / fixed 41).

### Control: same custom-lockfile path with an npm package
`{"package":{"name":"lodash","version":"4.17.15","ecosystem":"npm"}}` -> 6 findings reported.
So the pipeline works for npm; the GitHub Actions ecosystem specifically yields nothing.

## Result 3 — hand-written `osv-scanner.json` workaround
```
$ osv-scanner scan source -L osv-scanner:./osv-scanner.json --verbosity info
```
With `{"package":{"name":"tj-actions/changed-files","version":"45.0.7","ecosystem":"GitHub Actions"}}`:
```
Scanned .../osv-scanner.json file and found 1 package
No issues found
```
=> The package is NOT filtered out (no "Filtered N unscannable package/s" line), it IS queried,
   but the OSV API returns no match for the version -> zero findings.

With `{"name":"tj-actions/changed-files","ecosystem":"GitHub Actions"}` (no version):
```
Filtered 1 local/unscannable package/s from the scan.
No issues found
```
=> Without a version the package is dropped by the filter annotator
   (internal/scalibrannotator/filter/filter.go requires ecosystem+name+version, or a commit).

## Result 4 — offline mode with the extractor (panic still reproduces in v2.7.0)
```
$ osv-scanner scan source -r . --x-no-default-plugins --x-plugins github/actions \
    --offline-vulnerabilities --download-offline-databases
```
```
Loaded GitHub Actions local db from /home/krishna/.cache/osv-scalibr/GitHub Actions/all.zip
panic: unsupported ecosystem GitHub Actions
	panic: runtime error: invalid memory address or nil pointer dereference
[signal SIGSEGV: segmentation violation code=0x1 addr=0x10 pc=0x1a42ba3]
...
github.com/google/osv-scalibr/semantic.MustParse(...)
	.../osv-scalibr@v0.5.4-0.20261009010329-5be78a00e3c2/semantic/parse.go:36
github.com/google/osv-scalibr/enricher/vulnmatch/osvlocal/internal/vulns.rangeContainsVersion(...)
```
=> Exit code 2, process crash. This is the same class of bug reported in
   google/osv-scanner#2831 ("Offline scan panics with 'unsupported ecosystem GitHub Actions' on SBOMs
   containing actions that have OSV advisories", filed 2026-05-21, closed 2026-05-28).
   The 2026-05-28 fix covered osv-scanner's internal matcher, but the Scalibr local matcher path
   still panics in v2.7.0.

## Conclusion
As of v2.7.0 (2026-10-12), osv-scanner cannot report a vulnerability for a GitHub Action reference,
by any documented route, and crashes in offline mode if the (experimental, off-by-default) Actions
extractor is enabled.
