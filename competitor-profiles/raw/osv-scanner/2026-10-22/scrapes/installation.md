# Installation

 You may download the SLSA3 compliant binaries for Linux, macOS, and Windows from our releases page.

## Package Managers

### Windows Scoop

 Windows Scoop users can install osv-scanner from the official bucket:
 `scoop install osv-scanner`

### Windows WinGet

 Windows users can also install osv-scanner from the official WinGet repo:
 `winget install Google.OSVScanner`

### Homebrew

 Homebrew users can install osv-scanner via:
 `brew install osv-scanner`

### Arch Linux

 Arch Linux users can install osv-scanner from the official repo:
 `pacman -S osv-scanner`

### Alpine Linux

 Alpine Linux users can install osv-scanner from the official repo:
 `apk add osv-scanner`

### FreeBSD

 FreeBSD users can install osv-scanner from the official repo:
 `pkg install osv-scanner`

### NetBSD

 NetBSD users can install osv-scanner from the official repo:
 `pkg_add osv-scanner`

### OpenBSD

 OpenBSD users can install osv-scanner from the official repo:
 `pkg_add osv-scanner`

## Install from source

 Alternatively, you can install this from source by running:
 `go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest`

 This requires Go 1.26.2+ to be installed.

## Build from source

 See our contribution guidelines for instructions on how to build from source.

## Verifying Builds

 Each of our releases come with SLSA provenance data (`multiple.intoto.jsonl`), which can be used to verify the source and provenance of the binaries with the `slsa-verifier` tool.
 E.g.
 `slsa-verifier verify-artifact ./osv-scanner_1.2.0_linux_amd64 --provenance-path multiple.intoto2.jsonl --source-uri github.com/google/osv-scanner --source-tag v1.2.0`

## SemVer Adherence

 All releases on the same Major version will be guaranteed to have backward compatible JSON output and CLI arguments. However, features prefixed with `x` (e.g. `--x-call-analysis`) are experimental and might be changed or removed with only a Minor version change.
