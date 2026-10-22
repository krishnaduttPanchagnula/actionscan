# License Scanning

 Table of contents
- License Scanning License Summary and Violations License violations example

- Override License

 OSV-Scanner supports license checking as an official feature. The data comes from the deps.dev API.

## License Summary and Violations

 The `--licenses` flag provides a summary of the licenses used by your dependencies. To also display violations, you can provide an allowlist of permitted licenses as an argument:
 `# Show license summary only
osv-scanner --licenses path/to/repository

# Show the license summary and violations against an allowlist (provide the list after the = sign):
osv-scanner --licenses="comma-separated list of allowed licenses" path/to/directory`

 Include your allowed licenses as a comma-separated list. OSV-Scanner recognizes licenses in SPDX format. Please indicate your allowed licenses using SPDX license identifiers.

### License violations example

 If you wanted to allow the following licenses:

- BSD 3-Clause “New” or “Revised” License
- Apache License 2.0
- MIT
 Your command would be in this form:
 `osv-scanner --licenses="BSD-3-Clause,Apache-2.0,MIT" path/to/directory`

## Override License

 Sometimes, the license either cannot be retrieved, or does not apply to your specific use. In those cases, you can override the license of a specific package by setting it in the config file.
 See the configuration docs for how to do this.
