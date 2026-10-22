# scharf-action
A GitHub action to detect mutable third-party references used in a GitHub repository.

This action uses Cybrota Scharf tool to identify actions with mutable tags. See https://github.com/cybrota/scharf for more details.

## Usage

```yaml
jobs:
  run-unit-tests:
    runs-on: ubuntu-22.04

    steps:
      - name: Checkout repository
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683

      - name: Audit GitHub actions
        uses: cybrota/scharf-action@71662a3ec833b0c915a67f21e500e81786b95901 #v1
        with:
          raise-error: true
```

## Inputs

* raise-error (Raises Exit 1 error if any violating actions found. Default is false)

## Sample output

If there are matches, you will see a table on the GitHub action log

```ascii
Mutable references found in your GitHub actions. Please replace them to secure your CI from supply chain attacks.
+---------------------+-------------------------------------------------------+------------------------------------------+
|        MATCH        |                       FILEPATH                        |             REPLACE WITH SHA             |
+---------------------+-------------------------------------------------------+------------------------------------------+
| actions/checkout@v4 | /Users/neo/scharf/.github/workflows/ci.yml | 11bd71901bbe5b1630ceea73d27597364c9af683 |
+---------------------+-------------------------------------------------------+------------------------------------------+
```
If no macthes found, you will see:

```ascii
No mutable references found. Good job!
```


## Why mutable tags in GitHub CI/CD workflows are bad ?

Using mutable references like tag-based or branch-based references in your CI/CD workflows can lead to unexpected changes or potential security vulnerabilities if the referenced action is compromised by malicious actors.

Scharf lets you identify and mitigate against supply-chain attacks similar to "tj-actions/changed-files" compromise occured in March 2025.

"GitHub's own official tutorials use tags instead of full commit shas. What a mess" - A YCombinator Hackernews Reader

"Github Actions is definitely a vector for abuse." - Another Hackernews Reader

## Links
* https://github.com/cybrota/scharf
* https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-github-action-cve-2025-30066

* https://alexwlchan.net/2025/github-actions-audit/

* https://github.com/advisories/ghsa-mrrh-fwg8-r2c3
