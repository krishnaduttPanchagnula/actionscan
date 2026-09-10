#!/usr/bin/env bash
set -euo pipefail

mkdir -p actionscan/{cmd,internal/{config,github,rules,scanner,report},web}
cd actionscan

touch main.go config.yaml go.mod \
      cmd/root.go cmd/scan.go cmd/serve.go \
      internal/config/config.go \
      internal/github/client.go \
      internal/rules/feeds.go internal/rules/osv.go internal/rules/ruleset.go \
      internal/scanner/scanner.go \
      internal/report/report.go \
      web/template.html

echo "Done. Structure created:"
find . -type f | sort
