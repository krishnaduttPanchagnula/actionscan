# Feed 404 verification

Date: 2026-10-22

```
$ curl -s -o /dev/null -w "%{http_code}" https://raw.githubusercontent.com/step-security/secure-repo/main/compromised-actions/compromised-actions.json
404
```

- GitHub API recursive tree of step-security/secure-repo@main (1887 paths) contains NO compromised-actions/ directory.
- No path in the repo tree matches "compromis" or "threat".
- Tag v1.0.0 tree also has no compromised-actions path.
- GitHub code search: filename:compromised-actions.json org:step-security -> total_count 0.
- Commits API with path=compromised-actions -> empty.
- Only remaining JSON data files in repo: remediation/workflow/maintainedactions/maintainedActions.json, knowledge-base/actions/*/action-security.yml (453 files).
