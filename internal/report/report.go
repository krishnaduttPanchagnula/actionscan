package report

import (
	"encoding/csv"
	"encoding/json"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/krishnaduttPanchagnula/actionscan/internal/scanner"
	"github.com/krishnaduttPanchagnula/actionscan/web"
)

// dashboard is the report template, embedded in the binary. Reading it
// from disk made every released binary fail at the last step of a scan.
var dashboard = template.Must(template.New("report").Parse(web.TemplateHTML()))

// HTML writes the dashboard to <dir>/report.html.
func HTML(s *scanner.Summary, dir string) (string, error) {
	return HTMLWithBaseline(s, dir, nil)
}

// HTMLWithBaseline writes the dashboard, marking the findings that are
// new relative to a baseline scan.
//
// newFingerprints is the set of finding fingerprints that are new. It
// may be nil, in which case nothing is marked.
func HTMLWithBaseline(s *scanner.Summary, dir string, newFingerprints map[string]bool) (string, error) {
	p := filepath.Join(dir, "report.html")
	f, err := os.Create(p)
	if err != nil {
		return "", err
	}
	defer f.Close()

	data := struct {
		*scanner.Summary
		Empty bool
		// NewFingerprints lets the template render a NEW badge.
		NewFingerprints map[string]bool
		// TransitiveRows renders the transitive dependency table.
		TransitiveRows [][]string
	}{s, len(s.Findings) == 0, newFingerprints, transitiveRows(s)}

	return p, dashboard.Execute(f, data)
}

// transitiveRows renders the transitive dependency analysis as table
// rows, or nil when the analysis did not run.
func transitiveRows(s *scanner.Summary) [][]string {
	if s == nil || s.Transitive == nil {
		return nil
	}
	return scanner.TransitiveRows(*s.Transitive)
}

// CSV writes the findings to <dir>/report.csv.
func CSV(s *scanner.Summary, dir string) (string, error) {
	p := filepath.Join(dir, "report.csv")
	f, err := os.Create(p)
	if err != nil {
		return "", err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	w.Write([]string{"repo", "workflow", "job", "action", "ref", "severity", "category", "advisory", "reason", "fix"})
	for _, fi := range s.Findings {
		w.Write([]string{
			sanitizeCell(fi.Repo), sanitizeCell(fi.Workflow), sanitizeCell(fi.Job),
			sanitizeCell(fi.Action), sanitizeCell(fi.Ref),
			sanitizeCell(fi.Severity), sanitizeCell(fi.Category), sanitizeCell(fi.AdvisoryID),
			sanitizeCell(fi.Reason), sanitizeCell(fi.Fix),
		})
	}
	w.Flush()
	return p, w.Error()
}

// JSON writes the full summary to <dir>/report.json.
func JSON(s *scanner.Summary, dir string) (string, error) {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return "", err
	}
	p := filepath.Join(dir, "report.json")
	return p, os.WriteFile(p, b, 0o644)
}

// sanitizeCell neutralizes spreadsheet formula injection.
//
// The action and reason columns come from scanned repositories, so a
// hostile repo can plant "=cmd|'/c calc'!A1" and have it executed by
// Excel or Sheets when the report is opened. Prefixing with an apostrophe
// makes the cell literal text.
func sanitizeCell(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

// SARIF writes a SARIF 2.1.0 report to <dir>/report.sarif so findings
// can be uploaded to GitHub code scanning.
func SARIF(s *scanner.Summary, dir string) (string, error) {
	b, err := json.MarshalIndent(sarif(s), "", "  ")
	if err != nil {
		return "", err
	}
	p := filepath.Join(dir, "report.sarif")
	return p, os.WriteFile(p, b, 0o644)
}

// sarifRuleID is the stable id of a finding in SARIF, used so repeated
// runs of the same finding map to the same alert.
func sarifRuleID(f scanner.Finding) string {
	if f.AdvisoryID != "" {
		return f.AdvisoryID
	}
	return f.Category
}

func sarif(s *scanner.Summary) map[string]any {
	rules := map[string]any{}
	var results []any

	for _, f := range s.Findings {
		id := sarifRuleID(f)
		if _, ok := rules[id]; !ok {
			rules[id] = map[string]any{
				"id":               id,
				"name":             id,
				"shortDescription": map[string]any{"text": f.Reason},
				"fullDescription":  map[string]any{"text": f.Reason},
				"defaultConfiguration": map[string]any{
					"level": sarifLevel(f.Severity),
				},
				"properties": map[string]any{
					"category": f.Category,
					"tags":     []string{f.Category, strings.ToLower(f.Severity)},
				},
			}
		}
		results = append(results, map[string]any{
			"ruleId":  id,
			"level":   sarifLevel(f.Severity),
			"message": map[string]any{"text": f.Reason},
			"locations": []any{map[string]any{
				"physicalLocation": map[string]any{
					"artifactLocation": map[string]any{
						"uri": f.Workflow,
					},
				},
			}},
			"partialFingerprints": map[string]any{
				"actionscanFindingId": sarifFingerprint(f),
			},
		})
	}

	if results == nil {
		results = []any{}
	}
	return map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool": map[string]any{
				"driver": map[string]any{
					"name":           "actionscan",
					"informationUri": "https://github.com/krishnaduttPanchagnula/actionscan",
					"version":        s.ToolVersion,
					"rules":          rulesAsList(rules),
				},
			},
			"results": results,
		}},
	}
}

// rulesAsList turns the rule map into a stable-ordered list.
func rulesAsList(rules map[string]any) []any {
	keys := make([]string, 0, len(rules))
	for k := range rules {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]any, 0, len(keys))
	for _, k := range keys {
		out = append(out, rules[k])
	}
	return out
}

// sarifFingerprint identifies one finding across runs so that code
// scanning can track it.
func sarifFingerprint(f scanner.Finding) string {
	return strings.Join([]string{f.Repo, f.Workflow, f.Job, f.Action, f.Category, f.AdvisoryID}, "|")
}

// sarifLevel maps our severity to the SARIF levels.
func sarifLevel(sev string) string {
	switch strings.ToUpper(sev) {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	}
	return "note"
}
