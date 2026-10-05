package cmd

import (
	"bytes"
	"html/template"
	"os"
	"strings"
	"testing"

	"github.com/krishnaduttPanchagnula/actionscan/internal/scanner"
)

// TestServePageRendersFindings executes the real web/template.html with
// the exact data shape the serve handler passes. Regression: the handler
// used to pass gin.H{"Summary": ...}, so {{.Critical}}/{{range
// .Findings}} resolved to nothing and the live page always rendered an
// empty table.
func TestServePageRendersFindings(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })
	// Template lives at the repository root.
	if err := os.Chdir(".."); err != nil {
		t.Fatal(err)
	}

	tmpl, err := template.ParseFiles("web/template.html")
	if err != nil {
		t.Fatal(err)
	}

	s := &scanner.Summary{
		Findings: []scanner.Finding{{
			Repo: "acme/beta", Workflow: "ci.yml",
			Action: "tj-actions/changed-files@v41", Ref: "v41",
			Severity: "CRITICAL", Category: "malicious",
			Reason: "dumped runner memory",
			Fix:    "Remove tj-actions/changed-files from all workflows; rotate any secrets it could have accessed",
		}},
		Critical: 1, TotalRepos: 42, AffectedRepos: 1, ActionsChecked: 7,
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, templateData(s)); err != nil {
		t.Fatal(err)
	}
	html := buf.String()

	for _, want := range []string{
		"sev CRITICAL",
		"acme/beta",
		"tj-actions/changed-files@v41",
		`<div class="stat-num">1</div><div class="stat-label">Critical</div>`,
		`<div class="stat-num">42</div><div class="stat-label">Repos scanned</div>`,
		"Recommended fix",
		"Remove tj-actions/changed-files from all workflows",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("served page missing %q — summary fields not promoted?", want)
		}
	}
	if strings.Contains(html, "No findings") {
		t.Error("page rendered empty state despite having findings")
	}
}

// TestServePageEmptySummary verifies the empty state still renders.
func TestServePageEmptySummary(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })
	if err := os.Chdir(".."); err != nil {
		t.Fatal(err)
	}

	tmpl, err := template.ParseFiles("web/template.html")
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, templateData(&scanner.Summary{TotalRepos: 3})); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "No findings") {
		t.Error("empty summary must render the empty state")
	}
}
