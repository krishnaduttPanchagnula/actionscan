package cmd

import (
	"bytes"
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/krishnaduttPanchagnula/actionscan/internal/scanner"
	"github.com/krishnaduttPanchagnula/actionscan/web"
)

// writeJSON writes a summary as report.json.
func writeJSON(path string, s *scanner.Summary) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// serveTemplate builds the same template the serve command uses: the
// embedded one, registered under the name gin looks up.
func serveTemplate(t *testing.T) *template.Template {
	t.Helper()
	tmpl, err := template.New("report.html").Parse(web.TemplateHTML())
	if err != nil {
		t.Fatal(err)
	}
	return tmpl
}

// TestServePageRendersFindings executes the real dashboard with the exact
// data shape the serve handler passes. Regression: the handler used to
// pass gin.H{"Summary": ...}, so {{.Critical}}/{{range .Findings}}
// resolved to nothing and the live page always rendered an empty table.
func TestServePageRendersFindings(t *testing.T) {
	s := &scanner.Summary{
		Findings: []scanner.Finding{{
			Repo: "acme/beta", Workflow: ".github/workflows/ci.yml", Job: "build",
			Action: "tj-actions/changed-files@v41", Ref: "v41",
			Severity: "CRITICAL", Category: "malicious",
			Reason: "dumped runner memory",
			Fix:    "Remove tj-actions/changed-files from all workflows; rotate any secrets it could have accessed",
		}},
		Critical: 1, TotalRepos: 42, AffectedRepos: 1, ActionsChecked: 7,
		Target: "org/acme", ToolVersion: "v1.0.0",
	}

	var buf bytes.Buffer
	if err := serveTemplate(t).Execute(&buf, templateData(s)); err != nil {
		t.Fatal(err)
	}
	html := buf.String()

	for _, want := range []string{
		"sev CRITICAL",
		"acme/beta",
		"tj-actions/changed-files@v41",
		"Critical",
		"Repos scanned",
		"Recommended fix",
		"Remove tj-actions/changed-files from all workflows",
		"org/acme",
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
	var buf bytes.Buffer
	if err := serveTemplate(t).Execute(&buf, templateData(&scanner.Summary{TotalRepos: 3})); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "No findings") {
		t.Error("empty summary must render the empty state")
	}
}

// The dashboard is embedded in the binary, so a released actionscan must
// render its report from any working directory.
func TestServeTemplateIsEmbedded(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := serveTemplate(t).Execute(&buf, templateData(&scanner.Summary{TotalRepos: 1})); err != nil {
		t.Fatalf("the dashboard must render without the repo checkout: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("embedded dashboard rendered nothing")
	}
}

// The HTTP surface must actually serve the report.
func TestServeEndpoints(t *testing.T) {
	gin.SetMode(gin.TestMode)
	dir := t.TempDir()

	s := &scanner.Summary{
		Findings: []scanner.Finding{{
			Repo: "acme/beta", Workflow: ".github/workflows/ci.yml",
			Action: "actions/checkout@v3", Ref: "v3",
			Severity: "LOW", Category: "outdated",
			Reason: "outdated", Fix: "uses: actions/checkout@v7.0.1",
		}},
		TotalRepos: 1,
	}
	if err := writeJSON(filepath.Join(dir, "report.json"), s); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "report.csv"), []byte("repo\nacme/beta\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "report.sarif"), []byte(`{"version":"2.1.0"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	r := gin.New()
	r.SetHTMLTemplate(serveTemplate(t))
	summary, err := loadSummary(dir)
	if err != nil {
		t.Fatal(err)
	}
	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "report.html", templateData(summary))
	})
	r.GET("/report.csv", func(c *gin.Context) {
		c.FileAttachment(filepath.Join(dir, "report.csv"), "report.csv")
	})
	r.GET("/report.sarif", func(c *gin.Context) {
		c.FileAttachment(filepath.Join(dir, "report.sarif"), "report.sarif")
	})

	for path, want := range map[string]int{
		"/":             http.StatusOK,
		"/report.csv":   http.StatusOK,
		"/report.sarif": http.StatusOK,
	} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != want {
			t.Errorf("GET %s = %d, want %d", path, w.Code, want)
		}
	}
}
