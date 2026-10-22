package report

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/krishnaduttPanchagnula/actionscan/internal/scanner"
)

func sampleSummary() *scanner.Summary {
	return &scanner.Summary{
		Findings: []scanner.Finding{
			{
				Repo: "acme/beta", Workflow: ".github/workflows/ci.yml", Job: "build",
				Action: "tj-actions/changed-files@v41",
				Ref:    "v41", Severity: "CRITICAL", Category: "malicious",
				Reason: "dumped runner memory to attacker C2",
				Fix:    "Remove tj-actions/changed-files from all workflows; rotate any secrets it could have accessed",
			},
			{
				Repo: "acme/alpha", Workflow: ".github/workflows/deploy.yaml", Job: "deploy",
				Action: "actions/checkout@v1.5.0",
				Ref:    "v1.5.0", Severity: "HIGH", Category: "vulnerable",
				Reason:      `GHSA-aaaa: bad, "really" bad`,
				Fix:         "Upgrade actions/checkout to >= 4.0.0",
				AdvisoryID:  "GHSA-aaaa-bbbb-cccc",
				AdvisoryURL: "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
			},
			{
				Repo: "acme/alpha", Workflow: ".github/workflows/ci.yml", Job: "test",
				Action: "actions/checkout@abc1234",
				Ref:    "abc1234", Severity: "MEDIUM", Category: "unpinned",
				Reason: "Short SHA — pin full 40-char commit SHA",
				Fix:    "uses: actions/checkout@0123456789abcdef0123456789abcdef01234567",
			},
		},
		Critical: 1, High: 1, Medium: 1, Low: 0, TotalRepos: 42,
		AffectedRepos: 2, ActionsChecked: 17,
		Target:       "org/acme",
		RulesSources: []string{"ghsa", "osv"},
		ToolVersion:  "v9.9.9",
	}
}

func TestCSV(t *testing.T) {
	dir := t.TempDir()
	p, err := CSV(sampleSummary(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if p != filepath.Join(dir, "report.csv") {
		t.Errorf("path = %q", p)
	}

	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatalf("output is not valid CSV: %v", err)
	}
	wantHeader := []string{"repo", "workflow", "job", "action", "ref", "severity", "category", "advisory", "reason", "fix"}
	if len(rows) != 4 { // header + 3 findings
		t.Fatalf("got %d rows, want 4", len(rows))
	}
	for i, want := range wantHeader {
		if rows[0][i] != want {
			t.Errorf("header[%d] = %q, want %q", i, rows[0][i], want)
		}
	}
	if rows[1][0] != "acme/beta" {
		t.Errorf("repo column = %q, want acme/beta", rows[1][0])
	}
	// The reason contains commas and quotes — csv must round-trip it.
	if rows[2][8] != `GHSA-aaaa: bad, "really" bad` {
		t.Errorf("reason column = %q, want exact text with comma+quotes", rows[2][8])
	}
	if rows[1][5] != "CRITICAL" {
		t.Errorf("severity column = %q", rows[1][5])
	}
	// The fix column must carry the remediation for every finding.
	if !strings.Contains(rows[1][9], "Remove tj-actions/changed-files") {
		t.Errorf("fix column = %q, want removal guidance", rows[1][9])
	}
	if !strings.Contains(rows[3][9], "uses: actions/checkout@") {
		t.Errorf("fix column = %q, want a pinned uses: line", rows[3][9])
	}
}

// A hostile repository can plant a formula in its own workflow file and
// have it land verbatim in the report. Opening the CSV in Excel must not
// execute it.
func TestCSVNeutralizesFormulaInjection(t *testing.T) {
	dir := t.TempDir()
	s := sampleSummary()
	s.Findings[0].Action = `=cmd|'/c calc'!A1`
	s.Findings[0].Reason = "+1+1"

	if _, err := CSV(s, dir); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "report.csv"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `,=cmd`) {
		t.Error("CSV cell starts with a formula character — spreadsheet would execute it")
	}
	if !strings.Contains(string(b), `'=cmd`) {
		t.Error("formula cell was not neutralized with a leading apostrophe")
	}
	if strings.Contains(string(b), `,+1+1`) {
		t.Error("formula cell was not neutralized with a leading apostrophe")
	}
}

func TestJSONRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p, err := JSON(sampleSummary(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if p != filepath.Join(dir, "report.json") {
		t.Errorf("path = %q", p)
	}

	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var back scanner.Summary
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if len(back.Findings) != 3 || back.Critical != 1 || back.TotalRepos != 42 {
		t.Errorf("round-trip lost data: %+v", &back)
	}
	if back.Findings[0].Action != "tj-actions/changed-files@v41" {
		t.Errorf("finding action = %q", back.Findings[0].Action)
	}
	if back.Target != "org/acme" || back.ToolVersion != "v9.9.9" {
		t.Errorf("report metadata lost: target=%q version=%q", back.Target, back.ToolVersion)
	}
	// Pretty-printed output.
	if !strings.Contains(string(b), "\n  \"findings\"") {
		t.Error("JSON output is not indented")
	}
}

func TestHTMLWithFindings(t *testing.T) {
	dir := t.TempDir()

	p, err := HTML(sampleSummary(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if p != filepath.Join(dir, "report.html") {
		t.Errorf("path = %q", p)
	}

	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	html := string(b)

	for _, want := range []string{
		"<title>actionscan", // title rendered
		"tj-actions/changed-files@v41",
		"acme/beta",
		".github/workflows/deploy.yaml",
		"Remove tj-actions/changed-files from all workflows",
		"uses: actions/checkout@0123456789abcdef0123456789abcdef01234567",
		"org/acme",  // the scan target must be in the report
		"v9.9.9",    // the tool version must be in the report
		"GHSA-aaaa", // the advisory id must be in the report
	} {
		if !strings.Contains(html, want) {
			t.Errorf("rendered HTML missing %q", want)
		}
	}
	if strings.Contains(html, "No critical or high-severity findings") {
		t.Error("summary has a CRITICAL finding but the template rendered the all-clear banner")
	}
}

func TestHTMLEmptySummary(t *testing.T) {
	dir := t.TempDir()

	empty := &scanner.Summary{TotalRepos: 10, Target: "org/acme"}
	p, err := HTML(empty, dir)
	if err != nil {
		t.Fatal(err)
	}

	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "No findings") {
		t.Error("empty summary must render the empty state")
	}
	if strings.Contains(string(b), "tj-actions/changed-files") {
		t.Error("empty summary must not render finding rows")
	}
	// A clean report must still say what was scanned.
	if !strings.Contains(string(b), "org/acme") {
		t.Error("empty summary must still report the scan target")
	}
}

// The template is embedded in the binary, so rendering must not depend
// on the working directory.
func TestHTMLWorksFromAnyDirectory(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}

	if _, err := HTML(sampleSummary(), t.TempDir()); err != nil {
		t.Fatalf("rendering must not depend on the working directory: %v", err)
	}
}

func TestSARIF(t *testing.T) {
	dir := t.TempDir()
	p, err := SARIF(sampleSummary(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if p != filepath.Join(dir, "report.sarif") {
		t.Errorf("path = %q", p)
	}

	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if doc["version"] != "2.1.0" {
		t.Errorf("sarif version = %v, want 2.1.0", doc["version"])
	}
	runs, ok := doc["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("sarif runs = %v, want one run", doc["runs"])
	}
	run := runs[0].(map[string]any)
	results, ok := run["results"].([]any)
	if !ok || len(results) != 3 {
		t.Fatalf("sarif results = %v, want 3", run["results"])
	}
	first := results[0].(map[string]any)
	if first["level"] != "error" {
		t.Errorf("CRITICAL finding level = %v, want error", first["level"])
	}
	if _, ok := first["ruleId"]; !ok {
		t.Error("sarif result missing ruleId")
	}

	// Every result's ruleId must be declared in the driver's rules,
	// otherwise a code-scanning consumer sees an unknown rule.
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	declared := map[string]bool{}
	for _, r := range driver["rules"].([]any) {
		declared[r.(map[string]any)["id"].(string)] = true
	}
	if len(declared) == 0 {
		t.Error("sarif driver declares no rules")
	}
	for _, res := range results {
		id := res.(map[string]any)["ruleId"].(string)
		if !declared[id] {
			t.Errorf("result references undeclared rule %q", id)
		}
	}
}

// Every spreadsheet formula character must be neutralized, not just "=".
func TestCSVNeutralizesEveryFormulaCharacter(t *testing.T) {
	dir := t.TempDir()
	s := sampleSummary()
	dangerous := []string{
		"=cmd|'/c calc'!A1",
		"+1+1",
		"-2+3",
		"@SUM(A1)",
		"\tleading tab",
		"\rleading cr",
	}
	for i, d := range dangerous {
		s.Findings[i%len(s.Findings)].Action = d
	}

	if _, err := CSV(s, dir); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "report.csv"))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(strings.NewReader(string(b))).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows[1:] {
		for _, cell := range row {
			if cell == "" {
				continue
			}
			switch cell[0] {
			case '=', '+', '-', '@', '\t', '\r':
				t.Errorf("cell %q still starts with a formula character", cell)
			}
		}
	}
}
