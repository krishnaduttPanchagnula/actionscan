package report

import (
	"encoding/json"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/krishnaduttPanchagnula/actionscan/internal/scanner"
)

// writeFile writes a file into a temp dir and returns its path.
func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// baselineJSON is a report.json as a previous scan wrote it.
func baselineJSON(t *testing.T, findings []scanner.Finding) string {
	t.Helper()
	s := scanner.Summary{
		Findings:    findings,
		ScannedAt:   time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		ToolVersion: "v1.0.0",
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestLoadBaselineReadsAPreviousReport(t *testing.T) {
	f := scanner.Finding{
		Repo: "acme/alpha", Workflow: ".github/workflows/ci.yml", Job: "build",
		Action: "actions/checkout@v4", Category: "unpinned", Severity: "MEDIUM",
		AdvisoryID: "GHSA-1234",
	}
	p := writeFile(t, "report.json", baselineJSON(t, []scanner.Finding{f}))

	got, err := LoadBaseline(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Findings) != 1 {
		t.Fatalf("loaded %d findings, want 1", len(got.Findings))
	}
	if got.Findings[0].Action != "actions/checkout@v4" {
		t.Errorf("action = %q", got.Findings[0].Action)
	}
	if got.ToolVersion != "v1.0.0" {
		t.Errorf("tool version = %q, want v1.0.0", got.ToolVersion)
	}
	if got.ScannedAt.IsZero() {
		t.Error("scan time was lost")
	}
}

// A report written before fingerprints existed must still work as a
// baseline: without fingerprints everything would look new.
func TestLoadBaselineRecomputesMissingFingerprints(t *testing.T) {
	f := scanner.Finding{
		Repo: "acme/alpha", Workflow: ".github/workflows/ci.yml", Job: "build",
		Action: "actions/checkout@v4", Category: "unpinned", Severity: "MEDIUM",
	}
	raw := `{"findings":[{"repo":"acme/alpha","workflow":".github/workflows/ci.yml","job":"build",` +
		`"action":"actions/checkout@v4","severity":"MEDIUM","category":"unpinned"}],"scanned_at":"2026-01-02T03:04:05Z"}`
	p := writeFile(t, "old-report.json", raw)

	got, err := LoadBaseline(p)
	if err != nil {
		t.Fatal(err)
	}
	if got.Findings[0].Fingerprint == "" {
		t.Fatal("baseline finding has no fingerprint after load")
	}
	if want := scanner.Fingerprint(f); got.Findings[0].Fingerprint != want {
		t.Errorf("fingerprint = %q, want %q", got.Findings[0].Fingerprint, want)
	}
}

func TestLoadBaselineMissingFile(t *testing.T) {
	_, err := LoadBaseline(filepath.Join(t.TempDir(), "nope.json"))
	if err == nil {
		t.Fatal("loading a missing baseline must fail")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %v, want it to say the file was not found", err)
	}
}

func TestLoadBaselineInvalidJSON(t *testing.T) {
	p := writeFile(t, "report.json", "{not json at all")
	_, err := LoadBaseline(p)
	if err == nil {
		t.Fatal("loading an invalid baseline must fail")
	}
	if !strings.Contains(err.Error(), "not valid JSON") {
		t.Errorf("error = %v, want it to say the file is not valid JSON", err)
	}
}

// A diff file is valid JSON and parses as a summary with no findings —
// which would diff as "everything is new". The error has to name the
// mistake, because nothing else about the file gives it away.
func TestLoadBaselineRejectsADiffFile(t *testing.T) {
	cur := sampleSummary()
	cur.ScannedAt = time.Now()
	base := sampleSummary()
	base.ScannedAt = time.Now().Add(-24 * time.Hour)

	diffPath := filepath.Join(t.TempDir(), "diff.json")
	if _, err := WriteBaselineDiff(cur, base, diffPath); err != nil {
		t.Fatal(err)
	}

	_, err := LoadBaseline(diffPath)
	if err == nil {
		t.Fatal("loading a diff file as a baseline must fail")
	}
	want := "baseline must be a report.json from a previous scan, not a diff file"
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
}

func TestLoadBaselineRejectsJSONWithoutFindings(t *testing.T) {
	p := writeFile(t, "something.json", `{"foo":1,"bar":[2,3]}`)
	_, err := LoadBaseline(p)
	if err == nil {
		t.Fatal("loading a JSON file without findings must fail")
	}
	if !strings.Contains(err.Error(), "findings") {
		t.Errorf("error = %v, want it to name the missing findings array", err)
	}
}

// A baseline from another version of the tool is usable — the
// fingerprints are stable — but the rule set behind it may differ, so
// it is worth a warning.
func TestLoadBaselineWarnsOnADifferentToolVersion(t *testing.T) {
	p := writeFile(t, "report.json", baselineJSON(t, nil))

	_, warnings, err := LoadBaselineWithWarnings(p, "v1.1.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 1 {
		t.Fatalf("got %d warnings, want 1: %v", len(warnings), warnings)
	}
	if !strings.Contains(warnings[0], "v1.0.0") || !strings.Contains(warnings[0], "v1.1.0") {
		t.Errorf("warning = %q, want it to name both versions", warnings[0])
	}
}

// The same version is not a warning, and neither is an unknown one.
func TestLoadBaselineNoWarningForTheSameVersion(t *testing.T) {
	p := writeFile(t, "report.json", baselineJSON(t, nil))

	_, warnings, err := LoadBaselineWithWarnings(p, "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Errorf("warnings = %v, want none for the same version", warnings)
	}

	_, warnings, err = LoadBaselineWithWarnings(p, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Errorf("warnings = %v, want none when the current version is unknown", warnings)
	}
}

// "v1.0.0" and "1.0.0" are the same version.
func TestLoadBaselineNoWarningForEquivalentVersions(t *testing.T) {
	p := writeFile(t, "report.json", baselineJSON(t, nil))
	_, warnings, err := LoadBaselineWithWarnings(p, "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Errorf("warnings = %v, want none for an equivalent version", warnings)
	}
}

func TestApplyBaselineFillsTheSummary(t *testing.T) {
	base := &scanner.Summary{
		Findings: []scanner.Finding{
			{Repo: "acme/alpha", Workflow: "a.yml", Action: "actions/checkout@v4", Category: "unpinned"},
			{Repo: "acme/alpha", Workflow: "b.yml", Action: "actions/setup-go@v5", Category: "outdated"},
		},
		ScannedAt: time.Date(2026, 1, 2, 3, 4, 0, 0, time.UTC),
	}
	cur := &scanner.Summary{
		Findings: []scanner.Finding{
			{Repo: "acme/alpha", Workflow: "a.yml", Action: "actions/checkout@v4", Category: "unpinned"},
			{Repo: "acme/alpha", Workflow: "c.yml", Action: "actions/cache@v4", Category: "malicious"},
		},
	}

	ApplyBaseline(cur, base, "/tmp/report.json")

	if cur.NewFindings != 1 {
		t.Errorf("new findings = %d, want 1", cur.NewFindings)
	}
	if cur.ResolvedFindgs != 1 {
		t.Errorf("resolved findings = %d, want 1", cur.ResolvedFindgs)
	}
	if cur.BaselineAt != "2026-01-02 03:04" {
		t.Errorf("baseline at = %q, want 2026-01-02 03:04", cur.BaselineAt)
	}
	if cur.BaselinePath != "/tmp/report.json" {
		t.Errorf("baseline path = %q", cur.BaselinePath)
	}
}

// A baseline with no scan time has no date. "0001-01-01 00:00" would
// be a date nobody scanned on.
func TestApplyBaselineWithoutAScanTime(t *testing.T) {
	cur := &scanner.Summary{}
	ApplyBaseline(cur, &scanner.Summary{}, "b.json")
	if cur.BaselineAt != "" {
		t.Errorf("baseline at = %q, want empty", cur.BaselineAt)
	}
}

func TestApplyBaselineWithNoBaseline(t *testing.T) {
	cur := sampleSummary()
	ApplyBaseline(cur, nil, "")
	if cur.NewFindings != len(cur.Findings) {
		t.Errorf("new findings = %d, want %d", cur.NewFindings, len(cur.Findings))
	}
	if cur.ResolvedFindgs != 0 {
		t.Errorf("resolved findings = %d, want 0", cur.ResolvedFindgs)
	}
}

// The current scan's findings may come from anywhere; without
// fingerprints the diff would find nothing at all.
func TestApplyBaselineComputesFingerprintsWhenTheyAreMissing(t *testing.T) {
	base := &scanner.Summary{
		Findings: []scanner.Finding{
			{Repo: "acme/alpha", Workflow: "a.yml", Action: "actions/checkout@v4", Category: "unpinned"},
		},
		ScannedAt: time.Date(2026, 1, 2, 3, 4, 0, 0, time.UTC),
	}
	cur := &scanner.Summary{
		Findings: []scanner.Finding{
			{Repo: "acme/alpha", Workflow: "a.yml", Action: "actions/checkout@v4", Category: "unpinned"},
		},
	}
	ApplyBaseline(cur, base, "b.json")
	if cur.NewFindings != 0 {
		t.Errorf("new findings = %d, want 0", cur.NewFindings)
	}
	if cur.Findings[0].Fingerprint == "" {
		t.Error("the current findings were not given fingerprints")
	}
}

func TestNewFingerprints(t *testing.T) {
	base := &scanner.Summary{
		Findings: []scanner.Finding{
			{Repo: "acme/alpha", Workflow: "a.yml", Action: "actions/checkout@v4", Category: "unpinned"},
		},
	}
	cur := &scanner.Summary{
		Findings: []scanner.Finding{
			{Repo: "acme/alpha", Workflow: "a.yml", Action: "actions/checkout@v4", Category: "unpinned"},
			{Repo: "acme/alpha", Workflow: "b.yml", Action: "actions/setup-go@v5", Category: "outdated"},
		},
	}

	got := NewFingerprints(cur, base)
	if len(got) != 1 {
		t.Fatalf("got %d new fingerprints, want 1: %v", len(got), got)
	}
	fp := scanner.Fingerprint(cur.Findings[1])
	if !got[fp] {
		t.Errorf("the new finding's fingerprint %q is not in the set", fp)
	}
	if got[scanner.Fingerprint(cur.Findings[0])] {
		t.Error("an unchanged finding was reported as new")
	}
}

func TestNewFingerprintsWithNoBaseline(t *testing.T) {
	cur := sampleSummary()
	got := NewFingerprints(cur, nil)
	if len(got) != len(cur.Findings) {
		t.Errorf("got %d new fingerprints, want %d", len(got), len(cur.Findings))
	}
}

func TestWriteBaselineDiff(t *testing.T) {
	base := &scanner.Summary{
		Findings: []scanner.Finding{
			{Repo: "acme/alpha", Workflow: "a.yml", Action: "actions/checkout@v4", Category: "unpinned"},
			{Repo: "acme/alpha", Workflow: "b.yml", Action: "actions/setup-go@v5", Category: "outdated"},
		},
		ScannedAt: time.Date(2026, 1, 2, 3, 4, 0, 0, time.UTC),
	}
	cur := &scanner.Summary{
		Findings: []scanner.Finding{
			{Repo: "acme/alpha", Workflow: "a.yml", Action: "actions/checkout@v4", Category: "unpinned"},
			{Repo: "acme/alpha", Workflow: "c.yml", Action: "actions/cache@v4", Category: "malicious"},
		},
	}

	p := filepath.Join(t.TempDir(), "diff.json")
	got, err := WriteBaselineDiff(cur, base, p)
	if err != nil {
		t.Fatal(err)
	}
	if got != p {
		t.Errorf("path = %q, want %q", got, p)
	}

	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var d BaselineDiff
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatalf("diff is not valid JSON: %v", err)
	}
	if d.NewCount != 1 || d.ResolvedCount != 1 {
		t.Errorf("counts = %d new / %d resolved, want 1 / 1", d.NewCount, d.ResolvedCount)
	}
	if d.BaselineAt != "2026-01-02 03:04" {
		t.Errorf("baseline at = %q", d.BaselineAt)
	}
	if len(d.New) != 1 || d.New[0] != scanner.Fingerprint(cur.Findings[1]) {
		t.Errorf("new = %v, want the new finding's fingerprint", d.New)
	}
	if len(d.Resolved) != 1 || d.Resolved[0] != scanner.Fingerprint(base.Findings[1]) {
		t.Errorf("resolved = %v, want the resolved finding's fingerprint", d.Resolved)
	}
}

// The same scan must produce the same diff file, or CI diffs noise.
func TestWriteBaselineDiffIsDeterministic(t *testing.T) {
	cur := sampleSummary()
	base := sampleSummary()
	base.Findings = base.Findings[:2] // one finding fewer, so the lists are not empty

	dir := t.TempDir()
	p1 := filepath.Join(dir, "one.json")
	p2 := filepath.Join(dir, "two.json")
	if _, err := WriteBaselineDiff(cur, base, p1); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteBaselineDiff(cur, base, p2); err != nil {
		t.Fatal(err)
	}
	b1, err := os.ReadFile(p1)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := os.ReadFile(p2)
	if err != nil {
		t.Fatal(err)
	}
	if string(b1) != string(b2) {
		t.Error("two diffs of the same scan differ")
	}
}

// The fingerprint lists are sorted, so a reader can diff them.
func TestWriteBaselineDiffSortsTheFingerprints(t *testing.T) {
	cur := &scanner.Summary{Findings: []scanner.Finding{
		{Repo: "a", Workflow: "1.yml", Action: "x/y@v1", Category: "malicious"},
		{Repo: "a", Workflow: "2.yml", Action: "x/y@v1", Category: "malicious"},
		{Repo: "a", Workflow: "3.yml", Action: "x/y@v1", Category: "malicious"},
	}}
	p := filepath.Join(t.TempDir(), "diff.json")
	if _, err := WriteBaselineDiff(cur, &scanner.Summary{}, p); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var d BaselineDiff
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	if len(d.New) != 3 {
		t.Fatalf("got %d new fingerprints, want 3", len(d.New))
	}
	for i := 1; i < len(d.New); i++ {
		if d.New[i-1] > d.New[i] {
			t.Errorf("fingerprints are not sorted: %v", d.New)
			break
		}
	}
}

// The dashboard renders a NEW badge by testing each row's fingerprint
// against the new-fingerprint set. This checks the set this package
// hands over is usable that way.
func TestNewFingerprintsRenderAsABadge(t *testing.T) {
	cur := sampleSummary()
	base := sampleSummary()
	base.Findings = base.Findings[:2]
	ApplyBaseline(cur, base, "baseline.json")

	tmpl := template.Must(template.New("t").Parse(
		`{{range .Findings}}{{if index $.NewFingerprints .Fingerprint}}NEW {{end}}{{.Action}};{{end}}`))
	var b strings.Builder
	data := struct {
		*scanner.Summary
		NewFingerprints map[string]bool
	}{cur, NewFingerprints(cur, base)}
	if err := tmpl.Execute(&b, data); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "NEW "+cur.Findings[2].Action) {
		t.Errorf("rendered = %q, want a NEW badge on the new finding", b.String())
	}
	if strings.Contains(b.String(), "NEW "+cur.Findings[0].Action) {
		t.Errorf("rendered = %q, want no NEW badge on an unchanged finding", b.String())
	}
}
