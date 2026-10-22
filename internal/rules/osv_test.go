package rules

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withOSVTransport swaps the package-level osvClient for a stubbed
// transport for the duration of one test.
func withOSVTransport(t *testing.T, rt http.RoundTripper) {
	t.Helper()
	orig := osvClient
	osvClient = &http.Client{Transport: rt}
	t.Cleanup(func() { osvClient = orig })
}

func TestQueryOSV_Success(t *testing.T) {
	var gotBody []byte
	var gotPath, gotMethod, gotCT string
	withOSVTransport(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotCT = r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		return fakeResp(200, `{"vulns":[{"id":"GHSA-1","summary":"RCE"}]}`, r), nil
	}))

	vulns, err := QueryOSV(context.Background(), "actions/checkout")
	if err != nil {
		t.Fatal(err)
	}
	if len(vulns) != 1 || vulns[0].ID != "GHSA-1" {
		t.Fatalf("vulns = %+v", vulns)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/query" {
		t.Errorf("request = %s %s, want POST /v1/query", gotMethod, gotPath)
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q", gotCT)
	}

	var q OSVQuery
	if err := json.Unmarshal(gotBody, &q); err != nil {
		t.Fatal(err)
	}
	if q.Package.Name != "actions/checkout" {
		t.Errorf("package name = %q", q.Package.Name)
	}
	if q.Package.Ecosystem != "GitHub Actions" {
		t.Errorf("ecosystem = %q, want %q", q.Package.Ecosystem, "GitHub Actions")
	}

	// The query must carry no version: OSV does not answer version
	// queries for this ecosystem.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(gotBody, &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["version"]; ok {
		t.Errorf("query must not carry a version: %s", gotBody)
	}
	if pkg, ok := raw["package"]; ok {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(pkg, &fields); err != nil {
			t.Fatal(err)
		}
		if _, ok := fields["version"]; ok {
			t.Errorf("package must not carry a version: %s", gotBody)
		}
	}
}

func TestQueryOSV_SourceHasNoWrongEcosystem(t *testing.T) {
	// The OSV ecosystem is spelled with a space. The variant without one
	// is rejected by the API with HTTP 400 and must not exist anywhere
	// in this package.
	forbidden := "GitHub" + "Actions"
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(".", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), forbidden) {
			t.Errorf("%s contains the invalid ecosystem spelling", e.Name())
		}
	}
}

func TestQueryOSV_EmptyRepoSkipsRequest(t *testing.T) {
	withOSVTransport(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		t.Fatal("no request must be sent for an empty repository")
		return nil, nil
	}))

	vulns, err := QueryOSV(context.Background(), "")
	if err != nil || vulns != nil {
		t.Errorf("got (%v, %v), want (nil, nil)", vulns, err)
	}
}

func TestQueryOSV_NotFoundMeansNoVulns(t *testing.T) {
	withOSVTransport(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return fakeResp(404, ``, r), nil
	}))

	vulns, err := QueryOSV(context.Background(), "actions/checkout")
	if err != nil || vulns != nil {
		t.Errorf("got (%v, %v), want (nil, nil)", vulns, err)
	}
}

func TestQueryOSV_ServerError(t *testing.T) {
	withOSVTransport(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return fakeResp(503, `unavailable`, r), nil
	}))

	if _, err := QueryOSV(context.Background(), "actions/checkout"); err == nil ||
		!strings.Contains(err.Error(), "HTTP 503") {
		t.Errorf("err = %v, want HTTP 503", err)
	}
}

func TestQueryOSV_CanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	vulns, err := QueryOSV(ctx, "actions/checkout")
	if err == nil {
		t.Fatal("canceled context must error")
	}
	if vulns != nil {
		t.Errorf("vulns = %v, want nil", vulns)
	}
}

// ── range matching ─────────────────────────────────────────────────────

const changedFilesVuln = `{
  "id": "GHSA-mrrh-fwg8-r2c3",
  "summary": "tj-actions changed-files through 45.0.7 allows remote attackers to discover secrets",
  "aliases": ["CVE-2025-30066"],
  "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N/E:H"}],
  "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-506"]},
  "affected": [{
    "package": {"name": "tj-actions/changed-files", "ecosystem": "GitHub Actions"},
    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "46.0.1"}]}]
  }]
}`

func parseVuln(t *testing.T, body string) OSVVuln {
	t.Helper()
	var v OSVVuln
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestAffects(t *testing.T) {
	v := parseVuln(t, changedFilesVuln)
	tests := []struct {
		ref  string
		want bool
	}{
		{"v45.0.7", true},
		{"45.0.7", true},
		{"v46.0.1", false}, // the fixed version is not affected
		{"v46.0.0", true},
		{"v47.0.0", false},
		{"v0.1.0", true},
		{"not-a-version", false}, // a ref that is not a version never matches
	}
	for _, tt := range tests {
		if got := v.Affects(tt.ref); got != tt.want {
			t.Errorf("Affects(%q) = %v, want %v", tt.ref, got, tt.want)
		}
	}
}

func TestAffects_IgnoresOtherEcosystemsAndGitRanges(t *testing.T) {
	v := parseVuln(t, `{
      "id": "GHSA-x",
      "affected": [
        {"package": {"name": "github.com/owner/repo", "ecosystem": "Go"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]},
        {"package": {"name": "owner/repo", "ecosystem": "GitHub Actions"},
         "ranges": [{"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "abc123"}]}]}
      ]
    }`)
	if v.Affects("1.0.0") {
		t.Error("a Go ecosystem range must not match an action ref")
	}
}

func TestAffects_LastAffected(t *testing.T) {
	v := parseVuln(t, `{
      "id": "GHSA-x",
      "affected": [{
        "package": {"name": "owner/repo", "ecosystem": "GitHub Actions"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"last_affected": "2.0.0"}]}]
      }]
    }`)
	if !v.Affects("2.0.0") {
		t.Error("last_affected is an inclusive bound")
	}
	if v.Affects("2.0.1") {
		t.Error("a ref after last_affected must not match")
	}
	if v.Affects("0.9.0") {
		t.Error("a ref before introduced must not match")
	}
}

func TestFixedVersion(t *testing.T) {
	v := parseVuln(t, changedFilesVuln)
	if got := v.FixedVersion(); got != "46.0.1" {
		t.Errorf("FixedVersion = %q, want 46.0.1", got)
	}
}

func TestOSVSeverityLevel(t *testing.T) {
	v := parseVuln(t, changedFilesVuln)
	if got := v.SeverityLevel(); got != "HIGH" {
		t.Errorf("SeverityLevel = %q, want HIGH", got)
	}

	crit := parseVuln(t, `{"id":"x","database_specific":{"severity":"CRITICAL"}}`)
	if got := crit.SeverityLevel(); got != "CRITICAL" {
		t.Errorf("SeverityLevel = %q, want CRITICAL", got)
	}
	mod := parseVuln(t, `{"id":"x","database_specific":{"severity":"MODERATE"}}`)
	if got := mod.SeverityLevel(); got != "MEDIUM" {
		t.Errorf("SeverityLevel = %q, want MEDIUM", got)
	}
	cvss := parseVuln(t, `{"id":"x","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N"}]}`)
	if got := cvss.SeverityLevel(); got != "HIGH" {
		t.Errorf("SeverityLevel = %q, want HIGH", got)
	}
	none := parseVuln(t, `{"id":"x"}`)
	if got := none.SeverityLevel(); got != "MEDIUM" {
		t.Errorf("SeverityLevel = %q, want MEDIUM", got)
	}
}

func TestOSVVulnParsesAdvisoryFields(t *testing.T) {
	v := parseVuln(t, changedFilesVuln)
	if v.ID != "GHSA-mrrh-fwg8-r2c3" {
		t.Errorf("id = %q", v.ID)
	}
	if len(v.Aliases) != 1 || v.Aliases[0] != "CVE-2025-30066" {
		t.Errorf("aliases = %v", v.Aliases)
	}
	if v.Summary == "" {
		t.Error("summary must be captured")
	}
	if len(v.Severity) != 1 || v.Severity[0].Type != "CVSS_V3" || v.Severity[0].Score == "" {
		t.Errorf("severity = %+v", v.Severity)
	}
	if v.DatabaseSpecific.Severity != "HIGH" {
		t.Errorf("database_specific severity = %q", v.DatabaseSpecific.Severity)
	}
	if len(v.DatabaseSpecific.CWEIDs) != 1 || v.DatabaseSpecific.CWEIDs[0] != "CWE-506" {
		t.Errorf("database_specific cwe_ids = %v", v.DatabaseSpecific.CWEIDs)
	}
}
