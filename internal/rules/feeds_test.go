package rules

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// roundTripFunc lets tests serve canned HTTP responses without a server.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func fakeResp(status int, body string, req *http.Request) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
		Request:    req,
	}
}

func clientReturning(status int, body string) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return fakeResp(status, body, r), nil
	})}
}

// ── FetchMalicious ─────────────────────────────────────────────────────

func TestFetchMalicious_ArraySchema(t *testing.T) {
	body := `[{
		"repo": "tj-actions/changed-files",
		"refs": ["v41", "v42"],
		"advisory_id": "GHSA-xxxx-yyyy-zzzz",
		"description": "dumped runner memory"
	}]`
	got, err := FetchMalicious(context.Background(), clientReturning(200, body), "https://feed.example/x.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	e := got[0]
	if e.Repo != "tj-actions/changed-files" || e.AdvisoryID != "GHSA-xxxx-yyyy-zzzz" ||
		len(e.Refs) != 2 || e.Refs[0] != "v41" {
		t.Errorf("entry = %+v, fields not mapped from json tags", e)
	}
}

func TestFetchMalicious_MapSchema(t *testing.T) {
	body := `{"reviewdog/action-setup": {"refs": [], "description": "injected code"}}`
	got, err := FetchMalicious(context.Background(), clientReturning(200, body), "https://feed.example/x.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Repo != "reviewdog/action-setup" {
		t.Errorf("map-schema repo key not captured: %+v", got)
	}
	if got[0].Description != "injected code" {
		t.Errorf("description = %q", got[0].Description)
	}
}

func TestFetchMalicious_CommitSchema(t *testing.T) {
	body := `{"compromised":[
		{"sha":"0e58ed8671d6b60d0890c21b07f8835ace038e67","action":"tj-actions/changed-files","incident":"retagged"}
	]}`
	got, err := FetchMalicious(context.Background(), clientReturning(200, body), "https://feed.example/x.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	if got[0].Repo != "tj-actions/changed-files" || len(got[0].Refs) != 1 ||
		got[0].Refs[0] != "0e58ed8671d6b60d0890c21b07f8835ace038e67" {
		t.Errorf("commit entry = %+v", got[0])
	}
}

func TestFetchMalicious_HTTPError(t *testing.T) {
	_, err := FetchMalicious(context.Background(), clientReturning(500, "boom"), "https://feed.example/x.json")
	if err == nil || !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("err = %v, want HTTP 500", err)
	}
}

func TestFetchMalicious_UnrecognizedSchema(t *testing.T) {
	_, err := FetchMalicious(context.Background(), clientReturning(200, `"just a string"`), "https://feed.example/x.json")
	if err == nil || !strings.Contains(err.Error(), "unrecognized schema") {
		t.Errorf("err = %v, want unrecognized schema", err)
	}
}

func TestFetchMalicious_EmptyArrayIsValid(t *testing.T) {
	got, err := FetchMalicious(context.Background(), clientReturning(200, `[]`), "https://feed.example/x.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("got %d entries, want 0", len(got))
	}
}

func TestFetchMalicious_EmptyURLIsSkipped(t *testing.T) {
	got, err := FetchMalicious(context.Background(), clientReturning(500, "boom"), "")
	if err != nil || got != nil {
		t.Errorf("got (%v, %v), want (nil, nil)", got, err)
	}
}

// ── FetchAdvisories ────────────────────────────────────────────────────

func TestFetchAdvisories_PaginatesUntilEmpty(t *testing.T) {
	var pages []string
	hc := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		page := r.URL.Query().Get("page")
		pages = append(pages, page)
		switch page {
		case "1":
			return fakeResp(200, `[{"ghsa_id":"GHSA-1","summary":"one"}]`, r), nil
		case "2":
			return fakeResp(200, `[{"ghsa_id":"GHSA-2","summary":"two"}]`, r), nil
		default:
			return fakeResp(200, `[]`, r), nil
		}
	})}

	got, err := FetchAdvisories(context.Background(), hc, "tok-123")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].GHSAID != "GHSA-1" || got[1].GHSAID != "GHSA-2" {
		t.Errorf("got %+v, want both pages concatenated in order", got)
	}
	if len(pages) != 3 {
		t.Errorf("requested pages %v, want 3 requests (stop on empty)", pages)
	}
}

func TestFetchAdvisories_SendsAuthAndAcceptHeaders(t *testing.T) {
	var auth, accept string
	hc := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		auth = r.Header.Get("Authorization")
		accept = r.Header.Get("Accept")
		return fakeResp(200, `[]`, r), nil
	})}

	if _, err := FetchAdvisories(context.Background(), hc, "secret"); err != nil {
		t.Fatal(err)
	}
	if auth != "Bearer secret" {
		t.Errorf("Authorization = %q, want \"Bearer secret\"", auth)
	}
	if accept != "application/vnd.github+json" {
		t.Errorf("Accept = %q", accept)
	}
}

func TestFetchAdvisories_OmitsAuthWithoutToken(t *testing.T) {
	var auth string
	hc := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		auth = r.Header.Get("Authorization")
		return fakeResp(200, `[]`, r), nil
	})}

	if _, err := FetchAdvisories(context.Background(), hc, ""); err != nil {
		t.Fatal(err)
	}
	if auth != "" {
		t.Errorf("Authorization = %q, want empty without token", auth)
	}
}

func TestFetchAdvisories_StopsAtPageCap(t *testing.T) {
	var requests int32
	hc := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		atomic.AddInt32(&requests, 1)
		// Never-empty feed: the 50-page safety cap must stop the loop.
		page := r.URL.Query().Get("page")
		return fakeResp(200, `[{"ghsa_id":"GHSA-`+page+`","summary":"s"}]`, r), nil
	})}

	got, err := FetchAdvisories(context.Background(), hc, "tok")
	if err != nil {
		t.Fatal(err)
	}
	n := atomic.LoadInt32(&requests)
	if n != 50 {
		t.Errorf("requests = %d, want exactly 50 (page cap)", n)
	}
	if len(got) != 50 {
		t.Errorf("advisories = %d, want 50", len(got))
	}
}

func TestFetchAdvisories_StopsOnRepeatedPage(t *testing.T) {
	// The endpoint answers with the same page when the result set fits on
	// one page: the loader must not ask for it 50 times.
	var requests int32
	hc := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		atomic.AddInt32(&requests, 1)
		return fakeResp(200, `[{"ghsa_id":"GHSA-1","summary":"s"}]`, r), nil
	})}

	got, err := FetchAdvisories(context.Background(), hc, "tok")
	if err != nil {
		t.Fatal(err)
	}
	if n := atomic.LoadInt32(&requests); n != 2 {
		t.Errorf("requests = %d, want 2 (second page repeats the first)", n)
	}
	if len(got) != 2 {
		t.Errorf("advisories = %d, want 2", len(got))
	}
}

func TestFetchAdvisories_DecodeErrorSurfaces(t *testing.T) {
	hc := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return fakeResp(200, `not json`, r), nil
	})}
	if _, err := FetchAdvisories(context.Background(), hc, "tok"); err == nil {
		t.Error("invalid JSON body must produce an error")
	}
}

func TestFetchAdvisories_HTTPErrorSurfaces(t *testing.T) {
	hc := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return fakeResp(403, `rate limited`, r), nil
	})}
	if _, err := FetchAdvisories(context.Background(), hc, "tok"); err == nil ||
		!strings.Contains(err.Error(), "HTTP 403") {
		t.Errorf("err = %v, want HTTP 403", err)
	}
}

// ── advisory parsing ───────────────────────────────────────────────────

func advisoryWith(pkg, ecosystem, rng, patched string) GHAdvisory {
	a := GHAdvisory{GHSAID: "GHSA-x", Summary: "summary", Severity: "high"}
	v := GHVulnerability{VulnerableVersionRange: rng}
	v.Package.Ecosystem = ecosystem
	v.Package.Name = pkg
	if patched != "" {
		v.FirstPatchedVersion = &PatchedVersion{Identifier: patched}
	}
	a.Vulnerabilities = []GHVulnerability{v}
	return a
}

func TestRulesFromAdvisories_UsesFirstPatchedVersion(t *testing.T) {
	rules := rulesFromAdvisories([]GHAdvisory{advisoryWith("owner/repo", "actions", "< 2.0.0", "2.0.0")})
	if len(rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(rules))
	}
	if rules[0].Fix != "Upgrade owner/repo to v2.0.0" {
		t.Errorf("fix = %q, want the first_patched_version to drive it", rules[0].Fix)
	}
	if rules[0].AdvisoryID != "GHSA-x" || rules[0].AdvisoryURL != "https://github.com/advisories/GHSA-x" {
		t.Errorf("advisory reference = %+v", rules[0])
	}
}

func TestRulesFromAdvisories_ToleratesPatchedVersions(t *testing.T) {
	a := advisoryWith("owner/repo", "actions", "< 2.0.0", "")
	a.Vulnerabilities[0].PatchedVersions = "2.0.1"
	rules := rulesFromAdvisories([]GHAdvisory{a})
	if len(rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(rules))
	}
	if rules[0].Fix != "Upgrade owner/repo to v2.0.1" {
		t.Errorf("fix = %q, want the legacy patched_versions to be tolerated", rules[0].Fix)
	}
}

func TestRulesFromAdvisories_NoPatchMeansRemove(t *testing.T) {
	rules := rulesFromAdvisories([]GHAdvisory{advisoryWith("owner/repo", "actions", "< 2.0.0", "")})
	if len(rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(rules))
	}
	if rules[0].Fix != "Remove or replace owner/repo" {
		t.Errorf("fix = %q", rules[0].Fix)
	}
}

func TestRulesFromAdvisories_DropsWithdrawn(t *testing.T) {
	a := advisoryWith("owner/repo", "actions", "< 2.0.0", "2.0.0")
	now := time.Now()
	a.WithdrawnAt = &now
	if rules := rulesFromAdvisories([]GHAdvisory{a}); len(rules) != 0 {
		t.Errorf("withdrawn advisories must be dropped, got %+v", rules)
	}
}

func TestRulesFromAdvisories_DropsOtherEcosystems(t *testing.T) {
	rules := rulesFromAdvisories([]GHAdvisory{
		advisoryWith("github.com/owner/repo", "go", "< 2.0.0", "2.0.0"),
		advisoryWith("owner/repo", "npm", "< 2.0.0", "2.0.0"),
		advisoryWith("owner/repo", "actions", "< 2.0.0", "2.0.0"),
	})
	if len(rules) != 1 {
		t.Fatalf("got %d rules, want only the actions one: %+v", len(rules), rules)
	}
	if rules[0].Repo != "owner/repo" {
		t.Errorf("repo = %q", rules[0].Repo)
	}
}

func TestRulesFromAdvisories_NormalizesPackageNames(t *testing.T) {
	names := []string{
		"aquasecurity/trivy-action",
		"github.com/aquasecurity/trivy",
		"https://github.com/pytorch/pytorch/.github/actions/filter-test-configs",
		"@google/gemini-cli",
		"super-linter/super-linter/slim",
	}
	for _, n := range names {
		rules := rulesFromAdvisories([]GHAdvisory{advisoryWith(n, "actions", "< 2.0.0", "2.0.0")})
		if len(rules) != 1 {
			t.Fatalf("%q: got %d rules, want 1", n, len(rules))
		}
		if rules[0].Repo != normalizeRepo(n) {
			t.Errorf("%q: repo = %q, want %q", n, rules[0].Repo, normalizeRepo(n))
		}
		if !strings.Contains(rules[0].Repo, "/") {
			t.Errorf("%q: repo = %q, want owner/repo", n, rules[0].Repo)
		}
	}
}

func TestRulesFromAdvisories_CarriesSeverity(t *testing.T) {
	a := advisoryWith("owner/repo", "actions", "< 2.0.0", "2.0.0")
	a.Severity = "critical"
	rules := rulesFromAdvisories([]GHAdvisory{a})
	if rules[0].Severity != "CRITICAL" {
		t.Errorf("severity = %q, want CRITICAL", rules[0].Severity)
	}
	a.Severity = "low"
	rules = rulesFromAdvisories([]GHAdvisory{a})
	if rules[0].Severity != "LOW" {
		t.Errorf("severity = %q, want LOW", rules[0].Severity)
	}
}

func TestRulesFromAdvisories_KeepsDuplicateRepoRangePairs(t *testing.T) {
	a := advisoryWith("owner/repo", "actions", "< 2.0.0", "2.0.0")
	b := advisoryWith("owner/repo", "actions", "< 2.0.0", "2.0.0")
	b.GHSAID = "GHSA-y"
	rules := rulesFromAdvisories([]GHAdvisory{a, b})
	if len(rules) != 2 {
		t.Fatalf("got %d rules, want both advisories", len(rules))
	}
	if rules[0].AdvisoryID == rules[1].AdvisoryID {
		t.Errorf("duplicate advisories collapsed: %+v", rules)
	}
}

// ── compromise classification ──────────────────────────────────────────

func TestCompromiseClassification(t *testing.T) {
	cwe := advisoryWith("owner/repo", "actions", "< 46.0.1", "46.0.1")
	cwe.CWEs = append(cwe.CWEs, struct {
		CWEID string `json:"cwe_id"`
		Name  string `json:"name"`
	}{CWEID: "CWE-506", Name: "Embedded Malicious Code"})

	rules := rulesFromAdvisories([]GHAdvisory{cwe})
	if len(rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(rules))
	}
	if rules[0].Category != CategoryMalicious {
		t.Errorf("category = %q, want %q", rules[0].Category, CategoryMalicious)
	}
	if rules[0].Severity != "CRITICAL" {
		t.Errorf("severity = %q, want CRITICAL", rules[0].Severity)
	}
}

func TestCompromiseClassification_SummaryPatterns(t *testing.T) {
	summaries := []string{
		"tj-actions changed-files was compromised",
		"xygeni-action v5 tag poisoned with C2 backdoor",
		"Malicious code shipped in the release",
		"A supply chain attack hit the action",
		"Maintainer account hijacked",
		"Backdoor in the build step",
	}
	for _, s := range summaries {
		a := advisoryWith("owner/repo", "actions", "< 2.0.0", "2.0.0")
		a.Summary = s
		rules := rulesFromAdvisories([]GHAdvisory{a})
		if len(rules) != 1 {
			t.Fatalf("%q: got %d rules, want 1", s, len(rules))
		}
		if rules[0].Category != CategoryMalicious || rules[0].Severity != "CRITICAL" {
			t.Errorf("%q: rule = %+v, want a malicious CRITICAL rule", s, rules[0])
		}
	}
}

func TestCompromiseClassification_OrdinaryVulnerability(t *testing.T) {
	a := advisoryWith("owner/repo", "actions", "< 2.0.0", "2.0.0")
	a.Summary = "Potential Actions command injection in output filenames"
	a.Severity = "high"
	rules := rulesFromAdvisories([]GHAdvisory{a})
	if len(rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(rules))
	}
	if rules[0].Category != CategoryVulnerable {
		t.Errorf("category = %q, want %q", rules[0].Category, CategoryVulnerable)
	}
	if rules[0].Severity != "HIGH" {
		t.Errorf("severity = %q, want HIGH", rules[0].Severity)
	}
}

// ── default fallback lists ─────────────────────────────────────────────

func TestBuiltinFallbackListsAreSane(t *testing.T) {
	if len(DefaultMalicious) == 0 {
		t.Fatal("DefaultMalicious must never be empty")
	}
	seen := map[string]bool{}
	for _, r := range DefaultMalicious {
		if !strings.Contains(r.Repo, "/") {
			t.Errorf("DefaultMalicious repo %q must be owner/repo", r.Repo)
		}
		if r.Reason == "" {
			t.Errorf("DefaultMalicious %q missing reason", r.Repo)
		}
		if r.Fix == "" {
			t.Errorf("DefaultMalicious %q missing fix", r.Repo)
		}
		if r.Category != CategoryMalicious {
			t.Errorf("DefaultMalicious %q category = %q", r.Repo, r.Category)
		}
		if r.Severity != "CRITICAL" {
			t.Errorf("DefaultMalicious %q severity = %q", r.Repo, r.Severity)
		}
		if seen[r.Repo] {
			t.Errorf("duplicate DefaultMalicious entry: %q", r.Repo)
		}
		seen[r.Repo] = true
	}
	for _, repo := range []string{"tj-actions/changed-files", "reviewdog/action-setup", "aquasecurity/trivy-action", "xygeni/xygeni-action"} {
		if !seen[repo] {
			t.Errorf("DefaultMalicious must keep %q detectable offline", repo)
		}
	}
	if len(DefaultVulnerable) == 0 {
		t.Fatal("DefaultVulnerable must never be empty")
	}
	for _, r := range DefaultVulnerable {
		if !strings.Contains(r.Repo, "/") {
			t.Errorf("DefaultVulnerable repo %q must be owner/repo", r.Repo)
		}
		if r.Reason == "" {
			t.Errorf("DefaultVulnerable %q missing reason", r.Repo)
		}
		if r.Fix == "" {
			t.Errorf("DefaultVulnerable %q missing fix", r.Repo)
		}
		if r.Category != CategoryVulnerable {
			t.Errorf("DefaultVulnerable %q category = %q", r.Repo, r.Category)
		}
	}
}

func TestBuiltinFallbacksMatchOffline(t *testing.T) {
	rs := &RuleSet{Rules: append(append([]Rule{}, DefaultMalicious...), DefaultVulnerable...)}
	cases := []struct {
		repo, ref string
		want      bool
	}{
		{"tj-actions/changed-files", "v45.0.7", true},
		{"tj-actions/changed-files", "v46.0.1", false},
		{"reviewdog/action-setup", "v1", true},
		{"reviewdog/action-setup", "v2", false},
		{"aquasecurity/trivy-action", "v0.34.0", true},
		{"aquasecurity/trivy-action", "v0.35.0", false},
		{"xygeni/xygeni-action", "v5.1.0", true},
		{"xygeni/xygeni-action", "v6.4.0", false},
		{"actions/checkout", "v2", true},
		{"actions/checkout", "v4", false},
	}
	for _, tt := range cases {
		got := len(rs.Match(tt.repo, tt.ref)) > 0
		if got != tt.want {
			t.Errorf("Match(%q, %q) = %v, want %v", tt.repo, tt.ref, got, tt.want)
		}
	}
}

// ── serialization ──────────────────────────────────────────────────────

func TestRuleJSONShape(t *testing.T) {
	b, err := json.Marshal(Rule{
		Category: CategoryMalicious, Repo: "owner/repo", Range: "< 2.0.0",
		Reason: "r", Fix: "f", Severity: "CRITICAL", AdvisoryID: "GHSA-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"category", "repo", "range", "reason", "fix", "severity", "advisory_id"} {
		if _, ok := m[key]; !ok {
			t.Errorf("missing json key %q in %s", key, b)
		}
	}
	if _, ok := m["refs"]; ok {
		t.Errorf("empty refs must be omitted: %s", b)
	}
}
