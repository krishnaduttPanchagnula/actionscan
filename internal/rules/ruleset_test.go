package rules

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ── Match ──────────────────────────────────────────────────────────────

func testRuleSet() *RuleSet {
	return &RuleSet{Rules: []Rule{
		{Category: CategoryVulnerable, Repo: "actions/checkout", Range: ">= 1.0.0, < 2.0.0",
			Reason: "ghsa-b", Fix: "fix", Severity: "HIGH", AdvisoryID: "GHSA-b"},
		{Category: CategoryMalicious, Repo: "tj-actions/changed-files", Refs: []string{"v41"},
			Reason: "ghsa-a", Fix: "fix", Severity: "CRITICAL", AdvisoryID: "GHSA-a"},
		{Category: CategoryVulnerable, Repo: "tj-actions/changed-files", Range: "< 46.0.1",
			Reason: "ghsa-c", Fix: "fix", Severity: "HIGH", AdvisoryID: "GHSA-c"},
		{Category: CategoryVulnerable, Repo: "reviewdog/action-setup",
			Reason: "ghsa-d", Fix: "fix", Severity: "MEDIUM", AdvisoryID: "GHSA-d"},
	}}
}

func TestMatchRange(t *testing.T) {
	rs := testRuleSet()
	got := rs.Match("actions/checkout", "v1.5.0")
	if len(got) != 1 || got[0].AdvisoryID != "GHSA-b" {
		t.Errorf("in-range ref: got %+v, want GHSA-b", got)
	}
	if got := rs.Match("actions/checkout", "v2.0.0"); len(got) != 0 {
		t.Errorf("out-of-range ref must not match: %+v", got)
	}
}

func TestMatchIsCaseInsensitiveOnRepo(t *testing.T) {
	rs := testRuleSet()
	if got := rs.Match("ACTIONS/Checkout", "v1.5.0"); len(got) != 1 {
		t.Errorf("case-insensitive repo must match: %+v", got)
	}
	if got := rs.Match("  actions/checkout  ", "v1.5.0"); len(got) != 1 {
		t.Errorf("padded repo must match: %+v", got)
	}
}

func TestMatchExactRef(t *testing.T) {
	rs := testRuleSet()
	got := rs.Match("tj-actions/changed-files", "v41")
	if len(got) != 2 {
		t.Fatalf("v41 must match the exact-ref rule and the range rule, got %+v", got)
	}
	if got[0].AdvisoryID != "GHSA-a" || got[0].Category != CategoryMalicious {
		t.Errorf("most severe rule must come first: %+v", got)
	}
}

func TestMatchSemverEqualRef(t *testing.T) {
	rs := &RuleSet{Rules: []Rule{
		{Category: CategoryMalicious, Repo: "owner/repo", Refs: []string{"1.0.0"}, Severity: "CRITICAL"},
	}}
	if got := rs.Match("owner/repo", "v1.0.0"); len(got) != 1 {
		t.Errorf("semver-equal ref must match: %+v", got)
	}
	if got := rs.Match("owner/repo", "v1.0.1"); len(got) != 0 {
		t.Errorf("different version must not match: %+v", got)
	}
}

func TestMatchExactRefIgnoresRange(t *testing.T) {
	rs := &RuleSet{Rules: []Rule{
		{Category: CategoryMalicious, Repo: "owner/repo", Refs: []string{"v41"}, Range: "< 10.0.0", Severity: "CRITICAL"},
	}}
	if got := rs.Match("owner/repo", "v42"); len(got) != 0 {
		t.Errorf("exact-ref rule must ignore its range: %+v", got)
	}
	if got := rs.Match("owner/repo", "v41"); len(got) != 1 {
		t.Errorf("exact ref must match: %+v", got)
	}
}

func TestMatchUnparsableRef(t *testing.T) {
	rs := testRuleSet()
	if got := rs.Match("actions/checkout", "not-a-version"); len(got) != 0 {
		t.Errorf("unparsable ref must not satisfy a range: %+v", got)
	}
	// A rule without any constraint still matches an unparsable ref.
	if got := rs.Match("reviewdog/action-setup", "not-a-version"); len(got) != 1 {
		t.Errorf("unconstrained rule must match every ref: %+v", got)
	}
}

func TestMatchUnconstrainedRuleMatchesEveryRef(t *testing.T) {
	rs := testRuleSet()
	for _, ref := range []string{"v1", "main", "abc123", ""} {
		if got := rs.Match("reviewdog/action-setup", ref); len(got) != 1 {
			t.Errorf("ref %q must match an unconstrained rule: %+v", ref, got)
		}
	}
}

func TestMatchOrdersBySeverityThenAdvisoryID(t *testing.T) {
	rs := &RuleSet{Rules: []Rule{
		{Repo: "owner/repo", Range: "", Severity: "LOW", AdvisoryID: "GHSA-1"},
		{Repo: "owner/repo", Range: "", Severity: "CRITICAL", AdvisoryID: "GHSA-9"},
		{Repo: "owner/repo", Range: "", Severity: "HIGH", AdvisoryID: "GHSA-5"},
		{Repo: "owner/repo", Range: "", Severity: "MEDIUM", AdvisoryID: "GHSA-3"},
		{Repo: "owner/repo", Range: "", Severity: "HIGH", AdvisoryID: "GHSA-2"},
	}}
	got := rs.Match("owner/repo", "v1")
	want := []string{"GHSA-9", "GHSA-2", "GHSA-5", "GHSA-3", "GHSA-1"}
	if len(got) != len(want) {
		t.Fatalf("got %d rules, want %d", len(got), len(want))
	}
	for i, id := range want {
		if got[i].AdvisoryID != id {
			t.Errorf("rule %d = %q, want %q", i, got[i].AdvisoryID, id)
		}
	}
}

func TestMatchUnknownRepo(t *testing.T) {
	rs := testRuleSet()
	if got := rs.Match("other/action", "v1.5.0"); len(got) != 0 {
		t.Errorf("unknown repo must not match: %+v", got)
	}
}

func TestMatchNilRuleSet(t *testing.T) {
	var rs *RuleSet
	if got := rs.Match("owner/repo", "v1"); got != nil {
		t.Errorf("nil rule set must not match: %+v", got)
	}
}

func TestMatchKeepsDuplicateRepoRangePairs(t *testing.T) {
	// The same package and range published by two advisories must stay
	// two findings.
	rs := &RuleSet{Rules: []Rule{
		{Repo: "owner/repo", Range: "< 1.0.0", Severity: "HIGH", AdvisoryID: "GHSA-1"},
		{Repo: "owner/repo", Range: "< 1.0.0", Severity: "HIGH", AdvisoryID: "GHSA-2"},
	}}
	if got := rs.Match("owner/repo", "v0.5.0"); len(got) != 2 {
		t.Errorf("both advisories must be reported, got %d", len(got))
	}
}

// ── ranges ─────────────────────────────────────────────────────────────

func TestRangeMatches(t *testing.T) {
	tests := []struct {
		ref, rng string
		want     bool
	}{
		{"1.5.0", ">= 1.0.0, < 2.0.0", true},
		{"v1.5.0", ">= 1.0.0, < 2.0.0", true},
		{"2.0.0", ">= 1.0.0, < 2.0.0", false},
		{"3.0.0", ">= 1.0.0, < 2.0.0", false}, // both bounds must hold
		{"45.0.7", "<= 45.0.7", true},
		{"45.0.8", "<= 45.0.7", false},
		{"46.0.1", "< 46.0.1", false},
		{"46.0.0", "< 46.0.1", true},
		{"1.0.0", "= 1", true},  // equality on a partial version
		{"1.5.0", "= 1", false}, // ... and not a tilde range
		{"5.0.0", ">= 5, < 6.4.0", true},
		{"6.4.0", ">= 5, < 6.4.0", false},
		{"1.2.5", "~> 1.2.0", true},
		{"1.3.0", "~> 1.2.0", false},
		{"1.9.0", "^1.2.0", true},
		{"2.0.0", "^1.2.0", false},
		{"2.5.0", "<= 1.0.0 || >= 2.0.0", true},
		{"1.5.0", "<= 1.0.0 || >= 2.0.0", false},
		{"not-a-version", ">= 1.0.0", false},
	}
	for _, tt := range tests {
		if got := rangeMatches(tt.rng, tt.ref); got != tt.want {
			t.Errorf("rangeMatches(%q, %q) = %v, want %v", tt.ref, tt.rng, got, tt.want)
		}
	}
}

// ── helpers ────────────────────────────────────────────────────────────

func TestNormalizeRepo(t *testing.T) {
	tests := map[string]string{
		" Owner/Repo ":                  "owner/repo",
		"owner/repo":                    "owner/repo",
		"OWNER/REPO":                    "owner/repo",
		"aquasecurity/trivy-action":     "aquasecurity/trivy-action",
		"github.com/aquasecurity/trivy": "aquasecurity/trivy",
		"https://github.com/pytorch/pytorch/.github/actions/filter-test-configs": "pytorch/pytorch",
		"@google/gemini-cli":             "google/gemini-cli",
		"super-linter/super-linter/slim": "super-linter/super-linter",
		"https://github.com/owner/repo":  "owner/repo",
		"single":                         "",
		"":                               "",
	}
	for in, want := range tests {
		if got := normalizeRepo(in); got != want {
			t.Errorf("normalizeRepo(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAdvisoryFix(t *testing.T) {
	if got := advisoryFix("owner/repo", "1.2.1"); got != "Upgrade owner/repo to v1.2.1" {
		t.Errorf("fix = %q", got)
	}
	if got := advisoryFix("owner/repo", "v1.2.1"); got != "Upgrade owner/repo to v1.2.1" {
		t.Errorf("fix = %q", got)
	}
	if got := advisoryFix("owner/repo", ""); got != "Remove or replace owner/repo" {
		t.Errorf("fix = %q", got)
	}
	if got := advisoryFix("owner/repo", "none"); got != "Remove or replace owner/repo" {
		t.Errorf("fix = %q", got)
	}
}

func TestSeverityLevel(t *testing.T) {
	tests := map[string]string{
		"critical": "CRITICAL",
		"HIGH":     "HIGH",
		"medium":   "MEDIUM",
		"MODERATE": "MEDIUM",
		"low":      "LOW",
		"":         "MEDIUM",
		"unknown":  "MEDIUM",
	}
	for in, want := range tests {
		if got := severityLevel(in); got != want {
			t.Errorf("severityLevel(%q) = %q, want %q", in, got, want)
		}
	}
}

// ── Load ───────────────────────────────────────────────────────────────

func writeCache(t *testing.T, dir string, c cacheFile) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, cacheFileName)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func withFeedTransport(t *testing.T, rt http.RoundTripper) {
	t.Helper()
	orig := feedClient
	feedClient = &http.Client{Transport: rt}
	t.Cleanup(func() { feedClient = orig })
}

func TestLoadFreshCacheSkipsNetwork(t *testing.T) {
	dir := t.TempDir()
	fetched := time.Now().Add(-1 * time.Hour)
	writeCache(t, dir, cacheFile{
		FetchedAt: fetched,
		Rules: []Rule{
			{Category: CategoryMalicious, Repo: "cached/bad-action", Range: "< 2.0.0", Reason: "cached", Fix: "fix", Severity: "CRITICAL"},
		},
		Sources: []string{"ghsa"},
	})
	withFeedTransport(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		t.Fatal("a fresh cache must not trigger a network request")
		return nil, nil
	}))

	rs, err := Load(context.Background(), LoadOptions{
		CacheDir:    dir,
		TTL:         12 * time.Hour,
		Token:       "tok",
		UseOSV:      true,
		FetchLatest: false,
	})
	if err != nil {
		t.Fatalf("fresh cache load must not error: %v", err)
	}
	if len(rs.Rules) != 1 || rs.Rules[0].Repo != "cached/bad-action" {
		t.Errorf("Rules = %+v, want the cached rule", rs.Rules)
	}
	if got := strings.Join(rs.Sources, ","); got != "ghsa" {
		t.Errorf("Sources = %v, want cached sources", rs.Sources)
	}
	if !rs.UseOSV || rs.FetchLatest {
		t.Errorf("opts not propagated: UseOSV=%v FetchLatest=%v", rs.UseOSV, rs.FetchLatest)
	}
	if !rs.LoadedAt.Equal(fetched) {
		t.Errorf("LoadedAt = %v, want cache time %v", rs.LoadedAt, fetched)
	}
	if rs.Degraded {
		t.Error("a cached rule set is not degraded")
	}
}

func TestLoadDegradedDoesNotPoisonTheCache(t *testing.T) {
	dir := t.TempDir()
	cached := cacheFile{
		FetchedAt: time.Now().Add(-72 * time.Hour), // older than the TTL
		Rules: []Rule{
			{Category: CategoryMalicious, Repo: "stale/action", Range: "< 2.0.0", Reason: "stale", Fix: "fix", Severity: "CRITICAL"},
		},
		Sources: []string{"ghsa"},
	}
	path := writeCache(t, dir, cached)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// A canceled context makes the fetchers fail instantly without
	// touching the network — exercises the offline fallback path.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	rs, err := Load(ctx, LoadOptions{CacheDir: dir, TTL: 12 * time.Hour, UseOSV: false, FetchLatest: true})
	if err == nil {
		t.Fatal("expired cache + unreachable feeds must surface a partial-load error")
	}
	if !strings.Contains(err.Error(), "partial load") {
		t.Errorf("error = %q, want it to mention partial load", err)
	}
	if !rs.Degraded || rs.DegradedReason == "" {
		t.Errorf("a failed load must be degraded with a reason: %+v", rs)
	}
	if len(rs.Rules) == 0 {
		t.Error("a degraded load must still return the builtin fallback rules")
	}
	if !hasRule(rs, "tj-actions/changed-files") {
		t.Errorf("builtin fallback must stay available: %+v", rs.Rules)
	}
	if !hasRule(rs, "reviewdog/action-setup") {
		t.Errorf("builtin fallback must stay available: %+v", rs.Rules)
	}
	if rs.UseOSV || !rs.FetchLatest {
		t.Errorf("opts not propagated: UseOSV=%v FetchLatest=%v", rs.UseOSV, rs.FetchLatest)
	}

	// The stale cache must be left untouched: a degraded rule set must
	// never be written with a fresh timestamp.
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Errorf("cache was rewritten by a degraded load:\nbefore %s\nafter  %s", before, after)
	}
}

func TestLoadSuccessRoundTripsThroughTheCache(t *testing.T) {
	dir := t.TempDir()
	withFeedTransport(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.String(), "api.github.com/advisories") {
			return fakeResp(200, `[{"ghsa_id":"GHSA-1","summary":"one","severity":"critical",`+
				`"vulnerabilities":[{"package":{"ecosystem":"actions","name":"owner/repo"},`+
				`"vulnerable_version_range":"< 2.0.0","first_patched_version":{"identifier":"2.0.0"}}]}]`, r), nil
		}
		return fakeResp(200, `[]`, r), nil
	}))

	rs, err := Load(context.Background(), LoadOptions{CacheDir: dir, TTL: 12 * time.Hour})
	if err != nil {
		t.Fatalf("load must succeed: %v", err)
	}
	if rs.Degraded {
		t.Errorf("a successful load must not be degraded: %s", rs.DegradedReason)
	}
	if len(rs.Rules) != 1 || rs.Rules[0].AdvisoryID != "GHSA-1" {
		t.Fatalf("Rules = %+v", rs.Rules)
	}

	// The cache must hold the rules and be reused on the next load.
	cached, err := Load(context.Background(), LoadOptions{CacheDir: dir, TTL: 12 * time.Hour})
	if err != nil {
		t.Fatalf("cached load must not error: %v", err)
	}
	if len(cached.Rules) != 1 || cached.Rules[0].AdvisoryID != "GHSA-1" {
		t.Errorf("cached rules = %+v", cached.Rules)
	}
	if !cached.LoadedAt.Equal(rs.LoadedAt) {
		t.Errorf("cached LoadedAt = %v, want %v", cached.LoadedAt, rs.LoadedAt)
	}
}

func TestLoadWritesTheCacheAtomically(t *testing.T) {
	dir := t.TempDir()
	withFeedTransport(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return fakeResp(200, `[]`, r), nil
	}))

	if _, err := Load(context.Background(), LoadOptions{CacheDir: dir, TTL: time.Hour}); err != nil {
		t.Fatalf("load must succeed: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	for _, n := range names {
		if n != cacheFileName {
			t.Errorf("unexpected leftover file %q (cache write is not atomic)", n)
		}
	}
	data, err := os.ReadFile(filepath.Join(dir, cacheFileName))
	if err != nil {
		t.Fatal(err)
	}
	var c cacheFile
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatalf("cache file must hold valid JSON: %v", err)
	}
	if c.FetchedAt.IsZero() {
		t.Error("cache file must carry a fetch timestamp")
	}
}

func TestLoadCorruptCacheRecovers(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, cacheFileName), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // force offline fallback

	rs, err := Load(ctx, LoadOptions{CacheDir: dir, TTL: time.Hour})
	if err == nil {
		t.Fatal("corrupt cache + unreachable feeds must error")
	}
	if rs == nil {
		t.Fatal("Load must always return a usable RuleSet, even on error")
	}
	if len(rs.Rules) == 0 {
		t.Error("corrupt cache must fall back to builtin rules")
	}
}

func hasRule(rs *RuleSet, repo string) bool {
	for _, r := range rs.Rules {
		if r.Repo == repo {
			return true
		}
	}
	return false
}
