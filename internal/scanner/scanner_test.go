package scanner

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/krishnaduttPanchagnula/actionscan/internal/github"
	"github.com/krishnaduttPanchagnula/actionscan/internal/rules"
)

// ── fakes ──────────────────────────────────────────────────────────────

// fakeClient implements the scanner.Client interface so tests never
// touch the network.
type fakeClient struct {
	mu          sync.Mutex
	workflows   map[string]map[string][]byte // repo full name -> file name -> content
	workflowErr map[string]error
	latest      map[string]string
	latestCalls map[string]int
	shas        map[string]string // "repo@shortsha" -> full 40-char sha
	shaCalls    int
}

func (f *fakeClient) ListWorkflows(_ context.Context, r github.Repo) (map[string][]byte, error) {
	if err, ok := f.workflowErr[r.FullName]; ok {
		return nil, err
	}
	return f.workflows[r.FullName], nil
}

func (f *fakeClient) LatestTag(_ context.Context, actionRepo string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.latestCalls == nil {
		f.latestCalls = map[string]int{}
	}
	f.latestCalls[actionRepo]++
	return f.latest[actionRepo]
}

// ResolveSHA implements Client; tests seed f.shas to simulate GitHub
// expanding a short SHA, or leave it empty for the "unresolvable" path.
func (f *fakeClient) ResolveSHA(_ context.Context, actionRepo, short string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.shaCalls++
	return f.shas[actionRepo+"@"+short]
}

func (f *fakeClient) calls(repo string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.latestCalls[repo]
}

// stubOSV replaces the package-level queryOSV hook for one test.
func stubOSV(t *testing.T, fn func(ctx context.Context, repo, version string) ([]rules.OSVVuln, error)) {
	t.Helper()
	orig := queryOSV
	queryOSV = fn
	t.Cleanup(func() { queryOSV = orig })
}

// noOSV installs a deterministic empty OSV stub so tests never touch
// the real api.osv.dev endpoint.
func noOSV(t *testing.T) {
	t.Helper()
	stubOSV(t, func(_ context.Context, _, _ string) ([]rules.OSVVuln, error) {
		return nil, nil
	})
}

func countingOSV(t *testing.T, vulns []rules.OSVVuln) *int {
	t.Helper()
	calls := 0
	stubOSV(t, func(_ context.Context, _, _ string) ([]rules.OSVVuln, error) {
		calls++
		return vulns, nil
	})
	return &calls
}

func testRuleSet() *rules.RuleSet {
	return &rules.RuleSet{
		OSVCache:    map[string][]rules.OSVVuln{},
		LatestTags:  map[string]string{},
		UseOSV:      true,
		FetchLatest: true,
	}
}

func newTestScanner(c *fakeClient, rs *rules.RuleSet) *Scanner {
	if rs == nil {
		rs = testRuleSet()
	}
	return &Scanner{Client: c, RuleSet: rs}
}

func findByCategory(fs []Finding, cat string) []Finding {
	var out []Finding
	for _, f := range fs {
		if f.Category == cat {
			out = append(out, f)
		}
	}
	return out
}

// ── ExtractActions ─────────────────────────────────────────────────────

func TestExtractActions(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want []string
	}{
		{
			name: "standard list-step syntax",
			yaml: "steps:\n  - uses: actions/checkout@v4\n  - uses: actions/setup-node@v4\n",
			want: []string{"actions/checkout@v4", "actions/setup-node@v4"},
		},
		{
			name: "mixed list and reduced form",
			yaml: "steps:\n  - uses: actions/checkout@v4\n  - name: Setup\n    uses: actions/setup-node@v4\n",
			want: []string{"actions/checkout@v4", "actions/setup-node@v4"},
		},
		{
			name: "double-quoted value",
			yaml: "- uses: \"actions/checkout@v4\"\n",
			want: []string{"actions/checkout@v4"},
		},
		{
			name: "single-quoted value",
			yaml: "- uses: 'actions/checkout@v4'\n",
			want: []string{"actions/checkout@v4"},
		},
		{
			name: "trailing comment stripped",
			yaml: "- uses: actions/checkout@v4 # pin me\n",
			want: []string{"actions/checkout@v4"},
		},
		{
			name: "empty value skipped",
			yaml: "- uses:\n- uses:   \n",
			want: nil,
		},
		{
			name: "CRLF line endings",
			yaml: "- uses: actions/checkout@v4\r\n  uses: actions/cache@v4\r\n",
			want: []string{"actions/checkout@v4", "actions/cache@v4"},
		},
		{
			name: "no trailing newline",
			yaml: "- uses: actions/checkout@v4",
			want: []string{"actions/checkout@v4"},
		},
		{
			name: "ignores unrelated lines",
			yaml: "name: CI\non: push\nruns-on: ubuntu-latest\n",
			want: nil,
		},
		{
			name: "malicious example from real workflows",
			yaml: "jobs:\n  build:\n    steps:\n      - uses: tj-actions/changed-files@v41\n",
			want: []string{"tj-actions/changed-files@v41"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractActions([]byte(tt.yaml))
			if len(got) != len(tt.want) {
				t.Fatalf("ExtractActions() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("ExtractActions()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// ── Check ──────────────────────────────────────────────────────────────

func TestCheck_NoRefIsUnpinned(t *testing.T) {
	s := newTestScanner(&fakeClient{}, nil)
	got := s.Check(context.Background(), "acme/app", "ci.yml", "actions/checkout")

	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(got), got)
	}
	f := got[0]
	if f.Severity != "MEDIUM" || f.Category != "unpinned" {
		t.Errorf("got %s/%s, want MEDIUM/unpinned", f.Severity, f.Category)
	}
	if f.Ref != "" {
		t.Errorf("ref = %q, want empty", f.Ref)
	}
}

func TestCheck_MaliciousShortCircuits(t *testing.T) {
	rs := testRuleSet()
	rs.Malicious = []rules.CompromisedEntry{{
		Repo:        "TJ-Actions/Changed-Files",
		Description: "dumped runner memory",
	}}
	// Would also match the GHSA layer — malicious must win alone.
	rs.Vulnerable = map[string]rules.VulnRule{
		"tj-actions/changed-files@>= 1.0.0": {Reason: "should never surface", Fix: "should never surface"},
	}
	calls := countingOSV(t, []rules.OSVVuln{{ID: "GHSA-should-not-appear"}})
	c := &fakeClient{latest: map[string]string{"tj-actions/changed-files": "v99.0.0"}}
	s := newTestScanner(c, rs)

	got := s.Check(context.Background(), "acme/app", "ci.yml", "tj-actions/changed-files@v41")

	if len(got) != 1 {
		t.Fatalf("expected only the CRITICAL finding, got %d: %+v", len(got), got)
	}
	f := got[0]
	if f.Severity != "CRITICAL" || f.Category != "malicious" {
		t.Errorf("got %s/%s, want CRITICAL/malicious", f.Severity, f.Category)
	}
	if f.Reason != "dumped runner memory" {
		t.Errorf("reason = %q", f.Reason)
	}
	// Short-circuit must skip OSV and latest-tag lookups entirely.
	if *calls != 0 {
		t.Errorf("OSV queried %d times despite malicious short-circuit", *calls)
	}
	if n := c.calls("tj-actions/changed-files"); n != 0 {
		t.Errorf("LatestTag called %d times despite malicious short-circuit", n)
	}
}

func TestCheck_MaliciousRefFiltering(t *testing.T) {
	noOSV(t)
	rs := testRuleSet()
	rs.Malicious = []rules.CompromisedEntry{{
		Repo: "evil/action",
		Refs: []string{"v1.0.0", "v1.0.1"},
	}}
	s := newTestScanner(&fakeClient{}, rs)

	if got := s.Check(ctx(), "acme/app", "ci.yml", "evil/action@v1.0.0"); len(got) != 1 || got[0].Severity != "CRITICAL" {
		t.Errorf("pinned bad ref should be CRITICAL, got %+v", got)
	}
	if got := s.Check(ctx(), "acme/app", "ci.yml", "evil/action@v2.0.0"); len(got) != 0 {
		t.Errorf("unlisted ref should be clean, got %+v", got)
	}
}

func TestCheck_GHSARangeHit(t *testing.T) {
	noOSV(t)
	rs := testRuleSet()
	rs.Vulnerable = map[string]rules.VulnRule{
		"actions/checkout@>= 1.0.0, < 2.0.0": {Reason: "GHSA-xxxx: upgrade", Fix: "Upgrade actions/checkout to >= 2.0.0"},
	}
	s := newTestScanner(&fakeClient{}, rs)

	got := s.Check(ctx(), "acme/app", "ci.yml", "actions/checkout@v1.5.0")
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %+v", got)
	}
	if got[0].Severity != "HIGH" || got[0].Category != "vulnerable" {
		t.Errorf("got %s/%s, want HIGH/vulnerable", got[0].Severity, got[0].Category)
	}
	if !strings.Contains(got[0].Reason, "GHSA-xxxx") {
		t.Errorf("reason %q missing advisory id", got[0].Reason)
	}
	if !strings.Contains(got[0].Fix, ">= 2.0.0") {
		t.Errorf("fix %q should carry the advisory's remediation", got[0].Fix)
	}

	if got := s.Check(ctx(), "acme/app", "ci.yml", "actions/checkout@v2.0.0"); len(got) != 0 {
		t.Errorf("out-of-range version should be clean, got %+v", got)
	}
}

func TestCheck_OSVLayer(t *testing.T) {
	calls := countingOSV(t, []rules.OSVVuln{{ID: "GHSA-osv-1", Summary: "RCE"}})
	s := newTestScanner(&fakeClient{}, nil)

	got := s.Check(ctx(), "acme/app", "ci.yml", "actions/checkout@v4.1.1")
	osv := findByCategory(got, "osv")
	if len(osv) != 1 {
		t.Fatalf("expected 1 osv finding, got %+v", got)
	}
	if osv[0].Severity != "HIGH" {
		t.Errorf("severity = %s, want HIGH", osv[0].Severity)
	}
	if !strings.Contains(osv[0].Reason, "GHSA-osv-1") || !strings.Contains(osv[0].Reason, "RCE") {
		t.Errorf("reason = %q, want id and summary", osv[0].Reason)
	}
	if *calls != 1 {
		t.Errorf("OSV queried %d times, want 1", *calls)
	}
}

func TestCheck_OSVDisabled(t *testing.T) {
	calls := countingOSV(t, []rules.OSVVuln{{ID: "GHSA-should-not-appear"}})
	rs := testRuleSet()
	rs.UseOSV = false // --no-osv
	s := newTestScanner(&fakeClient{}, rs)

	got := s.Check(ctx(), "acme/app", "ci.yml", "actions/checkout@v4.1.1")
	if len(got) != 0 {
		t.Errorf("expected no findings with OSV disabled, got %+v", got)
	}
	if *calls != 0 {
		t.Errorf("OSV queried %d times despite UseOSV=false", *calls)
	}
}

func TestCheck_OSVSkipsNonVersionRefs(t *testing.T) {
	calls := countingOSV(t, []rules.OSVVuln{{ID: "GHSA-x"}})
	s := newTestScanner(&fakeClient{}, nil)

	s.Check(ctx(), "acme/app", "ci.yml", "actions/checkout@main")
	s.Check(ctx(), "acme/app", "ci.yml", "actions/checkout@deadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	if *calls != 0 {
		t.Errorf("OSV queried %d times for non-version refs, want 0", *calls)
	}
}

func TestCheck_Outdated(t *testing.T) {
	tests := []struct {
		name    string
		ref     string
		latest  string
		wantOut bool
	}{
		{"major behind", "v4.1.0", "v5.0.0", true},
		{"same major different minor", "v4.1.0", "v4.9.9", false},
		{"dotless tags compare numerically", "v41", "v42.0.0", true},
		{"same dotless major", "v41", "v41.2.0", false},
		{"non-v-prefixed tags", "4.1.0", "4.2.0", false},
		{"non-v-prefixed major behind", "4.1.0", "5.0.0", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			noOSV(t)
			c := &fakeClient{latest: map[string]string{"actions/checkout": tt.latest}}
			s := newTestScanner(c, nil)
			got := s.Check(ctx(), "acme/app", "ci.yml", "actions/checkout@"+tt.ref)
			out := findByCategory(got, "outdated")
			if tt.wantOut && len(out) != 1 {
				t.Fatalf("want outdated finding, got %+v", got)
			}
			if !tt.wantOut && len(out) != 0 {
				t.Fatalf("want no outdated finding, got %+v", got)
			}
			if tt.wantOut && !strings.Contains(out[0].Reason, tt.latest) {
				t.Errorf("reason = %q, want it to mention latest %s", out[0].Reason, tt.latest)
			}
		})
	}
}

func TestCheck_LatestDisabled(t *testing.T) {
	noOSV(t)
	c := &fakeClient{latest: map[string]string{"actions/checkout": "v5.0.0"}}
	rs := testRuleSet()
	rs.FetchLatest = false // --no-latest
	s := newTestScanner(c, rs)

	got := s.Check(ctx(), "acme/app", "ci.yml", "actions/checkout@v4.1.0")
	if len(got) != 0 {
		t.Errorf("expected no findings with FetchLatest=false, got %+v", got)
	}
	if n := c.calls("actions/checkout"); n != 0 {
		t.Errorf("LatestTag called %d times despite FetchLatest=false", n)
	}
}

func TestCheck_ShortSHA(t *testing.T) {
	noOSV(t)
	s := newTestScanner(&fakeClient{}, nil)

	got := s.Check(ctx(), "acme/app", "ci.yml", "actions/checkout@abc1234")
	if len(got) != 1 || got[0].Severity != "MEDIUM" || got[0].Category != "unpinned" {
		t.Fatalf("short SHA should be one MEDIUM unpinned finding, got %+v", got)
	}

	full := "0123456789abcdef0123456789abcdef01234567"
	if got := s.Check(ctx(), "acme/app", "ci.yml", "actions/checkout@"+full); len(got) != 0 {
		t.Errorf("full 40-char SHA should be clean, got %+v", got)
	}
}

func TestCheck_BranchRefOnlyFlagsUnpinnedSemantics(t *testing.T) {
	noOSV(t)
	s := newTestScanner(&fakeClient{latest: map[string]string{"actions/checkout": "v5.0.0"}}, nil)
	got := s.Check(ctx(), "acme/app", "ci.yml", "actions/checkout@main")

	for _, f := range got {
		if f.Category == "outdated" || f.Category == "osv" {
			t.Errorf("branch ref must not trigger %s checks: %+v", f.Category, f)
		}
	}
}

// ── Fix recommendations ────────────────────────────────────────────────

// Every finding category must carry a concrete, copy-pasteable fix — the
// report shows a "Fix" column and it must never be empty.
func TestCheck_FixSuggestions(t *testing.T) {
	fullSHA := "0123456789abcdef0123456789abcdef01234567"

	t.Run("unpinned no ref suggests pinning", func(t *testing.T) {
		noOSV(t)
		s := newTestScanner(&fakeClient{}, nil)
		got := s.Check(ctx(), "acme/app", "ci.yml", "actions/checkout")
		if len(got) != 1 || !strings.Contains(got[0].Fix, "uses: actions/checkout@") {
			t.Errorf("fix = %+v, want a pin suggestion", got)
		}
	})

	t.Run("short SHA resolves to full pin", func(t *testing.T) {
		noOSV(t)
		c := &fakeClient{shas: map[string]string{
			"actions/checkout@abc1234": fullSHA,
		}}
		s := newTestScanner(c, nil)
		got := s.Check(ctx(), "acme/app", "ci.yml", "actions/checkout@abc1234")
		if len(got) != 1 {
			t.Fatalf("got %+v", got)
		}
		want := "uses: actions/checkout@" + fullSHA
		if got[0].Fix != want {
			t.Errorf("fix = %q, want %q", got[0].Fix, want)
		}
	})

	t.Run("short SHA falls back when unresolvable", func(t *testing.T) {
		noOSV(t)
		s := newTestScanner(&fakeClient{}, nil)
		got := s.Check(ctx(), "acme/app", "ci.yml", "actions/checkout@abc1234")
		if len(got) != 1 || !strings.Contains(got[0].Fix, "full 40-char") {
			t.Errorf("fix = %+v, want generic full-SHA advice", got)
		}
	})

	t.Run("outdated suggests exact latest uses line", func(t *testing.T) {
		noOSV(t)
		c := &fakeClient{latest: map[string]string{"actions/checkout": "v7.0.1"}}
		s := newTestScanner(c, nil)
		got := s.Check(ctx(), "acme/app", "ci.yml", "actions/checkout@v3")
		out := findByCategory(got, "outdated")
		if len(out) != 1 || out[0].Fix != "uses: actions/checkout@v7.0.1" {
			t.Errorf("fix = %+v, want uses: actions/checkout@v7.0.1", out)
		}
	})

	t.Run("malicious demands removal and secret rotation", func(t *testing.T) {
		noOSV(t)
		rs := testRuleSet()
		rs.Malicious = []rules.CompromisedEntry{{
			Repo: "evil/action", Refs: []string{"v1"}, AdvisoryID: "GHSA-aaaa-bbbb-cccc",
		}}
		s := newTestScanner(&fakeClient{}, rs)
		got := s.Check(ctx(), "acme/app", "ci.yml", "evil/action@v1")
		if len(got) != 1 {
			t.Fatalf("got %+v", got)
		}
		for _, want := range []string{"Remove evil/action", "rotate", "GHSA-aaaa-bbbb-cccc"} {
			if !strings.Contains(got[0].Fix, want) {
				t.Errorf("fix %q missing %q", got[0].Fix, want)
			}
		}
	})

	t.Run("osv uses the advisory's fixed version", func(t *testing.T) {
		countingOSV(t, []rules.OSVVuln{{
			ID: "GHSA-osv-1", Summary: "RCE",
			Affected: []rules.OSVAffected{{
				Ranges: []rules.OSVRange{{
					Events: []rules.OSVEvent{{Introduced: "0"}, {Fixed: "4.2.1"}},
				}},
			}},
		}})
		s := newTestScanner(&fakeClient{}, nil)
		got := s.Check(ctx(), "acme/app", "ci.yml", "actions/checkout@v4.1.1")
		osv := findByCategory(got, "osv")
		if len(osv) != 1 || osv[0].Fix != "Upgrade actions/checkout to >= 4.2.1" {
			t.Errorf("fix = %+v, want upgrade to >= 4.2.1", osv)
		}
	})

	t.Run("osv without fixed version still advises upgrade", func(t *testing.T) {
		countingOSV(t, []rules.OSVVuln{{ID: "GHSA-osv-2", Summary: "RCE"}})
		s := newTestScanner(&fakeClient{}, nil)
		got := s.Check(ctx(), "acme/app", "ci.yml", "actions/checkout@v4.1.1")
		osv := findByCategory(got, "osv")
		if len(osv) != 1 || !strings.Contains(osv[0].Fix, "latest release") {
			t.Errorf("fix = %+v, want generic upgrade advice", osv)
		}
	})
}

// ── queryOSVCached ─────────────────────────────────────────────────────

func TestQueryOSVCached_Deduplicates(t *testing.T) {
	calls := countingOSV(t, nil)
	s := newTestScanner(&fakeClient{}, nil)

	s.queryOSVCached(ctx(), "actions/checkout", "v4.1.1")
	s.queryOSVCached(ctx(), "actions/checkout", "v4.1.1")
	s.queryOSVCached(ctx(), "actions/checkout", "v4.1.2")

	if *calls != 2 {
		t.Errorf("OSV queried %d times for 2 unique keys, want 2", *calls)
	}
}

func TestQueryOSVCached_ConcurrentAccess(t *testing.T) {
	var calls int64
	stubOSV(t, func(_ context.Context, _, _ string) ([]rules.OSVVuln, error) {
		atomic.AddInt64(&calls, 1)
		return []rules.OSVVuln{{ID: "GHSA-conc"}}, nil
	})
	s := newTestScanner(&fakeClient{}, nil)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v := s.queryOSVCached(ctx(), "actions/checkout", "v4.1.1")
			if len(v) != 1 || v[0].ID != "GHSA-conc" {
				t.Errorf("inconsistent cache result: %+v", v)
			}
		}()
	}
	wg.Wait()

	// Single-flight: 50 concurrent readers must produce exactly one
	// upstream query.
	if n := atomic.LoadInt64(&calls); n != 1 {
		t.Errorf("OSV queried %d times for 50 concurrent readers, want 1", n)
	}
}

func TestQueryOSVCached_SwallowsErrors(t *testing.T) {
	stubOSV(t, func(_ context.Context, _, _ string) ([]rules.OSVVuln, error) {
		return nil, fmt.Errorf("osv unreachable")
	})
	s := newTestScanner(&fakeClient{}, nil)

	v := s.queryOSVCached(ctx(), "actions/checkout", "v4.1.1")
	if v != nil {
		t.Errorf("errors must degrade to nil vulns, got %+v", v)
	}
}

// ── ScanAll ────────────────────────────────────────────────────────────

func TestScanAll_AggregatesCountsSortsAndSurvivesErrors(t *testing.T) {
	noOSV(t)
	c := &fakeClient{
		workflows: map[string]map[string][]byte{
			"acme/alpha": {
				"ci.yml": []byte("steps:\n  - uses: tj-actions/changed-files@v41\n"),
			},
			"acme/beta": {
				"ci.yml": []byte("steps:\n  - uses: actions/checkout@abc1234\n"),
			},
			"acme/aaa": {
				"ci.yml": []byte("steps:\n  - uses: actions/cache@def5678\n"),
			},
		},
		workflowErr: map[string]error{
			"acme/gamma": fmt.Errorf("repo gone"),
		},
	}
	rs := testRuleSet()
	rs.Malicious = []rules.CompromisedEntry{{Repo: "tj-actions/changed-files", Description: "bad"}}
	s := newTestScanner(c, rs)

	repos := []github.Repo{
		{FullName: "acme/alpha", Owner: "acme", Name: "alpha", DefaultBranch: "main"},
		{FullName: "acme/gamma", Owner: "acme", Name: "gamma", DefaultBranch: "main"},
		{FullName: "acme/beta", Owner: "acme", Name: "beta", DefaultBranch: "main"},
		{FullName: "acme/aaa", Owner: "acme", Name: "aaa", DefaultBranch: "main"},
	}

	sum := s.ScanAll(ctx(), repos, 2)

	if sum.TotalRepos != 4 {
		t.Errorf("TotalRepos = %d, want 4 (errored repos still count)", sum.TotalRepos)
	}
	if sum.ActionsChecked != 3 {
		t.Errorf("ActionsChecked = %d, want 3 (one action per reachable repo)", sum.ActionsChecked)
	}
	if sum.AffectedRepos != 3 {
		t.Errorf("AffectedRepos = %d, want 3 (alpha, aaa, beta)", sum.AffectedRepos)
	}
	if sum.ScannedAt.IsZero() {
		t.Error("ScannedAt must be set for the dashboard header")
	}
	if len(sum.Findings) != 3 {
		t.Fatalf("Findings = %+v, want 3", sum.Findings)
	}
	if sum.Critical != 1 || sum.Medium != 2 || sum.High != 0 || sum.Low != 0 {
		t.Errorf("counts = C%d/H%d/M%d/L%d, want C1/H0/M2/L0",
			sum.Critical, sum.High, sum.Medium, sum.Low)
	}
	// Findings must be sorted by severity, then repo (deterministic
	// tie-break so identical runs produce identical reports).
	wantOrder := []string{"acme/alpha", "acme/aaa", "acme/beta"}
	wantSev := []string{"CRITICAL", "MEDIUM", "MEDIUM"}
	for i := range wantOrder {
		if sum.Findings[i].Repo != wantOrder[i] || sum.Findings[i].Severity != wantSev[i] {
			t.Errorf("findings[%d] = %s/%s, want %s/%s",
				i, sum.Findings[i].Repo, sum.Findings[i].Severity,
				wantOrder[i], wantSev[i])
		}
	}
}

func TestScanAll_ZeroConcurrencyDoesNotDeadlock(t *testing.T) {
	noOSV(t)
	// Regression: concurrency 0 previously allocated a zero-capacity
	// semaphore and hung forever.
	c := &fakeClient{workflows: map[string]map[string][]byte{
		"acme/app": {"ci.yml": []byte("- uses: actions/checkout@v4\n")},
	}}
	s := newTestScanner(c, nil)

	done := make(chan *Summary, 1)
	go func() {
		done <- s.ScanAll(ctx(), []github.Repo{
			{FullName: "acme/app", Owner: "acme", Name: "app", DefaultBranch: "main"},
		}, 0)
	}()

	select {
	case sum := <-done:
		if sum.TotalRepos != 1 {
			t.Errorf("TotalRepos = %d, want 1", sum.TotalRepos)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ScanAll(concurrency=0) deadlocked")
	}
}

func TestScanAll_NoRepos(t *testing.T) {
	s := newTestScanner(&fakeClient{}, nil)
	sum := s.ScanAll(ctx(), nil, 4)

	if sum.TotalRepos != 0 || len(sum.Findings) != 0 || sum.AffectedRepos != 0 || sum.ActionsChecked != 0 {
		t.Errorf("empty scan = %+v, want zero everything", sum)
	}
}

// ── helpers ────────────────────────────────────────────────────────────

func ctx() context.Context { return context.Background() }

// ── pure helper functions ──────────────────────────────────────────────

func TestMajorOf(t *testing.T) {
	tests := map[string]string{
		"v4.1.1":  "4",
		"4.1.1":   "4",
		"v4":      "4",
		"4":       "4",
		"v41":     "41",
		"41":      "41",
		"v41.2.0": "41",
		"nightly": "nightly",
		"":        "",
		"v10.0.0": "10",
		"2024.01": "2024",
	}
	for in, want := range tests {
		if got := majorOf(in); got != want {
			t.Errorf("majorOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsVersionRef(t *testing.T) {
	tests := map[string]bool{
		"v41":     true,
		"41":      true,
		"v4.1.1":  true,
		"4.1.1":   true,
		"main":    false,
		"":        false,
		"V4":      false,
		"release": false,
	}
	for in, want := range tests {
		if got := isVersionRef(in); got != want {
			t.Errorf("isVersionRef(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestIsSHA(t *testing.T) {
	tests := map[string]bool{
		"":        false,
		"abc":     false, // too short
		"abc1234": true,  // 7-char short SHA
		"0123456789abcdef0123456789abcdef01234567":  true,  // 40-char
		"0123456789abcdef0123456789abcdef012345678": false, // 41-char
		"g123456":  false, // non-hex
		"v4.1.1":   false, // punctuation + v
		"deadbeef": true,  // 8 hex chars
	}
	for in, want := range tests {
		if got := isSHA(in); got != want {
			t.Errorf("isSHA(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestOSVSeverityDefaultsToHigh(t *testing.T) {
	// OSV action advisories frequently ship without CVSS data; the
	// current implementation always returns HIGH for a known-vulnerable
	// exact version.
	v := rules.OSVVuln{ID: "GHSA-x"}
	if got := osvSeverity(v); got != "HIGH" {
		t.Errorf("osvSeverity() = %q, want HIGH", got)
	}
}

func TestOSVSummaryFallback(t *testing.T) {
	if got := osvSummary(rules.OSVVuln{}); got != "Known vulnerability in this action version" {
		t.Errorf("empty summary fallback = %q", got)
	}
	if got := osvSummary(rules.OSVVuln{Summary: "RCE"}); got != "RCE" {
		t.Errorf("summary = %q, want RCE", got)
	}
}
