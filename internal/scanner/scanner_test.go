package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
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
	workflows   map[string]map[string][]byte // repo full name -> workflow path -> content
	workflowErr map[string]error
	latest      map[string]string
	latestCalls map[string]int
	shas        map[string]string // "repo@shortsha" -> full 40-char sha
	shaCalls    int
	block       bool // simulate a hanging GitHub API
}

func (f *fakeClient) ListWorkflows(ctx context.Context, r github.Repo) (map[string][]byte, error) {
	if f.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
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
func stubOSV(t *testing.T, fn func(ctx context.Context, actionRepo string) ([]rules.OSVVuln, error)) {
	t.Helper()
	orig := queryOSV
	queryOSV = fn
	t.Cleanup(func() { queryOSV = orig })
}

// noOSV installs a deterministic empty OSV stub so tests never touch
// the real api.osv.dev endpoint.
func noOSV(t *testing.T) {
	t.Helper()
	stubOSV(t, func(_ context.Context, _ string) ([]rules.OSVVuln, error) {
		return nil, nil
	})
}

func countingOSV(t *testing.T, vulns []rules.OSVVuln) *int {
	t.Helper()
	calls := 0
	stubOSV(t, func(_ context.Context, _ string) ([]rules.OSVVuln, error) {
		calls++
		return vulns, nil
	})
	return &calls
}

// testRuleSet builds a rule set. Rules are matched by owner/repo, so a
// rule for "tj-actions/changed-files" fires for the action
// "tj-actions/changed-files@v41" whatever sub-path it uses.
func testRuleSet(rs ...rules.Rule) *rules.RuleSet {
	return &rules.RuleSet{
		Rules:       rs,
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

func ctx() context.Context { return context.Background() }

// ── extraction ─────────────────────────────────────────────────────────

func TestExtractActionRefs_StepLevelUses(t *testing.T) {
	wf := []byte("name: CI\njobs:\n  build:\n    steps:\n" +
		"      - uses: actions/checkout@v4\n" +
		"      - name: Setup\n        uses: actions/setup-node@v4\n")

	refs := ExtractActionRefs(wf)
	if len(refs) != 2 {
		t.Fatalf("got %d refs (%+v), want 2", len(refs), refs)
	}
	if refs[0].Raw != "actions/checkout@v4" || refs[0].Name != "actions/checkout" ||
		refs[0].Ref != "v4" || refs[0].Job != "build" || refs[0].Step != 0 {
		t.Errorf("refs[0] = %+v", refs[0])
	}
	if refs[1].Raw != "actions/setup-node@v4" || refs[1].Step != 1 {
		t.Errorf("refs[1] = %+v", refs[1])
	}
}

func TestExtractActionRefs_JobLevelReusableWorkflow(t *testing.T) {
	wf := []byte("jobs:\n  call:\n    uses: org/repo/.github/workflows/build.yml@v1\n")

	refs := ExtractActionRefs(wf)
	if len(refs) != 1 {
		t.Fatalf("got %d refs (%+v), want 1", len(refs), refs)
	}
	if refs[0].Name != "org/repo" {
		t.Errorf("Name = %q, want org/repo", refs[0].Name)
	}
	if refs[0].FullName != "org/repo/.github/workflows/build.yml" {
		t.Errorf("FullName = %q", refs[0].FullName)
	}
	if refs[0].Step != -1 {
		t.Errorf("Step = %d, want -1 for a job-level call", refs[0].Step)
	}
	if refs[0].Job != "call" {
		t.Errorf("Job = %q, want call", refs[0].Job)
	}
}

func TestExtractActionRefs_ReducesToOwnerRepo(t *testing.T) {
	tests := []struct {
		uses string
		want string
		full string
	}{
		{"github/codeql-action/analyze@v2.1.0", "github/codeql-action", "github/codeql-action/analyze"},
		{"tj-actions/changed-files/sub@v41", "tj-actions/changed-files", "tj-actions/changed-files/sub"},
		{"org/repo/.github/workflows/wf.yml@v1", "org/repo", "org/repo/.github/workflows/wf.yml"},
		{"actions/checkout@v4", "actions/checkout", "actions/checkout"},
	}
	for _, tt := range tests {
		wf := []byte("jobs:\n  b:\n    steps:\n      - uses: " + tt.uses + "\n")
		refs := ExtractActionRefs(wf)
		if len(refs) != 1 {
			t.Fatalf("%s: got %d refs, want 1", tt.uses, len(refs))
		}
		if refs[0].Name != tt.want {
			t.Errorf("%s: Name = %q, want %q", tt.uses, refs[0].Name, tt.want)
		}
		if refs[0].FullName != tt.full {
			t.Errorf("%s: FullName = %q, want %q", tt.uses, refs[0].FullName, tt.full)
		}
	}
}

func TestExtractActionRefs_SkipsNonRemoteActions(t *testing.T) {
	wf := []byte("jobs:\n  b:\n    steps:\n" +
		"      - uses: ./local/action\n" +
		"      - uses: docker://alpine:3.8\n" +
		"      - uses: ${{ matrix.action }}\n" +
		"      - uses: ${{ env.ACTION }}\n" +
		"      - uses: onlyowner\n" +
		"      - uses: $/.github/workflows/audit.yaml\n")

	if refs := ExtractActionRefs(wf); len(refs) != 0 {
		t.Errorf("got %+v, want no refs (local/docker/expression/one-segment/self-repo)", refs)
	}
}

// GitHub's self-repository syntax ("$/...") resolves to the workflow's
// own repository at the running commit. It is not a remote reference,
// so it must not be reported as an unpinned action.
func TestExtractActionRefs_SkipsSelfRepositorySyntax(t *testing.T) {
	wf := []byte("jobs:\n" +
		"  b:\n" +
		"    uses: $/.github/workflows/audit.yaml\n")

	if refs := ExtractActionRefs(wf); len(refs) != 0 {
		t.Errorf("got %+v, want no refs for a self-repository reference", refs)
	}
}

func TestExtractActionRefs_IgnoresUsesInsideRunBlock(t *testing.T) {
	wf := []byte("jobs:\n  b:\n    steps:\n" +
		"      - run: |\n" +
		"          echo 'uses: evil/action@v1'\n" +
		"          uses: not/an/action@v2\n")

	if refs := ExtractActionRefs(wf); len(refs) != 0 {
		t.Errorf("got %+v, want no refs (the word uses: inside run: is not an action)", refs)
	}
}

func TestExtractActionRefs_FoldedScalarAndValueOnNextLine(t *testing.T) {
	wf := []byte("jobs:\n  b:\n    steps:\n" +
		"      - uses: >\n          actions/checkout@v4\n" +
		"      - uses:\n          actions/setup-node@v4\n")

	refs := ExtractActionRefs(wf)
	if len(refs) != 2 {
		t.Fatalf("got %d refs (%+v), want 2", len(refs), refs)
	}
	if refs[0].Raw != "actions/checkout@v4" {
		t.Errorf("refs[0].Raw = %q, want actions/checkout@v4", refs[0].Raw)
	}
	if refs[1].Raw != "actions/setup-node@v4" {
		t.Errorf("refs[1].Raw = %q, want actions/setup-node@v4", refs[1].Raw)
	}
}

func TestExtractActionRefs_QuotedValuesAndComments(t *testing.T) {
	wf := []byte("jobs:\n  b:\n    steps:\n" +
		"      - uses: \"actions/checkout@v4\"\n" +
		"      - uses: 'actions/setup-node@v4'\n" +
		"      - uses: actions/cache@v4 # pin me\n")

	refs := ExtractActionRefs(wf)
	if len(refs) != 3 {
		t.Fatalf("got %d refs (%+v), want 3", len(refs), refs)
	}
	for i, want := range []string{"actions/checkout@v4", "actions/setup-node@v4", "actions/cache@v4"} {
		if refs[i].Raw != want {
			t.Errorf("refs[%d].Raw = %q, want %q", i, refs[i].Raw, want)
		}
	}
}

func TestExtractActionRefs_NoAtSignKeepsRefEmpty(t *testing.T) {
	wf := []byte("jobs:\n  b:\n    steps:\n      - uses: actions/checkout\n")

	refs := ExtractActionRefs(wf)
	if len(refs) != 1 {
		t.Fatalf("got %d refs (%+v), want 1", len(refs), refs)
	}
	if refs[0].Ref != "" || refs[0].Name != "actions/checkout" {
		t.Errorf("refs[0] = %+v, want an unpinned action/checkout", refs[0])
	}
}

func TestExtractActionRefs_MalformedYAMLDoesNotPanic(t *testing.T) {
	for _, bad := range []string{
		"jobs:\n  b:\n   steps:\n  - uses: [unclosed\n",
		"\t\tnot yaml at all: : :\n",
		"jobs: 3\n",
	} {
		refs := ExtractActionRefs([]byte(bad))
		if len(refs) != 0 {
			t.Errorf("%q: got %+v, want no refs", bad, refs)
		}
	}
}

func TestExtractActionRefs_EmptyAndJoblessWorkflows(t *testing.T) {
	for _, wf := range []string{"", "name: CI\non: push\n", "jobs: {}\n"} {
		if refs := ExtractActionRefs([]byte(wf)); len(refs) != 0 {
			t.Errorf("%q: got %+v, want no refs", wf, refs)
		}
	}
}

func TestExtractActionRefs_ToleratesOneBrokenStep(t *testing.T) {
	// A step whose `uses` is not a scalar must not cost us the other
	// findings of the workflow.
	wf := []byte("jobs:\n  b:\n    steps:\n" +
		"      - uses:\n          key: value\n" +
		"      - uses: actions/checkout@v4\n")

	refs := ExtractActionRefs(wf)
	if len(refs) != 1 || refs[0].Raw != "actions/checkout@v4" {
		t.Errorf("got %+v, want the checkout ref only", refs)
	}
}

func TestExtractActions_ReturnsRawValues(t *testing.T) {
	wf := []byte("jobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n")
	got := ExtractActions(wf)
	if len(got) != 1 || got[0] != "actions/checkout@v4" {
		t.Errorf("ExtractActions() = %v", got)
	}
}

// ── check layers ───────────────────────────────────────────────────────

func TestCheck_NoRefIsUnpinned(t *testing.T) {
	noOSV(t)
	s := newTestScanner(&fakeClient{}, nil)

	got := s.Check(ctx(), "acme/app", ".github/workflows/ci.yml",
		ActionRef{Raw: "actions/checkout", Name: "actions/checkout", FullName: "actions/checkout", Job: "build"})

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
	if f.Job != "build" {
		t.Errorf("job = %q, want build", f.Job)
	}
}

func TestCheck_MaliciousShortCircuits(t *testing.T) {
	rs := testRuleSet(
		rules.Rule{
			Category: "malicious", Repo: "tj-actions/changed-files",
			Reason: "dumped runner memory",
		},
		rules.Rule{
			Category: "vulnerable", Repo: "tj-actions/changed-files",
			Range: ">= 1.0.0, < 99.0.0", Severity: "HIGH",
			Reason: "should never surface", Fix: "should never surface",
		},
	)
	calls := countingOSV(t, nil)
	c := &fakeClient{latest: map[string]string{"tj-actions/changed-files": "v99.0.0"}}
	s := newTestScanner(c, rs)

	got := s.Check(ctx(), "acme/app", ".github/workflows/ci.yml",
		ActionRef{Raw: "tj-actions/changed-files@v41", Name: "tj-actions/changed-files",
			FullName: "tj-actions/changed-files", Ref: "v41"})

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
	if *calls != 0 {
		t.Errorf("OSV queried %d times despite malicious short-circuit", *calls)
	}
	if n := c.calls("tj-actions/changed-files"); n != 0 {
		t.Errorf("LatestTag called %d times despite malicious short-circuit", n)
	}
}

func TestCheck_MaliciousUsesRuleMetadata(t *testing.T) {
	noOSV(t)
	rs := testRuleSet(rules.Rule{
		Category: "malicious", Repo: "evil/action", Refs: []string{"v1"},
		Reason: "compromised", AdvisoryID: "GHSA-aaaa-bbbb-cccc",
		AdvisoryURL: "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
	})
	s := newTestScanner(&fakeClient{}, rs)

	got := s.Check(ctx(), "acme/app", "ci.yml",
		ActionRef{Raw: "evil/action@v1", Name: "evil/action", FullName: "evil/action", Ref: "v1"})
	if len(got) != 1 {
		t.Fatalf("got %+v, want 1 finding", got)
	}
	if got[0].AdvisoryID != "GHSA-aaaa-bbbb-cccc" || got[0].AdvisoryURL == "" {
		t.Errorf("advisory metadata lost: %+v", got[0])
	}
	// No concrete replacement exists for a compromised action → prose.
	if got[0].HasCopyableFix() {
		t.Errorf("fix %q must not be offered as a copyable uses: line", got[0].Fix)
	}
	if !strings.Contains(got[0].Fix, "Remove evil/action") {
		t.Errorf("fix = %q, want removal advice", got[0].Fix)
	}
}

func TestCheck_MaliciousRefFiltering(t *testing.T) {
	noOSV(t)
	rs := testRuleSet(rules.Rule{
		Category: "malicious", Repo: "evil/action", Refs: []string{"v1.0.0", "v1.0.1"},
	})
	s := newTestScanner(&fakeClient{}, rs)

	got := s.Check(ctx(), "acme/app", "ci.yml",
		ActionRef{Raw: "evil/action@v1.0.0", Name: "evil/action", FullName: "evil/action", Ref: "v1.0.0"})
	if len(got) != 1 || got[0].Severity != "CRITICAL" {
		t.Errorf("pinned bad ref should be CRITICAL, got %+v", got)
	}
	got = s.Check(ctx(), "acme/app", "ci.yml",
		ActionRef{Raw: "evil/action@v2.0.0", Name: "evil/action", FullName: "evil/action", Ref: "v2.0.0"})
	if len(got) != 0 {
		t.Errorf("unlisted ref should be clean, got %+v", got)
	}
}

func TestCheck_VulnerableUsesRuleSeverity(t *testing.T) {
	noOSV(t)
	rs := testRuleSet(rules.Rule{
		Category: "vulnerable", Repo: "actions/checkout",
		Range: ">= 1.0.0, < 2.0.0", Severity: "MEDIUM",
		Reason: "GHSA-xxxx: upgrade", Fix: "Upgrade actions/checkout to >= 2.0.0",
		AdvisoryID: "GHSA-xxxx",
	})
	s := newTestScanner(&fakeClient{}, rs)

	got := s.Check(ctx(), "acme/app", "ci.yml",
		ActionRef{Raw: "actions/checkout@v1.5.0", Name: "actions/checkout",
			FullName: "actions/checkout", Ref: "v1.5.0"})
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %+v", got)
	}
	if got[0].Severity != "MEDIUM" || got[0].Category != "vulnerable" {
		t.Errorf("got %s/%s, want MEDIUM/vulnerable (the rule's own severity)", got[0].Severity, got[0].Category)
	}
	if got[0].AdvisoryID != "GHSA-xxxx" {
		t.Errorf("advisory id lost: %+v", got[0])
	}
	if !strings.Contains(got[0].Fix, ">= 2.0.0") {
		t.Errorf("fix %q should carry the advisory's remediation", got[0].Fix)
	}

	got = s.Check(ctx(), "acme/app", "ci.yml",
		ActionRef{Raw: "actions/checkout@v2.0.0", Name: "actions/checkout",
			FullName: "actions/checkout", Ref: "v2.0.0"})
	if len(got) != 0 {
		t.Errorf("out-of-range version should be clean, got %+v", got)
	}
}

func TestCheck_VulnerableWithoutSeverityDefaultsToHigh(t *testing.T) {
	noOSV(t)
	rs := testRuleSet(rules.Rule{
		Category: "vulnerable", Repo: "actions/checkout", Range: ">= 1.0.0, < 2.0.0",
		Reason: "GHSA-xxxx",
	})
	s := newTestScanner(&fakeClient{}, rs)

	got := s.Check(ctx(), "acme/app", "ci.yml",
		ActionRef{Raw: "actions/checkout@v1.5.0", Name: "actions/checkout",
			FullName: "actions/checkout", Ref: "v1.5.0"})
	if len(got) != 1 || got[0].Severity != "HIGH" {
		t.Errorf("got %+v, want a HIGH finding", got)
	}
}

func TestCheck_SubPathActionMatchesOwnerRepoRules(t *testing.T) {
	noOSV(t)
	rs := testRuleSet(rules.Rule{
		Category: "malicious", Repo: "github/codeql-action", Reason: "compromised",
	})
	s := newTestScanner(&fakeClient{}, rs)

	got := s.Check(ctx(), "acme/app", "ci.yml",
		ActionRef{Raw: "github/codeql-action/analyze@v2.1.0", Name: "github/codeql-action",
			FullName: "github/codeql-action/analyze", Ref: "v2.1.0"})
	if len(got) != 1 || got[0].Category != "malicious" {
		t.Fatalf("sub-path action must be checked against its owner/repo, got %+v", got)
	}
	if got[0].Action != "github/codeql-action/analyze@v2.1.0" {
		t.Errorf("action = %q, want the original uses: value", got[0].Action)
	}
}

func TestCheck_OSVLayer(t *testing.T) {
	vuln := osvFixture(t, "GHSA-osv-1", "RCE", "4.2.1")
	calls := countingOSV(t, []rules.OSVVuln{vuln})
	s := newTestScanner(&fakeClient{}, nil)

	got := s.Check(ctx(), "acme/app", "ci.yml",
		ActionRef{Raw: "actions/checkout@v4.1.1", Name: "actions/checkout",
			FullName: "actions/checkout", Ref: "v4.1.1"})
	osv := findByCategory(got, "osv")
	if len(osv) != 1 {
		t.Fatalf("expected 1 osv finding, got %+v", got)
	}
	if !strings.Contains(osv[0].Reason, "GHSA-osv-1") {
		t.Errorf("reason = %q, want the advisory id", osv[0].Reason)
	}
	if osv[0].AdvisoryID != "GHSA-osv-1" {
		t.Errorf("advisory id = %q", osv[0].AdvisoryID)
	}
	if *calls != 1 {
		t.Errorf("OSV queried %d times, want 1", *calls)
	}
}

func TestCheck_OSVOnlyWhenRefIsAffected(t *testing.T) {
	// The advisory covers < 4.2.1 — a newer ref must stay clean.
	vuln := osvFixture(t, "GHSA-osv-1", "RCE", "4.2.1")
	countingOSV(t, []rules.OSVVuln{vuln})
	s := newTestScanner(&fakeClient{}, nil)

	got := s.Check(ctx(), "acme/app", "ci.yml",
		ActionRef{Raw: "actions/checkout@v4.5.0", Name: "actions/checkout",
			FullName: "actions/checkout", Ref: "v4.5.0"})
	if osv := findByCategory(got, "osv"); len(osv) != 0 {
		t.Errorf("out-of-range ref must not produce an OSV finding, got %+v", osv)
	}
}

func TestCheck_OSVQueriedOncePerOwnerRepo(t *testing.T) {
	calls := countingOSV(t, nil)
	s := newTestScanner(&fakeClient{}, nil)

	for _, ref := range []string{"v4.1.1", "v4.1.2", "v4.2.0"} {
		s.Check(ctx(), "acme/app", "ci.yml",
			ActionRef{Raw: "actions/checkout@" + ref, Name: "actions/checkout",
				FullName: "actions/checkout", Ref: ref})
	}
	if *calls != 1 {
		t.Errorf("OSV queried %d times for 3 refs of one action, want 1", *calls)
	}
}

// OSV's "GitHub Actions" ecosystem mirrors GHSA, so the same advisory
// arrives through both layers. Reporting it twice double-counts every
// vulnerable action and produces two code-scanning alerts for one
// advisory.
func TestCheck_OSVDoesNotDuplicateAGHSAAdvisory(t *testing.T) {
	vuln := osvFixture(t, "GHSA-dup-1", "RCE", "4.2.1")
	countingOSV(t, []rules.OSVVuln{vuln})

	rs := testRuleSet()
	rs.Rules = append(rs.Rules, rules.Rule{
		Category: rules.CategoryVulnerable, Repo: "actions/checkout",
		Range: "< 4.2.1", Reason: "GHSA-dup-1: RCE", Fix: "Upgrade actions/checkout to v4.2.1",
		Severity: "HIGH", AdvisoryID: "GHSA-dup-1",
	})
	s := newTestScanner(&fakeClient{}, rs)

	got := s.Check(ctx(), "acme/app", "ci.yml",
		ActionRef{Raw: "actions/checkout@v4.1.1", Name: "actions/checkout",
			FullName: "actions/checkout", Ref: "v4.1.1"})

	if v := findByCategory(got, "vulnerable"); len(v) != 1 {
		t.Fatalf("want 1 vulnerable finding, got %+v", got)
	}
	if o := findByCategory(got, "osv"); len(o) != 0 {
		t.Errorf("the OSV layer must not repeat an advisory GHSA already reported, got %+v", o)
	}
}

// The same advisory under its CVE id must also be recognised.
func TestCheck_OSVDoesNotDuplicateAGHSAAdvisoryByAlias(t *testing.T) {
	vuln := osvFixture(t, "CVE-2026-1234", "RCE", "4.2.1")
	vuln.Aliases = []string{"GHSA-alias-1"}
	countingOSV(t, []rules.OSVVuln{vuln})

	rs := testRuleSet()
	rs.Rules = append(rs.Rules, rules.Rule{
		Category: rules.CategoryVulnerable, Repo: "actions/checkout",
		Range: "< 4.2.1", Reason: "GHSA-alias-1: RCE", Fix: "Upgrade actions/checkout to v4.2.1",
		Severity: "HIGH", AdvisoryID: "GHSA-alias-1",
	})
	s := newTestScanner(&fakeClient{}, rs)

	got := s.Check(ctx(), "acme/app", "ci.yml",
		ActionRef{Raw: "actions/checkout@v4.1.1", Name: "actions/checkout",
			FullName: "actions/checkout", Ref: "v4.1.1"})

	if o := findByCategory(got, "osv"); len(o) != 0 {
		t.Errorf("an OSV advisory aliased to a reported GHSA id must be skipped, got %+v", o)
	}
}

func TestCheck_OSVDisabled(t *testing.T) {
	calls := countingOSV(t, []rules.OSVVuln{osvFixture(t, "GHSA-should-not-appear", "x", "1.0.0")})
	rs := testRuleSet()
	rs.UseOSV = false // --no-osv
	s := newTestScanner(&fakeClient{}, rs)

	got := s.Check(ctx(), "acme/app", "ci.yml",
		ActionRef{Raw: "actions/checkout@v4.1.1", Name: "actions/checkout",
			FullName: "actions/checkout", Ref: "v4.1.1"})
	if len(got) != 0 {
		t.Errorf("expected no findings with OSV disabled, got %+v", got)
	}
	if *calls != 0 {
		t.Errorf("OSV queried %d times despite UseOSV=false", *calls)
	}
}

func TestCheck_OSVSkipsNonVersionRefs(t *testing.T) {
	calls := countingOSV(t, []rules.OSVVuln{osvFixture(t, "GHSA-x", "x", "1.0.0")})
	s := newTestScanner(&fakeClient{}, nil)

	s.Check(ctx(), "acme/app", "ci.yml",
		ActionRef{Raw: "actions/checkout@main", Name: "actions/checkout",
			FullName: "actions/checkout", Ref: "main"})
	s.Check(ctx(), "acme/app", "ci.yml",
		ActionRef{Raw: "actions/checkout@deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", Name: "actions/checkout",
			FullName: "actions/checkout", Ref: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"})
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
		// A latest tag that is not a version cannot be compared, and
		// reporting it would tell the user to move to a tag that is not
		// a release version.
		{"non-version latest tag", "v1.0.0", "release-2024", false},
		// A ref ahead of the latest release is not outdated, and
		// reporting it would advise a downgrade.
		{"ref ahead of latest", "v3.0.0", "v2.0.0", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			noOSV(t)
			c := &fakeClient{latest: map[string]string{"actions/checkout": tt.latest}}
			s := newTestScanner(c, nil)
			got := s.Check(ctx(), "acme/app", "ci.yml",
				ActionRef{Raw: "actions/checkout@" + tt.ref, Name: "actions/checkout",
					FullName: "actions/checkout", Ref: tt.ref})
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
			if tt.wantOut && out[0].Fix != "uses: actions/checkout@"+tt.latest {
				t.Errorf("fix = %q, want a paste-ready uses: line", out[0].Fix)
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

	got := s.Check(ctx(), "acme/app", "ci.yml",
		ActionRef{Raw: "actions/checkout@v4.1.0", Name: "actions/checkout",
			FullName: "actions/checkout", Ref: "v4.1.0"})
	if len(got) != 0 {
		t.Errorf("expected no findings with FetchLatest=false, got %+v", got)
	}
	if n := c.calls("actions/checkout"); n != 0 {
		t.Errorf("LatestTag called %d times despite FetchLatest=false", n)
	}
}

func TestCheck_LatestNotCalledForNonVersionRefs(t *testing.T) {
	noOSV(t)
	c := &fakeClient{latest: map[string]string{"actions/checkout": "v5.0.0"}}
	s := newTestScanner(c, nil)

	// A SHA-pinned, branch-pinned or sub-path action has no release to
	// compare against — the release API call would be a guaranteed 404.
	s.Check(ctx(), "acme/app", "ci.yml",
		ActionRef{Raw: "actions/checkout@0123456789abcdef0123456789abcdef01234567",
			Name: "actions/checkout", FullName: "actions/checkout",
			Ref: "0123456789abcdef0123456789abcdef01234567"})
	s.Check(ctx(), "acme/app", "ci.yml",
		ActionRef{Raw: "actions/checkout@main", Name: "actions/checkout",
			FullName: "actions/checkout", Ref: "main"})
	if n := c.calls("actions/checkout"); n != 0 {
		t.Errorf("LatestTag called %d times for non-version refs, want 0", n)
	}
}

func TestCheck_ShortSHA(t *testing.T) {
	noOSV(t)
	s := newTestScanner(&fakeClient{}, nil)

	got := s.Check(ctx(), "acme/app", "ci.yml",
		ActionRef{Raw: "actions/checkout@abc1234", Name: "actions/checkout",
			FullName: "actions/checkout", Ref: "abc1234"})
	if len(got) != 1 || got[0].Severity != "MEDIUM" || got[0].Category != "unpinned" {
		t.Fatalf("short SHA should be one MEDIUM unpinned finding, got %+v", got)
	}

	full := "0123456789abcdef0123456789abcdef01234567"
	got = s.Check(ctx(), "acme/app", "ci.yml",
		ActionRef{Raw: "actions/checkout@" + full, Name: "actions/checkout",
			FullName: "actions/checkout", Ref: full})
	if len(got) != 0 {
		t.Errorf("full 40-char SHA should be clean, got %+v", got)
	}
}

func TestCheck_DateTagIsNotASHA(t *testing.T) {
	noOSV(t)
	c := &fakeClient{shas: map[string]string{}}
	s := newTestScanner(c, nil)

	got := s.Check(ctx(), "acme/app", "ci.yml",
		ActionRef{Raw: "actions/checkout@20240101", Name: "actions/checkout",
			FullName: "actions/checkout", Ref: "20240101"})
	for _, f := range got {
		if f.Category == "unpinned" {
			t.Errorf("a date-like tag must not be flagged as a short SHA: %+v", f)
		}
	}
	if c.shaCalls != 0 {
		t.Errorf("ResolveSHA called %d times for a date-like tag, want 0", c.shaCalls)
	}
}

func TestCheck_BranchRefOnlyFlagsUnpinnedSemantics(t *testing.T) {
	noOSV(t)
	s := newTestScanner(&fakeClient{latest: map[string]string{"actions/checkout": "v5.0.0"}}, nil)
	got := s.Check(ctx(), "acme/app", "ci.yml",
		ActionRef{Raw: "actions/checkout@main", Name: "actions/checkout",
			FullName: "actions/checkout", Ref: "main"})

	for _, f := range got {
		if f.Category == "outdated" || f.Category == "osv" {
			t.Errorf("branch ref must not trigger %s checks: %+v", f.Category, f)
		}
	}
}

// ── fix recommendations ────────────────────────────────────────────────

func TestCheck_FixSuggestions(t *testing.T) {
	fullSHA := "0123456789abcdef0123456789abcdef01234567"

	t.Run("short SHA resolves to full pin", func(t *testing.T) {
		noOSV(t)
		c := &fakeClient{shas: map[string]string{"actions/checkout@abc1234": fullSHA}}
		s := newTestScanner(c, nil)
		got := s.Check(ctx(), "acme/app", "ci.yml",
			ActionRef{Raw: "actions/checkout@abc1234", Name: "actions/checkout",
				FullName: "actions/checkout", Ref: "abc1234"})
		if len(got) != 1 {
			t.Fatalf("got %+v", got)
		}
		want := "uses: actions/checkout@" + fullSHA
		if got[0].Fix != want {
			t.Errorf("fix = %q, want %q", got[0].Fix, want)
		}
		if !got[0].HasCopyableFix() {
			t.Errorf("fix %q must be reported as copyable", got[0].Fix)
		}
	})

	t.Run("short SHA falls back when unresolvable", func(t *testing.T) {
		noOSV(t)
		s := newTestScanner(&fakeClient{}, nil)
		got := s.Check(ctx(), "acme/app", "ci.yml",
			ActionRef{Raw: "actions/checkout@abc1234", Name: "actions/checkout",
				FullName: "actions/checkout", Ref: "abc1234"})
		if len(got) != 1 || !strings.Contains(got[0].Fix, "full 40-char") {
			t.Errorf("fix = %+v, want generic full-SHA advice", got)
		}
		if got[0].HasCopyableFix() {
			t.Errorf("prose fix %q must not be copyable", got[0].Fix)
		}
	})

	t.Run("unpinned without ref has no concrete replacement", func(t *testing.T) {
		noOSV(t)
		s := newTestScanner(&fakeClient{}, nil)
		got := s.Check(ctx(), "acme/app", "ci.yml",
			ActionRef{Raw: "actions/checkout", Name: "actions/checkout",
				FullName: "actions/checkout"})
		if len(got) != 1 {
			t.Fatalf("got %+v", got)
		}
		if got[0].HasCopyableFix() {
			t.Errorf("fix %q must not be offered as a copyable uses: line", got[0].Fix)
		}
	})

	t.Run("outdated suggests exact latest uses line", func(t *testing.T) {
		noOSV(t)
		c := &fakeClient{latest: map[string]string{"actions/checkout": "v7.0.1"}}
		s := newTestScanner(c, nil)
		got := s.Check(ctx(), "acme/app", "ci.yml",
			ActionRef{Raw: "actions/checkout@v3", Name: "actions/checkout",
				FullName: "actions/checkout", Ref: "v3"})
		out := findByCategory(got, "outdated")
		if len(out) != 1 || out[0].Fix != "uses: actions/checkout@v7.0.1" {
			t.Errorf("fix = %+v, want uses: actions/checkout@v7.0.1", out)
		}
	})
}

func TestHasCopyableFix(t *testing.T) {
	if !(Finding{Fix: "uses: actions/checkout@v4"}).HasCopyableFix() {
		t.Error("a uses: fix must be copyable")
	}
	if (Finding{Fix: "Pin the action to a version"}).HasCopyableFix() {
		t.Error("a prose fix must not be copyable")
	}
	if (Finding{}).HasCopyableFix() {
		t.Error("an empty fix must not be copyable")
	}
}

// ── ScanAll ────────────────────────────────────────────────────────────

func TestScanAll_AggregatesCountsSortsAndSurvivesErrors(t *testing.T) {
	noOSV(t)
	c := &fakeClient{
		workflows: map[string]map[string][]byte{
			"acme/alpha": {
				".github/workflows/ci.yml": []byte("jobs:\n  b:\n    steps:\n      - uses: tj-actions/changed-files@v41\n"),
			},
			"acme/beta": {
				".github/workflows/ci.yml": []byte("jobs:\n  b:\n    steps:\n      - uses: actions/checkout@abc1234\n"),
			},
			"acme/aaa": {
				".github/workflows/ci.yml": []byte("jobs:\n  b:\n    steps:\n      - uses: actions/cache@def5678\n"),
			},
		},
		workflowErr: map[string]error{
			"acme/gamma": fmt.Errorf("repo gone"),
		},
	}
	rs := testRuleSet(rules.Rule{Category: "malicious", Repo: "tj-actions/changed-files", Reason: "bad"})
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
	if sum.Findings[0].Workflow != ".github/workflows/ci.yml" {
		t.Errorf("workflow = %q, want the full workflow path", sum.Findings[0].Workflow)
	}
}

func TestScanAll_UnreadableRepoIsReported(t *testing.T) {
	noOSV(t)
	c := &fakeClient{
		workflows: map[string]map[string][]byte{
			"acme/ok": {".github/workflows/ci.yml": []byte("jobs:\n  b:\n    steps:\n      - uses: actions/checkout@abc1234\n")},
		},
		workflowErr: map[string]error{
			"acme/gone": fmt.Errorf("repository too large to scan completely"),
		},
	}
	s := newTestScanner(c, nil)

	sum := s.ScanAll(ctx(), []github.Repo{
		{FullName: "acme/ok", Owner: "acme", Name: "ok", DefaultBranch: "main"},
		{FullName: "acme/gone", Owner: "acme", Name: "gone", DefaultBranch: "main"},
	}, 2)

	if len(sum.UnreadableRepos) != 1 {
		t.Fatalf("UnreadableRepos = %v, want one entry", sum.UnreadableRepos)
	}
	if !strings.Contains(sum.UnreadableRepos[0], "acme/gone") {
		t.Errorf("UnreadableRepos[0] = %q, want the repo full name", sum.UnreadableRepos[0])
	}
	if sum.TotalRepos != 2 {
		t.Errorf("TotalRepos = %d, want 2", sum.TotalRepos)
	}
}

func TestScanAll_DeterministicOutput(t *testing.T) {
	noOSV(t)
	workflows := map[string]map[string][]byte{}
	var repos []github.Repo
	for i := 0; i < 20; i++ {
		name := fmt.Sprintf("acme/repo-%02d", i)
		repos = append(repos, github.Repo{FullName: name, Owner: "acme", Name: name, DefaultBranch: "main"})
		workflows[name] = map[string][]byte{
			".github/workflows/ci.yml":       []byte("jobs:\n  b:\n    steps:\n      - uses: actions/checkout@abc1234\n      - uses: actions/cache@def5678\n"),
			".github/workflows/release.yaml": []byte("jobs:\n  r:\n    steps:\n      - uses: actions/setup-node@v4\n"),
		}
	}

	var first string
	for run := 0; run < 3; run++ {
		c := &fakeClient{workflows: workflows}
		sum := newTestScanner(c, nil).ScanAll(ctx(), repos, 8)
		b, err := json.Marshal(sum.Findings)
		if err != nil {
			t.Fatal(err)
		}
		if run == 0 {
			first = string(b)
			continue
		}
		if string(b) != first {
			t.Fatalf("run %d produced different findings:\n%s\n%s", run, first, string(b))
		}
	}
}

func TestScanAll_ContextCancellation(t *testing.T) {
	noOSV(t)
	c := &fakeClient{block: true}
	s := newTestScanner(c, nil)

	repos := make([]github.Repo, 50)
	for i := range repos {
		repos[i] = github.Repo{FullName: fmt.Sprintf("acme/repo-%02d", i), Owner: "acme",
			Name: fmt.Sprintf("repo-%02d", i), DefaultBranch: "main"}
	}

	cctx, cancel := context.WithCancel(ctx())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	done := make(chan *Summary, 1)
	go func() { done <- s.ScanAll(cctx, repos, 4) }()

	select {
	case sum := <-done:
		if sum.TotalRepos >= len(repos) {
			t.Errorf("TotalRepos = %d, want fewer than %d (scan must stop on cancellation)",
				sum.TotalRepos, len(repos))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ScanAll did not honour context cancellation")
	}
}

func TestScanAll_ZeroConcurrencyDoesNotDeadlock(t *testing.T) {
	noOSV(t)
	// Regression: concurrency 0 previously allocated a zero-capacity
	// semaphore and hung forever.
	c := &fakeClient{workflows: map[string]map[string][]byte{
		"acme/app": {".github/workflows/ci.yml": []byte("jobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n")},
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
	if sum.Total() != 0 {
		t.Errorf("Total() = %d, want 0", sum.Total())
	}
}

// ── helpers ────────────────────────────────────────────────────────────

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

func TestIsShortSHA(t *testing.T) {
	tests := map[string]bool{
		"":         false,
		"abc":      false, // too short
		"abc1234":  true,  // 7-char short SHA
		"deadbeef": true,  // 8 hex chars
		"20240101": false, // a date-like tag, not a SHA
		"0123456789abcdef0123456789abcdef01234567":  false, // full 40-char SHA
		"0123456789abcdef0123456789abcdef012345678": false, // 41 chars
		"g123456": false, // non-hex
		"v4.1.1":  false, // punctuation + v
	}
	for in, want := range tests {
		if got := isShortSHA(in); got != want {
			t.Errorf("isShortSHA(%q) = %v, want %v", in, got, want)
		}
	}
}

// ── OSV fixtures ───────────────────────────────────────────────────────

// osvFixture builds an OSV advisory from its JSON form so the test does
// not depend on the internal layout of the advisory type.
func osvFixture(t *testing.T, id, summary, fixed string) rules.OSVVuln {
	t.Helper()
	body := fmt.Sprintf(`{"id":%q,"summary":%q,"affected":[{"package":{"name":"actions/checkout","ecosystem":"GitHub Actions"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":%q}]}]}]}`,
		id, summary, fixed)
	var v rules.OSVVuln
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		t.Fatalf("building OSV fixture: %v", err)
	}
	return v
}
