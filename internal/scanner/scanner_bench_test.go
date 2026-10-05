package scanner

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/krishnaduttPanchagnula/actionscan/internal/github"
	"github.com/krishnaduttPanchagnula/actionscan/internal/rules"
)

// realisticWorkflow mimics a busy CI file: ~150 lines, 20 action refs.
func realisticWorkflow() []byte {
	var sb strings.Builder
	sb.WriteString("name: CI\non: [push, pull_request]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n")
	for i := 0; i < 20; i++ {
		sb.WriteString(fmt.Sprintf("      - name: Step %d\n", i))
		sb.WriteString(fmt.Sprintf("        uses: owner%02d/action-%02d@v%d.%d.0\n", i%10, i, i%5+1, i))
		sb.WriteString("        with:\n          key: value\n")
	}
	sb.WriteString("  test:\n    runs-on: ubuntu-latest\n    steps:\n")
	sb.WriteString("      - uses: actions/checkout@v4\n")
	sb.WriteString("      - uses: actions/setup-node@v4\n")
	sb.WriteString("      - uses: tj-actions/changed-files@v41\n")
	return []byte(sb.String())
}

// largeRuleSet mirrors feed sizes at benchmark time (kept local to this
// package so scanner benches do not depend on rules internals).
func largeRuleSet() *rules.RuleSet {
	v := map[string]rules.VulnRule{}
	for i := 0; i < 1200; i++ {
		v[fmt.Sprintf("pkg%04d/action@>= %d.0.0, < %d.0.0", i, i%9+1, i%9+2)] =
			rules.VulnRule{Reason: "GHSA: vuln", Fix: "Upgrade to a patched version"}
	}
	for i := 0; i < 20; i++ {
		v[fmt.Sprintf("owner%02d/action%02d@>= 1.0.0, < 2.0.0", i%10, i)] =
			rules.VulnRule{Reason: "GHSA: hit", Fix: "Upgrade to >= 2.0.0"}
	}
	return &rules.RuleSet{
		Malicious: []rules.CompromisedEntry{
			{Repo: "tj-actions/changed-files", Description: "CVE-2025-30066"},
		},
		Vulnerable:  v,
		OSVCache:    map[string][]rules.OSVVuln{},
		LatestTags:  map[string]string{},
		UseOSV:      true,
		FetchLatest: true,
	}
}

// ── ExtractActions ─────────────────────────────────────────────────────

func BenchmarkExtractActions(b *testing.B) {
	wf := realisticWorkflow()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got := ExtractActions(wf)
		if len(got) != 23 {
			b.Fatalf("got %d actions, want 23", len(got))
		}
	}
}

// ── Check ──────────────────────────────────────────────────────────────

func BenchmarkCheck_CleanAction(b *testing.B) {
	noOSVBench(b)
	rs := largeRuleSet()
	c := &fakeClient{latest: map[string]string{}}
	s := newTestScanner(c, rs)
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got := s.Check(ctx, "acme/app", "ci.yml", "actions/checkout@v4.1.1")
		if len(got) != 0 {
			b.Fatalf("unexpected findings: %+v", got)
		}
	}
}

func BenchmarkCheck_VulnerableAction(b *testing.B) {
	noOSVBench(b)
	rs := largeRuleSet()
	c := &fakeClient{latest: map[string]string{}}
	s := newTestScanner(c, rs)
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got := s.Check(ctx, "acme/app", "ci.yml", "owner05/action05@v1.5.0")
		if len(got) != 1 || got[0].Category != "vulnerable" {
			b.Fatalf("unexpected findings: %+v", got)
		}
	}
}

func BenchmarkCheck_MaliciousAction(b *testing.B) {
	noOSVBench(b)
	rs := largeRuleSet()
	c := &fakeClient{latest: map[string]string{}}
	s := newTestScanner(c, rs)
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got := s.Check(ctx, "acme/app", "ci.yml", "tj-actions/changed-files@v41")
		if len(got) != 1 || got[0].Category != "malicious" {
			b.Fatalf("unexpected findings: %+v", got)
		}
	}
}

// ── ScanAll ────────────────────────────────────────────────────────────

func BenchmarkScanAll_200Repos(b *testing.B) {
	noOSVBench(b)

	repos := make([]github.Repo, 200)
	workflows := map[string]map[string][]byte{}
	for i := range repos {
		full := fmt.Sprintf("acme/repo-%03d", i)
		repos[i] = github.Repo{
			FullName: full, Owner: "acme",
			Name: fmt.Sprintf("repo-%03d", i), DefaultBranch: "main",
		}
		workflows[full] = map[string][]byte{
			"ci.yml":     realisticWorkflow(),
			"deploy.yml": realisticWorkflow(),
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c := &fakeClient{
			workflows: workflows,
			latest:    map[string]string{},
		}
		s := newTestScanner(c, largeRuleSet())
		sum := s.ScanAll(context.Background(), repos, 8)
		if sum.TotalRepos != 200 {
			b.Fatalf("TotalRepos = %d", sum.TotalRepos)
		}
	}
}

// noOSVBench stubs out OSV for benchmark runs (network would dominate).
func noOSVBench(b *testing.B) {
	b.Helper()
	orig := queryOSV
	queryOSV = func(_ context.Context, _, _ string) ([]rules.OSVVuln, error) {
		return nil, nil
	}
	b.Cleanup(func() { queryOSV = orig })
}
