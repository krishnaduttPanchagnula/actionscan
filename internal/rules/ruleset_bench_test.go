package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// buildLargeRuleSet simulates a realistic threat-intel feed: ~800
// vulnerable packages with ~2000 range entries and ~100 compromised
// actions — the sizes seen from GHSA.
func buildLargeRuleSet() *RuleSet {
	var rules []Rule
	for i := 0; i < 800; i++ {
		repo := fmt.Sprintf("owner%03d/action-%03d", i%50, i)
		rules = append(rules, Rule{
			Category: CategoryVulnerable,
			Repo:     repo,
			Range:    fmt.Sprintf(">= %d.0.0, < %d.0.0", i%9+1, i%9+2),
			Reason:   fmt.Sprintf("GHSA-%04d: vulnerability in package", i),
			Fix:      "Upgrade to a patched version",
			Severity: "HIGH",
		})
	}
	// Popular packages with multiple advisory ranges each.
	for i := 0; i < 400; i++ {
		repo := fmt.Sprintf("popular/pkg-%03d", i)
		rules = append(rules,
			Rule{Category: CategoryVulnerable, Repo: repo, Range: ">= 1.0.0, < 1.5.0",
				Reason: fmt.Sprintf("GHSA-a%03d: low range", i), Fix: "Upgrade to >= 1.5.0", Severity: "HIGH"},
			Rule{Category: CategoryVulnerable, Repo: repo, Range: ">= 2.0.0, < 2.2.0",
				Reason: fmt.Sprintf("GHSA-b%03d: mid range", i), Fix: "Upgrade to >= 2.2.0", Severity: "MEDIUM"},
		)
	}
	for i := 0; i < 100; i++ {
		rules = append(rules, Rule{
			Category: CategoryMalicious,
			Repo:     fmt.Sprintf("compromised/action-%03d", i),
			Refs:     []string{"v1", "v2"},
			Reason:   "supply-chain compromise",
			Severity: "CRITICAL",
		})
	}
	rules = append(rules, Rule{
		Category: CategoryMalicious,
		Repo:     "tj-actions/changed-files",
		Range:    "< 46.0.1",
		Reason:   "CVE-2025-30066",
		Severity: "CRITICAL",
	})
	return &RuleSet{Rules: rules}
}

// ── Match ──────────────────────────────────────────────────────────────

func BenchmarkMatch_Miss(b *testing.B) {
	rs := buildLargeRuleSet()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if got := rs.Match("actions/checkout", "v4.1.1"); len(got) != 0 {
			b.Fatal("unexpected hit")
		}
	}
}

func BenchmarkMatch_Hit(b *testing.B) {
	rs := buildLargeRuleSet()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if got := rs.Match("owner049/action-499", "v5.0.0"); len(got) == 0 {
			b.Fatal("expected hit")
		}
	}
}

func BenchmarkMatch_MultiRangePackage(b *testing.B) {
	rs := buildLargeRuleSet()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if got := rs.Match("popular/pkg-200", "v2.1.0"); len(got) == 0 {
			b.Fatal("expected hit")
		}
	}
}

func BenchmarkMatch_ExactRef(b *testing.B) {
	rs := buildLargeRuleSet()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if got := rs.Match("compromised/action-042", "v1"); len(got) == 0 {
			b.Fatal("expected hit")
		}
	}
}

// ── Load hot paths ─────────────────────────────────────────────────────

func BenchmarkLoad_FreshCache(b *testing.B) {
	dir := b.TempDir()
	writeCacheForBench(b, dir)

	opts := LoadOptions{
		CacheDir:    dir,
		TTL:         12 * time.Hour,
		UseOSV:      true,
		FetchLatest: true,
	}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rs, err := Load(ctx, opts)
		if err != nil {
			b.Fatal(err)
		}
		_ = rs
	}
}

// ── helpers ────────────────────────────────────────────────────────────

func writeCacheForBench(b *testing.B, dir string) {
	b.Helper()
	rs := buildLargeRuleSet()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		b.Fatal(err)
	}
	data, err := json.Marshal(cacheFile{
		FetchedAt: time.Now(),
		Rules:     rs.Rules,
		Sources:   []string{"ghsa", "compromised-feed"},
	})
	if err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, cacheFileName), data, 0o644); err != nil {
		b.Fatal(err)
	}
}
