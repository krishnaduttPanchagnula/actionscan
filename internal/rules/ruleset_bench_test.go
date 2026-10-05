package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	semver "github.com/Masterminds/semver/v3"
)

type semverPkgVersion = semver.Version

// buildLargeRuleSet simulates a realistic threat-intel feed:
// ~800 vulnerable packages with ~2000 range entries and ~100
// compromised actions — the sizes seen from GHSA + StepSecurity.
func buildLargeRuleSet() *RuleSet {
	v := map[string]VulnRule{}
	for i := 0; i < 800; i++ {
		repo := fmt.Sprintf("owner%03d/action-%03d", i%50, i)
		v[repo+fmt.Sprintf("@>= %d.0.0, < %d.0.0", i%9+1, i%9+2)] = VulnRule{
			Reason: fmt.Sprintf("GHSA-%04d: vulnerability in package", i),
			Fix:    "Upgrade to a patched version",
		}
	}
	// Popular packages with multiple advisory ranges each.
	for i := 0; i < 400; i++ {
		repo := fmt.Sprintf("popular/pkg-%03d", i)
		v[repo+"@>= 1.0.0, < 1.5.0"] = VulnRule{Reason: fmt.Sprintf("GHSA-a%03d: low range", i), Fix: "Upgrade to >= 1.5.0"}
		v[repo+"@>= 2.0.0, < 2.2.0"] = VulnRule{Reason: fmt.Sprintf("GHSA-b%03d: mid range", i), Fix: "Upgrade to >= 2.2.0"}
	}

	mal := make([]CompromisedEntry, 0, 100)
	for i := 0; i < 100; i++ {
		mal = append(mal, CompromisedEntry{
			Repo:        fmt.Sprintf("compromised/action-%03d", i),
			Refs:        []string{"v1", "v2"},
			Description: "supply-chain compromise",
		})
	}
	mal = append(mal, CompromisedEntry{
		Repo: "tj-actions/changed-files", Description: "CVE-2025-30066",
	})

	return &RuleSet{
		Malicious:  mal,
		Vulnerable: v,
		OSVCache:   map[string][]OSVVuln{},
		LatestTags: map[string]string{},
	}
}

// ── CheckVulnerable ────────────────────────────────────────────────────

func BenchmarkCheckVulnerable_Miss(b *testing.B) {
	// Most common real case: a clean popular action checked against the
	// full feed.
	rs := buildLargeRuleSet()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := rs.CheckVulnerable("actions/checkout", "v4.1.1"); ok {
			b.Fatal("unexpected hit")
		}
	}
}

func BenchmarkCheckVulnerable_Hit(b *testing.B) {
	rs := buildLargeRuleSet()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := rs.CheckVulnerable("owner049/action-499", "v5.0.0"); !ok {
			b.Fatal("expected hit")
		}
	}
}

func BenchmarkCheckVulnerable_MultiRangePackage(b *testing.B) {
	rs := buildLargeRuleSet()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := rs.CheckVulnerable("popular/pkg-200", "v2.1.0"); !ok {
			b.Fatal("expected hit")
		}
	}
}

// ── IsMalicious ────────────────────────────────────────────────────────

func BenchmarkIsMalicious_Miss(b *testing.B) {
	rs := buildLargeRuleSet()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := rs.IsMalicious("actions/checkout", "v4"); ok {
			b.Fatal("unexpected hit")
		}
	}
}

func BenchmarkIsMalicious_HitLast(b *testing.B) {
	rs := buildLargeRuleSet()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := rs.IsMalicious("tj-actions/changed-files", "v41"); !ok {
			b.Fatal("expected hit")
		}
	}
}

// ── range matching primitives ──────────────────────────────────────────

func BenchmarkRefInRange(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !refInRange("v1.2.3", ">= 1.0.0, < 2.0.0") {
			b.Fatal("expected match")
		}
	}
}

func BenchmarkMatchesConstraint(b *testing.B) {
	rs := buildLargeRuleSet()
	_ = rs
	v := parseTestVersion(b, "1.2.3")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !matchesConstraint(v, ">= 1.0.0") {
			b.Fatal("expected match")
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

func parseTestVersion(b *testing.B, s string) *semverPkgVersion {
	b.Helper()
	v, err := semver.NewVersion(s)
	if err != nil {
		b.Fatal(err)
	}
	return v
}

func writeCacheForBench(b *testing.B, dir string) {
	b.Helper()
	rs := buildLargeRuleSet()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		b.Fatal(err)
	}
	data, err := json.Marshal(cacheFile{
		FetchedAt:  time.Now(),
		Malicious:  rs.Malicious,
		Vulnerable: rs.Vulnerable,
		Sources:    []string{"stepsecurity", "ghsa"},
	})
	if err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(dir+"/rules-cache.json", data, 0o644); err != nil {
		b.Fatal(err)
	}
}
