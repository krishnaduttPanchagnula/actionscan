package rules

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	semver "github.com/Masterminds/semver/v3"
)

// ── refInRange / matchesConstraint ─────────────────────────────────────

func TestRefInRange(t *testing.T) {
	tests := []struct {
		ref    string
		ranStr string
		want   bool
	}{
		{"1.5.0", ">= 1.0.0, < 2.0.0", true},
		{"v1.0.0", ">= 1.0.0, < 2.0.0", true}, // v-prefix tolerated
		{"0.9.9", ">= 1.0.0, < 2.0.0", false},
		{"2.0.0", ">= 1.0.0, < 2.0.0", false}, // upper bound exclusive
		{"1.9.9", ">= 1.0.0, < 2.0.0", true},
		{"3.1.4", "", true},                  // empty constraint matches (documented)
		{"not-a-version", ">= 1.0.0", false}, // unparsable ref
		{"1.0.0", ">= garbage", false},       // unparsable range
		{"2.5.0", "<= 2.5.0", true},
		{"2.5.1", "<= 2.5.0", false},
		{"2.5.0", "< 2.5.0", false},
		{"2.4.9", "< 2.5.0", true},
		{"1.0.0", "> 1.0.0", false},
		{"1.0.1", "> 1.0.0", true},
		{"1.2.3", "== 1.2.3", true},
		{"1.2.3", "= 1.2.3", true},
		{"1.2.4", "= 1.2.3", false},
		{"1.2.3", "1.2.3", true}, // bare version = equality
		{"1.2", ">= 1.0", true},  // two-part version padded
		{"1", ">= 1.0.0", true},  // one-part version padded
	}
	for _, tt := range tests {
		if got := refInRange(tt.ref, tt.ranStr); got != tt.want {
			t.Errorf("refInRange(%q, %q) = %v, want %v", tt.ref, tt.ranStr, got, tt.want)
		}
	}
}

func TestRefInRangeRequiresAllCommaParts(t *testing.T) {
	// GHSA ranges are AND-comma-separated: a ref satisfying only the
	// first bound must not match.
	if refInRange("3.0.0", ">= 1.0.0, < 2.0.0") {
		t.Error("3.0.0 must not satisfy '>= 1.0.0, < 2.0.0'")
	}
}

func TestMatchesConstraint(t *testing.T) {
	v := semver.MustParse("1.5.0")
	tests := []struct {
		c    string
		want bool
	}{
		{"", true}, // empty = match
		{">= 1.0.0", true},
		{"<= 2.0.0", true},
		{"> 1.5.0", false},
		{"< 1.5.0", false},
		{"== 1.5.0", true},
		{"= 1.5.0", true},
		{"1.5.0", true},
		{"v1.5.0", true},
		{"1.5", true},      // padded to 1.5.0
		{"1", false},       // padded to 1.0.0 — 1.5.0 != 1.0.0
		{"garbage", false}, // unparsable
	}
	for _, tt := range tests {
		if got := matchesConstraint(v, tt.c); got != tt.want {
			t.Errorf("matchesConstraint(%q) = %v, want %v", tt.c, got, tt.want)
		}
	}
}

// ── IsMalicious ────────────────────────────────────────────────────────

func TestIsMalicious(t *testing.T) {
	rs := &RuleSet{Malicious: []CompromisedEntry{
		{Repo: "tj-actions/changed-files", Refs: []string{"v41", "v42"}, Description: "CVE-2025-30066"},
		{Repo: "reviewdog/action-setup", Description: "no refs = all versions"}, // empty Refs
	}}

	tests := []struct {
		repo, ref string
		want      bool
	}{
		{"tj-actions/changed-files", "v41", true},
		{"tj-actions/changed-files", "v42", true},
		{"tj-actions/changed-files", "v43", false}, // not in ref list
		{"TJ-Actions/Changed-Files", "v41", true},  // case-insensitive
		{" reviewdog/action-setup ", "anything", true},
		{"actions/checkout", "v4", false},
	}
	for _, tt := range tests {
		got, ok := rs.IsMalicious(tt.repo, tt.ref)
		if ok != tt.want {
			t.Errorf("IsMalicious(%q, %q) ok = %v, want %v", tt.repo, tt.ref, ok, tt.want)
			continue
		}
		if ok && got.Repo == "" {
			t.Errorf("matched entry has empty Repo: %+v", got)
		}
	}
}

func TestIsMaliciousEmptyRuleSet(t *testing.T) {
	rs := &RuleSet{}
	if _, ok := rs.IsMalicious("anything", "v1"); ok {
		t.Error("empty rule set must not match")
	}
}

// ── CheckVulnerable ────────────────────────────────────────────────────

func TestCheckVulnerable(t *testing.T) {
	rs := &RuleSet{Vulnerable: map[string]VulnRule{
		"actions/checkout@>= 1.0.0, < 2.0.0": {Reason: "GHSA-aaaa: upgrade", Fix: "Upgrade to >= 2.0.0"},
	}}

	rule, ok := rs.CheckVulnerable("actions/checkout", "v1.5.0")
	if !ok || !strings.Contains(rule.Reason, "GHSA-aaaa") {
		t.Errorf("in-range ref: got (%q, %v), want hit", rule.Reason, ok)
	}
	if rule.Fix == "" {
		t.Error("matched advisory must carry a fix")
	}
	if _, ok := rs.CheckVulnerable("actions/checkout", "v2.0.0"); ok {
		t.Error("out-of-range ref must not match")
	}
	if _, ok := rs.CheckVulnerable("other/action", "v1.5.0"); ok {
		t.Error("different repo must not match")
	}
	if _, ok := rs.CheckVulnerable("actions/checkout", "not-semver"); ok {
		t.Error("non-semver ref must not match")
	}
}

func TestCheckVulnerableDefaultFallbacks(t *testing.T) {
	// DefaultVulnerable uses "repo@version" keys where the "range" is an
	// exact version equality.
	rs := &RuleSet{Vulnerable: DefaultVulnerable}
	if _, ok := rs.CheckVulnerable("actions/checkout", "v2"); !ok {
		t.Error("actions/checkout@v2 should be flagged by builtin fallback")
	}
	if _, ok := rs.CheckVulnerable("actions/upload-artifact", "v3"); !ok {
		t.Error("actions/upload-artifact@v3 should be flagged by builtin fallback")
	}
	if _, ok := rs.CheckVulnerable("actions/checkout", "v4"); ok {
		t.Error("actions/checkout@v4 must not be flagged")
	}
}

// ── helpers ────────────────────────────────────────────────────────────

func TestNormalizeRepo(t *testing.T) {
	tests := map[string]string{
		" Owner/Repo ": "owner/repo",
		"owner/repo":   "owner/repo",
		"OWNER/REPO":   "owner/repo",
	}
	for in, want := range tests {
		if got := normalizeRepo(in); got != want {
			t.Errorf("normalizeRepo(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestOrNone(t *testing.T) {
	if got := orNone(""); got != "none" {
		t.Errorf("orNone(\"\") = %q, want \"none\"", got)
	}
	if got := orNone(">= 4.0.0"); got != ">= 4.0.0" {
		t.Errorf("orNone(\">= 4.0.0\") = %q", got)
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
	p := filepath.Join(dir, "rules-cache.json")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoad_FreshCacheSkipsNetwork(t *testing.T) {
	dir := t.TempDir()
	fetched := time.Now().Add(-1 * time.Hour)
	writeCache(t, dir, cacheFile{
		FetchedAt: fetched,
		Malicious: []CompromisedEntry{{Repo: "cached/bad-action", Description: "from cache"}},
		Vulnerable: map[string]VulnRule{
			"cached/action@>= 1.0.0": {Reason: "cached advisory", Fix: "Upgrade to >= 2.0.0"},
		},
		Sources: []string{"stepsecurity", "ghsa"},
	})

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
	if len(rs.Malicious) != 1 || rs.Malicious[0].Repo != "cached/bad-action" {
		t.Errorf("Malicious = %+v, want cached entry", rs.Malicious)
	}
	if got := strings.Join(rs.Sources, ","); got != "stepsecurity,ghsa" {
		t.Errorf("Sources = %v, want cached sources", rs.Sources)
	}
	if !rs.UseOSV || rs.FetchLatest {
		t.Errorf("opts not propagated: UseOSV=%v FetchLatest=%v", rs.UseOSV, rs.FetchLatest)
	}
	if !rs.LoadedAt.Equal(fetched) {
		t.Errorf("LoadedAt = %v, want cache time %v", rs.LoadedAt, fetched)
	}
}

func TestLoad_ExpiredCacheFallsBackOffline(t *testing.T) {
	dir := t.TempDir()
	writeCache(t, dir, cacheFile{
		FetchedAt: time.Now().Add(-72 * time.Hour), // older than TTL
		Malicious: []CompromisedEntry{{Repo: "stale/action"}},
		Sources:   []string{"stepsecurity"},
	})

	// Canceled context makes the fetchers fail instantly without
	// touching the network — exercises the offline fallback path.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	rs, err := Load(ctx, LoadOptions{
		CacheDir:    dir,
		TTL:         12 * time.Hour,
		UseOSV:      false,
		FetchLatest: true,
	})
	if err == nil {
		t.Fatal("expired cache + unreachable feeds must surface a partial-load error")
	}
	if !strings.Contains(err.Error(), "partial load") {
		t.Errorf("error = %q, want it to mention partial load", err)
	}
	if len(rs.Malicious) != len(DefaultMalicious) {
		t.Errorf("expected builtin malicious fallback (%d entries), got %d",
			len(DefaultMalicious), len(rs.Malicious))
	}
	if len(rs.Vulnerable) != len(DefaultVulnerable) {
		t.Errorf("expected builtin vulnerable fallback (%d entries), got %d",
			len(DefaultVulnerable), len(rs.Vulnerable))
	}
	if !contains(rs.Sources, "builtin-malicious-fallback") {
		t.Errorf("Sources = %v, want builtin-malicious-fallback", rs.Sources)
	}
	if rs.UseOSV || !rs.FetchLatest {
		t.Errorf("opts not propagated: UseOSV=%v FetchLatest=%v", rs.UseOSV, rs.FetchLatest)
	}

	// Cache must be rewritten with the fresh fallback data.
	b, err := os.ReadFile(filepath.Join(dir, "rules-cache.json"))
	if err != nil {
		t.Fatal(err)
	}
	var c cacheFile
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	if time.Since(c.FetchedAt) > time.Minute {
		t.Errorf("rewritten cache FetchedAt = %v, want ~now", c.FetchedAt)
	}
	if len(c.Malicious) == 0 {
		t.Error("rewritten cache lost malicious entries")
	}
}

func TestLoad_CorruptCacheRecovers(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rules-cache.json"), []byte("{not json"), 0o644); err != nil {
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
	if len(rs.Malicious) == 0 || len(rs.Vulnerable) == 0 {
		t.Error("corrupt cache must fall back to builtin rules")
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
