package rules

import (
	"context"
	"strings"
	"testing"
)

// A compromised-action feed usually states which versions were moved
// onto the malicious commit. A workflow pinned to one of those tags is
// just as compromised as one pinned to the SHA.
func TestCompromisedRange(t *testing.T) {
	tests := []struct {
		text string
		want string
	}{
		{"tj-actions/changed-files 2025-03-14 supply-chain attack — retagged v1..v45 to exfiltrate CI secrets", ">= 1, <= 45"},
		{"retagged v1 - v45", ">= 1, <= 45"},
		{"retagged v1 through v45", ">= 1, <= 45"},
		{"affected versions <= 45.0.7", "< 45.0.7"},
		{"affected versions < 46.0.1", "< 46.0.1"},
		{"broken starting with 3.1.0", ">= 3.1.0"},
		{"no version information here", ""},
		{"", ""},
	}
	for _, tt := range tests {
		if got := compromisedRange(tt.text); got != tt.want {
			t.Errorf("compromisedRange(%q) = %q, want %q", tt.text, got, tt.want)
		}
	}
}

// A feed entry that names a version range must match both the exact
// compromised SHA and the affected tags.
func TestCompromisedRuleMatchesRangeAndSHA(t *testing.T) {
	rules := rulesFromCompromised([]CompromisedEntry{{
		Repo:        "tj-actions/changed-files",
		Refs:        []string{"0e58ed8671d6b60d0890c21b07f8835ace038e67"},
		Description: "retagged v1..v45 to exfiltrate CI secrets",
	}})
	if len(rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(rules))
	}
	r := rules[0]
	if r.Range != ">= 1, <= 45" {
		t.Errorf("range = %q, want %q", r.Range, ">= 1, <= 45")
	}
	if !strings.Contains(r.Fix, "outside") {
		t.Errorf("fix = %q, want it to name the affected range", r.Fix)
	}

	rs := &RuleSet{Rules: rules}
	for _, ref := range []string{
		"v1", "v41", "v45", "0e58ed8671d6b60d0890c21b07f8835ace038e67",
	} {
		if len(rs.Match("tj-actions/changed-files", ref)) == 0 {
			t.Errorf("ref %q must match the compromised rule", ref)
		}
	}
	for _, ref := range []string{"v46.0.1", "v50", "v0.1.0"} {
		if len(rs.Match("tj-actions/changed-files", ref)) > 0 {
			t.Errorf("ref %q must not match the compromised rule", ref)
		}
	}
}

// A feed that renames its repository field parses without error but
// yields no usable entries — that must be an error, not a healthy
// source with nothing to report.
func TestFetchMalicious_RejectsEntriesWithoutRepo(t *testing.T) {
	hc := clientReturning(200, `[{"sha":"abc123","description":"something happened"}]`)
	if _, err := FetchMalicious(context.Background(), hc, "https://example.invalid/feed.json"); err == nil {
		t.Error("a feed whose entries name no repository must be an error")
	}
}

// Explicitly named versions in the incident text are exact refs.
func TestCompromisedVersions(t *testing.T) {
	got := compromisedVersions("Ultralytics Dec 2024 secondary compromise SHA (v8.3.41 / v8.3.42 backdoor).")
	want := []string{"v8.3.41", "v8.3.42"}
	if len(got) != len(want) {
		t.Fatalf("compromisedVersions = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("compromisedVersions[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if v := compromisedVersions("no versions here"); len(v) != 0 {
		t.Errorf("compromisedVersions = %v, want none", v)
	}
}
