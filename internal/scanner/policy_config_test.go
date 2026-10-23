package scanner

import (
	"strings"
	"sync"
	"testing"
)

// fullSHA is a 40-character commit SHA.
const fullSHA = "0123456789abcdef0123456789abcdef01234567"

// mustPolicy builds a policy or fails the test.
func mustPolicy(t *testing.T, c *PolicyConfig) Policy {
	t.Helper()
	p, err := NewPolicy(c)
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	return p
}

func TestNewPolicyNilConfig(t *testing.T) {
	p, err := NewPolicy(nil)
	if err != nil {
		t.Fatalf("NewPolicy(nil): %v", err)
	}
	// NoPolicy is a PolicyFuncs, which is not comparable — check what it
	// does instead of what it is.
	if p == nil {
		t.Fatal("NewPolicy(nil) = nil, want NoPolicy")
	}
	f := Finding{Category: "malicious", Action: "actions/checkout@v4"}
	if p.Suppress(f) {
		t.Error("NoPolicy suppressed a finding")
	}
	if sev := p.Severity(f); sev != "" {
		t.Errorf("NoPolicy remapped a severity to %q", sev)
	}
}

func TestNewPolicyInvalidConfig(t *testing.T) {
	p, err := NewPolicy(&PolicyConfig{Persona: "paranoid"})
	if err == nil {
		t.Fatalf("NewPolicy = %+v, want an error for an unknown persona", p)
	}
}

func TestPolicyIgnoreMatching(t *testing.T) {
	cfg := &PolicyConfig{
		IgnoreActions: []string{
			"actions/checkout",
			"owner/repo/*",
			"some-org/internal-*",
		},
	}
	p := mustPolicy(t, cfg)

	tests := []struct {
		action string
		want   bool
	}{
		{"actions/checkout@v4", true},             // exact owner/repo
		{"actions/checkout", true},                // exact owner/repo, no ref
		{"actions/checkout/extra@v4", true},       // sub-path of an ignored repo
		{"actions/checkout-extra@v4", false},      // not a sub-path of it
		{"owner/repo/sub@v1", true},               // owner/repo/* prefix
		{"owner/repo/sub/path@v1", true},          // ... at any depth
		{"owner/other@v1", false},                 // a different repo
		{"some-org/internal-thing@v1", true},      // glob
		{"some-org/other@v1", false},              // glob does not match
		{"some-org/internal-thing/sub@v1", false}, // glob stops at "/"
		{"ACTIONS/CHECKOUT@v4", true},             // case-insensitive
		{"owner/REPO/sub@v1", true},               // case-insensitive
	}
	for _, tt := range tests {
		f := Finding{Action: tt.action, Category: "vulnerable"}
		if got := p.Suppress(f); got != tt.want {
			t.Errorf("Suppress(%q) = %v, want %v", tt.action, got, tt.want)
		}
	}
}

func TestPolicyDenyIgnoreBeatsIgnoreActions(t *testing.T) {
	// A config that Validate would reject, built by hand: the policy
	// must still refuse to mute the denied action.
	cfg := &PolicyConfig{
		IgnoreActions: []string{"tj-actions/changed-files"},
		DenyIgnore:    []string{"tj-actions/changed-files"},
	}
	p := &ConfigPolicy{}
	for _, a := range cfg.IgnoreActions {
		p.ignores = append(p.ignores, compilePolicyIgnore(a))
	}
	for _, d := range cfg.DenyIgnore {
		p.denies = append(p.denies, compilePolicyIgnore(d))
	}
	p.rules = map[string]bool{}
	p.remap = map[string]string{}

	f := Finding{Action: "tj-actions/changed-files@v41", Category: "malicious"}
	if p.Suppress(f) {
		t.Error("a denied action was suppressed")
	}
}

func TestPolicyDenyIgnoreBeatsIgnoreRules(t *testing.T) {
	p := mustPolicy(t, &PolicyConfig{
		DenyIgnore:  []string{"tj-actions/changed-files"},
		IgnoreRules: []string{"malicious"},
	})
	denied := Finding{Action: "tj-actions/changed-files@v41", Category: "malicious"}
	if p.Suppress(denied) {
		t.Error("a denied action was suppressed by ignore_rules")
	}
	other := Finding{Action: "evil/other@v1", Category: "malicious"}
	if !p.Suppress(other) {
		t.Error("ignore_rules did not drop a malicious finding for another action")
	}
}

func TestPolicyIgnoreRules(t *testing.T) {
	p := mustPolicy(t, &PolicyConfig{IgnoreRules: []string{"outdated", "osv"}})
	tests := []struct {
		category string
		want     bool
	}{
		{"outdated", true},
		{"osv", true},
		{"malicious", false},
		{"vulnerable", false},
		{"unpinned", false},
	}
	for _, tt := range tests {
		f := Finding{Action: "actions/checkout@v4", Category: tt.category}
		if got := p.Suppress(f); got != tt.want {
			t.Errorf("Suppress(category %q) = %v, want %v", tt.category, got, tt.want)
		}
	}
}

func TestPolicySeverityRemap(t *testing.T) {
	p := mustPolicy(t, &PolicyConfig{
		SeverityRemap: map[string]string{
			"outdated":            "HIGH",
			"GHSA-mrrh-fwg8-r2c3": "CRITICAL",
			"some-unknown-key":    "LOW",
		},
	})
	tests := []struct {
		name    string
		finding Finding
		want    string
	}{
		{"by category", Finding{Category: "outdated"}, "HIGH"},
		{"by advisory", Finding{Category: "vulnerable", AdvisoryID: "GHSA-mrrh-fwg8-r2c3"}, "CRITICAL"},
		{"advisory wins over category", Finding{Category: "outdated", AdvisoryID: "GHSA-mrrh-fwg8-r2c3"}, "CRITICAL"},
		{"unknown key is ignored", Finding{Category: "vulnerable"}, ""},
		{"unmapped category", Finding{Category: "malicious"}, ""},
	}
	for _, tt := range tests {
		if got := p.Severity(tt.finding); got != tt.want {
			t.Errorf("%s: Severity = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestPolicySeverityRemapInvalidValueRejected(t *testing.T) {
	if _, err := NewPolicy(&PolicyConfig{SeverityRemap: map[string]string{"outdated": "SEVERE"}}); err == nil {
		t.Fatal("NewPolicy accepted an invalid severity")
	}
}

func TestPersonaFindings(t *testing.T) {
	ref := ActionRef{Raw: "actions/checkout@v4", Name: "actions/checkout", FullName: "actions/checkout", Ref: "v4"}
	sha := ActionRef{Raw: "actions/checkout@" + fullSHA, Name: "actions/checkout", FullName: "actions/checkout", Ref: fullSHA}
	exact := ActionRef{Raw: "actions/checkout@v4.2.2", Name: "actions/checkout", FullName: "actions/checkout", Ref: "v4.2.2"}

	tests := []struct {
		persona string
		ref     ActionRef
		want    int
	}{
		{"regular", ref, 0},
		{"", ref, 0},
		{"pedantic", ref, 1},
		{"pedantic", sha, 0},
		{"pedantic", exact, 0},
		{"auditor", ref, 1},
		{"auditor", exact, 1},
		{"auditor", sha, 0},
	}
	for _, tt := range tests {
		c := &PolicyConfig{Persona: tt.persona}
		got := c.PersonaFindings("owner/repo", ".github/workflows/ci.yml", "build", tt.ref)
		if len(got) != tt.want {
			t.Errorf("persona %q ref %q: %d findings, want %d", tt.persona, tt.ref.Ref, len(got), tt.want)
			continue
		}
		if tt.want == 0 {
			continue
		}
		f := got[0]
		if f.Severity != "LOW" {
			t.Errorf("persona %q: severity = %q, want LOW", tt.persona, f.Severity)
		}
		if f.Category != "unpinned" {
			t.Errorf("persona %q: category = %q, want unpinned", tt.persona, f.Category)
		}
		if f.Repo != "owner/repo" || f.Workflow != ".github/workflows/ci.yml" || f.Job != "build" {
			t.Errorf("persona %q: finding lost its location: %+v", tt.persona, f)
		}
		if f.Action != tt.ref.Raw {
			t.Errorf("persona %q: action = %q, want %q", tt.persona, f.Action, tt.ref.Raw)
		}
		if f.Fix == "" {
			t.Errorf("persona %q: finding has no fix", tt.persona)
		}
	}
}

func TestPersonaFindingsThroughPolicy(t *testing.T) {
	p := mustPolicy(t, &PolicyConfig{Persona: "auditor"})
	pp, ok := p.(PersonaPolicy)
	if !ok {
		t.Fatalf("policy %T does not implement PersonaPolicy", p)
	}
	ref := ActionRef{Raw: "actions/checkout@v4", FullName: "actions/checkout", Ref: "v4"}
	if got := pp.PersonaFindings("owner/repo", "ci.yml", "build", ref); len(got) != 1 {
		t.Fatalf("PersonaFindings = %d findings, want 1", len(got))
	}
}

func TestParseInlineIgnores(t *testing.T) {
	content := []byte(`jobs:
  build:
    steps:
      - uses: actions/checkout@v4 # actionscan: ignore
      - uses: actions/setup-go@v5 # actionscan: ignore[outdated]
      - uses: actions/cache@v4 # actionscan: ignore[outdated,unpinned]
      - uses: actions/upload-artifact@v4 # actionscan: ignore outdated on purpose
      - uses: actions/checkout@v4 # actionscan: keep
      - uses: actions/checkout@v4 # zizmor: ignore
      - run: echo "hello" # actionscan: ignore
        shell: bash
`)
	got := ParseInlineIgnores(content)

	if len(got) != 5 {
		t.Fatalf("parsed %d directives, want 5: %+v", len(got), got)
	}
	if ig := got[4]; len(ig.Rules) != 0 || ig.Reason != "" {
		t.Errorf("line 4 = %+v, want all rules and no reason", ig)
	}
	if ig := got[5]; len(ig.Rules) != 1 || ig.Rules[0] != "outdated" {
		t.Errorf("line 5 = %+v, want rules [outdated]", ig)
	}
	if ig := got[6]; len(ig.Rules) != 2 || ig.Rules[0] != "outdated" || ig.Rules[1] != "unpinned" {
		t.Errorf("line 6 = %+v, want rules [outdated unpinned]", ig)
	}
	if ig := got[7]; len(ig.Rules) != 0 || ig.Reason != "outdated on purpose" {
		t.Errorf("line 7 = %+v, want all rules and the reason", ig)
	}
	// "actionscan: keep" and "zizmor: ignore" are not actionscan directives.
	if _, ok := got[8]; ok {
		t.Error("line 8 was parsed, but it is not an actionscan directive")
	}
	if _, ok := got[9]; ok {
		t.Error("line 9 was parsed, but it is not an actionscan directive")
	}
	// A directive inside a run: block is still parsed — the caller decides.
	if _, ok := got[10]; !ok {
		t.Error("line 10 was not parsed; the caller must be able to see it")
	}
	for line, ig := range got {
		if ig.Line != line {
			t.Errorf("directive for line %d reports line %d", line, ig.Line)
		}
	}
}

func TestParseInlineIgnoresEmpty(t *testing.T) {
	if got := ParseInlineIgnores(nil); len(got) != 0 {
		t.Errorf("ParseInlineIgnores(nil) = %+v, want empty", got)
	}
	if got := ParseInlineIgnores([]byte("no directives here\n")); len(got) != 0 {
		t.Errorf("ParseInlineIgnores = %+v, want empty", got)
	}
}

func TestSuppressInline(t *testing.T) {
	content := []byte(`      - uses: actions/checkout@v4 # actionscan: ignore[outdated]
      - uses: actions/setup-go@v5 # actionscan: ignore
`)
	ignores := ParseInlineIgnores(content)

	if !SuppressInline(ignores, Finding{Category: "outdated"}, 1) {
		t.Error("line 1 outdated finding was not suppressed")
	}
	if SuppressInline(ignores, Finding{Category: "vulnerable"}, 1) {
		t.Error("line 1 vulnerable finding was suppressed by an outdated ignore")
	}
	if !SuppressInline(ignores, Finding{Category: "vulnerable"}, 2) {
		t.Error("line 2 finding was not suppressed by a bare ignore")
	}
	if SuppressInline(ignores, Finding{Category: "outdated"}, 3) {
		t.Error("a finding on a line without a directive was suppressed")
	}
	if SuppressInline(ignores, Finding{Category: "outdated"}, 0) {
		t.Error("a finding without a line number was suppressed")
	}
	if SuppressInline(nil, Finding{Category: "outdated"}, 1) {
		t.Error("a finding was suppressed without any directives")
	}
}

func TestSuppressInlineByAdvisory(t *testing.T) {
	ignores := ParseInlineIgnores([]byte("uses: a/b@v1 # actionscan: ignore[GHSA-mrrh-fwg8-r2c3]\n"))
	if !SuppressInline(ignores, Finding{Category: "vulnerable", AdvisoryID: "GHSA-mrrh-fwg8-r2c3"}, 1) {
		t.Error("advisory-specific ignore did not match")
	}
	if SuppressInline(ignores, Finding{Category: "vulnerable", AdvisoryID: "GHSA-other"}, 1) {
		t.Error("a different advisory was suppressed")
	}
}

func TestPolicyIsConcurrencySafe(t *testing.T) {
	p := mustPolicy(t, &PolicyConfig{
		IgnoreActions: []string{"actions/checkout"},
		DenyIgnore:    []string{"tj-actions/changed-files"},
		IgnoreRules:   []string{"outdated"},
		SeverityRemap: map[string]string{"outdated": "HIGH"},
		Persona:       "auditor",
	})
	findings := []Finding{
		{Action: "actions/checkout@v4", Category: "outdated"},
		{Action: "tj-actions/changed-files@v41", Category: "malicious"},
		{Action: "owner/other@v1", Category: "vulnerable", AdvisoryID: "GHSA-mrrh-fwg8-r2c3"},
	}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				f := findings[(i+j)%len(findings)]
				_ = p.Suppress(f)
				_ = p.Severity(f)
			}
		}(i)
	}
	wg.Wait()
}

func TestPolicyReasoningIsStable(t *testing.T) {
	// The same finding must always get the same answer: a scan that
	// reports a finding on one run and hides it on the next is worse
	// than no scan at all.
	p := mustPolicy(t, &PolicyConfig{IgnoreActions: []string{"Owner/Repo"}})
	for i := 0; i < 100; i++ {
		f := Finding{Action: "owner/repo@v1", Category: "vulnerable"}
		if !p.Suppress(f) {
			t.Fatal("the ignore stopped matching")
		}
	}
}

func TestConfigPolicyKeepsInlineIgnoreFlag(t *testing.T) {
	p, ok := mustPolicy(t, &PolicyConfig{RespectInlineIgnores: true}).(*ConfigPolicy)
	if !ok {
		t.Fatal("NewPolicy did not return a *ConfigPolicy")
	}
	if !p.RespectInlineIgnores() {
		t.Error("RespectInlineIgnores() = false, want true")
	}
}

func TestPolicyConfigPersonaUnknownIsRejected(t *testing.T) {
	err := (&PolicyConfig{Persona: "shouty"}).Validate()
	if err == nil || !strings.Contains(err.Error(), "persona") {
		t.Fatalf("Validate = %v, want a persona error", err)
	}
}
