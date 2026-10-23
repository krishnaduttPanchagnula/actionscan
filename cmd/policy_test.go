package cmd

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/krishnaduttPanchagnula/actionscan/internal/feed"
	"github.com/krishnaduttPanchagnula/actionscan/internal/rules"
	"github.com/krishnaduttPanchagnula/actionscan/internal/scanner"
)

// The policy file is how a user silences the findings they have already
// triaged. Without it, actionscan is unusable in the large orgs that
// need it most.
func TestLoadPolicyFromDirectory(t *testing.T) {
	dir := t.TempDir()
	body := `
version: 1
ignore_actions:
  - actions/checkout
deny_ignore:
  - tj-actions/changed-files
ignore_rules:
  - outdated
severity_remap:
  outdated: LOW
persona: pedantic
`
	if err := os.WriteFile(filepath.Join(dir, "actionscan.yml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	pc, err := loadPolicyForTest(dir)
	if err != nil {
		t.Fatal(err)
	}
	if pc == nil {
		t.Fatal("a policy file must be found")
	}
	if err := pc.Validate(); err != nil {
		t.Fatalf("policy must validate: %v", err)
	}
	if len(pc.IgnoreActions) != 1 || pc.IgnoreActions[0] != "actions/checkout" {
		t.Errorf("ignore_actions = %v", pc.IgnoreActions)
	}
	if pc.Persona != "pedantic" {
		t.Errorf("persona = %q, want pedantic", pc.Persona)
	}
}

// No policy file is a valid state, not an error.
func TestLoadPolicyMissingIsNotAnError(t *testing.T) {
	pc, err := loadPolicyForTest(t.TempDir())
	if err != nil {
		t.Fatalf("a missing policy file must not be an error: %v", err)
	}
	if pc != nil {
		t.Errorf("got %+v, want nil", pc)
	}
}

// A malformed policy must fail loudly, not be silently ignored.
func TestLoadPolicyMalformedIsAnError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "actionscan.yml"), []byte("version: 1\nignore_actions: [oops\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPolicyForTest(dir); err == nil {
		t.Error("a malformed policy file must be an error")
	}
}

// A policy that would mute a known-compromised action must be rejected.
func TestPolicyRejectsIgnoringACompromisedAction(t *testing.T) {
	pc := &scanner.PolicyConfig{
		Version:       1,
		IgnoreActions: []string{"tj-actions/changed-files"},
		DenyIgnore:    []string{"tj-actions/changed-files"},
	}
	if err := pc.Validate(); err == nil {
		t.Error("ignoring an action that is also denied must be an error")
	}
}

// The ignore list must actually suppress, and the deny list must beat
// it.
func TestPolicySuppressAndDeny(t *testing.T) {
	pc := &scanner.PolicyConfig{
		Version:       1,
		IgnoreActions: []string{"actions/checkout"},
		DenyIgnore:    []string{"tj-actions/changed-files"},
	}
	p, err := scanner.NewPolicy(pc)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Suppress(scanner.Finding{Action: "actions/checkout@v4", Category: "outdated"}) {
		t.Error("an ignored action must be suppressed")
	}
	if p.Suppress(scanner.Finding{Action: "tj-actions/changed-files@v41", Category: "malicious"}) {
		t.Error("a denied action must never be suppressed")
	}
	if p.Suppress(scanner.Finding{Action: "actions/setup-node@v4", Category: "outdated"}) {
		t.Error("an action that is not ignored must not be suppressed")
	}
}

// An inline ignore comment must suppress the finding on that line, and
// only that line.
func TestInlineIgnoreSuppressesItsOwnLine(t *testing.T) {
	ignores := scanner.ParseInlineIgnores([]byte(
		"jobs:\n" +
			"  b:\n" +
			"    steps:\n" +
			"      - uses: actions/checkout@v3 # actionscan: ignore[outdated] pinned on purpose\n" +
			"      - uses: actions/setup-node@v3\n"))

	if len(ignores) != 1 {
		t.Fatalf("got %d inline ignores, want 1: %+v", len(ignores), ignores)
	}
	_, ok := ignores[4]
	if !ok {
		t.Errorf("the ignore should be on line 4, got %+v", ignores)
	}
	f := scanner.Finding{Action: "actions/checkout@v3", Category: "outdated"}
	if !scanner.SuppressInline(ignores, f, 4) {
		t.Error("the finding on the ignored line must be suppressed")
	}
	if scanner.SuppressInline(ignores, f, 5) {
		t.Error("a finding on a different line must not be suppressed")
	}
}

// The feed must be reproducible, or it cannot be diffed or cached.
func TestFeedIsReproducible(t *testing.T) {
	rs := &rules.RuleSet{
		Sources: []string{"ghsa"},
		Rules: []rules.Rule{
			{Category: rules.CategoryMalicious, Repo: "b/repo", Range: "< 2.0.0", Severity: "CRITICAL", AdvisoryID: "GHSA-b"},
			{Category: rules.CategoryVulnerable, Repo: "a/repo", Range: "< 1.0.0", Severity: "HIGH", AdvisoryID: "GHSA-a"},
		},
	}
	f1 := feed.Build(rs)
	f2 := feed.Build(rs)
	b1, err := f1.MarshalStable(time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	b2, err := f2.MarshalStable(time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if string(b1) != string(b2) {
		t.Error("the feed must be byte-identical for the same rules")
	}
	// Entries must be sorted, so a diff of two feeds is meaningful.
	// The order is (category, repo, range, advisory id).
	if len(f1.Entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(f1.Entries))
	}
	if f1.Entries[0].Category != rules.CategoryMalicious || f1.Entries[0].Repo != "b/repo" {
		t.Errorf("entries are not sorted by (category, repo): %+v", f1.Entries)
	}
	if f1.Entries[1].Category != rules.CategoryVulnerable || f1.Entries[1].Repo != "a/repo" {
		t.Errorf("entries are not sorted by (category, repo): %+v", f1.Entries)
	}
}
