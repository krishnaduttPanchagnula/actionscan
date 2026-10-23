package feed

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/krishnaduttPanchagnula/actionscan/internal/rules"
)

func testRuleSet() *rules.RuleSet {
	return &rules.RuleSet{
		LoadedAt: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC),
		Sources:  []string{"ghsa", "compromised-feed"},
		Rules: []rules.Rule{
			{
				Category:    rules.CategoryVulnerable,
				Repo:        "actions/checkout",
				Range:       "< 4.0.0",
				Reason:      "GHSA-aaaa: prototype pollution",
				Fix:         "Upgrade actions/checkout to v4",
				Severity:    "HIGH",
				AdvisoryID:  "GHSA-aaaa-bbbb-cccc",
				AdvisoryURL: "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
			},
			{
				Category: rules.CategoryMalicious,
				Repo:     "tj-actions/changed-files",
				Range:    "< 46.0.1",
				Refs:     []string{"v41", "abc1234"},
				Reason:   "Compromised Mar 2025 (CVE-2025-30066) — dumped runner memory to attacker C2",
				Fix:      "Remove or replace tj-actions/changed-files",
				Severity: "CRITICAL",
			},
		},
	}
}

func TestBuildEntries(t *testing.T) {
	f := Build(testRuleSet())

	if f.SchemaVersion != Version {
		t.Errorf("schema_version = %d, want %d", f.SchemaVersion, Version)
	}
	if f.GeneratedAt == "" {
		t.Error("generated_at is empty — a consumer cannot tell how fresh the feed is")
	}
	if _, err := time.Parse(time.RFC3339, f.GeneratedAt); err != nil {
		t.Errorf("generated_at %q is not RFC3339: %v", f.GeneratedAt, err)
	}
	if f.RulesLoadedAt != "2026-10-01T12:00:00Z" {
		t.Errorf("rules_loaded_at = %q", f.RulesLoadedAt)
	}
	if want := []string{"compromised-feed", "ghsa"}; !reflect.DeepEqual(f.Sources, want) {
		t.Errorf("sources = %v, want %v", f.Sources, want)
	}
	if len(f.Entries) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(f.Entries), f.Entries)
	}

	// "malicious" sorts before "vulnerable".
	mal := f.Entries[0]
	if mal.Category != rules.CategoryMalicious {
		t.Errorf("category = %q, want malicious", mal.Category)
	}
	if mal.Repo != "tj-actions/changed-files" {
		t.Errorf("repo = %q", mal.Repo)
	}
	if mal.Range != "< 46.0.1" {
		t.Errorf("range = %q", mal.Range)
	}
	if want := []string{"abc1234", "v41"}; !reflect.DeepEqual(mal.Refs, want) {
		t.Errorf("refs = %v, want %v (sorted)", mal.Refs, want)
	}
	if mal.Severity != "CRITICAL" {
		t.Errorf("severity = %q", mal.Severity)
	}
	if !strings.Contains(mal.Reason, "dumped runner memory") {
		t.Errorf("reason = %q", mal.Reason)
	}
	if mal.Fix == "" {
		t.Error("fix is empty — a consumer would not know what to do")
	}

	vul := f.Entries[1]
	if vul.Category != rules.CategoryVulnerable {
		t.Errorf("category = %q, want vulnerable", vul.Category)
	}
	if vul.AdvisoryID != "GHSA-aaaa-bbbb-cccc" {
		t.Errorf("advisory_id = %q", vul.AdvisoryID)
	}
	if vul.AdvisoryURL != "https://github.com/advisories/GHSA-aaaa-bbbb-cccc" {
		t.Errorf("advisory_url = %q", vul.AdvisoryURL)
	}
	if vul.Severity != "HIGH" {
		t.Errorf("severity = %q", vul.Severity)
	}
}

func TestBuildSortsEntries(t *testing.T) {
	rs := testRuleSet()
	// Shuffle the rules: the document must not depend on the order the
	// loaders happened to produce.
	rs.Rules = []rules.Rule{
		rs.Rules[1], rs.Rules[0],
		{
			Category: rules.CategoryVulnerable,
			Repo:     "actions/cache",
			Range:    "< 3.0.0",
			Reason:   "EOL",
			Severity: "MEDIUM",
		},
		{
			Category: rules.CategoryMalicious,
			Repo:     "aaa/compromised",
			Reason:   "compromised",
			Severity: "CRITICAL",
		},
	}
	f := Build(rs)

	var got []string
	for _, e := range f.Entries {
		got = append(got, e.Category+"|"+e.Repo+"|"+e.Range+"|"+e.AdvisoryID)
	}
	want := []string{
		"malicious|aaa/compromised||",
		"malicious|tj-actions/changed-files|< 46.0.1|",
		"vulnerable|actions/cache|< 3.0.0|",
		"vulnerable|actions/checkout|< 4.0.0|GHSA-aaaa-bbbb-cccc",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("entries are not sorted by (category, repo, range, advisory id):\n got %v\nwant %v", got, want)
	}
}

// Two builds of the same rule set must differ in nothing but the
// generation timestamp, or the feed cannot be diffed or cached.
func TestBuildIsDeterministic(t *testing.T) {
	rs := testRuleSet()
	a, err := Build(rs).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	b, err := Build(rs).Marshal()
	if err != nil {
		t.Fatal(err)
	}

	strippedA := withoutGeneratedAt(t, a)
	strippedB := withoutGeneratedAt(t, b)
	if !reflect.DeepEqual(strippedA, strippedB) {
		t.Errorf("builds differ outside generated_at:\n%s\n---\n%s", a, b)
	}

	// The same holds when the two documents are pinned to different
	// timestamps: the timestamp is the only thing that may move.
	at := time.Date(2026, 10, 23, 9, 30, 0, 0, time.UTC)
	c, err := Build(rs).MarshalStable(at)
	if err != nil {
		t.Fatal(err)
	}
	d, err := Build(rs).MarshalStable(at.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(withoutGeneratedAt(t, c), withoutGeneratedAt(t, d)) {
		t.Errorf("pinned builds differ outside generated_at:\n%s\n---\n%s", c, d)
	}
}

func TestMarshalStableIsReproducible(t *testing.T) {
	at := time.Date(2026, 10, 23, 9, 30, 0, 0, time.UTC)
	a, err := Build(testRuleSet()).MarshalStable(at)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Build(testRuleSet()).MarshalStable(at)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Errorf("MarshalStable is not byte-for-byte reproducible:\n%s\n---\n%s", a, b)
	}
	if !strings.Contains(string(a), `"generated_at": "2026-10-23T09:30:00Z"`) {
		t.Errorf("generated_at was not pinned: %s", a)
	}
}

func TestDegradedRuleSetIsVisible(t *testing.T) {
	rs := testRuleSet()
	rs.Degraded = true
	rs.DegradedReason = "ghsa: HTTP 500; compromised feed: timeout"

	f := Build(rs)
	if !f.Degraded {
		t.Error("degraded is false — a consumer cannot tell the feed has a gap")
	}
	if f.DegradedReason != "ghsa: HTTP 500; compromised feed: timeout" {
		t.Errorf("degraded_reason = %q", f.DegradedReason)
	}

	b, err := f.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"degraded": true`) {
		t.Errorf("degraded is not in the document: %s", b)
	}
	if !strings.Contains(string(b), `"degraded_reason"`) {
		t.Errorf("degraded_reason is not in the document: %s", b)
	}
}

func TestCleanTextStripsControlCharacters(t *testing.T) {
	rs := testRuleSet()
	rs.Rules[0].Reason = "line one\nline two\ttabbed\r\nCRLF\x00null"
	rs.Rules[0].Fix = "fix\nwith\nnewlines"

	f := Build(rs)
	got := f.Entries[1].Reason
	want := "line one line two tabbed CRLF null"
	if got != want {
		t.Errorf("reason = %q, want %q", got, want)
	}
	if strings.ContainsAny(got, "\n\r\t\x00") {
		t.Errorf("reason still carries control characters: %q", got)
	}
	if f.Entries[1].Fix != "fix with newlines" {
		t.Errorf("fix = %q", f.Entries[1].Fix)
	}
}

func TestEmptyRuleSet(t *testing.T) {
	f := Build(&rules.RuleSet{})
	if len(f.Entries) != 0 {
		t.Errorf("got %d entries, want 0", len(f.Entries))
	}
	b, err := f.Marshal()
	if err != nil {
		t.Fatalf("an empty rule set must still produce a document: %v", err)
	}
	if !strings.Contains(string(b), `"entries": []`) {
		t.Errorf("entries must be an empty array, not null: %s", b)
	}
	if !strings.Contains(string(b), `"sources": []`) {
		t.Errorf("sources must be an empty array, not null: %s", b)
	}
	var back Feed
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if back.SchemaVersion != Version {
		t.Errorf("schema_version = %d", back.SchemaVersion)
	}
}

func TestNilRuleSet(t *testing.T) {
	f := Build(nil)
	if len(f.Entries) != 0 {
		t.Errorf("got %d entries, want 0", len(f.Entries))
	}
	if _, err := f.Marshal(); err != nil {
		t.Fatalf("marshalling a nil rule set: %v", err)
	}
}

// withoutGeneratedAt decodes a feed document and drops the one field
// that is allowed to change between two builds.
func withoutGeneratedAt(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	delete(doc, "generated_at")
	return doc
}
