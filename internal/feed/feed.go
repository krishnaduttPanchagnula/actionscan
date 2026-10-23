// Package feed builds the public actionscan threat feed: the set of
// known-compromised and known-vulnerable GitHub Actions, with the
// affected version ranges, as a stable JSON document.
//
// The feed is meant to be consumed by other tools, so it is versioned,
// self-describing (a consumer can tell how fresh it is and which
// sources answered) and deterministic: two builds of the same rule set
// produce byte-identical JSON, apart from the generation timestamp.
// That is what makes the feed diffable and cacheable.
package feed

import (
	"encoding/json"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/krishnaduttPanchagnula/actionscan/internal/rules"
)

// Version is the feed schema version. Bump it on a breaking change.
const Version = 1

// Entry is one action in the feed.
type Entry struct {
	Repo        string   `json:"repo"`            // "owner/repo", normalized
	Category    string   `json:"category"`        // "malicious" | "vulnerable"
	Range       string   `json:"range,omitempty"` // semver range, empty = all versions
	Refs        []string `json:"refs,omitempty"`  // exact refs (e.g. a compromised SHA)
	Severity    string   `json:"severity"`        // CRITICAL | HIGH | MEDIUM | LOW
	AdvisoryID  string   `json:"advisory_id,omitempty"`
	AdvisoryURL string   `json:"advisory_url,omitempty"`
	Reason      string   `json:"reason"`
	Fix         string   `json:"fix,omitempty"`
}

// Feed is the document.
type Feed struct {
	SchemaVersion  int      `json:"schema_version"`
	GeneratedAt    string   `json:"generated_at"` // RFC3339 UTC
	Sources        []string `json:"sources"`      // which feeds answered
	RulesLoadedAt  string   `json:"rules_loaded_at,omitempty"`
	Degraded       bool     `json:"degraded,omitempty"`
	DegradedReason string   `json:"degraded_reason,omitempty"`
	Entries        []Entry  `json:"entries"`
}

// Build converts a rule set into a feed document.
//
// The document is deterministic: the entries are sorted, the sources are
// sorted, and every text value is flattened to a single line, so the
// same rule set always renders the same JSON.
func Build(rs *rules.RuleSet) Feed {
	f := Feed{
		SchemaVersion: Version,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Sources:       []string{},
		Entries:       []Entry{},
	}
	if rs == nil {
		return f
	}
	f.Sources = sourceList(rs.Sources)
	if !rs.LoadedAt.IsZero() {
		f.RulesLoadedAt = rs.LoadedAt.UTC().Format(time.RFC3339)
	}
	// A feed that silently looks complete is worse than one that admits
	// a gap, so a degraded load says so in the document itself.
	f.Degraded = rs.Degraded
	f.DegradedReason = cleanText(rs.DegradedReason)

	for _, r := range rs.Rules {
		if e, ok := entryOf(r); ok {
			f.Entries = append(f.Entries, e)
		}
	}
	sortEntries(f.Entries)
	return f
}

// Marshal renders the feed as indented JSON.
//
// The standard library's HTML escaping is left on: the document then
// carries no raw "<" or ">" at all, so a consumer can embed it in a
// page without escaping it again. The decoded values are unchanged.
func (f Feed) Marshal() ([]byte, error) {
	return json.MarshalIndent(f, "", "  ")
}

// MarshalStable renders the feed with a fixed timestamp, for
// reproducible output.
func (f Feed) MarshalStable(generatedAt time.Time) ([]byte, error) {
	g := f
	g.GeneratedAt = generatedAt.UTC().Format(time.RFC3339)
	return g.Marshal()
}

// ── building ────────────────────────────────────────────────────────────

// entryOf converts one rule into a feed entry.
//
// Only the malicious and vulnerable categories are published: the feed
// describes what is known-bad, not what is merely old or unpinned.
func entryOf(r rules.Rule) (Entry, bool) {
	category := strings.ToLower(strings.TrimSpace(r.Category))
	switch category {
	case rules.CategoryMalicious, rules.CategoryVulnerable:
	default:
		return Entry{}, false
	}
	repo := normalizeRepo(r.Repo)
	if repo == "" {
		return Entry{}, false
	}
	return Entry{
		Repo:        repo,
		Category:    category,
		Range:       strings.TrimSpace(r.Range),
		Refs:        refList(r.Refs),
		Severity:    severityOf(category, r.Severity),
		AdvisoryID:  strings.TrimSpace(r.AdvisoryID),
		AdvisoryURL: strings.TrimSpace(r.AdvisoryURL),
		Reason:      cleanText(r.Reason),
		Fix:         cleanText(r.Fix),
	}, true
}

// sortEntries orders the entries so the feed is byte-stable.
func sortEntries(entries []Entry) {
	sort.SliceStable(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		if a.Repo != b.Repo {
			return a.Repo < b.Repo
		}
		if a.Range != b.Range {
			return a.Range < b.Range
		}
		if a.AdvisoryID != b.AdvisoryID {
			return a.AdvisoryID < b.AdvisoryID
		}
		return a.Reason < b.Reason
	})
}

// sourceList normalizes the source names: trimmed, de-duplicated and
// sorted, so the order the loaders happened to append them in does not
// leak into the document.
func sourceList(sources []string) []string {
	out := make([]string, 0, len(sources))
	seen := map[string]bool{}
	for _, s := range sources {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// refList normalizes the exact refs of a rule.
func refList(refs []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, r := range refs {
		r = strings.TrimSpace(r)
		if r == "" || seen[r] {
			continue
		}
		seen[r] = true
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// severityOf maps a rule severity onto the feed's vocabulary.
//
// A rule without a severity is not silently downgraded: a compromised
// action is CRITICAL and a vulnerable one is HIGH, the same defaults the
// scanner reports with.
func severityOf(category, severity string) string {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL":
		return "CRITICAL"
	case "HIGH":
		return "HIGH"
	case "MEDIUM", "MODERATE":
		return "MEDIUM"
	case "LOW":
		return "LOW"
	}
	if category == rules.CategoryMalicious {
		return "CRITICAL"
	}
	return "HIGH"
}

// normalizeRepo reduces a repository name to a lowercase "owner/repo".
//
// The rules already normalize their repositories; this is the last line
// of defence for a public document, where a malformed entry would be
// published to every consumer.
func normalizeRepo(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	for _, prefix := range []string{"https://", "http://", "git://", "ssh://", "github.com/", "@"} {
		s = strings.TrimPrefix(s, prefix)
	}
	var segs []string
	for _, p := range strings.Split(s, "/") {
		if p != "" {
			segs = append(segs, p)
		}
	}
	if len(segs) < 2 {
		return ""
	}
	if len(segs) > 2 && strings.Contains(segs[0], ".") {
		segs = segs[1:] // drop a leading host-like segment
	}
	return segs[0] + "/" + segs[1]
}

// cleanText flattens a value to a single line of plain text.
//
// Advisory text comes from third parties. Control characters (a newline
// in a reason would break a one-line feed and a diff) are replaced with
// a space and runs of whitespace collapse into one, so the JSON stays
// one-line-safe and comparable.
func cleanText(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if unicode.IsPrint(r) {
			b.WriteRune(r)
			continue
		}
		b.WriteRune(' ')
	}
	return strings.Join(strings.Fields(b.String()), " ")
}
