package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	semver "github.com/Masterminds/semver/v3"
)

// Rule categories.
const (
	CategoryMalicious  = "malicious"
	CategoryVulnerable = "vulnerable"
)

// Severities, most severe first.
const (
	severityCritical = "CRITICAL"
	severityHigh     = "HIGH"
	severityMedium   = "MEDIUM"
	severityLow      = "LOW"
)

// Rule is one advisory or compromise rule.
type Rule struct {
	Category string   `json:"category"`       // malicious | vulnerable
	Repo     string   `json:"repo"`           // normalized "owner/repo"
	Range    string   `json:"range"`          // GHSA-style semver range; "" = all refs
	Refs     []string `json:"refs,omitempty"` // exact refs (e.g. ["v41"]); when set, Range is ignored
	Reason   string   `json:"reason"`
	Fix      string   `json:"fix"`
	Severity string   `json:"severity"` // CRITICAL | HIGH | MEDIUM | LOW

	AdvisoryID  string `json:"advisory_id,omitempty"`
	AdvisoryURL string `json:"advisory_url,omitempty"`
}

// RuleSet is the loaded rule set.
type RuleSet struct {
	Rules    []Rule
	Sources  []string
	LoadedAt time.Time

	// Degraded reports that at least one feed failed; DegradedReason
	// says which. A degraded rule set is never written to the cache.
	Degraded       bool
	DegradedReason string

	// UseOSV and FetchLatest gate the OSV and latest-tag layers
	// (wired from --no-osv / --no-latest and config).
	UseOSV      bool
	FetchLatest bool

	// Lookup index, built on first use. Mutating Rules after the first
	// Match call is not supported.
	idxOnce sync.Once
	idx     map[string][]compiledRule
}

// compiledRule is a rule with its semver range pre-compiled, so a match
// costs one version parse.
type compiledRule struct {
	rule Rule
	// hasRange reports whether the rule carries a range constraint.
	hasRange bool
	// cons is the compiled range; nil with hasRange set means the range
	// could not be parsed and therefore matches nothing.
	cons *semver.Constraints
}

// Match returns every rule that applies to repo@ref, most severe first.
//
// A rule matches when its repository equals the queried one and either
// one of its exact refs equals the ref (string or semver equality), or
// its semver range contains the ref, or it carries no constraint at all
// and therefore matches every ref.
func (rs *RuleSet) Match(repo, ref string) []Rule {
	if rs == nil {
		return nil
	}
	candidates := rs.index()[normalizeRepo(repo)]
	if len(candidates) == 0 {
		return nil
	}
	var out []Rule
	for _, c := range candidates {
		if c.matches(ref) {
			out = append(out, c.rule)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if a, b := severityRank(out[i].Severity), severityRank(out[j].Severity); a != b {
			return a > b
		}
		return out[i].AdvisoryID < out[j].AdvisoryID
	})
	return out
}

// index maps a normalized repository to its rules.
func (rs *RuleSet) index() map[string][]compiledRule {
	rs.idxOnce.Do(func() {
		rs.idx = make(map[string][]compiledRule, len(rs.Rules))
		for _, r := range rs.Rules {
			key := normalizeRepo(r.Repo)
			if key == "" {
				continue
			}
			rs.idx[key] = append(rs.idx[key], compileRule(r))
		}
	})
	return rs.idx
}

// compileRule pre-compiles the semver range of a rule.
func compileRule(r Rule) compiledRule {
	c := compiledRule{rule: r}
	rng := strings.TrimSpace(r.Range)
	if rng == "" {
		return c // no range constraint
	}
	c.hasRange = true
	if cons, err := semver.NewConstraint(padRangeVersions(rng)); err == nil {
		c.cons = cons
	}
	return c
}

// matches reports whether the rule applies to ref.
//
// A rule may carry an exact-ref list, a version range, or both. When it
// carries both, either matching is enough: a compromised commit SHA and
// the tag range that was moved onto it are two views of the same
// compromise.
func (c compiledRule) matches(ref string) bool {
	hasRefs := len(c.rule.Refs) > 0
	if !hasRefs && !c.hasRange {
		return true // no constraint: matches every ref
	}
	if hasRefs {
		for _, want := range c.rule.Refs {
			if want == ref || semverEqual(want, ref) {
				return true
			}
		}
	}
	if !c.hasRange {
		return false
	}
	if c.cons == nil {
		return false // unparsable range matches nothing
	}
	v, err := parseVersion(ref)
	if err != nil {
		return false // an unparsable ref can never satisfy a range
	}
	return c.cons.Check(v)
}

// semverEqual reports whether two refs denote the same version.
func semverEqual(a, b string) bool {
	va, err := parseVersion(a)
	if err != nil {
		return false
	}
	vb, err := parseVersion(b)
	if err != nil {
		return false
	}
	return va.Equal(vb)
}

// parseVersion parses a ref into a semver version.
func parseVersion(s string) (*semver.Version, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty version")
	}
	return semver.NewVersion(strings.TrimPrefix(s, "v"))
}

// rangeMatches reports whether ref falls inside a GHSA-style range.
func rangeMatches(rangeStr, ref string) bool {
	v, err := parseVersion(ref)
	if err != nil {
		return false // an unparsable ref can never satisfy a range
	}
	cons, err := semver.NewConstraint(padRangeVersions(rangeStr))
	if err != nil {
		return false
	}
	return cons.Check(v)
}

// padRangeVersions expands partial versions of equality-style bounds
// ("= 1" becomes "= 1.0.0"). Masterminds would otherwise read "= 1" as
// the tilde range >= 1.0.0, < 2.0.0.
func padRangeVersions(rangeStr string) string {
	parts := strings.Split(rangeStr, ",")
	for i, p := range parts {
		op, ver := splitBound(p)
		switch op {
		case "=", "==":
			parts[i] = op + " " + padVersion(ver)
		case "":
			parts[i] = padVersion(ver)
		}
	}
	return strings.Join(parts, ",")
}

// splitBound splits a range bound into its operator and its version.
func splitBound(bound string) (op, ver string) {
	bound = strings.TrimSpace(bound)
	for _, candidate := range []string{">=", "<=", "==", "=>", "=<", "~>", ">", "<", "=", "~", "^"} {
		if strings.HasPrefix(bound, candidate) {
			return candidate, strings.TrimSpace(strings.TrimPrefix(bound, candidate))
		}
	}
	return "", bound
}

// padVersion expands a partial version ("1", "1.2") to a full one.
func padVersion(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || strings.ContainsAny(v, " -+") {
		return v
	}
	switch strings.Count(v, ".") {
	case 0:
		return v + ".0.0"
	case 1:
		return v + ".0"
	}
	return v
}

// severityLevel maps an advisory severity to the scanner's vocabulary.
func severityLevel(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case severityCritical:
		return severityCritical
	case severityHigh:
		return severityHigh
	case severityMedium, "MODERATE":
		return severityMedium
	case severityLow:
		return severityLow
	}
	return severityMedium
}

// severityRank orders severities for sorting.
func severityRank(s string) int {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case severityCritical:
		return 4
	case severityHigh:
		return 3
	case severityMedium:
		return 2
	case severityLow:
		return 1
	}
	return 0
}

// advisoryFix turns a patched version into an actionable recommendation.
func advisoryFix(actionRepo, patched string) string {
	p := strings.TrimSpace(patched)
	if p == "" || strings.EqualFold(p, "none") {
		return fmt.Sprintf("Remove or replace %s", actionRepo)
	}
	if !strings.HasPrefix(p, "v") {
		p = "v" + p
	}
	return fmt.Sprintf("Upgrade %s to %s", actionRepo, p)
}

// ── Loading ────────────────────────────────────────────────────────────

// LoadOptions configures Load.
type LoadOptions struct {
	CacheDir    string
	TTL         time.Duration
	Token       string
	UseOSV      bool
	FetchLatest bool
	// MaliciousFeedURL is an optional extra compromised-actions feed.
	// Empty means DefaultMaliciousFeedURL.
	MaliciousFeedURL string
}

const cacheFileName = "rules-cache.json"

// feedClient fetches the advisory and compromised feeds.
var feedClient = &http.Client{Timeout: 30 * time.Second}

// cacheFile is the on-disk shape of the rule cache.
type cacheFile struct {
	FetchedAt time.Time `json:"fetched_at"`
	Rules     []Rule    `json:"rules"`
	Sources   []string  `json:"sources"`
}

// Load fetches live rules with disk cache + TTL, falling back to defaults.
func Load(ctx context.Context, opts LoadOptions) (*RuleSet, error) {
	cachePath := filepath.Join(opts.CacheDir, cacheFileName)

	if rs, ok := readCache(cachePath, opts); ok {
		return rs, nil
	}

	hc := feedClient
	rs := &RuleSet{
		LoadedAt:    time.Now(),
		UseOSV:      opts.UseOSV,
		FetchLatest: opts.FetchLatest,
	}
	var failures []string

	advisories, err := FetchAdvisories(ctx, hc, opts.Token)
	if err != nil {
		failures = append(failures, "ghsa: "+err.Error())
		rs.Rules = append(rs.Rules, DefaultMalicious...)
		rs.Rules = append(rs.Rules, DefaultVulnerable...)
		rs.Sources = append(rs.Sources, "builtin-fallback")
	} else {
		rs.Rules = append(rs.Rules, rulesFromAdvisories(advisories)...)
		rs.Sources = append(rs.Sources, "ghsa")
	}

	feedURL := opts.MaliciousFeedURL
	if feedURL == "" {
		feedURL = DefaultMaliciousFeedURL
	}
	entries, feedErr := FetchMalicious(ctx, hc, feedURL)
	if feedErr != nil {
		// The GHSA-derived layer is the primary source: a broken extra
		// feed degrades the load, it does not fail it.
		failures = append(failures, "compromised feed: "+feedErr.Error())
	} else {
		rs.Rules = append(rs.Rules, rulesFromCompromised(entries)...)
		rs.Sources = append(rs.Sources, "compromised-feed")
	}

	if len(failures) > 0 {
		rs.Degraded = true
		rs.DegradedReason = strings.Join(failures, "; ")
	}

	// A degraded rule set (typically the builtin fallback) must never be
	// cached with a fresh timestamp: one transient outage would poison the
	// cache for the whole TTL.
	if !rs.Degraded {
		if err := saveCache(cachePath, cacheFile{
			FetchedAt: rs.LoadedAt,
			Rules:     rs.Rules,
			Sources:   rs.Sources,
		}); err != nil {
			rs.Degraded = true
			rs.DegradedReason = strings.TrimSpace(rs.DegradedReason + "; cache: " + err.Error())
		}
	}

	if len(failures) > 0 {
		return rs, fmt.Errorf("partial load (%s)", strings.Join(failures, "; "))
	}
	return rs, nil
}

// readCache returns the cached rule set when it is still fresh.
func readCache(path string, opts LoadOptions) (*RuleSet, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var c cacheFile
	if json.Unmarshal(data, &c) != nil {
		return nil, false
	}
	if len(c.Rules) == 0 || time.Since(c.FetchedAt) >= opts.TTL {
		return nil, false
	}
	return &RuleSet{
		Rules:       c.Rules,
		Sources:     c.Sources,
		LoadedAt:    c.FetchedAt,
		UseOSV:      opts.UseOSV,
		FetchLatest: opts.FetchLatest,
	}, true
}

// saveCache stores the rule set atomically: a temporary file next to the
// cache is renamed over it, so a crash never leaves a half-written cache.
func saveCache(path string, c cacheFile) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".rules-cache-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // no-op once the rename succeeded
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, 0o644); err != nil {
		return err
	}
	return os.Rename(name, path)
}
