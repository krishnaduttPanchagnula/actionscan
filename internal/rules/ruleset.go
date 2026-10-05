package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	semver "github.com/Masterminds/semver/v3"
)

// VulnRule is one advisory: why it matters and how to fix it.
type VulnRule struct {
	Reason string `json:"reason"`
	Fix    string `json:"fix"`
}

type RuleSet struct {
	Malicious  []CompromisedEntry
	Vulnerable map[string]VulnRule  // "repo@range" -> advisory (GHSA)
	OSVCache   map[string][]OSVVuln // "repo@version" -> vulns (per-ref, populated lazily)
	LatestTags map[string]string    // "repo" -> latest tag (populated lazily)
	Sources    []string
	LoadedAt   time.Time

	// UseOSV and FetchLatest gate the OSV and latest-tag layers
	// (wired from --no-osv / --no-latest and config).
	UseOSV      bool
	FetchLatest bool

	// Lookup indexes built lazily on first check. Mutating Malicious or
	// Vulnerable after the first check is not supported.
	idxOnce  sync.Once
	malIdx   map[string][]CompromisedEntry // normalized repo -> entries
	vulIdx   map[string][]compiledVuln     // normalized repo -> compiled ranges
	refCache sync.Map                      // ref -> *semver.Version (typed nil = unparsable)
}

// compiledVuln is one pre-parsed advisory range bound to its reason+fix.
type compiledVuln struct {
	cr     compiledRange
	reason string
	fix    string
}

// compiledPart is a single pre-parsed range bound ("< 2.0.0", ">= 1.0.0").
type compiledPart struct {
	op  string // "", "=", "==", ">", ">=", "<", "<="
	ok  bool   // false → unparsable version, never matches
	ver *semver.Version
}

// compiledRange is a fully pre-parsed GHSA-style version range.
// Matching later is allocation-free: only the caller's ref is parsed.
type compiledRange struct {
	always bool // empty constraint matches every version
	parts  []compiledPart
}

func compileRange(rangeStr string) compiledRange {
	rangeStr = strings.TrimSpace(rangeStr)
	if rangeStr == "" {
		return compiledRange{always: true}
	}
	rawParts := strings.Split(rangeStr, ",")
	cr := compiledRange{parts: make([]compiledPart, 0, len(rawParts))}
	for _, raw := range rawParts {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue // an empty bound matches everything (matchesConstraint semantics)
		}
		cr.parts = append(cr.parts, compilePart(raw))
	}
	return cr
}

func compilePart(constraint string) compiledPart {
	op := ""
	verStr := constraint
	for _, candidate := range []string{">=", "<=", "==", ">", "<", "="} {
		if strings.HasPrefix(constraint, candidate) {
			op = candidate
			verStr = strings.TrimSpace(strings.TrimPrefix(constraint, candidate))
			break
		}
	}
	verStr = strings.TrimPrefix(verStr, "v")
	switch n := len(strings.Split(verStr, ".")); {
	case n == 2:
		verStr += ".0"
	case n == 1:
		verStr += ".0.0"
	}
	v, err := semver.NewVersion(verStr)
	return compiledPart{op: op, ver: v, ok: err == nil}
}

// matches reports whether v satisfies every bound of the range.
func (cr compiledRange) matches(v *semver.Version) bool {
	if cr.always {
		return true
	}
	for _, p := range cr.parts {
		if !p.ok {
			return false
		}
		switch p.op {
		case ">=":
			if !v.GreaterThanEqual(p.ver) {
				return false
			}
		case "<=":
			if !v.LessThanEqual(p.ver) {
				return false
			}
		case ">":
			if !v.GreaterThan(p.ver) {
				return false
			}
		case "<":
			if !v.LessThan(p.ver) {
				return false
			}
		default: // "", "=", "=="
			if !v.Equal(p.ver) {
				return false
			}
		}
	}
	return true
}

func (rs *RuleSet) buildIndex() {
	rs.malIdx = make(map[string][]CompromisedEntry, len(rs.Malicious))
	for _, e := range rs.Malicious {
		key := normalizeRepo(e.Repo)
		rs.malIdx[key] = append(rs.malIdx[key], e)
	}
	rs.vulIdx = make(map[string][]compiledVuln, len(rs.Vulnerable))
	for k, rule := range rs.Vulnerable {
		i := strings.Index(k, "@")
		if i < 0 {
			continue
		}
		key := normalizeRepo(k[:i])
		rs.vulIdx[key] = append(rs.vulIdx[key],
			compiledVuln{cr: compileRange(k[i+1:]), reason: rule.Reason, fix: rule.Fix})
	}
}

// parseRef returns the cached parsed version for ref, parsing on miss.
func (rs *RuleSet) parseRef(ref string) (*semver.Version, bool) {
	if val, ok := rs.refCache.Load(ref); ok {
		v, _ := val.(*semver.Version)
		return v, v != nil
	}
	v, err := semver.NewVersion(strings.TrimPrefix(strings.TrimSpace(ref), "v"))
	if err != nil {
		rs.refCache.Store(ref, (*semver.Version)(nil))
		return nil, false
	}
	rs.refCache.Store(ref, v)
	return v, true
}

type cacheFile struct {
	FetchedAt  time.Time           `json:"fetched_at"`
	Malicious  []CompromisedEntry  `json:"malicious"`
	Vulnerable map[string]VulnRule `json:"vulnerable"`
	Sources    []string            `json:"sources"`
}

type LoadOptions struct {
	CacheDir    string
	TTL         time.Duration
	Token       string
	UseOSV      bool
	FetchLatest bool
}

// Load fetches live rules with disk cache + TTL, falling back to defaults.
func Load(ctx context.Context, opts LoadOptions) (*RuleSet, error) {
	cachePath := filepath.Join(opts.CacheDir, "rules-cache.json")

	if data, err := os.ReadFile(cachePath); err == nil {
		var c cacheFile
		if json.Unmarshal(data, &c) == nil && time.Since(c.FetchedAt) < opts.TTL {
			return &RuleSet{
				Malicious:   c.Malicious,
				Vulnerable:  c.Vulnerable,
				OSVCache:    map[string][]OSVVuln{},
				LatestTags:  map[string]string{},
				Sources:     c.Sources,
				LoadedAt:    c.FetchedAt,
				UseOSV:      opts.UseOSV,
				FetchLatest: opts.FetchLatest,
			}, nil
		}
	}

	hc := &http.Client{Timeout: 30 * time.Second}
	rs := &RuleSet{
		Vulnerable:  map[string]VulnRule{},
		OSVCache:    map[string][]OSVVuln{},
		LatestTags:  map[string]string{},
		LoadedAt:    time.Now(),
		UseOSV:      opts.UseOSV,
		FetchLatest: opts.FetchLatest,
	}
	var errs []string

	if entries, err := FetchMalicious(ctx, hc); err == nil {
		rs.Malicious = entries
		rs.Sources = append(rs.Sources, "stepsecurity")
	} else {
		errs = append(errs, "malicious feed: "+err.Error())
	}

	if advisories, err := FetchAdvisories(ctx, hc, opts.Token); err == nil {
		for _, a := range advisories {
			for _, v := range a.Vulnerabilities {
				name := normalizeRepo(v.Package.Name)
				if name == "" || v.VulnerableVersionRange == "" {
					continue
				}
				key := name + "@" + v.VulnerableVersionRange
				rs.Vulnerable[key] = VulnRule{
					Reason: fmt.Sprintf("%s: %s", a.GHSAID, a.Summary),
					Fix:    advisoryFix(name, v.PatchedVersions),
				}
			}
		}
		rs.Sources = append(rs.Sources, "ghsa")
	} else {
		errs = append(errs, "ghsa: "+err.Error())
	}

	if rs.Malicious == nil {
		rs.Malicious = DefaultMalicious
		rs.Sources = append(rs.Sources, "builtin-malicious-fallback")
	}
	if len(rs.Vulnerable) == 0 {
		rs.Vulnerable = DefaultVulnerable
		rs.Sources = append(rs.Sources, "builtin-vulnerable-fallback")
	}

	if c, err := json.Marshal(cacheFile{
		FetchedAt:  rs.LoadedAt,
		Malicious:  rs.Malicious,
		Vulnerable: rs.Vulnerable,
		Sources:    rs.Sources,
	}); err == nil {
		_ = os.MkdirAll(opts.CacheDir, 0o755)
		_ = os.WriteFile(cachePath, c, 0o644)
	}

	if len(errs) > 0 {
		return rs, fmt.Errorf("partial load (%s)", strings.Join(errs, "; "))
	}
	return rs, nil
}

// ── Malicious ──

// IsMalicious reports whether repo@ref matches the compromised-actions
// feed. The feed is indexed by normalized repo on first use, so a check
// costs one map lookup instead of scanning every entry.
func (rs *RuleSet) IsMalicious(repo, ref string) (CompromisedEntry, bool) {
	rs.idxOnce.Do(rs.buildIndex)
	for _, e := range rs.malIdx[normalizeRepo(repo)] {
		if len(e.Refs) == 0 {
			return e, true
		}
		for _, bad := range e.Refs {
			if bad == ref {
				return e, true
			}
		}
	}
	return CompromisedEntry{}, false
}

// advisoryFix turns a GHSA "patched_versions" value into an actionable
// recommendation.
func advisoryFix(actionRepo, patchedVersions string) string {
	p := strings.TrimSpace(patchedVersions)
	if p == "" || strings.EqualFold(p, "none") {
		return fmt.Sprintf("No patched version published — remove or replace %s", actionRepo)
	}
	return fmt.Sprintf("Upgrade %s to %s", actionRepo, p)
}

// ── GHSA ranges ──

// CheckVulnerable reports whether ref falls in any advisory range for
// repo. Advisory ranges are compiled once and parsed refs are cached, so
// repeat checks for the same ref are allocation-free.
func (rs *RuleSet) CheckVulnerable(repo, ref string) (VulnRule, bool) {
	rs.idxOnce.Do(rs.buildIndex)
	entries := rs.vulIdx[normalizeRepo(repo)]
	if len(entries) == 0 {
		return VulnRule{}, false
	}
	v, ok := rs.parseRef(ref)
	if !ok {
		return VulnRule{}, false
	}
	for _, e := range entries {
		if e.cr.matches(v) {
			return VulnRule{Reason: e.reason, Fix: e.fix}, true
		}
	}
	return VulnRule{}, false
}

func refInRange(ref, rangeStr string) bool {
	v, err := semver.NewVersion(strings.TrimPrefix(strings.TrimSpace(ref), "v"))
	if err != nil {
		return false
	}
	return compileRange(rangeStr).matches(v)
}

func matchesConstraint(v *semver.Version, constraint string) bool {
	return compileRange(constraint).matches(v)
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}
