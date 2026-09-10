package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	semver "github.com/Masterminds/semver/v3"
)

type RuleSet struct {
	Malicious  []CompromisedEntry
	Vulnerable map[string]string    // "repo@range" -> reason (GHSA)
	OSVCache   map[string][]OSVVuln // "repo@version" -> vulns (per-ref, populated lazily)
	LatestTags map[string]string    // "repo" -> latest tag (populated lazily)
	Sources    []string
	LoadedAt   time.Time

	useOSV bool
}

type cacheFile struct {
	FetchedAt  time.Time          `json:"fetched_at"`
	Malicious  []CompromisedEntry `json:"malicious"`
	Vulnerable map[string]string  `json:"vulnerable"`
	Sources    []string           `json:"sources"`
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
				Malicious:  c.Malicious,
				Vulnerable: c.Vulnerable,
				OSVCache:   map[string][]OSVVuln{},
				LatestTags: map[string]string{},
				Sources:    c.Sources,
				LoadedAt:   c.FetchedAt,
			}, nil
		}
	}

	hc := &http.Client{Timeout: 30 * time.Second}
	rs := &RuleSet{
		Vulnerable: map[string]string{},
		OSVCache:   map[string][]OSVVuln{},
		LatestTags: map[string]string{},
		LoadedAt:   time.Now(),
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
				rs.Vulnerable[key] = fmt.Sprintf("%s: %s (patched: %s)",
					a.GHSAID, a.Summary, orNone(v.PatchedVersions))
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

func (rs *RuleSet) IsMalicious(repo, ref string) (CompromisedEntry, bool) {
	for _, e := range rs.Malicious {
		if normalizeRepo(e.Repo) != normalizeRepo(repo) {
			continue
		}
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

// ── GHSA ranges ──

func (rs *RuleSet) CheckVulnerable(repo, ref string) (string, bool) {
	for key, reason := range rs.Vulnerable {
		idx := strings.Index(key, "@")
		if idx < 0 {
			continue
		}
		keyRepo, keyRange := key[:idx], key[idx+1:]
		if normalizeRepo(keyRepo) != normalizeRepo(repo) {
			continue
		}
		if refInRange(ref, keyRange) {
			return reason, true
		}
	}
	return "", false
}

func refInRange(ref, rangeStr string) bool {
	v, err := semver.NewVersion(strings.TrimPrefix(strings.TrimSpace(ref), "v"))
	if err != nil {
		return false
	}
	for _, part := range strings.Split(rangeStr, ",") {
		if !matchesConstraint(v, strings.TrimSpace(part)) {
			return false
		}
	}
	return true
}

func matchesConstraint(v *semver.Version, constraint string) bool {
	constraint = strings.TrimSpace(constraint)
	if constraint == "" {
		return true
	}
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
	if len(strings.Split(verStr, ".")) == 2 {
		verStr += ".0"
	}
	if len(strings.Split(verStr, ".")) == 1 {
		verStr += ".0.0"
	}
	other, err := semver.NewVersion(verStr)
	if err != nil {
		return false
	}
	switch op {
	case ">=":
		return v.GreaterThan(other) || v.Equal(other)
	case "<=":
		return v.LessThan(other) || v.Equal(other)
	case "==", "=":
		return v.Equal(other)
	case ">":
		return v.GreaterThan(other)

	case "<":
		return v.LessThan(other)
	default:
		return v.Equal(other)
	}
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}
