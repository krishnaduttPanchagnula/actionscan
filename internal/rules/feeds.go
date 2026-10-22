package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// ── GitHub Security Advisories (ecosystem=actions) ─────────────────────

const advisoriesURL = "https://api.github.com/advisories?type=reviewed&ecosystem=actions&per_page=100"

// maxAdvisoryPages caps the pagination of the advisories feed.
const maxAdvisoryPages = 50

// GHAdvisory is one entry of the GitHub global advisories API.
type GHAdvisory struct {
	GHSAID   string `json:"ghsa_id"`
	Summary  string `json:"summary"`
	Severity string `json:"severity"`
	// WithdrawnAt is set for advisories that were pulled back (usually
	// duplicates). Withdrawn advisories are skipped.
	WithdrawnAt *time.Time `json:"withdrawn_at"`
	CWEs        []struct {
		CWEID string `json:"cwe_id"`
		Name  string `json:"name"`
	} `json:"cwes"`
	Vulnerabilities []GHVulnerability `json:"vulnerabilities"`
}

// GHVulnerability is one affected package of an advisory.
type GHVulnerability struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	VulnerableVersionRange string `json:"vulnerable_version_range"`
	// FirstPatchedVersion is the current API field. PatchedVersions is the
	// legacy spelling and is still tolerated.
	FirstPatchedVersion *PatchedVersion `json:"first_patched_version"`
	PatchedVersions     string          `json:"patched_versions"`
}

// PatchedVersion is the first patched version of an advisory. The API
// returns {"identifier": "1.2.3"}; a bare string is tolerated too.
type PatchedVersion struct {
	Identifier string `json:"identifier"`
}

// UnmarshalJSON accepts both {"identifier": "1.2.3"} and "1.2.3".
func (p *PatchedVersion) UnmarshalJSON(b []byte) error {
	raw := strings.TrimSpace(string(b))
	if raw == "" || raw == "null" {
		return nil
	}
	if strings.HasPrefix(raw, `"`) {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		p.Identifier = s
		return nil
	}
	type plain PatchedVersion
	var v plain
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*p = PatchedVersion(v)
	return nil
}

// patched returns the first patched version of a vulnerability, preferring
// the current API field over the legacy one.
func (v GHVulnerability) patched() string {
	if v.FirstPatchedVersion != nil {
		if id := strings.TrimSpace(v.FirstPatchedVersion.Identifier); id != "" {
			return id
		}
	}
	return strings.TrimSpace(v.PatchedVersions)
}

// FetchAdvisories pages through the GitHub advisories API.
func FetchAdvisories(ctx context.Context, hc *http.Client, token string) ([]GHAdvisory, error) {
	var all []GHAdvisory
	seen := map[string]bool{}
	for page := 1; page <= maxAdvisoryPages; page++ {
		url := fmt.Sprintf("%s&page=%d", advisoriesURL, page)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := hc.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("ghsa feed: HTTP %d", resp.StatusCode)
		}
		var batch []GHAdvisory
		err = json.NewDecoder(resp.Body).Decode(&batch)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if len(batch) == 0 {
			break
		}
		all = append(all, batch...)
		// The endpoint repeats the same page when the result set fits on
		// one page: stop as soon as a page brings nothing new.
		fresh, hasID := 0, false
		for _, a := range batch {
			if a.GHSAID == "" {
				continue
			}
			hasID = true
			if !seen[a.GHSAID] {
				seen[a.GHSAID] = true
				fresh++
			}
		}
		if hasID && fresh == 0 {
			break
		}
	}
	return all, nil
}

// ── Advisory → Rule ───────────────────────────────────────────────────

// compromisePatterns mark an advisory summary as a supply-chain compromise.
// These are deliberately narrow: a bare "malicious" would flag advisories
// whose subject is an attacker's payload ("Malicious MCP Server
// Configuration in PRs..."), which is an ordinary vulnerability, not a
// compromised action.
var compromisePatterns = []string{
	"was compromised",
	"were compromised",
	"has been compromised",
	"have been compromised",
	"supply chain",
	"tag poisoned",
	"backdoor",
	"malicious code",
	"malicious commit",
	"malicious release",
	"malicious package",
	"malicious version",
	"hijacked",
}

// isCompromise reports whether an advisory describes a supply-chain
// compromise rather than an ordinary vulnerability: either it carries
// CWE-506 (embedded malicious code) or its summary matches a known
// compromise wording.
func isCompromise(a GHAdvisory) bool {
	for _, c := range a.CWEs {
		if strings.EqualFold(strings.TrimSpace(c.CWEID), "CWE-506") {
			return true
		}
	}
	summary := strings.ToLower(a.Summary)
	summary = strings.ReplaceAll(summary, "-", " ")
	summary = strings.ReplaceAll(summary, "_", " ")
	for _, p := range compromisePatterns {
		if strings.Contains(summary, p) {
			return true
		}
	}
	return false
}

// rulesFromAdvisories converts GitHub advisories into rules. Advisories
// with the same package and range are all kept: duplicates are separate
// advisories and losing them hides real findings.
func rulesFromAdvisories(advisories []GHAdvisory) []Rule {
	var rules []Rule
	seen := make(map[string]bool)
	for _, a := range advisories {
		if a.WithdrawnAt != nil && !a.WithdrawnAt.IsZero() {
			continue // withdrawn advisories are not valid findings
		}
		compromise := isCompromise(a)
		severity := severityLevel(a.Severity)
		for _, v := range a.Vulnerabilities {
			if !strings.EqualFold(strings.TrimSpace(v.Package.Ecosystem), "actions") {
				continue // only the actions ecosystem is relevant
			}
			repo := normalizeRepo(v.Package.Name)
			if repo == "" {
				continue
			}
			r := Rule{
				Category:    CategoryVulnerable,
				Repo:        repo,
				Range:       strings.TrimSpace(v.VulnerableVersionRange),
				Reason:      advisoryReason(a),
				Fix:         advisoryFix(repo, v.patched()),
				Severity:    severity,
				AdvisoryID:  a.GHSAID,
				AdvisoryURL: advisoryURL(a.GHSAID),
			}
			if compromise {
				r.Category = CategoryMalicious
				r.Severity = severityCritical
				r.Reason += " (supply-chain compromise)"
			}
			key := r.AdvisoryID + "|" + r.Repo + "|" + r.Range
			if seen[key] {
				continue
			}
			seen[key] = true
			rules = append(rules, r)
		}
	}
	return rules
}

// advisoryReason is the human readable reason of an advisory rule.
func advisoryReason(a GHAdvisory) string {
	if a.GHSAID == "" {
		return a.Summary
	}
	if a.Summary == "" {
		return a.GHSAID
	}
	return a.GHSAID + ": " + a.Summary
}

// advisoryURL is the canonical page of an advisory.
func advisoryURL(id string) string {
	if id == "" {
		return ""
	}
	return "https://github.com/advisories/" + id
}

// ── External compromised-actions feed ──────────────────────────────────

// DefaultMaliciousFeedURL is the optional extra compromised-actions feed.
// The GHSA-derived layer is the primary source of malicious rules; this
// feed only adds entries on top of it (known compromised commit SHAs, for
// instance). A failure here degrades the load, it never fails it.
const DefaultMaliciousFeedURL = "https://raw.githubusercontent.com/TreRB/gh-actions-pwn-hunter/main/internal/data/compromised-actions.json"

// CompromisedEntry is one entry of an external compromised-actions feed.
type CompromisedEntry struct {
	Repo        string   `json:"repo"`
	Refs        []string `json:"refs"`
	AdvisoryID  string   `json:"advisory_id"`
	Description string   `json:"description"`
}

// FetchMalicious downloads an external compromised-actions feed. Three
// schemas are accepted: a list of entries, a map keyed by repository, and
// a {"compromised": [...]} wrapper of commit-SHA entries.
func FetchMalicious(ctx context.Context, hc *http.Client, feedURL string) ([]CompromisedEntry, error) {
	if feedURL == "" {
		return nil, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("compromised feed: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var list []CompromisedEntry
	if err := json.Unmarshal(body, &list); err == nil {
		return reposOnly(list)
	}
	var wrapper struct {
		Compromised []struct {
			SHA      string `json:"sha"`
			Action   string `json:"action"`
			Incident string `json:"incident"`
		} `json:"compromised"`
	}
	if err := json.Unmarshal(body, &wrapper); err == nil && len(wrapper.Compromised) > 0 {
		entries := make([]CompromisedEntry, 0, len(wrapper.Compromised))
		for _, c := range wrapper.Compromised {
			e := CompromisedEntry{Repo: c.Action, Description: c.Incident}
			if c.SHA != "" {
				e.Refs = []string{c.SHA}
			}
			entries = append(entries, e)
		}
		return reposOnly(entries)
	}
	var byRepo map[string]CompromisedEntry
	if err := json.Unmarshal(body, &byRepo); err == nil {
		entries := make([]CompromisedEntry, 0, len(byRepo))
		for repo, e := range byRepo {
			e.Repo = repo
			entries = append(entries, e)
		}
		return reposOnly(entries)
	}
	return nil, fmt.Errorf("compromised feed: unrecognized schema")
}

// reposOnly drops entries that name no repository.
//
// A feed that renames its "repo" field parses without error but yields
// zero usable entries, which would look like a healthy source that
// simply has nothing to report. That is an error, not an empty feed.
func reposOnly(entries []CompromisedEntry) ([]CompromisedEntry, error) {
	out := make([]CompromisedEntry, 0, len(entries))
	for _, e := range entries {
		if strings.TrimSpace(e.Repo) == "" {
			continue
		}
		out = append(out, e)
	}
	if len(entries) > 0 && len(out) == 0 {
		return nil, fmt.Errorf("compromised feed: no entry names a repository (the schema may have changed)")
	}
	return out, nil
}

// rulesFromCompromised converts an external feed into malicious rules.
func rulesFromCompromised(entries []CompromisedEntry) []Rule {
	var rules []Rule
	for _, e := range entries {
		repo := normalizeRepo(e.Repo)
		if repo == "" {
			continue
		}
		reason := strings.TrimSpace(e.Description)
		if reason == "" {
			reason = repo + " is a known compromised action"
		}
		// A feed entry usually names the compromised commit SHA, but the
		// attack often moved TAGS to that commit ("retagged v1..v45").
		// A workflow pinned to one of those tags is just as compromised
		// as one pinned to the SHA, so the affected version range and
		// any named versions are taken from the incident text.
		rng := compromisedRange(reason)
		refs := append([]string{}, e.Refs...)
		refs = append(refs, compromisedVersions(reason)...)
		fix := fmt.Sprintf("Remove or replace %s", repo)
		if rng != "" {
			fix = fmt.Sprintf("Upgrade %s to a version outside %s", repo, rng)
		} else if len(refs) > 0 {
			fix = fmt.Sprintf("Remove or replace %s (avoid the compromised refs listed in the advisory)", repo)
		}
		rules = append(rules, Rule{
			Category:    CategoryMalicious,
			Repo:        repo,
			Range:       rng,
			Refs:        refs,
			Reason:      reason,
			Fix:         fix,
			Severity:    severityCritical,
			AdvisoryID:  e.AdvisoryID,
			AdvisoryURL: advisoryURL(e.AdvisoryID),
		})
	}
	return rules
}

// compromisedVersions extracts explicitly named versions from an incident
// description, e.g. "v8.3.41 / v8.3.42 backdoor".
//
// These become exact refs, so a workflow pinned to one of the named
// tags is flagged.
func compromisedVersions(text string) []string {
	matches := regexp.MustCompile(`\bv(\d+(?:\.\d+)*)\b`).FindAllStringSubmatch(strings.ToLower(text), -1)
	var out []string
	seen := map[string]bool{}
	for _, m := range matches {
		v := "v" + m[1]
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// compromisedRange extracts the affected version range from an incident
// description, e.g. "retagged v1..v45" or "versions <= 45.0.7".
//
// It returns "" when the text states no range, in which case the rule
// matches only the exact refs it carries.
func compromisedRange(text string) string {
	lower := strings.ToLower(text)

	// "v1..v45", "v1 - v45", "v1 through v45". The "v" is required so a
	// date in the text ("2025-03-14") is not read as a version range.
	if m := regexp.MustCompile(`v(\d+)\s*(?:\.\.|–|—|-|to|through)\s*v?(\d+)`).FindStringSubmatch(lower); m != nil {
		return fmt.Sprintf(">= %s, <= %s", m[1], m[2])
	}
	// "<= 45.0.7", "< 46.0.1", "before 46.0.1"
	if m := regexp.MustCompile(`(?:<=|<|before)\s*v?(\d+(?:\.\d+)*)`).FindStringSubmatch(lower); m != nil {
		return "< " + m[1]
	}
	// ">= 5", "since 5", "starting with 3.1.0"
	if m := regexp.MustCompile(`(?:>=|since|starting (?:with|at|from))\s*v?(\d+(?:\.\d+)*)`).FindStringSubmatch(lower); m != nil {
		return ">= " + m[1]
	}
	return ""
}

// ── Built-in fallbacks ─────────────────────────────────────────────────

// DefaultMalicious is the offline fallback for known compromised actions.
var DefaultMalicious = []Rule{
	{
		Category: CategoryMalicious,
		Repo:     "tj-actions/changed-files",
		Range:    "< 46.0.1",
		Reason:   "Compromised Mar 2025 (CVE-2025-30066) — dumped runner memory to attacker C2",
		Fix:      "Upgrade tj-actions/changed-files to v46.0.1 or replace it with step-security/changed-files",
		Severity: severityCritical,
	},
	{
		Category: CategoryMalicious,
		Repo:     "tj-actions/github-files",
		Range:    "< 46.0.1",
		Reason:   "Same supply-chain compromise family (CVE-2025-30066)",
		Fix:      "Remove or replace tj-actions/github-files",
		Severity: severityCritical,
	},
	{
		Category: CategoryMalicious,
		Repo:     "tj-actions/eslint-changed-files",
		Range:    "< 46.0.1",
		Reason:   "Same supply-chain compromise family (CVE-2025-30066)",
		Fix:      "Remove or replace tj-actions/eslint-changed-files",
		Severity: severityCritical,
	},
	{
		Category: CategoryMalicious,
		Repo:     "reviewdog/action-setup",
		Range:    "= 1.0.0",
		Reason:   "Compromised Mar 2025 (CVE-2025-30154) — injected malicious runner code",
		Fix:      "Remove or replace reviewdog/action-setup",
		Severity: severityCritical,
	},
	{
		Category: CategoryMalicious,
		Repo:     "aquasecurity/trivy-action",
		Range:    "< 0.35.0",
		Reason:   "Trivy ecosystem supply chain was briefly compromised (CVE-2025-30066 family)",
		Fix:      "Upgrade aquasecurity/trivy-action to v0.35.0",
		Severity: severityCritical,
	},
	{
		Category: CategoryMalicious,
		Repo:     "xygeni/xygeni-action",
		Range:    ">= 5.0.0, < 6.4.0",
		Reason:   "xygeni-action v5 tag poisoned with C2 backdoor",
		Fix:      "Upgrade xygeni/xygeni-action to v6.4.0",
		Severity: severityCritical,
	},
}

// DefaultVulnerable is the offline fallback for known vulnerable actions.
var DefaultVulnerable = []Rule{
	{
		Category: CategoryVulnerable,
		Repo:     "actions/checkout",
		Range:    "< 3.0.0",
		Reason:   "EOL — upgrade to v4",
		Fix:      "Upgrade to actions/checkout@v4",
		Severity: severityMedium,
	},
	{
		Category: CategoryVulnerable,
		Repo:     "actions/cache",
		Range:    "< 3.0.0",
		Reason:   "EOL — upgrade to v4",
		Fix:      "Upgrade to actions/cache@v4",
		Severity: severityMedium,
	},
	{
		Category: CategoryVulnerable,
		Repo:     "actions/upload-artifact",
		Range:    "< 4.0.0",
		Reason:   "Deprecated Dec 2024 — upgrade to v4",
		Fix:      "Upgrade to actions/upload-artifact@v4",
		Severity: severityMedium,
	},
	{
		Category: CategoryVulnerable,
		Repo:     "actions/download-artifact",
		Range:    "< 4.0.0",
		Reason:   "Deprecated Dec 2024 — upgrade to v4",
		Fix:      "Upgrade to actions/download-artifact@v4",
		Severity: severityMedium,
	},
}

// normalizeRepo reduces any package name to a lowercase "owner/repo".
// It copes with the shapes the advisories API uses: plain repositories,
// URLs, "github.com/" module paths and "@scope/name" packages.
func normalizeRepo(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	for _, prefix := range []string{"https://", "http://", "git://", "ssh://"} {
		s = strings.TrimPrefix(s, prefix)
	}
	s = strings.TrimPrefix(s, "github.com/")
	s = strings.TrimPrefix(s, "@")
	parts := strings.Split(s, "/")
	var segs []string
	for _, p := range parts {
		if p != "" {
			segs = append(segs, p)
		}
	}
	if len(segs) == 0 {
		return ""
	}
	// A leading host-like segment ("github.com", "gitlab.com") is dropped
	// when the name carries a repository path.
	if len(segs) > 2 && strings.Contains(segs[0], ".") {
		segs = segs[1:]
	}
	if len(segs) < 2 {
		return ""
	}
	return segs[0] + "/" + segs[1]
}
