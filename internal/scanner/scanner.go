package scanner

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/krishnaduttPanchagnula/actionscan/internal/github"
	"github.com/krishnaduttPanchagnula/actionscan/internal/rules"
)

type Finding struct {
	Repo     string `json:"repo"`
	Workflow string `json:"workflow"`
	Action   string `json:"action"`
	Ref      string `json:"ref"`
	Severity string `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW
	Category string `json:"category"` // malicious, vulnerable, osv, outdated, unpinned
	Reason   string `json:"reason"`
}

type Summary struct {
	Findings   []Finding `json:"findings"`
	Critical   int       `json:"critical"`
	High       int       `json:"high"`
	Medium     int       `json:"medium"`
	Low        int       `json:"low"`
	TotalRepos int       `json:"total_repos"`
}

type Scanner struct {
	Client  *github.Client
	RuleSet *rules.RuleSet

	osvMu sync.Mutex
}

func ExtractActions(yamlBytes []byte) []string {
	var uses []string
	for _, line := range strings.Split(string(yamlBytes), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "uses:") {
			uses = append(uses, strings.Trim(strings.TrimPrefix(line, "uses:"), `"'`))
		}
	}
	return uses
}

// Check evaluates one action usage against all rule layers:
//  1. Malicious (StepSecurity)
//  2. Vulnerable (GHSA ranges)
//  3. OSV.dev (exact-version query, lazily per repo@version)
//  4. Outdated (latest tag)
//  5. Unpinned hygiene
func (s *Scanner) Check(ctx context.Context, repo, workflow, action string) []Finding {
	parts := strings.SplitN(action, "@", 2)
	if len(parts) != 2 {
		return []Finding{{repo, workflow, action, "", "MEDIUM", "unpinned",
			"No ref pinned — mutable action reference"}}
	}
	name, ref := parts[0], parts[1]
	var out []Finding

	// 1. Malicious
	if entry, ok := s.RuleSet.IsMalicious(name, ref); ok {
		out = append(out, Finding{repo, workflow, action, ref, "CRITICAL", "malicious", entry.Description})
		return out
	}

	// 2. GHSA ranges
	if reason, ok := s.RuleSet.CheckVulnerable(name, ref); ok {
		out = append(out, Finding{repo, workflow, action, ref, "HIGH", "vulnerable", reason})
	}

	// 3. OSV.dev (only for semver-like refs; cached per repo@version)
	if isVersionRef(ref) {
		for _, v := range s.queryOSVCached(ctx, name, ref) {
			sev := osvSeverity(v)
			out = append(out, Finding{repo, workflow, action, ref, sev, "osv",
				fmt.Sprintf("%s: %s", v.ID, osvSummary(v))})
		}
	}

	// 4. Outdated
	latest := s.Client.LatestTag(ctx, name)
	if latest != "" && isVersionRef(ref) && majorOf(ref) != majorOf(latest) {
		out = append(out, Finding{repo, workflow, action, ref, "LOW", "outdated",
			fmt.Sprintf("Currently on %s, latest release is %s", ref, latest)})
	}

	// 5. Short-SHA hygiene
	if isSHA(ref) && len(ref) < 40 {
		out = append(out, Finding{repo, workflow, action, ref, "MEDIUM", "unpinned",
			"Short SHA — pin full 40-char commit SHA for immutability"})
	}
	return out
}

// queryOSVCached queries OSV once per unique repo@version (in-memory dedupe).
func (s *Scanner) queryOSVCached(ctx context.Context, repo, ref string) []rules.OSVVuln {
	key := repo + "@" + ref

	s.osvMu.Lock()
	if v, ok := s.RuleSet.OSVCache[key]; ok {
		s.osvMu.Unlock()
		return v
	}
	s.osvMu.Unlock()

	vulns, err := rules.QueryOSV(ctx, repo, ref)
	if err != nil {
		vulns = nil // silent — OSV is an extra layer, don't fail the scan
	}

	s.osvMu.Lock()
	s.RuleSet.OSVCache[key] = vulns
	s.osvMu.Unlock()
	return vulns
}

func (s *Scanner) ScanAll(ctx context.Context, repos []github.Repo, concurrency int) *Summary {
	summary := &Summary{}
	var mu sync.Mutex
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, r := range repos {
		wg.Add(1)
		go func(r github.Repo) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			var findings []Finding
			workflows, err := s.Client.ListWorkflows(ctx, r)
			if err == nil {
				for wf, content := range workflows {
					for _, action := range ExtractActions(content) {
						findings = append(findings, s.Check(ctx, r.FullName, wf, action)...)
					}
				}
			}

			mu.Lock()
			summary.TotalRepos++
			summary.Findings = append(summary.Findings, findings...)
			mu.Unlock()
		}(r)
	}
	wg.Wait()

	for _, f := range summary.Findings {
		switch f.Severity {
		case "CRITICAL":
			summary.Critical++
		case "HIGH":
			summary.High++
		case "MEDIUM":
			summary.Medium++
		case "LOW":
			summary.Low++
		}
	}

	ord := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
	sort.Slice(summary.Findings, func(i, j int) bool {
		return ord[summary.Findings[i].Severity] < ord[summary.Findings[j].Severity]
	})

	return summary
}

// osvSeverity maps OSV severity to our badge levels.
func osvSeverity(v rules.OSVVuln) string {
	for _, sv := range v.Severity {
		if sv.Type == "CVSS_V3" && strings.HasPrefix(sv.Score, "CVSS:3") {
			// crude: use base score prefix heuristics via vector's first metric
			// Simplest robust approach: parse severity from the vector's
			// "S:" is not severity; fall back to summary below.
		}
	}
	// OSV database severity is often empty for action advisories;
	// default to HIGH since it's a known-vulnerable version.
	return "HIGH"
}

func osvSummary(v rules.OSVVuln) string {
	if v.Summary != "" {
		return v.Summary
	}
	return "Known vulnerability in this action version"
}

func majorOf(ref string) string {
	if strings.HasPrefix(ref, "v") {
		if i := strings.Index(ref, "."); i > 0 {
			return ref[:i]
		}
	}
	return ref
}

func isVersionRef(ref string) bool {
	if strings.HasPrefix(ref, "v") && len(ref) > 1 && ref[1] >= '0' && ref[1] <= '9' {
		return true
	}
	if ref != "" && ref[0] >= '0' && ref[0] <= '9' {
		return true
	}
	return false
}

func isSHA(ref string) bool {
	if len(ref) < 7 || len(ref) > 40 {
		return false
	}
	for _, c := range ref {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}
