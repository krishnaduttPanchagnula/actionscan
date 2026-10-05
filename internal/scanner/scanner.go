package scanner

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

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
	Fix      string `json:"fix"` // concrete remediation for this finding
}

type Summary struct {
	Findings       []Finding `json:"findings"`
	Critical       int       `json:"critical"`
	High           int       `json:"high"`
	Medium         int       `json:"medium"`
	Low            int       `json:"low"`
	TotalRepos     int       `json:"total_repos"`
	AffectedRepos  int       `json:"affected_repos"`  // repos with >= 1 finding
	ActionsChecked int       `json:"actions_checked"` // action usages evaluated
	ScannedAt      time.Time `json:"scanned_at"`
}

type Scanner struct {
	Client  Client
	RuleSet *rules.RuleSet

	osvMu       sync.Mutex
	osvInflight map[string]chan struct{}
}

// Client is the subset of GitHub access the scanner needs. It is an
// interface so tests can substitute a fake without hitting the network.
// *github.Client satisfies it.
type Client interface {
	ListWorkflows(ctx context.Context, r github.Repo) (map[string][]byte, error)
	LatestTag(ctx context.Context, actionRepo string) string
	// ResolveSHA expands a short commit SHA to its full 40-char form so
	// unpinned findings can recommend the exact pin. Returns "" when the
	// SHA cannot be resolved (network error, unknown commit).
	ResolveSHA(ctx context.Context, actionRepo, ref string) string
}

// queryOSV is a package-level indirection over rules.QueryOSV so tests
// can stub OSV lookups without network access.
var queryOSV = rules.QueryOSV

func ExtractActions(yamlBytes []byte) []string {
	uses := make([]string, 0, 8)
	for _, line := range strings.Split(string(yamlBytes), "\n") {
		line = strings.TrimSpace(line)
		// Steps are YAML list items: "- uses: owner/repo@ref".
		// Strip an optional list marker so both "- uses:" and plain
		// "uses:" forms are recognized.
		line = strings.TrimSpace(strings.TrimPrefix(line, "- "))
		if !strings.HasPrefix(line, "uses:") {
			continue
		}
		val := strings.TrimSpace(strings.TrimPrefix(line, "uses:"))
		// Drop trailing YAML comments ("uses: x@v1 # pin me").
		if i := strings.Index(val, " #"); i >= 0 {
			val = strings.TrimSpace(val[:i])
		}
		val = strings.Trim(val, `"'`)
		if val != "" {
			uses = append(uses, val)
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
//
// Every finding carries a concrete Fix — what to change in the workflow.
func (s *Scanner) Check(ctx context.Context, repo, workflow, action string) []Finding {
	// strings.IndexByte instead of SplitN: no per-check allocation.
	at := strings.IndexByte(action, '@')
	if at < 0 {
		return []Finding{{
			Repo: repo, Workflow: workflow, Action: action, Ref: "",
			Severity: "MEDIUM", Category: "unpinned",
			Reason: "No ref pinned — mutable action reference",
			Fix:    fmt.Sprintf("Pin to a version or SHA: uses: %s@<full-sha>", action),
		}}
	}
	name, ref := action[:at], action[at+1:]
	var out []Finding

	// 1. Malicious
	if entry, ok := s.RuleSet.IsMalicious(name, ref); ok {
		out = append(out, Finding{
			Repo: repo, Workflow: workflow, Action: action, Ref: ref,
			Severity: "CRITICAL", Category: "malicious",
			Reason: entry.Description,
			Fix:    maliciousFix(name, entry),
		})
		return out
	}

	// 2. GHSA ranges
	if rule, ok := s.RuleSet.CheckVulnerable(name, ref); ok {
		fix := rule.Fix
		if fix == "" {
			fix = fmt.Sprintf("Upgrade %s to a non-vulnerable version", name)
		}
		out = append(out, Finding{
			Repo: repo, Workflow: workflow, Action: action, Ref: ref,
			Severity: "HIGH", Category: "vulnerable",
			Reason: rule.Reason, Fix: fix,
		})
	}

	// 3. OSV.dev (only for semver-like refs; cached per repo@version)
	if s.RuleSet.UseOSV && isVersionRef(ref) {
		for _, v := range s.queryOSVCached(ctx, name, ref) {
			sev := osvSeverity(v)
			out = append(out, Finding{
				Repo: repo, Workflow: workflow, Action: action, Ref: ref,
				Severity: sev, Category: "osv",
				Reason: fmt.Sprintf("%s: %s", v.ID, osvSummary(v)),
				Fix:    osvFix(name, v),
			})
		}
	}

	// 4. Outdated
	if s.RuleSet.FetchLatest {
		latest := s.Client.LatestTag(ctx, name)
		if latest != "" && isVersionRef(ref) && majorOf(ref) != majorOf(latest) {
			out = append(out, Finding{
				Repo: repo, Workflow: workflow, Action: action, Ref: ref,
				Severity: "LOW", Category: "outdated",
				Reason: fmt.Sprintf("Currently on %s, latest release is %s", ref, latest),
				Fix:    fmt.Sprintf("uses: %s@%s", name, latest),
			})
		}
	}

	// 5. Short-SHA hygiene
	if isSHA(ref) && len(ref) < 40 {
		out = append(out, Finding{
			Repo: repo, Workflow: workflow, Action: action, Ref: ref,
			Severity: "MEDIUM", Category: "unpinned",
			Reason: "Short SHA — pin full 40-char commit SHA for immutability",
			Fix:    shortSHAFix(ctx, s.Client, name, ref),
		})
	}
	return out
}

// maliciousFix tells the operator exactly what to do about a
// compromised action: remove it, and rotate whatever it could read.
func maliciousFix(name string, entry rules.CompromisedEntry) string {
	fix := fmt.Sprintf("Remove %s from all workflows", name)
	if len(entry.Refs) > 0 {
		fix += " (avoid compromised refs: " + strings.Join(entry.Refs, ", ") + ")"
	}
	fix += "; rotate any secrets/tokens it could have accessed and audit recent workflow runs"
	if entry.AdvisoryID != "" {
		fix += fmt.Sprintf("; see %s", entry.AdvisoryID)
	}
	return fix
}

// shortSHAFix resolves the short SHA to its full 40-char form so the
// report can show the exact pin to copy into the workflow.
func shortSHAFix(ctx context.Context, c Client, name, short string) string {
	if full := c.ResolveSHA(ctx, name, short); len(full) == 40 {
		return fmt.Sprintf("uses: %s@%s", name, full)
	}
	return fmt.Sprintf("Replace %s@%s with the full 40-char commit SHA", name, short)
}

// osvFix extracts the first fixed version from an OSV advisory's
// affected ranges, falling back to generic upgrade advice.
func osvFix(name string, v rules.OSVVuln) string {
	for _, a := range v.Affected {
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					return fmt.Sprintf("Upgrade %s to >= %s", name, e.Fixed)
				}
			}
		}
	}
	return fmt.Sprintf("Upgrade %s to the latest release (no fixed version in advisory)", name)
}

// queryOSVCached queries OSV once per unique repo@version. Concurrent
// requests for the same key share a single in-flight query instead of
// stampeding the endpoint.
func (s *Scanner) queryOSVCached(ctx context.Context, repo, ref string) []rules.OSVVuln {
	key := repo + "@" + ref

	s.osvMu.Lock()
	if v, ok := s.RuleSet.OSVCache[key]; ok {
		s.osvMu.Unlock()
		return v
	}
	if s.osvInflight == nil {
		s.osvInflight = map[string]chan struct{}{}
	}
	if done, ok := s.osvInflight[key]; ok {
		// Another worker is already fetching this key — wait for it.
		s.osvMu.Unlock()
		<-done
		s.osvMu.Lock()
		v := s.RuleSet.OSVCache[key]
		s.osvMu.Unlock()
		return v
	}
	done := make(chan struct{})
	s.osvInflight[key] = done
	s.osvMu.Unlock()

	vulns, err := queryOSV(ctx, repo, ref)
	if err != nil {
		vulns = nil // silent — OSV is an extra layer, don't fail the scan
	}

	s.osvMu.Lock()
	s.RuleSet.OSVCache[key] = vulns
	delete(s.osvInflight, key)
	s.osvMu.Unlock()
	close(done)
	return vulns
}

// ScanAll checks every repo with a bounded worker pool (at most
// `concurrency` goroutines regardless of repo count) and returns a
// severity-sorted summary.
func (s *Scanner) ScanAll(ctx context.Context, repos []github.Repo, concurrency int) *Summary {
	summary := &Summary{ScannedAt: time.Now().UTC()}
	if len(repos) == 0 {
		return summary
	}
	if concurrency < 1 {
		concurrency = 1
	}
	if concurrency > len(repos) {
		concurrency = len(repos)
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	jobs := make(chan github.Repo)

	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for r := range jobs {
				var findings []Finding
				checked := 0
				workflows, err := s.Client.ListWorkflows(ctx, r)
				if err == nil {
					for wf, content := range workflows {
						for _, action := range ExtractActions(content) {
							checked++
							findings = append(findings, s.Check(ctx, r.FullName, wf, action)...)
						}
					}
				}

				mu.Lock()
				summary.TotalRepos++
				summary.ActionsChecked += checked
				summary.Findings = append(summary.Findings, findings...)
				mu.Unlock()
			}
		}()
	}
	for _, r := range repos {
		jobs <- r
	}
	close(jobs)
	wg.Wait()

	affected := make(map[string]bool)
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
		affected[f.Repo] = true
	}
	summary.AffectedRepos = len(affected)

	// Stable + full tie-breakers → identical reports run to run.
	ord := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
	sort.SliceStable(summary.Findings, func(i, j int) bool {
		a, b := summary.Findings[i], summary.Findings[j]
		if ord[a.Severity] != ord[b.Severity] {
			return ord[a.Severity] < ord[b.Severity]
		}
		if a.Repo != b.Repo {
			return a.Repo < b.Repo
		}
		if a.Workflow != b.Workflow {
			return a.Workflow < b.Workflow
		}
		if a.Action != b.Action {
			return a.Action < b.Action
		}
		return a.Reason < b.Reason
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

// majorOf returns the major version of a ref, tolerating an optional "v"
// prefix, missing minor/patch components, and non-"v"-prefixed tags so
// that "v4.1.1", "4.1.1", "v41" and "41" all compare consistently.
func majorOf(ref string) string {
	v := strings.TrimPrefix(ref, "v")
	if i := strings.Index(v, "."); i > 0 {
		return v[:i]
	}
	return v
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
