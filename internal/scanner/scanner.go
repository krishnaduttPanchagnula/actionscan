package scanner

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	semver "github.com/Masterminds/semver/v3"
	"github.com/krishnaduttPanchagnula/actionscan/internal/github"
	"github.com/krishnaduttPanchagnula/actionscan/internal/rules"
	"gopkg.in/yaml.v3"
)

// Finding is one audit result for one action usage in one workflow.
type Finding struct {
	Repo     string `json:"repo"`
	Workflow string `json:"workflow"` // full path, e.g. ".github/workflows/ci.yml"
	Job      string `json:"job"`      // workflow job id; "" when unknown
	Action   string `json:"action"`   // the original `uses:` value, e.g. "actions/checkout@v4"
	Ref      string `json:"ref"`
	Severity string `json:"severity"` // CRITICAL | HIGH | MEDIUM | LOW
	Category string `json:"category"` // malicious | vulnerable | osv | outdated | unpinned
	Reason   string `json:"reason"`
	Fix      string `json:"fix"`

	AdvisoryID  string `json:"advisory_id,omitempty"`  // GHSA-xxxx / OSV id
	AdvisoryURL string `json:"advisory_url,omitempty"` // link to the advisory
}

// HasCopyableFix reports whether Fix is a paste-ready `uses:` line.
// Prose fixes (e.g. "rotate your secrets") must not be offered as a
// one-click copy — that is how a CRITICAL finding ends up copied as a
// paragraph of prose into a workflow file.
func (f Finding) HasCopyableFix() bool {
	return strings.HasPrefix(f.Fix, "uses:")
}

// Summary is the whole result of a scan.
type Summary struct {
	Findings       []Finding `json:"findings"`
	Critical       int       `json:"critical"`
	High           int       `json:"high"`
	Medium         int       `json:"medium"`
	Low            int       `json:"low"`
	TotalRepos     int       `json:"total_repos"`
	AffectedRepos  int       `json:"affected_repos"`  // repos with >= 1 finding
	ActionsChecked int       `json:"actions_checked"` // remote action refs evaluated
	ScannedAt      time.Time `json:"scanned_at"`

	// Report metadata — a report nobody can attribute is not evidence.
	Target          string    `json:"target"`
	RulesSources    []string  `json:"rules_sources"`
	RulesLoadedAt   time.Time `json:"rules_loaded_at"`
	Degraded        bool      `json:"degraded"`
	DegradedReason  string    `json:"degraded_reason,omitempty"`
	UnreadableRepos []string  `json:"unreadable_repos,omitempty"`
	ToolVersion     string    `json:"tool_version"`
}

// Total is the number of findings.
func (s *Summary) Total() int { return len(s.Findings) }

// Scanner evaluates workflows against the rule feeds.
type Scanner struct {
	Client  Client
	RuleSet *rules.RuleSet

	// OSV results are cached per owner/repo for the lifetime of one
	// scan: the query is by package name, so every ref of the same
	// action reuses the same answer.
	osvMu       sync.Mutex
	osvCache    map[string][]rules.OSVVuln
	osvInflight map[string]chan struct{}
}

// Client is the subset of GitHub access the scanner needs. It is an
// interface so tests can substitute a fake without hitting the network.
// *github.Client satisfies it.
type Client interface {
	// ListWorkflows returns the workflow files of a repo keyed by their
	// FULL path (".github/workflows/ci.yml").
	ListWorkflows(ctx context.Context, r github.Repo) (map[string][]byte, error)
	// LatestTag returns the newest release tag of an action repo.
	// actionRepo is "owner/repo".
	LatestTag(ctx context.Context, actionRepo string) string
	// ResolveSHA expands a short commit SHA to its full 40-char form so
	// unpinned findings can recommend the exact pin. Returns "" when the
	// SHA cannot be resolved (network error, unknown commit).
	// actionRepo is "owner/repo".
	ResolveSHA(ctx context.Context, actionRepo, ref string) string
}

// queryOSV is a package-level indirection over rules.QueryOSV so tests
// can stub OSV lookups without network access.
var queryOSV = rules.QueryOSV

// ── extraction ─────────────────────────────────────────────────────────

// ActionRef is one `uses:` value found in a workflow.
type ActionRef struct {
	Raw      string // original `uses:` value
	Name     string // owner/repo — the feed lookup key
	FullName string // name as written, e.g. "github/codeql-action/analyze"
	Ref      string // version/sha/branch, "" when absent
	Job      string // job id
	Step     int    // step index within the job, -1 for job-level reusable workflow calls
}

// ExtractActionRefs parses a workflow file and returns every remote
// action usage it can verify.
//
// The YAML is walked as a node tree, not line-scanned, so a `uses:`
// inside a `run:` script, a folded scalar or a value on the next line
// cannot be mistaken for an action.
func ExtractActionRefs(yamlBytes []byte) []ActionRef {
	var doc yaml.Node
	if err := yaml.Unmarshal(yamlBytes, &doc); err != nil {
		return nil // malformed workflow — no findings rather than garbage
	}
	jobs := mapValue(docRoot(&doc), "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return nil
	}

	var out []ActionRef
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		jobName := jobs.Content[i].Value
		job := jobs.Content[i+1]
		if job.Kind != yaml.MappingNode {
			continue
		}
		// Job-level reusable workflow call: org/repo/.github/workflows/x.yml@v1
		if a, ok := newActionRef(scalarValue(mapValue(job, "uses")), jobName, -1); ok {
			out = append(out, a)
		}
		steps := mapValue(job, "steps")
		if steps == nil || steps.Kind != yaml.SequenceNode {
			continue
		}
		for si, step := range steps.Content {
			if step.Kind != yaml.MappingNode {
				continue
			}
			if a, ok := newActionRef(scalarValue(mapValue(step, "uses")), jobName, si); ok {
				out = append(out, a)
			}
		}
	}
	return out
}

// ExtractActions returns the raw `uses:` values of a workflow. Kept for
// callers that only need the strings; the scanner uses ExtractActionRefs.
func ExtractActions(yamlBytes []byte) []string {
	refs := ExtractActionRefs(yamlBytes)
	uses := make([]string, 0, len(refs))
	for _, r := range refs {
		uses = append(uses, r.Raw)
	}
	return uses
}

// newActionRef turns one raw `uses:` value into an ActionRef, or reports
// that the value is not a remote action we can verify.
func newActionRef(raw, job string, step int) (ActionRef, bool) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return ActionRef{}, false
	}
	if strings.Contains(v, "${{") {
		return ActionRef{}, false // expression — the real ref is not known
	}
	if strings.HasPrefix(v, "./") {
		return ActionRef{}, false // local action — not a remote reference
	}
	if strings.HasPrefix(v, "$/") {
		// GitHub's self-repository syntax: resolves to the workflow's own
		// repository at the running commit, not to a remote action.
		return ActionRef{}, false
	}
	if strings.HasPrefix(v, "docker://") {
		return ActionRef{}, false // docker action — out of scope
	}

	name, ref := v, ""
	if at := strings.Index(v, "@"); at >= 0 {
		name = strings.TrimSpace(v[:at])
		ref = strings.TrimSpace(v[at+1:])
	}
	segs := strings.Split(name, "/")
	if len(segs) < 2 || segs[0] == "" || segs[1] == "" {
		return ActionRef{}, false // not an "owner/repo" reference
	}
	return ActionRef{
		Raw:      v,
		Name:     segs[0] + "/" + segs[1],
		FullName: name,
		Ref:      ref,
		Job:      job,
		Step:     step,
	}, true
}

// docRoot unwraps the document node to the mapping it holds.
func docRoot(n *yaml.Node) *yaml.Node {
	if n == nil {
		return nil
	}
	if n.Kind == yaml.DocumentNode {
		if len(n.Content) == 0 {
			return nil
		}
		return n.Content[0]
	}
	return n
}

// mapValue returns the value node for key in a mapping node.
func mapValue(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// scalarValue returns the resolved scalar of a node (quotes and inline
// comments already stripped by the YAML parser). Non-scalars yield "".
func scalarValue(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}

// ── checks ─────────────────────────────────────────────────────────────

// Check evaluates one action usage against all rule layers:
//  1. Malicious (compromised actions)
//  2. Vulnerable (advisory ranges)
//  3. OSV.dev (package query, refs matched locally)
//  4. Outdated (latest tag)
//  5. Unpinned hygiene
//
// Every finding carries a concrete Fix — what to change in the workflow.
func (s *Scanner) Check(ctx context.Context, repo, workflow string, a ActionRef) []Finding {
	if s.RuleSet == nil {
		return nil
	}

	var malicious, vulnerable []rules.Rule
	for _, r := range s.RuleSet.Match(a.Name, a.Ref) {
		switch r.Category {
		case "malicious":
			malicious = append(malicious, r)
		case "vulnerable":
			vulnerable = append(vulnerable, r)
		}
	}

	// 1. Malicious — one CRITICAL finding, no further layers.
	if len(malicious) > 0 {
		r := malicious[0]
		return []Finding{{
			Repo: repo, Workflow: workflow, Job: a.Job,
			Action: a.Raw, Ref: a.Ref,
			Severity: "CRITICAL", Category: "malicious",
			Reason: r.Reason, Fix: maliciousFix(a, r),
			AdvisoryID: r.AdvisoryID, AdvisoryURL: r.AdvisoryURL,
		}}
	}

	var out []Finding

	// 2. Advisory ranges — the rule carries its own severity.
	for _, r := range vulnerable {
		sev := r.Severity
		if sev == "" {
			sev = "HIGH"
		}
		fix := r.Fix
		if fix == "" {
			fix = fmt.Sprintf("Upgrade %s to a patched version", a.Name)
		}
		out = append(out, Finding{
			Repo: repo, Workflow: workflow, Job: a.Job,
			Action: a.Raw, Ref: a.Ref,
			Severity: sev, Category: "vulnerable",
			Reason: r.Reason, Fix: fix,
			AdvisoryID: r.AdvisoryID, AdvisoryURL: r.AdvisoryURL,
		})
	}

	// 3. OSV.dev — queried once per owner/repo, matched against locally.
	//
	// OSV's "GitHub Actions" ecosystem mirrors GHSA, so the same
	// advisory usually arrives through both layers. Reporting it twice
	// double-counts every vulnerable action and produces two code
	// scanning alerts for one advisory, so an advisory already reported
	// by the GHSA layer is skipped here.
	if s.RuleSet.UseOSV && isVersionRef(a.Ref) {
		for _, v := range s.osvVulns(ctx, a.Name) {
			if !v.Affects(a.Ref) {
				continue
			}
			if alreadyReported(v, vulnerable) {
				continue
			}
			sev := v.SeverityLevel()
			if sev == "" {
				sev = "HIGH"
			}
			out = append(out, Finding{
				Repo: repo, Workflow: workflow, Job: a.Job,
				Action: a.Raw, Ref: a.Ref,
				Severity: sev, Category: "osv",
				Reason:      osvReason(v, a),
				Fix:         osvFix(a.Name, v),
				AdvisoryID:  v.ID,
				AdvisoryURL: "https://osv.dev/vulnerability/" + v.ID,
			})
		}
	}

	// 4. Outdated — only for version-like refs, and looked up by
	// owner/repo (a sub-path action has no release of its own).
	if s.RuleSet.FetchLatest && isVersionRef(a.Ref) {
		if latest := s.Client.LatestTag(ctx, a.Name); latest != "" && majorBehind(a.Ref, latest) {
			out = append(out, Finding{
				Repo: repo, Workflow: workflow, Job: a.Job,
				Action: a.Raw, Ref: a.Ref,
				Severity: "LOW", Category: "outdated",
				Reason: fmt.Sprintf("Currently on %s, latest release is %s", a.Ref, latest),
				Fix:    fmt.Sprintf("uses: %s@%s", a.Name, latest),
			})
		}
	}

	// 5. Unpinned hygiene.
	if a.Ref == "" {
		out = append(out, Finding{
			Repo: repo, Workflow: workflow, Job: a.Job,
			Action: a.Raw, Ref: "",
			Severity: "MEDIUM", Category: "unpinned",
			Reason: "No ref pinned — mutable action reference",
			Fix:    fmt.Sprintf("Pin %s to a version or commit SHA", a.FullName),
		})
	} else if isShortSHA(a.Ref) {
		out = append(out, Finding{
			Repo: repo, Workflow: workflow, Job: a.Job,
			Action: a.Raw, Ref: a.Ref,
			Severity: "MEDIUM", Category: "unpinned",
			Reason: "Short SHA — pin the full 40-char commit SHA for immutability",
			Fix:    shortSHAFix(ctx, s.Client, a),
		})
	}
	return out
}

// alreadyReported reports whether an OSV advisory is the same advisory
// the GHSA layer already reported for this action.
//
// OSV's GitHub Actions ecosystem is a mirror of the GitHub Advisory
// Database, so the same GHSA id arrives through both layers. The ids
// are compared including the aliases, because OSV may list the advisory
// under its CVE id while GHSA uses the GHSA id.
func alreadyReported(v rules.OSVVuln, reported []rules.Rule) bool {
	ids := append([]string{v.ID}, v.Aliases...)
	for _, r := range reported {
		if r.AdvisoryID == "" {
			continue
		}
		for _, id := range ids {
			if id != "" && strings.EqualFold(id, r.AdvisoryID) {
				return true
			}
		}
	}
	return false
}

// maliciousFix tells the operator exactly what to do about a
// compromised action: remove it, and rotate whatever it could read.
//
// The rule's own fix (e.g. "upgrade to v46.0.1") is only the first
// half of the answer — a compromised action may already have read the
// runner's secrets, so the rotation guidance is always appended.
func maliciousFix(a ActionRef, r rules.Rule) string {
	fix := ""
	if r.Fix != "" {
		fix = r.Fix
	} else {
		fix = fmt.Sprintf("Remove %s from all workflows", a.FullName)
	}
	if len(r.Refs) > 0 {
		fix += " (avoid compromised refs: " + strings.Join(r.Refs, ", ") + ")"
	}
	fix += "; rotate any secrets/tokens it could have accessed and audit recent workflow runs"
	if r.AdvisoryID != "" {
		fix += "; see " + r.AdvisoryID
	}
	return fix
}

// shortSHAFix resolves the short SHA to its full 40-char form so the
// report can show the exact pin to copy into the workflow.
func shortSHAFix(ctx context.Context, c Client, a ActionRef) string {
	if full := c.ResolveSHA(ctx, a.Name, a.Ref); len(full) == 40 {
		return fmt.Sprintf("uses: %s@%s", a.Name, full)
	}
	return fmt.Sprintf("Replace %s@%s with the full 40-char commit SHA", a.FullName, a.Ref)
}

// osvFix recommends the fixed version from the advisory, falling back
// to generic upgrade advice.
func osvFix(actionRepo string, v rules.OSVVuln) string {
	if fixed := v.FixedVersion(); fixed != "" {
		return fmt.Sprintf("Upgrade %s to >= %s", actionRepo, fixed)
	}
	return fmt.Sprintf("Upgrade %s to the latest release (no fixed version in advisory)", actionRepo)
}

// osvReason describes the advisory in one line.
func osvReason(v rules.OSVVuln, a ActionRef) string {
	if v.Summary != "" {
		return fmt.Sprintf("%s: %s", v.ID, v.Summary)
	}
	return fmt.Sprintf("%s affects %s@%s", v.ID, a.Name, a.Ref)
}

// osvVulns returns the OSV advisories for an action repo, querying the
// endpoint at most once per repo. Concurrent callers share a single
// in-flight query instead of stampeding the endpoint.
func (s *Scanner) osvVulns(ctx context.Context, actionRepo string) []rules.OSVVuln {
	s.osvMu.Lock()
	if s.osvCache == nil {
		s.osvCache = map[string][]rules.OSVVuln{}
	}
	if v, ok := s.osvCache[actionRepo]; ok {
		s.osvMu.Unlock()
		return v
	}
	if s.osvInflight == nil {
		s.osvInflight = map[string]chan struct{}{}
	}
	if done, ok := s.osvInflight[actionRepo]; ok {
		// Another worker is already fetching this repo — wait for it.
		s.osvMu.Unlock()
		<-done
		s.osvMu.Lock()
		v := s.osvCache[actionRepo]
		s.osvMu.Unlock()
		return v
	}
	done := make(chan struct{})
	s.osvInflight[actionRepo] = done
	s.osvMu.Unlock()

	vulns, err := queryOSV(ctx, actionRepo)
	if err != nil {
		vulns = nil // silent — OSV is an extra layer, don't fail the scan
	}

	s.osvMu.Lock()
	s.osvCache[actionRepo] = vulns
	delete(s.osvInflight, actionRepo)
	s.osvMu.Unlock()
	close(done)
	return vulns
}

// ── scan ───────────────────────────────────────────────────────────────

// ScanAll checks every repo with a bounded worker pool (at most
// `concurrency` goroutines regardless of repo count) and returns a
// severity-sorted summary. A repo that could not be read is reported as
// unreadable instead of counting as clean.
func (s *Scanner) ScanAll(ctx context.Context, repos []github.Repo, concurrency int) *Summary {
	summary := &Summary{ScannedAt: time.Now().UTC()}
	if s.RuleSet != nil {
		summary.RulesSources = s.RuleSet.Sources
		summary.RulesLoadedAt = s.RuleSet.LoadedAt
		summary.Degraded = s.RuleSet.Degraded
		summary.DegradedReason = s.RuleSet.DegradedReason
	}
	if len(repos) == 0 {
		return summary
	}
	if concurrency < 1 {
		concurrency = 1
	}
	if concurrency > len(repos) {
		concurrency = len(repos)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var mu sync.Mutex
	var wg sync.WaitGroup
	jobs := make(chan github.Repo)

	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for r := range jobs {
				if ctx.Err() != nil {
					return // cancelled: the remaining repos are not scanned
				}
				findings, checked, err := s.scanRepo(ctx, r)

				mu.Lock()
				summary.TotalRepos++
				summary.ActionsChecked += checked
				summary.Findings = append(summary.Findings, findings...)
				if err != nil {
					summary.UnreadableRepos = append(summary.UnreadableRepos,
						fmt.Sprintf("%s: %v", r.FullName, err))
				}
				mu.Unlock()
			}
		}()
	}

feed:
	for _, r := range repos {
		select {
		case jobs <- r:
		case <-ctx.Done():
			break feed
		}
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
	sort.Strings(summary.UnreadableRepos)

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
		if a.Job != b.Job {
			return a.Job < b.Job
		}
		if a.Action != b.Action {
			return a.Action < b.Action
		}
		return a.Reason < b.Reason
	})

	return summary
}

// scanRepo evaluates every workflow of one repo.
//
// A partially readable repo still yields the findings from the files
// that could be read, and is reported as unreadable at the same time —
// so it never reads as fully scanned.
func (s *Scanner) scanRepo(ctx context.Context, r github.Repo) ([]Finding, int, error) {
	workflows, err := s.Client.ListWorkflows(ctx, r)
	if err != nil && len(workflows) == 0 {
		return nil, 0, err
	}

	// Sorted paths so two runs of the same repo produce the same order.
	paths := make([]string, 0, len(workflows))
	for p := range workflows {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	var findings []Finding
	checked := 0
	for _, p := range paths {
		for _, a := range ExtractActionRefs(workflows[p]) {
			checked++
			findings = append(findings, s.Check(ctx, r.FullName, p, a)...)
		}
	}
	return findings, checked, nil
}

// ── ref helpers ────────────────────────────────────────────────────────

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

// majorBehind reports whether ref is a major version behind latest.
//
// Both sides must be real versions: a latest tag like "release-2024" is
// not comparable, and a ref that is AHEAD of the latest release must
// never be reported as outdated (that would advise a downgrade).
func majorBehind(ref, latest string) bool {
	cur, err := semver.NewVersion(strings.TrimPrefix(strings.TrimSpace(ref), "v"))
	if err != nil {
		return false
	}
	lat, err := semver.NewVersion(strings.TrimPrefix(strings.TrimSpace(latest), "v"))
	if err != nil {
		return false
	}
	return cur.Major() < lat.Major()
}

// isVersionRef reports whether a ref looks like a release version
// ("v4", "4.1.1") rather than a branch or a commit SHA. Only such refs
// can be compared against a latest tag or an advisory range.
func isVersionRef(ref string) bool {
	if ref == "" {
		return false
	}
	if isFullSHA(ref) {
		return false // a commit SHA is not a release version
	}
	if strings.HasPrefix(ref, "v") && len(ref) > 1 && ref[1] >= '0' && ref[1] <= '9' {
		return true
	}
	if ref[0] >= '0' && ref[0] <= '9' {
		return true
	}
	return false
}

// isFullSHA reports whether a ref is a full 40-char commit SHA.
func isFullSHA(ref string) bool {
	return len(ref) == 40 && isHex(ref)
}

// isHex reports whether a ref consists only of hex digits.
func isHex(ref string) bool {
	if ref == "" {
		return false
	}
	for i := 0; i < len(ref); i++ {
		c := ref[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// isShortSHA reports whether a ref looks like an abbreviated commit SHA:
// 7–39 hex characters that are not all digits. A ref made only of digits
// is a version or date tag ("20240101"), not a SHA.
func isShortSHA(ref string) bool {
	if len(ref) < 7 || len(ref) > 39 {
		return false
	}
	if !isHex(ref) {
		return false
	}
	for i := 0; i < len(ref); i++ {
		if ref[i] < '0' || ref[i] > '9' {
			return true // at least one non-digit → a SHA
		}
	}
	return false // all digits → a version or date tag
}
