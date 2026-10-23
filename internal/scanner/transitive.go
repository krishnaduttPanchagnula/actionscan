package scanner

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/krishnaduttPanchagnula/actionscan/internal/github"
)

// ── transitive dependency graph ─────────────────────────────────────────
//
// The top-level scan reads the workflow files of a repository. A
// composite action or a reusable workflow that those files call can call
// further actions, and those are invisible to a top-level scan. This
// file turns the resolved graph into findings and hands the report layer
// something it can render.

// TransitiveClient is the subset of GitHub access the transitive
// resolver needs.
//
// *github.Client satisfies it. The scanner's own Client interface does
// NOT: the integration layer has to widen scanner.Client to include
// ResolveTransitive (or pass a separate client) for this to be usable
// from a scan.
type TransitiveClient interface {
	ResolveTransitive(ctx context.Context, r github.Repo, workflows map[string][]byte, limits github.TransitiveLimits) (github.TransitiveResult, error)
}

// *github.Client satisfies the interface; the assertion keeps the two
// signatures from drifting apart.
var _ TransitiveClient = (*github.Client)(nil)

// TransitiveFinding is a finding about a transitively-reached action.
type TransitiveFinding struct {
	Repo     string
	Workflow string // the top-level workflow that reaches it
	Job      string
	Via      []string // the chain of repos
	Action   string   // "owner/repo@ref"
	Depth    int
	Reason   string
	Fix      string
}

// TransitiveReport is the transitive analysis of one scan.
type TransitiveReport struct {
	// Nodes is the number of distinct actions the graph reached.
	Nodes int
	// Depth is the deepest chain that was walked.
	Depth int
	// Complete is false when the graph could not be resolved in full.
	// An incomplete graph is never clean.
	Complete bool
	// Reason explains why the traversal is incomplete.
	Reason string
	// Findings are the actions the top-level scan did not cover.
	Findings []TransitiveFinding
	// Root are the top-level workflows the graph was reached from.
	Root []string
}

// Status returns the scan status: "complete-clean",
// "complete-with-findings" or "incomplete". The three states are
// distinct on purpose — "incomplete" must never be mistaken for
// "complete-clean".
func (r TransitiveReport) Status() string {
	if !r.Complete {
		return "incomplete"
	}
	if len(r.Findings) > 0 {
		return "complete-with-findings"
	}
	return "complete-clean"
}

// AnalyzeTransitive resolves the transitive graph of a repo's workflows
// and reports the actions it reaches that the top-level scan did not
// already cover.
//
// The error return is reserved for a failed traversal (a cancelled
// context, an unusable client). Incompleteness is NOT an error: it is
// reported through TransitiveReport.Complete and TransitiveReport.Reason,
// because a caller that drops the report on error would throw away the
// findings that were resolved.
//
// The report is returned even when the error is non-nil, so the caller
// can still show what was found.
func AnalyzeTransitive(ctx context.Context, c TransitiveClient, r github.Repo, workflows map[string][]byte, limits github.TransitiveLimits) (TransitiveReport, error) {
	rep := TransitiveReport{Complete: true}
	if c == nil {
		rep.Complete = false
		rep.Reason = "no GitHub client available for the transitive traversal"
		return rep, nil
	}

	res, err := c.ResolveTransitive(ctx, r, workflows, limits)
	if err != nil {
		rep.Complete = false
		rep.Reason = err.Error()
	}
	if !res.Complete {
		rep.Complete = false
	}
	if res.Reason != "" {
		if rep.Reason == "" {
			rep.Reason = res.Reason
		} else {
			rep.Reason += "; " + res.Reason
		}
	}

	// The top-level scan already covered every reference written in the
	// workflow files themselves. An action that appears there must not
	// be reported a second time as a transitive one.
	covered := map[string]bool{}
	for _, p := range transitiveSortedPaths(workflows) {
		for _, a := range ExtractActionRefs(workflows[p]) {
			covered[a.FullName+"@"+a.Ref] = true
		}
	}

	reported := map[string]bool{}
	distinct := map[string]bool{}
	roots := map[string]bool{}
	for _, n := range res.Nodes {
		distinct[transitiveNodeKey(n)] = true
		if n.RootWorkflow != "" {
			roots[n.RootWorkflow] = true
		}
		if n.Depth > rep.Depth {
			rep.Depth = n.Depth
		}
		key := transitiveNodeKey(n)
		if n.Depth < 2 {
			continue // the top-level scan saw it
		}
		if covered[key] {
			continue // the top-level scan saw it too
		}
		if reported[key] {
			continue // already reported
		}
		reported[key] = true
		rep.Findings = append(rep.Findings, transitiveFinding(r, n))
	}
	rep.Nodes = len(distinct)
	rep.Root = transitiveSortedKeys(roots)
	return rep, err
}

// transitiveNodeKey is the identity of the action a node points at:
// "owner/repo[/subpath]@ref".
//
// The sub-path is part of the identity: owner/repo and owner/repo/sub are
// different actions, and collapsing them would hide one of the two.
func transitiveNodeKey(n github.TransitiveNode) string {
	return transitiveActionName(n.Repo, n.Path) + "@" + n.Ref
}

// transitiveActionName turns a repo and a metadata path into the name an
// action is referenced by.
func transitiveActionName(repo, path string) string {
	switch {
	case path == "action.yml" || path == "action.yaml":
		return repo
	case strings.HasSuffix(path, "/action.yml"):
		return repo + "/" + strings.TrimSuffix(path, "/action.yml")
	case strings.HasSuffix(path, "/action.yaml"):
		return repo + "/" + strings.TrimSuffix(path, "/action.yaml")
	default:
		return repo + "/" + path
	}
}

// transitiveFinding describes one transitively-reached action.
func transitiveFinding(r github.Repo, n github.TransitiveNode) TransitiveFinding {
	action := transitiveNodeKey(n)
	via := strings.Join(n.Via, " → ")
	reason := fmt.Sprintf("reached transitively via %s (depth %d); the top-level scan did not cover it",
		via, n.Depth)
	if n.Cycle {
		reason = "cycle detected: " + reason
	}
	if n.Ref != "" && !isFullSHA(n.Ref) {
		reason += "; its ref is mutable"
	}

	fix := fmt.Sprintf("Review %s: it runs in your CI but is outside the top-level scan", action)
	if n.SHA != "" && !isFullSHA(n.Ref) {
		fix = fmt.Sprintf("Ask the owner of %s to pin it to commit %s, or replace the action that pulls it in",
			n.Repo, n.SHA)
	}
	return TransitiveFinding{
		Repo:     r.FullName,
		Workflow: n.RootWorkflow,
		Job:      n.RootJob,
		Via:      n.Via,
		Action:   action,
		Depth:    n.Depth,
		Reason:   reason,
		Fix:      fix,
	}
}

// TransitiveRows returns the transitive findings as rows for a report.
//
// The columns match the finding report's CSV layout so the two can be
// rendered side by side: repo, workflow, job, action, depth, via,
// reason, fix.
func TransitiveRows(r TransitiveReport) [][]string {
	rows := make([][]string, 0, len(r.Findings))
	for _, f := range r.Findings {
		rows = append(rows, []string{
			f.Repo, f.Workflow, f.Job, f.Action,
			strconv.Itoa(f.Depth), strings.Join(f.Via, " → "),
			f.Reason, f.Fix,
		})
	}
	return rows
}

// transitiveSortedPaths returns the workflow paths in a stable order.
func transitiveSortedPaths(workflows map[string][]byte) []string {
	out := make([]string, 0, len(workflows))
	for p := range workflows {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// transitiveSortedKeys returns the keys of a set in a stable order.
func transitiveSortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
