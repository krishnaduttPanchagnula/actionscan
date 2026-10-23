package scanner

import (
	"context"
	"fmt"

	"github.com/krishnaduttPanchagnula/actionscan/internal/github"
)

// extraLayers is the result of the layers that run alongside the
// reference-level check: the transitive graph and the imposter-commit
// check.
type extraLayers struct {
	findings   []Finding
	transitive *TransitiveReport
}

// extraLayers runs the transitive and provenance layers for one repo.
//
// Both need the workflow contents, which the top-level scan has already
// fetched, so they cost no extra workflow reads — only the API calls
// that resolving a reference requires.
func (s *Scanner) extraLayers(ctx context.Context, r github.Repo) extraLayers {
	var out extraLayers
	workflows, err := s.Client.ListWorkflows(ctx, r)
	if err != nil {
		return out // the top-level scan already records this repo as unreadable
	}

	if s.Provenance {
		if pc, ok := s.Client.(ProvenanceClient); ok {
			out.findings = append(out.findings, s.provenanceFindings(ctx, pc, r, workflows)...)
		}
	}

	if s.Transitive {
		if tc, ok := s.Client.(TransitiveClient); ok {
			limits := s.TransitiveLimits
			if limits.MaxDepth == 0 {
				limits = github.DefaultTransitiveLimits()
			}
			rep, err := AnalyzeTransitive(ctx, tc, r, workflows, limits)
			if err != nil {
				return out // cancelled
			}
			out.transitive = &rep
			for _, tf := range rep.Findings {
				out.findings = append(out.findings, Finding{
					Repo: tf.Repo, Workflow: tf.Workflow, Job: tf.Job,
					Action: tf.Action, Ref: "",
					Severity: "MEDIUM", Category: "transitive",
					Reason: tf.Reason, Fix: tf.Fix,
				})
			}
		}
	}
	return out
}

// provenanceFindings turns the imposter-commit check into findings.
//
// A ref that could not be checked produces NO finding: it is a coverage
// gap, not a defect, and reporting it as a defect is how a tool becomes
// noise nobody reads.
func (s *Scanner) provenanceFindings(ctx context.Context, pc ProvenanceClient, r github.Repo, workflows map[string][]byte) []Finding {
	var out []Finding
	for path, content := range workflows {
		for _, a := range ExtractActionRefs(content) {
			for _, pf := range CheckProvenance(ctx, pc, r.FullName, path, a.Job, []ActionRef{a}) {
				if !pf.Checked || pf.Trusted {
					continue // unchecked is not untrusted; trusted is not a finding
				}
				out = append(out, Finding{
					Repo: pf.Repo, Workflow: pf.Workflow, Job: pf.Job,
					Action: pf.Action, Ref: pf.Ref,
					Severity: "HIGH", Category: "imposter",
					Reason: pf.Reason, Fix: pf.Fix,
				})
			}
		}
	}
	return out
}

// mergeTransitive folds one repo's transitive report into the scan
// total.
func mergeTransitive(dst *TransitiveReport, src *TransitiveReport) {
	dst.Nodes += src.Nodes
	dst.Depth = maxInt(dst.Depth, src.Depth)
	dst.Findings = append(dst.Findings, src.Findings...)
	dst.Root = append(dst.Root, src.Root...)
	if !src.Complete {
		dst.Complete = false
		if dst.Reason == "" {
			dst.Reason = src.Reason
		} else {
			dst.Reason = dst.Reason + "; " + src.Reason
		}
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// incompleteReason describes why a scan is not complete, or "".
func incompleteReason(s *Summary) string {
	if s.Complete {
		return ""
	}
	if s.IncompleteReason != "" {
		return s.IncompleteReason
	}
	return fmt.Sprintf("%d repo(s) could not be read", len(s.UnreadableRepos))
}
