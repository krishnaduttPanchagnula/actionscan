package scanner

import (
	"context"
	"fmt"

	"github.com/krishnaduttPanchagnula/actionscan/internal/github"
)

// ── provenance: is the pinned commit really the upstream's? ────────────
//
// A workflow that pins an action to a commit SHA looks immutable, and
// is not. The SHA is only as good as the repository's history: if the
// commit is not reachable from the action's default branch, then it
// exists only because someone with write access pushed it — an imposter
// commit that the upstream project never contained.
//
// This layer turns the verifier's answer into findings. It deliberately
// does not decide severity: that belongs to the integration layer,
// which owns the rule set and the report.
//
// Severity guidance for the integration layer:
//
//   - a SHA that is NOT on the default branch → HIGH ("imposter
//     commit"): the pin points at code the upstream project does not
//     contain, so it was published by someone with write access to the
//     repository.
//   - a SHA that COULD NOT be checked → NOT a finding at all. It is a
//     coverage gap — the tool does not know whether the pin is good —
//     and it belongs in the scan's incomplete accounting. Reporting it
//     as a defect would be a false positive, and a tool that cries
//     wolf on every API hiccup is a tool nobody reads.

// ProvenanceClient is the subset of GitHub access the provenance
// checker needs.
//
// *github.Client satisfies it. The scanner's own Client interface does
// NOT: the integration layer has to widen scanner.Client to include
// VerifyProvenance (or pass a separate client) for this to be usable
// from a scan.
type ProvenanceClient interface {
	VerifyProvenance(ctx context.Context, actionRepo, ref string) github.Provenance
}

// *github.Client satisfies the interface; the assertion keeps the two
// signatures from drifting apart.
var _ ProvenanceClient = (*github.Client)(nil)

// ProvenanceFinding is a finding about the trust of a pinned ref.
//
// Trusted and Checked are carried on the finding so the report can
// show what was verified. A finding always has Checked == true and
// Trusted == false: a ref that could not be checked is never a
// finding.
type ProvenanceFinding struct {
	Repo     string
	Workflow string
	Job      string
	Action   string
	Ref      string
	Trusted  bool
	Checked  bool
	Reason   string
	Fix      string
}

// CheckProvenance verifies the pinned refs of a set of action usages.
//
// Only refs pinned to a commit SHA are checked. A version tag is pinned
// to a tag, which is a different (and separate) trust question — a tag
// can be moved, but what runs is the commit it points at.
//
// A ref that could not be checked produces NO finding: the check did
// not run, so the tool knows nothing about the pin. That is a coverage
// gap for the integration layer to account for, not a defect to report.
//
// The job argument is the workflow job the refs belong to; a ref that
// carries its own job id (as the ones from ExtractActionRefs do) uses
// that instead.
func CheckProvenance(ctx context.Context, c ProvenanceClient, repo, workflow, job string, refs []ActionRef) []ProvenanceFinding {
	if c == nil || len(refs) == 0 {
		return nil
	}

	var out []ProvenanceFinding
	for _, a := range refs {
		// Only a full commit SHA is verified. Anything else is a tag or
		// a branch, which is a different trust question.
		if !isFullSHA(a.Ref) {
			continue
		}
		p := c.VerifyProvenance(ctx, a.Name, a.Ref)

		// The check did not run: the ref's trust is UNKNOWN, not bad.
		// No finding — the integration layer counts it as a gap.
		if !p.Checked {
			continue
		}
		if p.Trusted {
			continue
		}

		j := a.Job
		if j == "" {
			j = job
		}
		out = append(out, ProvenanceFinding{
			Repo:     repo,
			Workflow: workflow,
			Job:      j,
			Action:   a.Raw,
			Ref:      a.Ref,
			Trusted:  false,
			Checked:  true,
			Reason:   p.Reason,
			Fix:      provenanceFix(a, p),
		})
	}
	return out
}

// provenanceFix tells the operator what to do about an imposter commit:
// the pin has to move to a commit the upstream project actually has.
func provenanceFix(a ActionRef, p github.Provenance) string {
	return fmt.Sprintf(
		"Replace the pinned commit with one that is on the default branch of %s — %s is not reachable from it (resolve a good one with `gh api repos/%s/commits/main --jq .sha`, or use the commit a release tag points at)",
		a.Name, p.CommitSHA, a.Name)
}
