package scanner

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/krishnaduttPanchagnula/actionscan/internal/github"
)

// ── fake ───────────────────────────────────────────────────────────────

// fakeProvenanceClient returns a canned provenance result per ref and
// records every call.
type fakeProvenanceClient struct {
	mu      sync.Mutex
	results map[string]github.Provenance
	calls   []string
}

func newFakeProvenanceClient() *fakeProvenanceClient {
	return &fakeProvenanceClient{results: map[string]github.Provenance{}}
}

// set registers the result for one repo@ref.
func (f *fakeProvenanceClient) set(actionRepo, ref string, p github.Provenance) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.results[actionRepo+"@"+ref] = p
}

func (f *fakeProvenanceClient) VerifyProvenance(_ context.Context, actionRepo, ref string) github.Provenance {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, actionRepo+"@"+ref)
	return f.results[actionRepo+"@"+ref]
}

// called returns every repo@ref the checker asked about.
func (f *fakeProvenanceClient) called() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.calls...)
}

// ── fixtures ───────────────────────────────────────────────────────────

const (
	provSHA     = "1111111111111111111111111111111111111111"
	provOtherSH = "2222222222222222222222222222222222222222"
)

func provRef(name, ref string) ActionRef {
	return ActionRef{
		Raw:      name + "@" + ref,
		Name:     name,
		FullName: name,
		Ref:      ref,
		Job:      "build",
	}
}

// ── checks ─────────────────────────────────────────────────────────────

func TestCheckProvenance_OnlyCommitSHAsAreChecked(t *testing.T) {
	c := newFakeProvenanceClient()
	c.set("acme/tool", provSHA, github.Provenance{
		Repo: "acme/tool", Ref: provSHA, CommitSHA: provSHA,
		Trusted: true, Checked: true,
	})

	refs := []ActionRef{
		provRef("acme/tool", "v1.2.3"), // a tag: a different trust question
		provRef("acme/tool", "main"),   // a branch: likewise
		provRef("acme/tool", provSHA),  // a commit: this one is checked
	}

	findings := CheckProvenance(ctx(), c, "acme/app", ".github/workflows/ci.yml", "build", refs)
	if len(findings) != 0 {
		t.Fatalf("got %d findings (%+v), want none — the commit is trusted", len(findings), findings)
	}

	// Only the commit SHA may reach the verifier: a tag is not a
	// commit and has no business in this check.
	called := c.called()
	if len(called) != 1 || called[0] != "acme/tool@"+provSHA {
		t.Errorf("the verifier was asked about %v, want only acme/tool@%s", called, provSHA)
	}
}

func TestCheckProvenance_UntrustedSHAIsAFinding(t *testing.T) {
	c := newFakeProvenanceClient()
	c.set("acme/tool", provSHA, github.Provenance{
		Repo: "acme/tool", Ref: provSHA, CommitSHA: provSHA,
		Trusted: false, Checked: true,
		Reason: "imposter commit: acme/tool@" + provSHA + " is not reachable from the main branch of acme/tool",
	})

	refs := []ActionRef{provRef("acme/tool", provSHA)}
	findings := CheckProvenance(ctx(), c, "acme/app", ".github/workflows/ci.yml", "build", refs)

	if len(findings) != 1 {
		t.Fatalf("got %d findings (%+v), want 1", len(findings), findings)
	}
	f := findings[0]
	if f.Trusted {
		t.Error("an imposter commit must not be reported as trusted")
	}
	if !f.Checked {
		t.Error("a finding must say the check ran")
	}
	if f.Repo != "acme/app" {
		t.Errorf("repo = %q, want acme/app", f.Repo)
	}
	if f.Workflow != ".github/workflows/ci.yml" {
		t.Errorf("workflow = %q, want .github/workflows/ci.yml", f.Workflow)
	}
	if f.Job != "build" {
		t.Errorf("job = %q, want build", f.Job)
	}
	if f.Action != "acme/tool@"+provSHA {
		t.Errorf("action = %q, want the original uses: value", f.Action)
	}
	if f.Ref != provSHA {
		t.Errorf("ref = %q, want %q", f.Ref, provSHA)
	}
	if !strings.Contains(f.Reason, "imposter commit") {
		t.Errorf("reason = %q, want the verifier's reason", f.Reason)
	}
	// The fix must say what to do about it.
	if f.Fix == "" {
		t.Fatal("a finding must carry a fix")
	}
	if !strings.Contains(f.Fix, "acme/tool") {
		t.Errorf("fix = %q, want it to name the action", f.Fix)
	}
	if !strings.Contains(f.Fix, "default branch") {
		t.Errorf("fix = %q, want it to say what to pin to", f.Fix)
	}
}

func TestCheckProvenance_UncheckableRefIsNotAFinding(t *testing.T) {
	c := newFakeProvenanceClient()
	c.set("acme/tool", provSHA, github.Provenance{
		Repo: "acme/tool", Ref: provSHA,
		Trusted: false, Checked: false,
		Reason: "could not check: the API was rate limited",
	})

	refs := []ActionRef{provRef("acme/tool", provSHA)}
	findings := CheckProvenance(ctx(), c, "acme/app", ".github/workflows/ci.yml", "build", refs)

	// The important behaviour: a ref that could not be checked is a
	// coverage gap, not a defect. Reporting it would be a false
	// positive.
	if len(findings) != 0 {
		t.Fatalf("got %d findings (%+v), want none — an uncheckable ref is a coverage gap, not a defect",
			len(findings), findings)
	}
	// The check did run: the gap is the integration layer's to count.
	if len(c.called()) != 1 {
		t.Errorf("the verifier was asked about %v, want one call", c.called())
	}
}

func TestCheckProvenance_TrustedSHAIsNotAFinding(t *testing.T) {
	c := newFakeProvenanceClient()
	c.set("acme/tool", provSHA, github.Provenance{
		Repo: "acme/tool", Ref: provSHA, CommitSHA: provSHA,
		Trusted: true, Checked: true,
	})

	refs := []ActionRef{provRef("acme/tool", provSHA)}
	findings := CheckProvenance(ctx(), c, "acme/app", ".github/workflows/ci.yml", "build", refs)
	if len(findings) != 0 {
		t.Fatalf("got %d findings (%+v), want none — the commit is on the default branch",
			len(findings), findings)
	}
}

func TestCheckProvenance_EmptyRefList(t *testing.T) {
	c := newFakeProvenanceClient()

	findings := CheckProvenance(ctx(), c, "acme/app", ".github/workflows/ci.yml", "build", nil)
	if len(findings) != 0 {
		t.Fatalf("got %d findings (%+v), want none", len(findings), findings)
	}
	if len(c.called()) != 0 {
		t.Errorf("the verifier was asked about %v, want nothing", c.called())
	}
}

func TestCheckProvenance_NoClientIsNotAFinding(t *testing.T) {
	refs := []ActionRef{provRef("acme/tool", provSHA)}

	findings := CheckProvenance(ctx(), nil, "acme/app", ".github/workflows/ci.yml", "build", refs)
	if len(findings) != 0 {
		t.Fatalf("got %d findings (%+v), want none — without a verifier nothing can be claimed",
			len(findings), findings)
	}
}

func TestCheckProvenance_OnlyTheOffendingRefIsReported(t *testing.T) {
	c := newFakeProvenanceClient()
	c.set("acme/good", provSHA, github.Provenance{
		Repo: "acme/good", Ref: provSHA, CommitSHA: provSHA,
		Trusted: true, Checked: true,
	})
	c.set("acme/bad", provOtherSH, github.Provenance{
		Repo: "acme/bad", Ref: provOtherSH, CommitSHA: provOtherSH,
		Trusted: false, Checked: true,
		Reason: "imposter commit: acme/bad@" + provOtherSH + " is not reachable from the main branch of acme/bad",
	})

	refs := []ActionRef{
		provRef("acme/good", provSHA),
		provRef("acme/bad", provOtherSH),
	}
	findings := CheckProvenance(ctx(), c, "acme/app", ".github/workflows/ci.yml", "build", refs)

	if len(findings) != 1 {
		t.Fatalf("got %d findings (%+v), want 1", len(findings), findings)
	}
	if findings[0].Action != "acme/bad@"+provOtherSH {
		t.Errorf("action = %q, want acme/bad@%s", findings[0].Action, provOtherSH)
	}
}
