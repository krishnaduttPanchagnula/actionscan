package scanner

import (
	"context"
	"strings"
	"testing"

	"github.com/krishnaduttPanchagnula/actionscan/internal/github"
)

// fakeTransitiveClient returns a canned traversal result.
type fakeTransitiveClient struct {
	result github.TransitiveResult
	err    error
	calls  int
}

func (f *fakeTransitiveClient) ResolveTransitive(_ context.Context, _ github.Repo, _ map[string][]byte, _ github.TransitiveLimits) (github.TransitiveResult, error) {
	f.calls++
	return f.result, f.err
}

func transitiveRepo() github.Repo {
	return github.Repo{FullName: "acme/app", Owner: "acme", Name: "app", DefaultBranch: "main"}
}

// transitiveWorkflows is a workflow whose only reference is acme/known@v1.
func transitiveWorkflows() map[string][]byte {
	return map[string][]byte{
		".github/workflows/ci.yml": []byte("name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: acme/known@v1\n"),
	}
}

func TestAnalyzeTransitive_ActionAlreadySeenIsNotReportedTwice(t *testing.T) {
	c := &fakeTransitiveClient{result: github.TransitiveResult{
		Complete: true,
		Nodes: []github.TransitiveNode{
			// The reference written in the workflow itself.
			{Repo: "acme/known", Path: "action.yml", Ref: "v1", SHA: "sha1", Depth: 1,
				Via: []string{"acme/known"}, RootWorkflow: ".github/workflows/ci.yml", RootJob: "build"},
			// The same action, reached again through another action.
			{Repo: "acme/known", Path: "action.yml", Ref: "v1", SHA: "sha1", Depth: 2,
				Via: []string{"acme/other", "acme/known"}, RootWorkflow: ".github/workflows/ci.yml", RootJob: "build"},
		},
	}}

	rep, err := AnalyzeTransitive(ctx(), c, transitiveRepo(), transitiveWorkflows(), github.DefaultTransitiveLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 0 {
		t.Fatalf("got %d findings (%+v), want none — the top-level scan already covered acme/known@v1",
			len(rep.Findings), rep.Findings)
	}
}

func TestAnalyzeTransitive_UncoveredActionIsReportedWithItsChain(t *testing.T) {
	c := &fakeTransitiveClient{result: github.TransitiveResult{
		Complete: true,
		Nodes: []github.TransitiveNode{
			{Repo: "acme/known", Path: "action.yml", Ref: "v1", SHA: "sha1", Depth: 1,
				Via: []string{"acme/known"}, RootWorkflow: ".github/workflows/ci.yml", RootJob: "build"},
			{Repo: "acme/hidden", Path: "action.yml", Ref: "v2", SHA: "sha2", Depth: 3,
				Via:          []string{"acme/known", "acme/middle", "acme/hidden"},
				RootWorkflow: ".github/workflows/ci.yml", RootJob: "build"},
		},
	}}

	rep, err := AnalyzeTransitive(ctx(), c, transitiveRepo(), transitiveWorkflows(), github.DefaultTransitiveLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 1 {
		t.Fatalf("got %d findings (%+v), want 1", len(rep.Findings), rep.Findings)
	}
	f := rep.Findings[0]
	if f.Action != "acme/hidden@v2" {
		t.Errorf("action = %q, want acme/hidden@v2", f.Action)
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
	// The whole chain, root first.
	if got := strings.Join(f.Via, ">"); got != "acme/known>acme/middle>acme/hidden" {
		t.Errorf("via = %v, want the full chain acme/known > acme/middle > acme/hidden", f.Via)
	}
	// The depth is recorded.
	if f.Depth != 3 {
		t.Errorf("depth = %d, want 3", f.Depth)
	}
	if rep.Depth != 3 {
		t.Errorf("report depth = %d, want 3", rep.Depth)
	}
	if rep.Nodes != 2 {
		t.Errorf("report nodes = %d, want 2 distinct actions", rep.Nodes)
	}
	if len(rep.Root) != 1 || rep.Root[0] != ".github/workflows/ci.yml" {
		t.Errorf("root = %v, want the top-level workflow", rep.Root)
	}
	if !rep.Complete {
		t.Errorf("report must be complete, got %q", rep.Reason)
	}
	if rep.Status() != "complete-with-findings" {
		t.Errorf("status = %q, want complete-with-findings", rep.Status())
	}
}

func TestAnalyzeTransitive_SubPathActionIsNotHiddenByTheRootAction(t *testing.T) {
	c := &fakeTransitiveClient{result: github.TransitiveResult{
		Complete: true,
		Nodes: []github.TransitiveNode{
			// The root action of acme/tool is referenced by the workflow.
			{Repo: "acme/tool", Path: "action.yml", Ref: "v1", SHA: "sha1", Depth: 1,
				Via: []string{"acme/tool"}, RootWorkflow: ".github/workflows/ci.yml", RootJob: "build"},
			// A different action of the same repository, reached only
			// through a composite action.
			{Repo: "acme/tool", Path: "sub/action.yml", Ref: "v1", SHA: "sha2", Depth: 2,
				Via: []string{"acme/tool", "acme/tool"}, RootWorkflow: ".github/workflows/ci.yml", RootJob: "build"},
		},
	}}
	workflows := map[string][]byte{
		".github/workflows/ci.yml": []byte("name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: acme/tool@v1\n"),
	}

	rep, err := AnalyzeTransitive(ctx(), c, transitiveRepo(), workflows, github.DefaultTransitiveLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 1 {
		t.Fatalf("got %d findings (%+v), want 1 — acme/tool/sub is not acme/tool", len(rep.Findings), rep.Findings)
	}
	if rep.Findings[0].Action != "acme/tool/sub@v1" {
		t.Errorf("action = %q, want acme/tool/sub@v1", rep.Findings[0].Action)
	}
}

func TestAnalyzeTransitive_IncompleteTraversalIsSurfaced(t *testing.T) {
	c := &fakeTransitiveClient{result: github.TransitiveResult{
		Complete: false,
		Reason:   "depth budget of 12 exhausted at acme/middle",
		Nodes: []github.TransitiveNode{
			{Repo: "acme/known", Path: "action.yml", Ref: "v1", SHA: "sha1", Depth: 1,
				Via: []string{"acme/known"}, RootWorkflow: ".github/workflows/ci.yml", RootJob: "build"},
		},
	}}

	rep, err := AnalyzeTransitive(ctx(), c, transitiveRepo(), transitiveWorkflows(), github.DefaultTransitiveLimits())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Complete {
		t.Fatal("an incomplete traversal must not be reported as complete")
	}
	if !strings.Contains(rep.Reason, "depth") {
		t.Errorf("reason = %q, want the resolver's reason", rep.Reason)
	}
	if rep.Status() != "incomplete" {
		t.Errorf("status = %q, want incomplete", rep.Status())
	}
}

func TestAnalyzeTransitive_CycleIsReported(t *testing.T) {
	c := &fakeTransitiveClient{result: github.TransitiveResult{
		Complete: true,
		Nodes: []github.TransitiveNode{
			{Repo: "acme/known", Path: "action.yml", Ref: "v1", SHA: "sha1", Depth: 1,
				Via: []string{"acme/known"}, RootWorkflow: ".github/workflows/ci.yml", RootJob: "build"},
			{Repo: "acme/loop", Path: "action.yml", Ref: "v1", SHA: "sha2", Depth: 2, Cycle: true,
				Via: []string{"acme/known", "acme/loop"}, RootWorkflow: ".github/workflows/ci.yml", RootJob: "build"},
		},
	}}

	rep, err := AnalyzeTransitive(ctx(), c, transitiveRepo(), transitiveWorkflows(), github.DefaultTransitiveLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(rep.Findings))
	}
	if !strings.Contains(rep.Findings[0].Reason, "cycle") {
		t.Errorf("reason = %q, want it to mention the cycle", rep.Findings[0].Reason)
	}
}

func TestAnalyzeTransitive_RowsCarryTheFindings(t *testing.T) {
	c := &fakeTransitiveClient{result: github.TransitiveResult{
		Complete: true,
		Nodes: []github.TransitiveNode{
			{Repo: "acme/hidden", Path: "action.yml", Ref: "v2", SHA: "sha2", Depth: 2,
				Via:          []string{"acme/known", "acme/hidden"},
				RootWorkflow: ".github/workflows/ci.yml", RootJob: "build"},
		},
	}}

	rep, err := AnalyzeTransitive(ctx(), c, transitiveRepo(), transitiveWorkflows(), github.DefaultTransitiveLimits())
	if err != nil {
		t.Fatal(err)
	}
	rows := TransitiveRows(rep)
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	row := rows[0]
	if len(row) != 8 {
		t.Fatalf("got %d columns (%v), want 8", len(row), row)
	}
	if row[0] != "acme/app" || row[1] != ".github/workflows/ci.yml" || row[2] != "build" {
		t.Errorf("row = %v, want the repo, workflow and job first", row)
	}
	if row[3] != "acme/hidden@v2" || row[4] != "2" {
		t.Errorf("row = %v, want the action and its depth", row)
	}
	if row[5] != "acme/known → acme/hidden" {
		t.Errorf("row via = %q, want the chain", row[5])
	}
}

func TestAnalyzeTransitive_NoClientIsIncomplete(t *testing.T) {
	rep, err := AnalyzeTransitive(ctx(), nil, transitiveRepo(), transitiveWorkflows(), github.DefaultTransitiveLimits())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Complete {
		t.Error("a traversal without a client cannot be complete")
	}
	if rep.Status() != "incomplete" {
		t.Errorf("status = %q, want incomplete", rep.Status())
	}
}
