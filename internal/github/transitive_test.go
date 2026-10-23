package github

import (
	"net/http"
	"strings"
	"sync"
	"testing"
)

// ── fake GitHub API ─────────────────────────────────────────────────────

// Commit SHAs used by the fixtures.
const (
	shaA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	shaB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	shaC = "cccccccccccccccccccccccccccccccccccccccc"
)

// fakeAPI serves the two endpoints the transitive resolver uses: the
// commit lookup and the contents API.
type fakeAPI struct {
	mu      sync.Mutex
	commits map[string]string // "owner/repo@ref" -> commit SHA
	files   map[string]string // "owner/repo@path@sha" -> file content
	log     []string          // every request, as "path?query"
}

func newFakeAPI() *fakeAPI {
	return &fakeAPI{
		commits: map[string]string{},
		files:   map[string]string{},
	}
}

// commit registers the SHA a ref resolves to.
func (f *fakeAPI) commit(owner, name, ref, sha string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.commits[owner+"/"+name+"@"+ref] = sha
}

// file registers the content of a file at a commit.
func (f *fakeAPI) file(owner, name, path, sha, content string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files[owner+"/"+name+"@"+path+"@"+sha] = content
}

// requests returns every request the resolver made.
func (f *fakeAPI) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.log...)
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log = append(f.log, r.URL.Path+"?"+r.URL.RawQuery)

	rest := strings.TrimPrefix(r.URL.Path, "/repos/")
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) < 3 {
		writeJSON(w, 404, map[string]any{"message": "not found"})
		return
	}
	owner, name := parts[0], parts[1]
	switch {
	case strings.HasPrefix(parts[2], "commits/"):
		ref := strings.TrimPrefix(parts[2], "commits/")
		sha, ok := f.commits[owner+"/"+name+"@"+ref]
		if !ok {
			writeJSON(w, 404, map[string]any{"message": "no such commit"})
			return
		}
		writeJSON(w, 200, map[string]any{"sha": sha})
	case strings.HasPrefix(parts[2], "contents/"):
		path := strings.TrimPrefix(parts[2], "contents/")
		ref := r.URL.Query().Get("ref")
		content, ok := f.files[owner+"/"+name+"@"+path+"@"+ref]
		if !ok {
			writeJSON(w, 404, map[string]any{"message": "not found"})
			return
		}
		writeJSON(w, 200, map[string]any{
			"type": "file", "encoding": "base64",
			"content": b64(content), "size": len(content),
		})
	default:
		writeJSON(w, 404, map[string]any{"message": "not found"})
	}
}

// ── fixtures ────────────────────────────────────────────────────────────

const compositeAction = `name: builder
runs:
  using: composite
  steps:
    - uses: acme/deploy@v2
`

const plainAction = `name: deploy
runs:
  using: node20
  main: index.js
`

const reusableWorkflow = `name: shared
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: acme/tool@v3
`

func workflowUsing(uses string) map[string][]byte {
	return map[string][]byte{
		".github/workflows/ci.yml": []byte("name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: " + uses + "\n"),
	}
}

func transitiveRepo() Repo {
	return Repo{FullName: "acme/app", Owner: "acme", Name: "app", DefaultBranch: "main"}
}

// findNode returns the first node for a repo.
func findNode(t *testing.T, res TransitiveResult, repo string) TransitiveNode {
	t.Helper()
	for _, n := range res.Nodes {
		if n.Repo == repo {
			return n
		}
	}
	t.Fatalf("no node for %s in %+v", repo, res.Nodes)
	return TransitiveNode{}
}

// ── traversal ───────────────────────────────────────────────────────────

func TestResolveTransitive_CompositeActionIsFollowed(t *testing.T) {
	f := newFakeAPI()
	f.commit("acme", "builder", "v1", shaA)
	f.file("acme", "builder", "action.yml", shaA, compositeAction)
	f.commit("acme", "deploy", "v2", shaB)
	f.file("acme", "deploy", "action.yml", shaB, plainAction)

	c := newTestClient(t, f.ServeHTTP)
	res, err := c.ResolveTransitive(ctx(), transitiveRepo(), workflowUsing("acme/builder@v1"),
		DefaultTransitiveLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Complete {
		t.Fatalf("traversal must be complete, got %q", res.Reason)
	}

	builder := findNode(t, res, "acme/builder")
	if builder.Depth != 1 {
		t.Errorf("builder depth = %d, want 1", builder.Depth)
	}
	if !builder.Composite {
		t.Error("builder must be recognised as a composite action")
	}

	// The action the composite calls is invisible to a top-level scan.
	deploy := findNode(t, res, "acme/deploy")
	if deploy.Depth != 2 {
		t.Errorf("deploy depth = %d, want 2", deploy.Depth)
	}
	if deploy.Composite {
		t.Error("deploy is a plain action, not a composite one")
	}
	if got := strings.Join(deploy.Via, ">"); got != "acme/builder>acme/deploy" {
		t.Errorf("deploy via = %v, want the chain acme/builder > acme/deploy", deploy.Via)
	}
	if res.Structures == 0 {
		t.Error("the traversal must charge the YAML structures it parsed")
	}
}

func TestResolveTransitive_ReusableWorkflowIsFollowed(t *testing.T) {
	f := newFakeAPI()
	f.commit("acme", "pipelines", "v1", shaA)
	f.file("acme", "pipelines", ".github/workflows/ci.yml", shaA, reusableWorkflow)
	f.commit("acme", "tool", "v3", shaB)
	f.file("acme", "tool", "action.yml", shaB, plainAction)

	c := newTestClient(t, f.ServeHTTP)
	workflows := map[string][]byte{
		".github/workflows/ci.yml": []byte("name: CI\non: push\njobs:\n  call:\n    uses: acme/pipelines/.github/workflows/ci.yml@v1\n"),
	}
	res, err := c.ResolveTransitive(ctx(), transitiveRepo(), workflows, DefaultTransitiveLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Complete {
		t.Fatalf("traversal must be complete, got %q", res.Reason)
	}

	pipelines := findNode(t, res, "acme/pipelines")
	if !pipelines.Workflow {
		t.Error("a reusable workflow call must be recognised as a workflow")
	}
	if pipelines.Path != ".github/workflows/ci.yml" {
		t.Errorf("pipelines path = %q, want .github/workflows/ci.yml", pipelines.Path)
	}

	tool := findNode(t, res, "acme/tool")
	if tool.Depth != 2 {
		t.Errorf("tool depth = %d, want 2", tool.Depth)
	}
}

func TestResolveTransitive_PlainActionHasNoTransitiveReferences(t *testing.T) {
	f := newFakeAPI()
	f.commit("acme", "deploy", "v2", shaB)
	f.file("acme", "deploy", "action.yml", shaB, plainAction)

	c := newTestClient(t, f.ServeHTTP)
	res, err := c.ResolveTransitive(ctx(), transitiveRepo(), workflowUsing("acme/deploy@v2"),
		DefaultTransitiveLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Complete {
		t.Fatalf("traversal must be complete, got %q", res.Reason)
	}
	if len(res.Nodes) != 1 {
		t.Fatalf("got %d nodes (%+v), want 1 — a plain action has no references", len(res.Nodes), res.Nodes)
	}
	if res.Nodes[0].Composite {
		t.Error("a node20 action is not a composite action")
	}
}

func TestResolveTransitive_CycleTerminatesAndStaysComplete(t *testing.T) {
	f := newFakeAPI()
	f.commit("acme", "a", "v1", shaA)
	f.file("acme", "a", "action.yml", shaA, "name: a\nruns:\n  using: composite\n  steps:\n    - uses: acme/b@v1\n")
	f.commit("acme", "b", "v1", shaB)
	f.file("acme", "b", "action.yml", shaB, "name: b\nruns:\n  using: composite\n  steps:\n    - uses: acme/a@v1\n")

	c := newTestClient(t, f.ServeHTTP)
	res, err := c.ResolveTransitive(ctx(), transitiveRepo(), workflowUsing("acme/a@v1"),
		DefaultTransitiveLimits())
	if err != nil {
		t.Fatal(err)
	}
	// A cycle is not incompleteness: the graph is complete, it is just
	// cyclic.
	if !res.Complete {
		t.Fatalf("a cycle must not make the traversal incomplete: %q", res.Reason)
	}

	var cycles int
	for _, n := range res.Nodes {
		if n.Cycle {
			cycles++
			if n.Repo != "acme/a" {
				t.Errorf("cycle node repo = %q, want acme/a", n.Repo)
			}
			if got := strings.Join(n.Via, ">"); got != "acme/a>acme/b>acme/a" {
				t.Errorf("cycle via = %v, want the chain acme/a > acme/b > acme/a", n.Via)
			}
		}
	}
	if cycles == 0 {
		t.Errorf("the cycle must be recorded, nodes = %+v", res.Nodes)
	}
}

func TestResolveTransitive_ResolvesRefToSHABeforeFetching(t *testing.T) {
	f := newFakeAPI()
	f.commit("acme", "tool", "v1", shaA)
	f.file("acme", "tool", "action.yml", shaA, plainAction)

	c := newTestClient(t, f.ServeHTTP)
	res, err := c.ResolveTransitive(ctx(), transitiveRepo(), workflowUsing("acme/tool@v1"),
		DefaultTransitiveLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Complete {
		t.Fatalf("traversal must be complete, got %q", res.Reason)
	}

	// The metadata must be read at the resolved commit, not at the
	// mutable tag.
	var fetchedAtSHA bool
	for _, req := range f.requests() {
		if strings.Contains(req, "/contents/action.yml") && strings.Contains(req, "ref="+shaA) {
			fetchedAtSHA = true
		}
		if strings.Contains(req, "/contents/action.yml") && strings.Contains(req, "ref=v1") {
			t.Errorf("the metadata was fetched at the mutable ref: %s", req)
		}
	}
	if !fetchedAtSHA {
		t.Errorf("the metadata was not fetched at the resolved SHA %s: %v", shaA, f.requests())
	}

	node := findNode(t, res, "acme/tool")
	if node.SHA != shaA {
		t.Errorf("node SHA = %q, want %q", node.SHA, shaA)
	}
	if node.Ref != "v1" {
		t.Errorf("node Ref = %q, want the ref as written (v1)", node.Ref)
	}
}

// ── budgets and failures ────────────────────────────────────────────────

func TestResolveTransitive_DepthBudgetExhausted(t *testing.T) {
	f := newFakeAPI()
	f.commit("acme", "a", "v1", shaA)
	f.file("acme", "a", "action.yml", shaA, "name: a\nruns:\n  using: composite\n  steps:\n    - uses: acme/b@v1\n")
	f.commit("acme", "b", "v1", shaB)
	f.file("acme", "b", "action.yml", shaB, "name: b\nruns:\n  using: composite\n  steps:\n    - uses: acme/c@v1\n")
	f.commit("acme", "c", "v1", shaC)
	f.file("acme", "c", "action.yml", shaC, plainAction)

	c := newTestClient(t, f.ServeHTTP)
	limits := DefaultTransitiveLimits()
	limits.MaxDepth = 1
	res, err := c.ResolveTransitive(ctx(), transitiveRepo(), workflowUsing("acme/a@v1"), limits)
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete {
		t.Fatal("a traversal that stopped at the depth budget must be incomplete")
	}
	if !strings.Contains(res.Reason, "depth") {
		t.Errorf("reason = %q, want it to mention the depth budget", res.Reason)
	}
	if len(res.Nodes) != 1 {
		t.Errorf("got %d nodes (%+v), want only the depth-1 node", len(res.Nodes), res.Nodes)
	}
}

func TestResolveTransitive_RequestBudgetExhausted(t *testing.T) {
	f := newFakeAPI()
	f.commit("acme", "a", "v1", shaA)
	f.file("acme", "a", "action.yml", shaA, plainAction)

	c := newTestClient(t, f.ServeHTTP)
	limits := DefaultTransitiveLimits()
	limits.MaxRequests = 1
	res, err := c.ResolveTransitive(ctx(), transitiveRepo(), workflowUsing("acme/a@v1"), limits)
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete {
		t.Fatal("a traversal that ran out of requests must be incomplete")
	}
	if !strings.Contains(res.Reason, "request") {
		t.Errorf("reason = %q, want it to mention the request budget", res.Reason)
	}
}

func TestResolveTransitive_OversizedResponseIsRefused(t *testing.T) {
	f := newFakeAPI()
	f.commit("acme", "a", "v1", shaA)
	f.file("acme", "a", "action.yml", shaA, plainAction+strings.Repeat("x", 2000))

	c := newTestClient(t, f.ServeHTTP)
	limits := DefaultTransitiveLimits()
	limits.MaxResponseBytes = 500
	res, err := c.ResolveTransitive(ctx(), transitiveRepo(), workflowUsing("acme/a@v1"), limits)
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete {
		t.Fatal("a traversal that refused an oversized response must be incomplete")
	}
	if !strings.Contains(res.Reason, "response") {
		t.Errorf("reason = %q, want it to mention the response size budget", res.Reason)
	}
}

func TestResolveTransitive_StructureBudgetExhausted(t *testing.T) {
	f := newFakeAPI()
	f.commit("acme", "builder", "v1", shaA)
	f.file("acme", "builder", "action.yml", shaA, compositeAction)

	c := newTestClient(t, f.ServeHTTP)
	limits := DefaultTransitiveLimits()
	// The budget is PER DOCUMENT: it bounds one pathological file, not
	// the whole traversal. Five structures is below the size of the
	// workflow itself, so the very first document trips it.
	limits.MaxStructures = 5
	res, err := c.ResolveTransitive(ctx(), transitiveRepo(), workflowUsing("acme/builder@v1"), limits)
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete {
		t.Fatal("a traversal that ran out of structures must be incomplete")
	}
	if !strings.Contains(res.Reason, "structure") {
		t.Errorf("reason = %q, want it to mention the structure budget", res.Reason)
	}
}

// The structure budget must NOT be charged against the whole
// traversal: a repo with thirty ordinary actions would otherwise
// always exhaust it and report INCOMPLETE, which is worse than not
// scanning at all. The total work is bounded by the request and byte
// budgets instead.
func TestResolveTransitive_StructureBudgetIsPerDocument(t *testing.T) {
	f := newFakeAPI()
	f.commit("acme", "one", "v1", shaA)
	f.file("acme", "one", "action.yml", shaA, plainAction)
	f.commit("acme", "two", "v1", shaB)
	f.file("acme", "two", "action.yml", shaB, plainAction)
	f.commit("acme", "three", "v1", shaC)
	f.file("acme", "three", "action.yml", shaC, plainAction)

	c := newTestClient(t, f.ServeHTTP)
	limits := DefaultTransitiveLimits()
	// Enough for any single document, but not for all of them together.
	limits.MaxStructures = 40

	wf := map[string][]byte{
		".github/workflows/ci.yml": []byte("name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: acme/one@v1\n      - uses: acme/two@v1\n      - uses: acme/three@v1\n"),
	}
	res, err := c.ResolveTransitive(ctx(), transitiveRepo(), wf, limits)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Complete {
		t.Errorf("the traversal must be complete: %s", res.Reason)
	}
	if len(res.Nodes) < 3 {
		t.Errorf("nodes = %d, want at least 3", len(res.Nodes))
	}
}

func TestResolveTransitive_MissingFileLeavesTheRestResolved(t *testing.T) {
	f := newFakeAPI()
	f.commit("acme", "gone", "v1", shaA) // the commit exists, the file does not
	f.commit("acme", "good", "v1", shaB)
	f.file("acme", "good", "action.yml", shaB, "name: good\nruns:\n  using: composite\n  steps:\n    - uses: acme/deeper@v1\n")
	f.commit("acme", "deeper", "v1", shaC)
	f.file("acme", "deeper", "action.yml", shaC, plainAction)

	c := newTestClient(t, f.ServeHTTP)
	workflows := map[string][]byte{
		".github/workflows/ci.yml": []byte("name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: acme/gone@v1\n      - uses: acme/good@v1\n"),
	}
	res, err := c.ResolveTransitive(ctx(), transitiveRepo(), workflows, DefaultTransitiveLimits())
	if err != nil {
		t.Fatal(err)
	}
	if res.Complete {
		t.Fatal("an unreadable reference must make the traversal incomplete")
	}
	if !strings.Contains(res.Reason, "acme/gone") {
		t.Errorf("reason = %q, want it to name the file that could not be read", res.Reason)
	}
	// The branch that could be resolved still is.
	deeper := findNode(t, res, "acme/deeper")
	if deeper.Depth != 2 {
		t.Errorf("deeper depth = %d, want 2", deeper.Depth)
	}
}

func TestResolveTransitive_SubPathActionIsReadFromItsOwnDirectory(t *testing.T) {
	f := newFakeAPI()
	f.commit("acme", "tool", "v1", shaA)
	f.file("acme", "tool", "sub/action.yml", shaA, plainAction)

	c := newTestClient(t, f.ServeHTTP)
	res, err := c.ResolveTransitive(ctx(), transitiveRepo(), workflowUsing("acme/tool/sub@v1"),
		DefaultTransitiveLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Complete {
		t.Fatalf("traversal must be complete, got %q", res.Reason)
	}
	node := findNode(t, res, "acme/tool")
	if node.Path != "sub/action.yml" {
		t.Errorf("path = %q, want sub/action.yml", node.Path)
	}
	var fetched bool
	for _, req := range f.requests() {
		if strings.Contains(req, "/contents/sub/action.yml") {
			fetched = true
		}
	}
	if !fetched {
		t.Errorf("the sub-path action.yml was not fetched: %v", f.requests())
	}
}

func TestResolveTransitive_DefaultLimitsAreTheDocumentedOnes(t *testing.T) {
	l := DefaultTransitiveLimits()
	if l.MaxDepth != 12 || l.MaxStructures != 5000 || l.MaxMetadataBytes != 8<<20 ||
		l.MaxRequests != 500 || l.MaxResponseBytes != 2<<20 || l.MaxFileBytes != 1<<20 ||
		l.RequestTimeout.Seconds() != 15 {
		t.Errorf("limits = %+v, want the documented budgets", l)
	}
}
