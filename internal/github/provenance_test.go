package github

import (
	"net/http"
	"strings"
	"sync"
	"testing"
)

// ── fake GitHub API ─────────────────────────────────────────────────────

// Commits used by the fixtures.
const (
	provOnBranch = "1111111111111111111111111111111111111111"
	provHead     = "2222222222222222222222222222222222222222"
	provOrphan   = "3333333333333333333333333333333333333333"
	provAhead    = "4444444444444444444444444444444444444444"
)

// provAPI serves the three endpoints a provenance check uses: the
// repository (for its default branch), the commit lookup and the
// comparison.
type provAPI struct {
	mu       sync.Mutex
	branches map[string]string // "owner/repo" -> default branch
	commits  map[string]string // "owner/repo@ref" -> commit SHA
	statuses map[string]string // "owner/repo@base...head" -> comparison status
	log      []string          // every request, as a path

	// branchList and tagSHAs are the published refs. When branchList is
	// unset for a repo, it defaults to the default branch alone, so the
	// older fixtures do not have to register one.
	branchList map[string][]string
	tagSHAs    map[string][]string

	// repoStatus, commitStatus and compareStatus force a status code
	// on the matching endpoint (0 = no forced failure).
	repoStatus    int
	commitStatus  int
	compareStatus int

	// rateLimit answers every request with a rate-limited 403.
	rateLimit bool
}

func newProvAPI() *provAPI {
	return &provAPI{
		branches:   map[string]string{},
		commits:    map[string]string{},
		statuses:   map[string]string{},
		branchList: map[string][]string{},
		tagSHAs:    map[string][]string{},
	}
}

// requests returns every request the client made.
func (f *provAPI) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.log...)
}

func (f *provAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log = append(f.log, r.URL.Path)

	if f.rateLimit {
		// A rate-limited 403: go-github reports this as a
		// RateLimitError, so the client waits it out and retries.
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", "0")
		writeJSON(w, 403, map[string]any{"message": "API rate limit exceeded"})
		return
	}

	rest := strings.TrimPrefix(r.URL.Path, "/repos/")
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) < 2 {
		writeJSON(w, 404, map[string]any{"message": "not found"})
		return
	}
	owner, name := parts[0], parts[1]
	key := owner + "/" + name

	switch {
	case len(parts) == 2: // the repository itself
		if f.repoStatus != 0 {
			writeJSON(w, f.repoStatus, map[string]any{"message": "boom"})
			return
		}
		branch, ok := f.branches[key]
		if !ok {
			writeJSON(w, 404, map[string]any{"message": "no such repository"})
			return
		}
		writeJSON(w, 200, map[string]any{
			"full_name": key, "name": name,
			"owner":          map[string]any{"login": owner},
			"default_branch": branch,
		})
	case strings.HasPrefix(parts[2], "commits/"):
		if f.commitStatus != 0 {
			writeJSON(w, f.commitStatus, map[string]any{"message": "boom"})
			return
		}
		ref := strings.TrimPrefix(parts[2], "commits/")
		sha, ok := f.commits[key+"@"+ref]
		if !ok {
			writeJSON(w, 404, map[string]any{"message": "no such commit"})
			return
		}
		writeJSON(w, 200, map[string]any{"sha": sha})
	case strings.HasPrefix(parts[2], "compare/"):
		if f.compareStatus != 0 {
			writeJSON(w, f.compareStatus, map[string]any{"message": "boom"})
			return
		}
		spec := strings.TrimPrefix(parts[2], "compare/")
		status, ok := f.statuses[key+"@"+spec]
		if !ok {
			writeJSON(w, 404, map[string]any{"message": "no such comparison"})
			return
		}
		writeJSON(w, 200, map[string]any{
			"status": status, "ahead_by": 0, "behind_by": 0, "total_commits": 1,
		})
	case parts[2] == "branches":
		names, ok := f.branchList[key]
		if !ok {
			// The older fixtures register only the default branch.
			if def, ok := f.branches[key]; ok {
				names = []string{def}
			}
		}
		out := make([]any, 0, len(names))
		for _, n := range names {
			out = append(out, map[string]any{"name": n})
		}
		writeJSON(w, 200, out)
	case parts[2] == "tags":
		shas := f.tagSHAs[key]
		out := make([]any, 0, len(shas))
		for _, s := range shas {
			out = append(out, map[string]any{
				"name": s[:7], "commit": map[string]any{"sha": s},
			})
		}
		writeJSON(w, 200, out)
	default:
		writeJSON(w, 404, map[string]any{"message": "not found"})
	}
}

// provRepo is a repository whose default branch is "main".
func provRepo(api *provAPI) {
	api.branches["acme/action"] = "main"
}

// ── checks ─────────────────────────────────────────────────────────────

func TestVerifyProvenance_CommitOnTheDefaultBranchIsTrusted(t *testing.T) {
	api := newProvAPI()
	provRepo(api)
	api.commits["acme/action@"+provOnBranch] = provOnBranch
	// base = the candidate, head = the default branch: "ahead" means
	// the branch is ahead of the candidate, i.e. the candidate is on
	// the branch's history.
	api.statuses["acme/action@"+provOnBranch+"...main"] = "ahead"

	c := newTestClient(t, api.ServeHTTP)
	p := c.VerifyProvenance(ctx(), "acme/action", provOnBranch)

	if !p.Checked {
		t.Fatalf("the check must have run, got %+v", p)
	}
	if !p.Trusted {
		t.Errorf("a commit on the default branch must be trusted, got %+v", p)
	}
	if p.CommitSHA != provOnBranch {
		t.Errorf("commit = %q, want %q", p.CommitSHA, provOnBranch)
	}
	if p.Reason != "" {
		t.Errorf("a trusted ref must carry no reason, got %q", p.Reason)
	}
	// The comparison must be base=candidate, head=default branch.
	want := "/repos/acme/action/compare/" + provOnBranch + "...main"
	var compared bool
	for _, req := range api.requests() {
		if req == want {
			compared = true
		}
	}
	if !compared {
		t.Errorf("the comparison %q was never made, requests: %v", want, api.requests())
	}
}

func TestVerifyProvenance_CommitIdenticalToTheBranchHeadIsTrusted(t *testing.T) {
	api := newProvAPI()
	provRepo(api)
	api.commits["acme/action@"+provHead] = provHead
	api.statuses["acme/action@"+provHead+"...main"] = "identical"

	c := newTestClient(t, api.ServeHTTP)
	p := c.VerifyProvenance(ctx(), "acme/action", provHead)

	if !p.Checked {
		t.Fatalf("the check must have run, got %+v", p)
	}
	if !p.Trusted {
		t.Errorf("the head of the default branch must be trusted, got %+v", p)
	}
}

func TestVerifyProvenance_OrphanCommitIsNotTrusted(t *testing.T) {
	api := newProvAPI()
	provRepo(api)
	api.commits["acme/action@"+provOrphan] = provOrphan
	// "diverged": the commit shares no history with the default
	// branch — a force-pushed or orphan commit.
	api.statuses["acme/action@"+provOrphan+"...main"] = "diverged"

	c := newTestClient(t, api.ServeHTTP)
	p := c.VerifyProvenance(ctx(), "acme/action", provOrphan)

	if !p.Checked {
		t.Fatalf("the check must have run, got %+v", p)
	}
	if p.Trusted {
		t.Errorf("an orphan commit must not be trusted, got %+v", p)
	}
	if p.Reason == "" {
		t.Error("an untrusted commit must say why")
	}
	if !strings.Contains(p.Reason, provOrphan) {
		t.Errorf("reason = %q, want it to name the commit", p.Reason)
	}
}

func TestVerifyProvenance_CommitAheadOfTheBranchIsNotTrusted(t *testing.T) {
	api := newProvAPI()
	provRepo(api)
	api.commits["acme/action@"+provAhead] = provAhead
	// "behind": the default branch is behind the candidate, so the
	// candidate contains the branch head but is not on the branch.
	api.statuses["acme/action@"+provAhead+"...main"] = "behind"

	c := newTestClient(t, api.ServeHTTP)
	p := c.VerifyProvenance(ctx(), "acme/action", provAhead)

	if !p.Checked {
		t.Fatalf("the check must have run, got %+v", p)
	}
	if p.Trusted {
		t.Errorf("a commit that is not on the default branch must not be trusted, got %+v", p)
	}
}

func TestVerifyProvenance_UnresolvableRefIsNotChecked(t *testing.T) {
	api := newProvAPI()
	provRepo(api)
	// No commit is registered: the lookup answers 404.

	c := newTestClient(t, api.ServeHTTP)
	p := c.VerifyProvenance(ctx(), "acme/action", provOrphan)

	if p.Checked {
		t.Errorf("a ref that cannot be resolved was not checked, got %+v", p)
	}
	if p.Trusted {
		t.Errorf("a ref that cannot be resolved must not be trusted, got %+v", p)
	}
	if !strings.Contains(p.Reason, "could not check") {
		t.Errorf("reason = %q, want it to say the check could not be made", p.Reason)
	}
}

func TestVerifyProvenance_RateLimitedAPIIsNotChecked(t *testing.T) {
	api := newProvAPI()
	api.rateLimit = true

	// The client waits out the rate limit and retries, so this test
	// takes a few seconds.
	c := newTestClient(t, api.ServeHTTP)
	p := c.VerifyProvenance(ctx(), "acme/action", provOnBranch)

	if p.Checked {
		t.Errorf("a rate-limited API must not report a checked result, got %+v", p)
	}
	if p.Trusted {
		t.Errorf("a rate-limited API must never report a trusted commit, got %+v", p)
	}
	if !strings.Contains(p.Reason, "could not check") {
		t.Errorf("reason = %q, want it to say the check could not be made", p.Reason)
	}
}

func TestVerifyProvenance_DefaultBranchLookupFailureIsNotChecked(t *testing.T) {
	api := newProvAPI()
	api.repoStatus = 500

	c := newTestClient(t, api.ServeHTTP)
	p := c.VerifyProvenance(ctx(), "acme/action", provOnBranch)

	if p.Checked {
		t.Errorf("a failed default branch lookup must not report a checked result, got %+v", p)
	}
	if p.Trusted {
		t.Errorf("a failed default branch lookup must never report a trusted commit, got %+v", p)
	}
	if !strings.Contains(p.Reason, "could not check") {
		t.Errorf("reason = %q, want it to say the check could not be made", p.Reason)
	}
}

func TestVerifyProvenance_UnknownComparisonStatusIsNotChecked(t *testing.T) {
	api := newProvAPI()
	provRepo(api)
	api.commits["acme/action@"+provOnBranch] = provOnBranch
	api.statuses["acme/action@"+provOnBranch+"...main"] = "something-else"

	c := newTestClient(t, api.ServeHTTP)
	p := c.VerifyProvenance(ctx(), "acme/action", provOnBranch)

	// An answer the tool does not understand is not a verdict.
	if p.Checked {
		t.Errorf("an unknown comparison status must not report a checked result, got %+v", p)
	}
	if p.Trusted {
		t.Errorf("an unknown comparison status must never report a trusted commit, got %+v", p)
	}
}

func TestVerifyProvenance_MalformedRepoIsNotChecked(t *testing.T) {
	api := newProvAPI()

	c := newTestClient(t, api.ServeHTTP)
	p := c.VerifyProvenance(ctx(), "no-slash", provOnBranch)

	if p.Checked || p.Trusted {
		t.Errorf("a malformed repository must not be checked, got %+v", p)
	}
	if len(api.requests()) != 0 {
		t.Errorf("a malformed repository must not reach the API, requests: %v", api.requests())
	}
}

func TestVerifyProvenance_EmptyRefIsNotChecked(t *testing.T) {
	api := newProvAPI()

	c := newTestClient(t, api.ServeHTTP)
	p := c.VerifyProvenance(ctx(), "acme/action", "")

	if p.Checked || p.Trusted {
		t.Errorf("an empty ref must not be checked, got %+v", p)
	}
	if len(api.requests()) != 0 {
		t.Errorf("an empty ref must not reach the API, requests: %v", api.requests())
	}
}

// ── caching ────────────────────────────────────────────────────────────

func TestVerifyProvenance_CachesResults(t *testing.T) {
	api := newProvAPI()
	provRepo(api)
	api.commits["acme/action@"+provOnBranch] = provOnBranch
	api.statuses["acme/action@"+provOnBranch+"...main"] = "ahead"

	c := newTestClient(t, api.ServeHTTP)
	for i := 0; i < 3; i++ {
		if p := c.VerifyProvenance(ctx(), "acme/action", provOnBranch); !p.Trusted {
			t.Fatalf("call %d: got %+v, want a trusted result", i, p)
		}
	}
	// Three calls, one upstream request each for the commit, the
	// repository and the comparison.
	if n := len(api.requests()); n != 3 {
		t.Errorf("server hits = %d (%v), want 3 (one per endpoint)", n, api.requests())
	}
}

func TestVerifyProvenance_CachesFailures(t *testing.T) {
	api := newProvAPI()
	provRepo(api)
	// The commit cannot be resolved: the lookup answers 404.

	c := newTestClient(t, api.ServeHTTP)
	for i := 0; i < 3; i++ {
		if p := c.VerifyProvenance(ctx(), "acme/action", provOrphan); p.Checked {
			t.Fatalf("call %d: got %+v, want an unchecked result", i, p)
		}
	}
	if n := len(api.requests()); n != 1 {
		t.Errorf("server hits = %d (%v), want 1 (failed lookups must be cached too)", n, api.requests())
	}
}

func TestVerifyProvenance_ConcurrentCallsShareOneRequest(t *testing.T) {
	api := newProvAPI()
	provRepo(api)
	api.commits["acme/action@"+provOnBranch] = provOnBranch
	api.statuses["acme/action@"+provOnBranch+"...main"] = "ahead"

	c := newTestClient(t, api.ServeHTTP)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if p := c.VerifyProvenance(ctx(), "acme/action", provOnBranch); !p.Trusted {
				t.Errorf("got %+v, want a trusted result", p)
			}
		}()
	}
	wg.Wait()

	if n := len(api.requests()); n != 3 {
		t.Errorf("server hits = %d (%v), want 3 (single-flight)", n, api.requests())
	}
}

func TestVerifyProvenance_TwoClientsDoNotShareTheCache(t *testing.T) {
	first := newProvAPI()
	provRepo(first)
	first.commits["acme/action@"+provOnBranch] = provOnBranch
	first.statuses["acme/action@"+provOnBranch+"...main"] = "ahead"

	second := newProvAPI()
	provRepo(second)
	second.commits["acme/action@"+provOnBranch] = provOnBranch
	second.statuses["acme/action@"+provOnBranch+"...main"] = "diverged"

	c1 := newTestClient(t, first.ServeHTTP)
	c2 := newTestClient(t, second.ServeHTTP)

	if p := c1.VerifyProvenance(ctx(), "acme/action", provOnBranch); !p.Trusted {
		t.Errorf("the first client must report a trusted commit, got %+v", p)
	}
	// The second client talks to a different API: it must not be
	// served the first client's answer.
	if p := c2.VerifyProvenance(ctx(), "acme/action", provOnBranch); p.Trusted {
		t.Errorf("the second client must not reuse the first client's result, got %+v", p)
	}
}
