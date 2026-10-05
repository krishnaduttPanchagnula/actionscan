package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func ctx() context.Context { return context.Background() }

// newTestClient starts a fake GitHub API server and points a Client at it.
func newTestClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	c := New("test-token")
	base, err := url.Parse(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	c.gh.BaseURL = base
	return c
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// ── ListRepos ──────────────────────────────────────────────────────────

func TestListRepos_OrgPaginationAndForkFiltering(t *testing.T) {
	var requests int32
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		if r.URL.Path != "/orgs/acme/repos" {
			t.Errorf("path = %q, want /orgs/acme/repos", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("Authorization = %q, want Bearer test-token", got)
		}
		if r.URL.Query().Get("type") != "all" {
			t.Errorf("type = %q, want all", r.URL.Query().Get("type"))
		}

		switch r.URL.Query().Get("page") {
		case "", "1":
			w.Header().Set("Link",
				`<https://api.github.com/orgs/acme/repos?per_page=100&page=2>; rel="next"`)
			writeJSON(w, 200, []map[string]any{
				{"full_name": "acme/one", "name": "one",
					"owner":          map[string]any{"login": "acme"},
					"default_branch": "main", "private": false},
			})
		case "2":
			writeJSON(w, 200, []map[string]any{
				{"full_name": "acme/forked", "name": "forked", "fork": true,
					"owner": map[string]any{"login": "acme"}, "default_branch": "main"},
				{"full_name": "acme/two", "name": "two",
					"owner":          map[string]any{"login": "acme"},
					"default_branch": "develop", "private": true},
			})
		default:
			writeJSON(w, 200, []map[string]any{})
		}
	})

	repos, err := c.ListRepos(ctx(), "acme", "")
	if err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&requests) != 2 {
		t.Errorf("requests = %d, want 2 pages", requests)
	}
	// The fork must be filtered out.
	if len(repos) != 2 {
		t.Fatalf("got %d repos (%+v), want 2 non-fork repos", len(repos), repos)
	}
	if repos[0].FullName != "acme/one" || repos[0].Owner != "acme" || repos[0].Name != "one" {
		t.Errorf("repos[0] = %+v", repos[0])
	}
	if repos[1].FullName != "acme/two" || repos[1].DefaultBranch != "develop" || !repos[1].Private {
		t.Errorf("repos[1] = %+v", repos[1])
	}
}

func TestListRepos_UserListing(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/users/bob/repos" {
			t.Errorf("path = %q, want /users/bob/repos", r.URL.Path)
		}
		if r.URL.Query().Get("type") != "owner" {
			t.Errorf("type = %q, want owner", r.URL.Query().Get("type"))
		}
		writeJSON(w, 200, []map[string]any{
			{"full_name": "bob/app", "name": "app",
				"owner": map[string]any{"login": "bob"}, "default_branch": "main"},
		})
	})

	repos, err := c.ListRepos(ctx(), "", "bob")
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 1 || repos[0].FullName != "bob/app" {
		t.Errorf("repos = %+v", repos)
	}
}

func TestListRepos_DefaultUsesAffiliation(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/user/repos" {
			t.Errorf("path = %q, want /user/repos", r.URL.Path)
		}
		aff := r.URL.Query().Get("affiliation")
		if !strings.Contains(aff, "owner") || !strings.Contains(aff, "collaborator") ||
			!strings.Contains(aff, "organization_member") {
			t.Errorf("affiliation = %q, want owner,collaborator,organization_member", aff)
		}
		writeJSON(w, 200, []map[string]any{})
	})

	repos, err := c.ListRepos(ctx(), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 0 {
		t.Errorf("repos = %+v, want empty", repos)
	}
}

func TestListRepos_ErrorPropagates(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 500, map[string]any{"message": "boom"})
	})

	if _, err := c.ListRepos(ctx(), "acme", ""); err == nil {
		t.Fatal("HTTP 500 must surface as an error")
	}
}

// ── ListWorkflows ──────────────────────────────────────────────────────

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// wrapBase64 mimics GitHub's habit of line-wrapping base64 content.
func wrapBase64(s string) string {
	enc := base64.StdEncoding.EncodeToString([]byte(s))
	var sb strings.Builder
	for i, r := range enc {
		if i > 0 && i%60 == 0 {
			sb.WriteByte('\n')
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

func TestListWorkflows_FiltersDecodesAndToleratesFailures(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/repos/acme/r/git/trees/main":
			if r.URL.Query().Get("recursive") != "1" {
				t.Errorf("recursive = %q, want 1", r.URL.Query().Get("recursive"))
			}
			writeJSON(w, 200, map[string]any{
				"sha": "abc", "truncated": false,
				"tree": []map[string]any{
					// Match: line-wrapped base64 content.
					{"path": ".github/workflows/ci.yml", "mode": "100644", "type": "blob", "sha": "1"},
					// Match: second extension.
					{"path": ".github/workflows/deploy.yaml", "mode": "100644", "type": "blob", "sha": "2"},
					// Skip: wrong extension.
					{"path": ".github/workflows/notes.txt", "mode": "100644", "type": "blob", "sha": "3"},
					// Skip: not under .github/workflows.
					{"path": "docs/workflows-guide.md", "mode": "100644", "type": "blob", "sha": "4"},
					{"path": "src/main.go", "mode": "100644", "type": "blob", "sha": "5"},
					// Match by prefix but broken content: decode fails, skipped.
					{"path": ".github/workflows/broken.yml", "mode": "100644", "type": "blob", "sha": "6"},
				},
			})
		case r.URL.Path == "/repos/acme/r/contents/.github/workflows/ci.yml":
			writeJSON(w, 200, map[string]any{
				"type": "file", "encoding": "base64",
				"content": wrapBase64("name: CI\non: push\n"),
			})
		case r.URL.Path == "/repos/acme/r/contents/.github/workflows/deploy.yaml":
			writeJSON(w, 200, map[string]any{
				"type": "file", "encoding": "base64",
				"content": b64("name: Deploy\n"),
			})
		case r.URL.Path == "/repos/acme/r/contents/.github/workflows/broken.yml":
			writeJSON(w, 200, map[string]any{
				"type": "file", "encoding": "base64",
				"content": "!!!not-base64!!!",
			})
		default:
			writeJSON(w, 404, map[string]any{"message": "not found"})
		}
	})

	repo := Repo{Owner: "acme", Name: "r", DefaultBranch: "main"}
	got, err := c.ListWorkflows(ctx(), repo)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d workflows (%v), want 2 (wrapped base64 must decode)", len(got), keys(got))
	}
	if string(got["ci.yml"]) != "name: CI\non: push\n" {
		t.Errorf("ci.yml content = %q, want decoded original (line-wrapped base64)",
			string(got["ci.yml"]))
	}
	if string(got["deploy.yaml"]) != "name: Deploy\n" {
		t.Errorf("deploy.yaml content = %q", string(got["deploy.yaml"]))
	}
}

func TestListWorkflows_TreeErrorPropagates(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 404, map[string]any{"message": "no such ref"})
	})

	repo := Repo{Owner: "acme", Name: "r", DefaultBranch: "missing"}
	if _, err := c.ListWorkflows(ctx(), repo); err == nil {
		t.Fatal("tree fetch failure must propagate")
	}
}

func TestListWorkflows_NoWorkflows(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{
			"sha": "abc", "truncated": false,
			"tree": []map[string]any{
				{"path": "README.md", "mode": "100644", "type": "blob", "sha": "1"},
			},
		})
	})

	got, err := c.ListWorkflows(ctx(), Repo{Owner: "acme", Name: "r", DefaultBranch: "main"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("got %v, want empty map", got)
	}
}

// ── LatestTag ──────────────────────────────────────────────────────────

func TestLatestTag_CachesSuccessfulLookups(t *testing.T) {
	var hits int32
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if r.URL.Path != "/repos/tj-actions/changed-files/releases/latest" {
			t.Errorf("path = %q", r.URL.Path)
		}
		writeJSON(w, 200, map[string]any{"tag_name": "v41"})
	})

	for i := 0; i < 3; i++ {
		if got := c.LatestTag(ctx(), "tj-actions/changed-files"); got != "v41" {
			t.Fatalf("call %d: got %q, want v41", i, got)
		}
	}
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Errorf("server hits = %d, want 1 (in-memory cache)", n)
	}
}

func TestLatestTag_CachesFailures(t *testing.T) {
	var hits int32
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		writeJSON(w, 404, map[string]any{"message": "no releases"})
	})

	for i := 0; i < 3; i++ {
		if got := c.LatestTag(ctx(), "some/action"); got != "" {
			t.Fatalf("call %d: got %q, want empty", i, got)
		}
	}
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Errorf("server hits = %d, want 1 (failed lookups must be cached too)", n)
	}
}

func TestLatestTag_MalformedRepoShortCircuits(t *testing.T) {
	var hits int32
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		writeJSON(w, 200, map[string]any{"tag_name": "v1"})
	})

	if got := c.LatestTag(ctx(), "no-slash"); got != "" {
		t.Errorf("got %q, want empty for repo without owner/", got)
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Errorf("server hits = %d, want 0", n)
	}
}

func TestLatestTag_ConcurrentSingleFetch(t *testing.T) {
	var hits int32
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		writeJSON(w, 200, map[string]any{"tag_name": "v41"})
	})

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got := c.LatestTag(ctx(), "tj-actions/changed-files"); got != "v41" {
				t.Errorf("got %q, want v41", got)
			}
		}()
	}
	wg.Wait()

	// Single-flight: 50 concurrent callers share one upstream request.
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Errorf("server hits = %d for 50 concurrent callers, want 1", n)
	}
}

// ── ResolveSHA ─────────────────────────────────────────────────────────

func TestResolveSHA_ExpandsShortSHAToFull(t *testing.T) {
	full := "0123456789abcdef0123456789abcdef01234567"
	var hits int32
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if r.URL.Path != "/repos/actions/checkout/commits/abc1234" {
			t.Errorf("path = %q", r.URL.Path)
		}
		writeJSON(w, 200, map[string]any{"sha": full})
	})

	for i := 0; i < 3; i++ {
		if got := c.ResolveSHA(ctx(), "actions/checkout", "abc1234"); got != full {
			t.Fatalf("call %d: got %q, want %q", i, got, full)
		}
	}
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Errorf("server hits = %d, want 1 (in-memory cache)", n)
	}
}

func TestResolveSHA_FailureReturnsEmptyAndCaches(t *testing.T) {
	var hits int32
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		writeJSON(w, 404, map[string]any{"message": "No commit found"})
	})

	for i := 0; i < 3; i++ {
		if got := c.ResolveSHA(ctx(), "actions/checkout", "deadbeef"); got != "" {
			t.Fatalf("call %d: got %q, want empty", i, got)
		}
	}
	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Errorf("server hits = %d, want 1 (failed lookups must be cached too)", n)
	}
}

func TestResolveSHA_MalformedRepoShortCircuits(t *testing.T) {
	var hits int32
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		writeJSON(w, 200, map[string]any{"sha": "irrelevant"})
	})

	if got := c.ResolveSHA(ctx(), "no-slash", "abc1234"); got != "" {
		t.Errorf("got %q, want empty for repo without owner/", got)
	}
	if got := c.ResolveSHA(ctx(), "actions/checkout", ""); got != "" {
		t.Errorf("got %q, want empty for empty short sha", got)
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Errorf("server hits = %d, want 0", n)
	}
}

func TestResolveSHA_ConcurrentSingleFetch(t *testing.T) {
	full := "fedcba9876543210fedcba9876543210fedcba98"
	var hits int32
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		writeJSON(w, 200, map[string]any{"sha": full})
	})

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got := c.ResolveSHA(ctx(), "actions/checkout", "abc1234"); got != full {
				t.Errorf("got %q, want %q", got, full)
			}
		}()
	}
	wg.Wait()

	if n := atomic.LoadInt32(&hits); n != 1 {
		t.Errorf("server hits = %d for 50 concurrent callers, want 1", n)
	}
}

// ── New ────────────────────────────────────────────────────────────────

func TestNew_WithoutTokenStillBuildsClient(t *testing.T) {
	c := New("")
	if c == nil || c.gh == nil {
		t.Fatal("New must return a usable client even without a token")
	}
	if c.latest == nil {
		t.Error("latest-tag cache must be initialized")
	}
}

func keys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
