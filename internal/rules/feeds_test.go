package rules

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

// roundTripFunc lets tests serve canned HTTP responses without a server.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func fakeResp(status int, body string, req *http.Request) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
		Request:    req,
	}
}

func clientReturning(status int, body string) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return fakeResp(status, body, r), nil
	})}
}

// ── FetchMalicious ─────────────────────────────────────────────────────

func TestFetchMalicious_ArraySchema(t *testing.T) {
	body := `[{
		"repo": "tj-actions/changed-files",
		"refs": ["v41", "v42"],
		"advisory_id": "GHSA-xxxx-yyyy-zzzz",
		"description": "dumped runner memory"
	}]`
	got, err := FetchMalicious(context.Background(), clientReturning(200, body))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	e := got[0]
	if e.Repo != "tj-actions/changed-files" || e.AdvisoryID != "GHSA-xxxx-yyyy-zzzz" ||
		len(e.Refs) != 2 || e.Refs[0] != "v41" {
		t.Errorf("entry = %+v, fields not mapped from json tags", e)
	}
}

func TestFetchMalicious_MapSchema(t *testing.T) {
	body := `{"reviewdog/action-setup": {"refs": [], "description": "injected code"}}`
	got, err := FetchMalicious(context.Background(), clientReturning(200, body))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Repo != "reviewdog/action-setup" {
		t.Errorf("map-schema repo key not captured: %+v", got)
	}
	if got[0].Description != "injected code" {
		t.Errorf("description = %q", got[0].Description)
	}
}

func TestFetchMalicious_HTTPError(t *testing.T) {
	_, err := FetchMalicious(context.Background(), clientReturning(500, "boom"))
	if err == nil || !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("err = %v, want HTTP 500", err)
	}
}

func TestFetchMalicious_UnrecognizedSchema(t *testing.T) {
	_, err := FetchMalicious(context.Background(), clientReturning(200, `"just a string"`))
	if err == nil || !strings.Contains(err.Error(), "unrecognized schema") {
		t.Errorf("err = %v, want unrecognized schema", err)
	}
}

func TestFetchMalicious_EmptyArrayIsValid(t *testing.T) {
	got, err := FetchMalicious(context.Background(), clientReturning(200, `[]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("got %d entries, want 0", len(got))
	}
}

// ── FetchAdvisories ────────────────────────────────────────────────────

func TestFetchAdvisories_PaginatesUntilEmpty(t *testing.T) {
	var pages []string
	hc := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		page := r.URL.Query().Get("page")
		pages = append(pages, page)
		switch page {
		case "1":
			return fakeResp(200, `[{"ghsa_id":"GHSA-1","summary":"one"}]`, r), nil
		case "2":
			return fakeResp(200, `[{"ghsa_id":"GHSA-2","summary":"two"}]`, r), nil
		default:
			return fakeResp(200, `[]`, r), nil
		}
	})}

	got, err := FetchAdvisories(context.Background(), hc, "tok-123")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].GHSAID != "GHSA-1" || got[1].GHSAID != "GHSA-2" {
		t.Errorf("got %+v, want both pages concatenated in order", got)
	}
	if len(pages) != 3 {
		t.Errorf("requested pages %v, want 3 requests (stop on empty)", pages)
	}
}

func TestFetchAdvisories_SendsAuthAndAcceptHeaders(t *testing.T) {
	var auth, accept string
	hc := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		auth = r.Header.Get("Authorization")
		accept = r.Header.Get("Accept")
		return fakeResp(200, `[]`, r), nil
	})}

	if _, err := FetchAdvisories(context.Background(), hc, "secret"); err != nil {
		t.Fatal(err)
	}
	if auth != "Bearer secret" {
		t.Errorf("Authorization = %q, want \"Bearer secret\"", auth)
	}
	if accept != "application/vnd.github+json" {
		t.Errorf("Accept = %q", accept)
	}
}

func TestFetchAdvisories_OmitsAuthWithoutToken(t *testing.T) {
	var auth string
	hc := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		auth = r.Header.Get("Authorization")
		return fakeResp(200, `[]`, r), nil
	})}

	if _, err := FetchAdvisories(context.Background(), hc, ""); err != nil {
		t.Fatal(err)
	}
	if auth != "" {
		t.Errorf("Authorization = %q, want empty without token", auth)
	}
}

func TestFetchAdvisories_StopsAtPageCap(t *testing.T) {
	var requests int32
	hc := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		atomic.AddInt32(&requests, 1)
		// Never-empty feed: the 50-page safety cap must stop the loop.
		return fakeResp(200, `[{"ghsa_id":"GHSA-x","summary":"s"}]`, r), nil
	})}

	got, err := FetchAdvisories(context.Background(), hc, "tok")
	if err != nil {
		t.Fatal(err)
	}
	n := atomic.LoadInt32(&requests)
	if n != 50 {
		t.Errorf("requests = %d, want exactly 50 (page cap)", n)
	}
	if len(got) != 50 {
		t.Errorf("advisories = %d, want 50", len(got))
	}
}

func TestFetchAdvisories_DecodeErrorSurfaces(t *testing.T) {
	hc := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return fakeResp(200, `not json`, r), nil
	})}
	if _, err := FetchAdvisories(context.Background(), hc, "tok"); err == nil {
		t.Error("invalid JSON body must produce an error")
	}
}

// ── default fallback lists ─────────────────────────────────────────────

func TestBuiltinFallbackListsAreSane(t *testing.T) {
	if len(DefaultMalicious) == 0 {
		t.Fatal("DefaultMalicious must never be empty")
	}
	seen := map[string]bool{}
	for _, e := range DefaultMalicious {
		if !strings.Contains(e.Repo, "/") {
			t.Errorf("DefaultMalicious repo %q must be owner/repo", e.Repo)
		}
		if e.Description == "" {
			t.Errorf("DefaultMalicious %q missing description", e.Repo)
		}
		if seen[e.Repo] {
			t.Errorf("duplicate DefaultMalicious entry: %q", e.Repo)
		}
		seen[e.Repo] = true
	}
	if len(DefaultVulnerable) == 0 {
		t.Fatal("DefaultVulnerable must never be empty")
	}
	for key, rule := range DefaultVulnerable {
		if strings.Count(key, "@") != 1 {
			t.Errorf("DefaultVulnerable key %q must be repo@version", key)
		}
		if rule.Reason == "" {
			t.Errorf("DefaultVulnerable %q missing reason", key)
		}
		if rule.Fix == "" {
			t.Errorf("DefaultVulnerable %q missing fix", key)
		}
	}
}
