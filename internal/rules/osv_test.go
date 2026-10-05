package rules

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// withOSVTransport swaps the package-level osvClient for a stubbed
// transport for the duration of one test.
func withOSVTransport(t *testing.T, rt http.RoundTripper) {
	t.Helper()
	orig := osvClient
	osvClient = &http.Client{Transport: rt}
	t.Cleanup(func() { osvClient = orig })
}

func TestQueryOSV_Success(t *testing.T) {
	var gotBody []byte
	var gotPath, gotMethod, gotCT string
	withOSVTransport(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotCT = r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		return fakeResp(200, `{"vulns":[{"id":"GHSA-1","summary":"RCE"}]}`, r), nil
	}))

	vulns, err := QueryOSV(context.Background(), "actions/checkout", "v4.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(vulns) != 1 || vulns[0].ID != "GHSA-1" {
		t.Fatalf("vulns = %+v", vulns)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/query" {
		t.Errorf("request = %s %s, want POST /v1/query", gotMethod, gotPath)
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q", gotCT)
	}

	var q OSVQuery
	if err := json.Unmarshal(gotBody, &q); err != nil {
		t.Fatal(err)
	}
	if q.Package.Name != "actions/checkout" || q.Package.Ecosystem != "GitHubActions" {
		t.Errorf("package = %+v", q.Package)
	}
	if q.Version != "4.1.1" {
		t.Errorf("version = %q, want v-prefix stripped", q.Version)
	}
}

func TestQueryOSV_EmptyVersionSkipsRequest(t *testing.T) {
	withOSVTransport(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		t.Fatal("no request must be sent for an empty version")
		return nil, nil
	}))

	vulns, err := QueryOSV(context.Background(), "actions/checkout", "")
	if err != nil || vulns != nil {
		t.Errorf("got (%v, %v), want (nil, nil)", vulns, err)
	}
}

func TestQueryOSV_NotFoundMeansNoVulns(t *testing.T) {
	withOSVTransport(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return fakeResp(404, ``, r), nil
	}))

	vulns, err := QueryOSV(context.Background(), "actions/checkout", "v1.0.0")
	if err != nil || vulns != nil {
		t.Errorf("got (%v, %v), want (nil, nil)", vulns, err)
	}
}

func TestQueryOSV_ServerError(t *testing.T) {
	withOSVTransport(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return fakeResp(503, `unavailable`, r), nil
	}))

	if _, err := QueryOSV(context.Background(), "actions/checkout", "v1.0.0"); err == nil ||
		!strings.Contains(err.Error(), "HTTP 503") {
		t.Errorf("err = %v, want HTTP 503", err)
	}
}

func TestQueryOSV_CanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	vulns, err := QueryOSV(ctx, "actions/checkout", "v1.0.0")
	if err == nil {
		t.Fatal("canceled context must error")
	}
	if vulns != nil {
		t.Errorf("vulns = %v, want nil", vulns)
	}
}

func TestQueryOSVBatch(t *testing.T) {
	withOSVTransport(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/v1/querybatch" {
			t.Errorf("path = %s, want /v1/querybatch", r.URL.Path)
		}
		var req struct {
			Queries []struct {
				Query OSVQuery `json:"query"`
			} `json:"queries"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if len(req.Queries) != 2 {
			t.Errorf("got %d queries, want 2", len(req.Queries))
		}
		// Positional results: return one hit and one clean result.
		return fakeResp(200,
			`{"results":[{"vulns":[{"id":"GHSA-a"}]},{"vulns":[]}]}`, r), nil
	}))

	out, err := QueryOSVBatch(context.Background(), map[string]string{
		"actions/checkout@k1": "4.1.1",
		"actions/cache@k2":    "3.0.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d results with vulns, want exactly 1 (the clean one dropped): %+v",
			len(out), out)
	}
	// Map iteration order is random; identify which key hit by value.
	for k, v := range out {
		if k != "actions/checkout@k1" && k != "actions/cache@k2" {
			t.Errorf("unexpected key %q", k)
		}
		if len(v) != 1 || v[0].ID != "GHSA-a" {
			t.Errorf("vulns = %+v", v)
		}
	}
}

func TestQueryOSVBatch_EmptyInput(t *testing.T) {
	withOSVTransport(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		t.Fatal("no request must be sent for empty input")
		return nil, nil
	}))

	out, err := QueryOSVBatch(context.Background(), nil)
	if err != nil || out != nil {
		t.Errorf("got (%v, %v), want (nil, nil)", out, err)
	}
}

func TestQueryOSVBatch_SkipsMalformedKeys(t *testing.T) {
	withOSVTransport(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		var req struct {
			Queries []struct {
				Query OSVQuery `json:"query"`
			} `json:"queries"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if len(req.Queries) != 1 {
			t.Errorf("got %d queries, want 1 (malformed key dropped)", len(req.Queries))
		}
		return fakeResp(200, `{"results":[{"vulns":[]}]}`, r), nil
	}))

	_, err := QueryOSVBatch(context.Background(), map[string]string{
		"no-at-sign-key":     "1.0.0",
		"actions/checkout@k": "4.1.1",
	})
	if err != nil {
		t.Fatal(err)
	}
}
