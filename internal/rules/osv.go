package rules

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// OSV.dev — query per action with exact version. The GitHub Actions
// ecosystem in OSV is keyed as "GitHubActions" with package name
// "owner/repo".

// OSVBatchSize limits per-request batch size (OSV recommends ≤ 1000, keep small).
const OSVBatchSize = 200

const osvQueryURL = "https://api.osv.dev/v1/query"

type OSVQuery struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version,omitempty"`
}

type OSVResponse struct {
	Vulns []OSVVuln `json:"vulns"`
}

type OSVVuln struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"` // often includes the GHSA id
	Summary  string   `json:"summary"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Type   string     `json:"type"`
			Events []OSVEvent `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

type OSVEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

var osvClient = &http.Client{Timeout: 20 * time.Second}

// QueryOSV asks OSV.dev whether actionRepo@versionRef has known vulns.
// version should be a bare semver ("4.1.1"); non-version refs return nothing.
func QueryOSV(ctx context.Context, actionRepo, version string) ([]OSVVuln, error) {
	if version == "" {
		return nil, nil
	}
	q := OSVQuery{
		Version: strings.TrimPrefix(version, "v"),
	}
	q.Package.Name = actionRepo
	q.Package.Ecosystem = "GitHubActions"

	body, err := json.Marshal(q)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", osvQueryURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := osvClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // no vulns
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv: HTTP %d", resp.StatusCode)
	}

	var r OSVResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	return r.Vulns, nil
}

// BatchOSV queries OSV for several actions at once using the batch endpoint.
// Returns repoRef -> vulns.
func QueryOSVBatch(ctx context.Context, queries map[string]string) (map[string][]OSVVuln, error) {
	if len(queries) == 0 {
		return nil, nil
	}

	type batchQuery struct {
		Query OSVQuery `json:"query"`
	}
	type batchReq struct {
		Queries []batchQuery `json:"queries"`
	}
	type batchResp struct {
		Results []OSVResponse `json:"results"`
	}

	bq := batchReq{}
	keys := make([]string, 0, len(queries))
	for repoRef, version := range queries {
		parts := strings.SplitN(repoRef, "@", 2)
		if len(parts) != 2 {
			continue
		}
		q := OSVQuery{Version: strings.TrimPrefix(version, "v")}
		q.Package.Name = parts[0]
		q.Package.Ecosystem = "GitHubActions"
		bq.Queries = append(bq.Queries, batchQuery{Query: q})
		keys = append(keys, repoRef)
	}

	body, err := json.Marshal(bq)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.osv.dev/v1/querybatch", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := osvClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var br batchResp
	if err := json.NewDecoder(resp.Body).Decode(&br); err != nil {
		return nil, err
	}

	out := map[string][]OSVVuln{}
	for i, res := range br.Results {
		if i < len(keys) && len(res.Vulns) > 0 {
			out[keys[i]] = res.Vulns
		}
	}
	return out, nil
}
