package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// ── StepSecurity compromised-actions ──

const stepSecurityURL = "https://raw.githubusercontent.com/step-security/secure-repo/main/compromised-actions/compromised-actions.json"

type CompromisedEntry struct {
	Repo        string   `json:"repo"`
	Refs        []string `json:"refs"`
	AdvisoryID  string   `json:"advisory_id"`
	Description string   `json:"description"`
}

func FetchMalicious(ctx context.Context, hc *http.Client) ([]CompromisedEntry, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", stepSecurityURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("stepsecurity feed: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var entries []CompromisedEntry
	if err := json.Unmarshal(body, &entries); err == nil {
		return entries, nil
	}
	var obj map[string]CompromisedEntry
	if err := json.Unmarshal(body, &obj); err == nil {
		for repo, e := range obj {
			e.Repo = repo
			entries = append(entries, e)
		}
		return entries, nil
	}
	return nil, fmt.Errorf("stepsecurity feed: unrecognized schema")
}

// ── GitHub Security Advisories (ecosystem=actions) ──

const advisoriesURL = "https://api.github.com/advisories?type=reviewed&ecosystem=actions&per_page=100"

type GHAdvisory struct {
	GHSAID          string `json:"ghsa_id"`
	Summary         string `json:"summary"`
	Severity        string `json:"severity"`
	Vulnerabilities []struct {
		Package struct {
			Name string `json:"name"`
		} `json:"package"`
		VulnerableVersionRange string `json:"vulnerable_version_range"`
		PatchedVersions        string `json:"patched_versions"`
	} `json:"vulnerabilities"`
}

func FetchAdvisories(ctx context.Context, hc *http.Client, token string) ([]GHAdvisory, error) {
	var all []GHAdvisory
	page := 1
	for {
		url := fmt.Sprintf("%s&page=%d", advisoriesURL, page)
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := hc.Do(req)
		if err != nil {
			return nil, err
		}
		var batch []GHAdvisory
		err = json.NewDecoder(resp.Body).Decode(&batch)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if len(batch) == 0 {
			break
		}
		all = append(all, batch...)
		page++
		if page > 50 {
			break
		}
	}
	return all, nil
}

// ── Built-in fallbacks ──

var DefaultMalicious = []CompromisedEntry{
	{Repo: "tj-actions/changed-files", Description: "Compromised Mar 2025 (CVE-2025-30066) — dumped runner memory to attacker C2"},
	{Repo: "tj-actions/github-files", Description: "Same supply-chain compromise family"},
	{Repo: "reviewdog/action-setup", Description: "Compromised Mar 2025 (CVE-2025-30154) — injected malicious runner code"},
}

var DefaultVulnerable = map[string]string{
	"actions/checkout@v2":          "EOL — upgrade to v4",
	"actions/cache@v2":             "EOL — upgrade to v4",
	"actions/upload-artifact@v2":   "Deprecated Dec 2024 — upgrade to v4",
	"actions/upload-artifact@v3":   "Deprecated Dec 2024 — upgrade to v4",
	"actions/download-artifact@v2": "Deprecated Dec 2024 — upgrade to v4",
	"actions/download-artifact@v3": "Deprecated Dec 2024 — upgrade to v4",
}

func normalizeRepo(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
