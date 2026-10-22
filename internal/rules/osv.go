package rules

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	semver "github.com/Masterminds/semver/v3"
)

// OSV.dev — the GitHub Actions ecosystem is keyed as "GitHub Actions"
// (with a space) and the package name is "owner/repo".

// osvEcosystem is the OSV ecosystem name for GitHub Actions.
const osvEcosystem = "GitHub Actions"

const osvQueryURL = "https://api.osv.dev/v1/query"

// OSVQuery is the body of an OSV query. It carries no version: OSV does
// not answer version queries for this ecosystem, so the affected ranges
// are matched locally instead.
type OSVQuery struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
}

// OSVResponse is the body OSV answers with.
type OSVResponse struct {
	Vulns []OSVVuln `json:"vulns"`
}

// OSVVuln is one advisory of an OSV response.
type OSVVuln struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"` // often includes the GHSA id
	Summary  string   `json:"summary"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific OSVDatabaseSpecific `json:"database_specific"`
	Affected         []OSVAffected       `json:"affected"`
}

// OSVDatabaseSpecific holds the advisory-specific fields OSV exposes for
// GitHub reviewed advisories.
type OSVDatabaseSpecific struct {
	Severity string   `json:"severity,omitempty"`
	CWEIDs   []string `json:"cwe_ids,omitempty"`
}

// UnmarshalJSON tolerates fields of an unexpected type.
func (d *OSVDatabaseSpecific) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	if s, ok := raw["severity"]; ok {
		_ = json.Unmarshal(s, &d.Severity)
	}
	if c, ok := raw["cwe_ids"]; ok {
		_ = json.Unmarshal(c, &d.CWEIDs)
	}
	return nil
}

// OSVAffected is one affected package entry of an advisory — named so
// callers can walk Ranges/Events to derive fix information.
type OSVAffected struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Ranges []OSVRange `json:"ranges"`
}

// OSVRange is a range of affected versions.
type OSVRange struct {
	Type   string     `json:"type"`
	Events []OSVEvent `json:"events"`
}

// OSVEvent is one boundary of a range.
type OSVEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

var osvClient = &http.Client{Timeout: 20 * time.Second}

// QueryOSV asks OSV.dev for every advisory affecting actionRepo. The
// query carries no version: the affected ranges are matched locally with
// Affects, which keeps one request per repository instead of one per
// repository and version.
func QueryOSV(ctx context.Context, actionRepo string) ([]OSVVuln, error) {
	if actionRepo == "" {
		return nil, nil
	}
	q := OSVQuery{}
	q.Package.Name = actionRepo
	q.Package.Ecosystem = osvEcosystem

	body, err := json.Marshal(q)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, osvQueryURL, bytes.NewReader(body))
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

// Affects reports whether ref falls into one of the affected ranges of
// the advisory. Refs that are not versions (a commit SHA, a branch) never
// match.
func (v OSVVuln) Affects(ref string) bool {
	ver, err := parseVersion(ref)
	if err != nil {
		return false
	}
	for _, aff := range v.Affected {
		if !isActionsEcosystem(aff.Package.Ecosystem) {
			continue
		}
		for _, r := range aff.Ranges {
			if !isVersionRange(r.Type) {
				continue
			}
			if rangeAffects(r, ver) {
				return true
			}
		}
	}
	return false
}

// FixedVersion returns the first fixed version of the advisory.
func (v OSVVuln) FixedVersion() string {
	for _, aff := range v.Affected {
		for _, r := range aff.Ranges {
			for _, ev := range r.Events {
				if ev.Fixed != "" {
					return ev.Fixed
				}
			}
		}
	}
	return ""
}

// SeverityLevel derives the severity of the advisory: the reviewed
// severity when the advisory carries one, otherwise the presence of a
// CVSS vector.
func (v OSVVuln) SeverityLevel() string {
	switch s := strings.ToUpper(strings.TrimSpace(v.DatabaseSpecific.Severity)); s {
	case severityCritical, severityHigh, severityMedium, severityLow:
		return s
	case "MODERATE":
		return severityMedium
	}
	for _, sv := range v.Severity {
		if sv.Type != "" && sv.Score != "" {
			return severityHigh
		}
	}
	return severityMedium
}

// isActionsEcosystem reports whether an affected entry belongs to the
// GitHub Actions ecosystem.
func isActionsEcosystem(ecosystem string) bool {
	ecosystem = strings.TrimSpace(ecosystem)
	return ecosystem == "" || strings.EqualFold(ecosystem, osvEcosystem)
}

// isVersionRange reports whether a range carries version boundaries (a
// GIT range holds commits, not versions).
func isVersionRange(t string) bool {
	switch strings.ToUpper(strings.TrimSpace(t)) {
	case "", "ECOSYSTEM", "SEMVER":
		return true
	}
	return false
}

// rangeAffects reports whether ver falls inside a range.
func rangeAffects(r OSVRange, ver *semver.Version) bool {
	var introduced, end *semver.Version
	endInclusive := false
	for _, ev := range r.Events {
		switch {
		case ev.Introduced != "":
			v, err := parseVersion(ev.Introduced)
			if err != nil {
				return false
			}
			introduced = v
			end = nil
		case ev.Fixed != "":
			v, err := parseVersion(ev.Fixed)
			if err != nil {
				return false
			}
			end = v
			endInclusive = false
		case ev.LastAffected != "":
			v, err := parseVersion(ev.LastAffected)
			if err != nil {
				return false
			}
			end = v
			endInclusive = true
		case ev.Limit != "":
			v, err := parseVersion(ev.Limit)
			if err != nil {
				return false
			}
			end = v
			endInclusive = false
		}
	}
	if introduced != nil && ver.LessThan(introduced) {
		return false
	}
	if end == nil {
		return introduced != nil
	}
	if endInclusive {
		return !ver.GreaterThan(end)
	}
	return ver.LessThan(end)
}
