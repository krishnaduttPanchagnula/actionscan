package report

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"

	semver "github.com/Masterminds/semver/v3"
	"github.com/krishnaduttPanchagnula/actionscan/internal/scanner"
)

// BaselineDiff is the JSON shape written by WriteBaselineDiff.
type BaselineDiff struct {
	BaselineAt    string   `json:"baseline_at"`
	NewCount      int      `json:"new_count"`
	ResolvedCount int      `json:"resolved_count"`
	New           []string `json:"new"`      // fingerprints
	Resolved      []string `json:"resolved"` // fingerprints
}

// LoadBaseline reads a previous report.json as a baseline.
//
// A baseline is a whole report, not a diff: the diff of fingerprints
// alone cannot answer "what is new now", because that needs the
// baseline's full fingerprint set. Pointing this at a diff file is
// therefore a mistake worth naming out loud.
func LoadBaseline(path string) (*scanner.Summary, error) {
	s, _, err := LoadBaselineWithWarnings(path, "")
	return s, err
}

// LoadBaselineWithWarnings reads a previous report.json as a baseline
// and returns warnings about it.
//
// The warnings are advisory, never fatal. A baseline written by another
// version of the tool is still usable: fingerprints are stable across
// versions by design, so only the rule set behind the findings can
// differ. currentVersion is the version of the tool running now; leave
// it empty when it is unknown, and no version warning is produced.
func LoadBaselineWithWarnings(path, currentVersion string) (*scanner.Summary, []string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, fmt.Errorf("baseline file not found: %s", path)
		}
		return nil, nil, fmt.Errorf("reading baseline %s: %w", path, err)
	}

	if !json.Valid(b) {
		return nil, nil, fmt.Errorf("baseline %s is not valid JSON", path)
	}

	// The file must carry a "findings" array to be a baseline.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, nil, fmt.Errorf("baseline %s is not a report.json from a previous scan: %w", path, err)
	}
	if _, ok := raw["findings"]; !ok {
		if looksLikeDiff(raw) {
			return nil, nil, errors.New("baseline must be a report.json from a previous scan, not a diff file")
		}
		return nil, nil, fmt.Errorf("baseline %s has no \"findings\" array: it is not a report.json from a previous scan", path)
	}

	var s scanner.Summary
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, nil, fmt.Errorf("baseline %s is not a valid report.json: %w", path, err)
	}

	// A report written before fingerprints existed has none of them,
	// and a baseline with no fingerprints diffs as "everything is new".
	ensureFingerprints(&s)

	var warnings []string
	if versionMismatch(s.ToolVersion, currentVersion) {
		warnings = append(warnings, fmt.Sprintf(
			"baseline was produced by actionscan %s but this is %s: the rule set may have changed, so findings may differ",
			s.ToolVersion, currentVersion))
	}
	return &s, warnings, nil
}

// ApplyBaseline compares a summary against a baseline and fills in the
// summary's NewFindings / ResolvedFindgs / BaselineAt / BaselinePath
// fields.
func ApplyBaseline(current *scanner.Summary, baseline *scanner.Summary, baselinePath string) {
	if current == nil {
		return
	}
	// Both sides need fingerprints, or the diff silently finds nothing.
	ensureFingerprints(current)
	ensureFingerprints(baseline)

	delta := scanner.Compare(current, baseline)
	current.NewFindings = len(delta.New)
	current.ResolvedFindgs = len(delta.Resolved)
	current.BaselineAt = baselineAt(delta, baseline)
	current.BaselinePath = baselinePath
}

// NewFingerprints returns the fingerprints of the findings that are new
// relative to a baseline.
//
// The dashboard tests each row's fingerprint against this set to render
// a NEW badge.
func NewFingerprints(current *scanner.Summary, baseline *scanner.Summary) map[string]bool {
	out := map[string]bool{}
	if current == nil {
		return out
	}
	base := map[string]bool{}
	if baseline != nil {
		base = fingerprintSet(baseline.Findings)
	}
	for fp := range fingerprintSet(current.Findings) {
		if !base[fp] {
			out[fp] = true
		}
	}
	return out
}

// WriteBaselineDiff writes the diff between a scan and a baseline.
//
// path is the file to write, and is returned unchanged. The fingerprint
// lists are sorted, so the same scan always produces the same file —
// an unstable diff is a diff nobody can review.
func WriteBaselineDiff(current *scanner.Summary, baseline *scanner.Summary, path string) (string, error) {
	ensureFingerprints(current)
	ensureFingerprints(baseline)

	delta := scanner.Compare(current, baseline)
	d := BaselineDiff{
		BaselineAt:    baselineAt(delta, baseline),
		NewCount:      len(delta.New),
		ResolvedCount: len(delta.Resolved),
		New:           sortedFingerprints(delta.New),
		Resolved:      sortedFingerprints(delta.Resolved),
	}
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// ── helpers ────────────────────────────────────────────────────────────

// ensureFingerprints fills in the fingerprints a scan is missing.
//
// The fingerprint is a pure function of the finding, so a report
// written before fingerprints existed can be given them on load. A
// report that already has them keeps them: they are the recorded
// identity of the finding.
func ensureFingerprints(s *scanner.Summary) {
	if s == nil {
		return
	}
	for _, f := range s.Findings {
		if f.Fingerprint == "" {
			scanner.SetFingerprints(s.Findings)
			return
		}
	}
}

// fingerprintSet is the set of fingerprints in a scan, computing the
// ones that are missing.
func fingerprintSet(fs []scanner.Finding) map[string]bool {
	out := make(map[string]bool, len(fs))
	for _, f := range fs {
		fp := f.Fingerprint
		if fp == "" {
			fp = scanner.Fingerprint(f)
		}
		out[fp] = true
	}
	return out
}

// sortedFingerprints returns the fingerprints in a stable order.
func sortedFingerprints(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for fp := range set {
		out = append(out, fp)
	}
	sort.Strings(out)
	return out
}

// baselineAt is when the baseline scan was taken.
//
// Compare formats the timestamp already, but a baseline with no scan
// time comes back as "0001-01-01 00:00" — a date nobody scanned on.
func baselineAt(delta scanner.Delta, baseline *scanner.Summary) string {
	if baseline != nil && baseline.ScannedAt.IsZero() {
		return ""
	}
	return delta.BaselineAt
}

// looksLikeDiff reports whether a JSON document is a baseline diff
// rather than a scan report.
func looksLikeDiff(raw map[string]json.RawMessage) bool {
	for _, k := range []string{"new", "resolved", "new_count", "resolved_count"} {
		if _, ok := raw[k]; ok {
			return true
		}
	}
	return false
}

// versionMismatch reports whether the baseline came from a different
// version of the tool than the one running now.
func versionMismatch(baselineVersion, currentVersion string) bool {
	if baselineVersion == "" || currentVersion == "" {
		return false // unknown — say nothing
	}
	a, errA := semver.NewVersion(baselineVersion)
	b, errB := semver.NewVersion(currentVersion)
	if errA == nil && errB == nil {
		return !a.Equal(b)
	}
	return baselineVersion != currentVersion
}
