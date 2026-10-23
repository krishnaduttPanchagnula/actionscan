package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Fingerprint is a stable identity for one finding.
//
// It is what makes delta scanning possible: a finding that is present in
// both the current scan and a baseline scan has the same fingerprint, so
// "what is new" is a set difference rather than a guess. The fingerprint
// deliberately excludes the finding's Reason and Fix text, which change
// whenever an advisory is reworded or a fix is improved — otherwise every
// upstream edit would look like a new finding.
//
// The identity is one finding at one place: the same action referenced
// by two workflows is two findings, because fixing one does not fix the
// other.
func Fingerprint(f Finding) string {
	h := sha256.New()
	for _, part := range []string{
		f.Repo, f.Workflow, f.Job, f.Action, f.Category, f.AdvisoryID,
	} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// SetFingerprints fills in the fingerprint of every finding.
func SetFingerprints(fs []Finding) {
	for i := range fs {
		fs[i].Fingerprint = Fingerprint(fs[i])
	}
}

// FingerprintSet is the set of fingerprints in a scan.
func FingerprintSet(fs []Finding) map[string]bool {
	out := make(map[string]bool, len(fs))
	for _, f := range fs {
		if f.Fingerprint == "" {
			continue
		}
		out[f.Fingerprint] = true
	}
	return out
}

// Delta is the result of comparing a scan against a baseline.
type Delta struct {
	// New are fingerprints present now but not in the baseline.
	New map[string]bool
	// Resolved are fingerprints in the baseline that are gone now.
	Resolved map[string]bool
	// BaselineAt is when the baseline scan was taken.
	BaselineAt string
}

// Compare computes the delta between a current scan and a baseline.
//
// A finding is "resolved" when it was in the baseline and is not in the
// current scan. That is not necessarily a fix — the rule may have been
// removed from the feed — but it is the only honest signal available
// without re-running the baseline against the same rules.
func Compare(current *Summary, baseline *Summary) Delta {
	d := Delta{
		New:      map[string]bool{},
		Resolved: map[string]bool{},
	}
	if current == nil {
		return d
	}
	cur := FingerprintSet(current.Findings)
	if baseline == nil {
		for fp := range cur {
			d.New[fp] = true
		}
		return d
	}
	base := FingerprintSet(baseline.Findings)
	for fp := range cur {
		if !base[fp] {
			d.New[fp] = true
		}
	}
	for fp := range base {
		if !cur[fp] {
			d.Resolved[fp] = true
		}
	}
	d.BaselineAt = baseline.ScannedAt.Format("2006-01-02 15:04")
	return d
}

// ActionKey is the identity of an action across the whole scan: the
// same action used in forty repos is one action, and that is the number
// that answers "how bad is it if I fix just this one".
func ActionKey(action string) string {
	if at := strings.Index(action, "@"); at >= 0 {
		action = action[:at]
	}
	return strings.ToLower(action)
}
