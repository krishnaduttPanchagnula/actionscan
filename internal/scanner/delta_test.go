package scanner

import (
	"testing"
	"time"
)

// sampleFinding is one finding as the scanner produces it.
func sampleFinding() Finding {
	return Finding{
		Repo:       "acme/alpha",
		Workflow:   ".github/workflows/ci.yml",
		Job:        "build",
		Action:     "actions/checkout@v4",
		Ref:        "v4",
		Severity:   "HIGH",
		Category:   "vulnerable",
		Reason:     "GHSA-1234: known vulnerable",
		Fix:        "Upgrade actions/checkout to >= 5.0.0",
		AdvisoryID: "GHSA-1234",
	}
}

// The fingerprint is the identity of a finding across runs. If it
// moved, every scan would look like a wall of new findings.
func TestFingerprintIsStableAcrossRuns(t *testing.T) {
	f := sampleFinding()
	first := Fingerprint(f)
	for i := 0; i < 100; i++ {
		if got := Fingerprint(f); got != first {
			t.Fatalf("fingerprint changed between runs: %q then %q", first, got)
		}
	}
	if len(first) != 16 {
		t.Errorf("fingerprint = %q, want 16 hex characters", first)
	}
}

// Every field that says *where* the finding is must change the
// fingerprint: moving a finding to another repo, workflow, job or
// advisory is a different finding.
func TestFingerprintChangesWithIdentity(t *testing.T) {
	base := sampleFinding()
	want := Fingerprint(base)

	cases := map[string]func(f *Finding){
		"repo":        func(f *Finding) { f.Repo = "acme/beta" },
		"workflow":    func(f *Finding) { f.Workflow = ".github/workflows/release.yml" },
		"job":         func(f *Finding) { f.Job = "test" },
		"action":      func(f *Finding) { f.Action = "actions/setup-go@v5" },
		"category":    func(f *Finding) { f.Category = "malicious" },
		"advisory id": func(f *Finding) { f.AdvisoryID = "GHSA-5678" },
	}
	for name, mutate := range cases {
		f := base
		mutate(&f)
		if got := Fingerprint(f); got == want {
			t.Errorf("changing the %s did not change the fingerprint", name)
		}
	}
}

// The reason and the fix are prose: an upstream advisory gets reworded
// and a fix gets improved. That must not read as a new finding.
func TestFingerprintIgnoresReasonAndFix(t *testing.T) {
	base := sampleFinding()
	want := Fingerprint(base)

	f := base
	f.Reason = "GHSA-1234: a completely different wording of the same problem"
	f.Fix = "Upgrade actions/checkout to >= 5.1.0"
	f.Severity = "CRITICAL"
	f.Ref = "v4.1.0"
	if got := Fingerprint(f); got != want {
		t.Errorf("fingerprint = %q, want %q — prose must not change the identity", got, want)
	}
}

// The same action in two workflows is two findings: fixing one does not
// fix the other.
func TestFingerprintIsPerWorkflow(t *testing.T) {
	a := sampleFinding()
	b := sampleFinding()
	b.Workflow = ".github/workflows/release.yml"
	b.Job = "release"

	if Fingerprint(a) == Fingerprint(b) {
		t.Error("the same action in two workflows has the same fingerprint")
	}
}

func TestSetFingerprints(t *testing.T) {
	fs := []Finding{sampleFinding(), sampleFinding()}
	SetFingerprints(fs)
	for i, f := range fs {
		if f.Fingerprint == "" {
			t.Errorf("finding %d has no fingerprint", i)
		}
		if f.Fingerprint != Fingerprint(f) {
			t.Errorf("finding %d fingerprint = %q, want %q", i, f.Fingerprint, Fingerprint(f))
		}
	}
}

func TestFingerprintSet(t *testing.T) {
	fs := []Finding{sampleFinding(), sampleFinding()}
	SetFingerprints(fs)
	set := FingerprintSet(fs)
	if len(set) != 1 {
		t.Errorf("set has %d fingerprints, want 1", len(set))
	}
	// A finding with no fingerprint is not in the set: it has no
	// identity to compare.
	if got := FingerprintSet([]Finding{{Repo: "a"}}); len(got) != 0 {
		t.Errorf("set = %v, want empty for a finding with no fingerprint", got)
	}
}

// ── Compare ────────────────────────────────────────────────────────────

func compareSummary(fs ...Finding) *Summary {
	return &Summary{Findings: fs, ScannedAt: time.Date(2026, 1, 2, 3, 4, 0, 0, time.UTC)}
}

func TestCompareNewResolvedAndUnchanged(t *testing.T) {
	kept := sampleFinding()
	fixed := sampleFinding()
	fixed.Workflow = ".github/workflows/fixed.yml"
	added := sampleFinding()
	added.Workflow = ".github/workflows/added.yml"

	base := compareSummary(kept, fixed)
	cur := compareSummary(kept, added)
	SetFingerprints(base.Findings)
	SetFingerprints(cur.Findings)

	d := Compare(cur, base)
	if len(d.New) != 1 || !d.New[Fingerprint(added)] {
		t.Errorf("new = %v, want only the added finding", d.New)
	}
	if len(d.Resolved) != 1 || !d.Resolved[Fingerprint(fixed)] {
		t.Errorf("resolved = %v, want only the fixed finding", d.Resolved)
	}
	if d.BaselineAt != "2026-01-02 03:04" {
		t.Errorf("baseline at = %q", d.BaselineAt)
	}
}

// A scan with no baseline has everything new.
func TestCompareWithNoBaseline(t *testing.T) {
	second := sampleFinding()
	second.Workflow = ".github/workflows/release.yml"
	cur := compareSummary(sampleFinding(), second)
	SetFingerprints(cur.Findings)

	d := Compare(cur, nil)
	if len(d.New) != 2 {
		t.Errorf("new = %v, want both findings", d.New)
	}
	if len(d.Resolved) != 0 {
		t.Errorf("resolved = %v, want none", d.Resolved)
	}
}

func TestCompareWithNoCurrentScan(t *testing.T) {
	d := Compare(nil, compareSummary(sampleFinding()))
	if len(d.New) != 0 || len(d.Resolved) != 0 {
		t.Errorf("delta = %+v, want empty", d)
	}
}

// ── ActionKey ──────────────────────────────────────────────────────────

func TestActionKeyNormalisesTheAction(t *testing.T) {
	cases := map[string]string{
		"actions/checkout@v4":     "actions/checkout",
		"actions/checkout":        "actions/checkout",
		"ACTIONS/Checkout@V4":     "actions/checkout",
		"actions/checkout@abc123": "actions/checkout",
		"":                        "",
	}
	for in, want := range cases {
		if got := ActionKey(in); got != want {
			t.Errorf("ActionKey(%q) = %q, want %q", in, got, want)
		}
	}
}
