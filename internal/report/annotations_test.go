package report

import (
	"strings"
	"testing"

	"github.com/krishnaduttPanchagnula/actionscan/internal/scanner"
)

func TestAnnotationFormat(t *testing.T) {
	s := &scanner.Summary{
		Findings: []scanner.Finding{{
			Repo:     "acme/beta",
			Workflow: ".github/workflows/ci.yml",
			Job:      "build",
			Action:   "tj-actions/changed-files@v41",
			Severity: "CRITICAL",
			Category: "malicious",
			Reason:   "Compromised action",
			Fix:      "Remove it",
		}},
	}

	got := Annotations(s)
	want := "::error file=.github/workflows/ci.yml,title=CRITICAL malicious::Compromised action%0ARemove it\n"
	if got != want {
		t.Errorf("annotations =\n%q\nwant\n%q", got, want)
	}
	// There is no line number to report: a wrong line sends the reader
	// to the wrong place, so the property is left out entirely.
	if strings.Contains(got, "line=") {
		t.Errorf("annotation carries a line property: %q", got)
	}
}

func TestSeverityMapsToCommand(t *testing.T) {
	cases := []struct {
		severity string
		want     string
	}{
		{"CRITICAL", "::error"},
		{"HIGH", "::error"},
		{"MEDIUM", "::warning"},
		{"LOW", "::notice"},
		{"", "::notice"},
	}
	for _, c := range cases {
		s := &scanner.Summary{Findings: []scanner.Finding{{
			Workflow: ".github/workflows/ci.yml",
			Severity: c.severity,
			Category: "malicious",
			Reason:   "r",
		}}}
		got := Annotations(s)
		if !strings.HasPrefix(got, c.want+" ") {
			t.Errorf("severity %q → %q, want it to start with %q", c.severity, got, c.want)
		}
	}
}

// The runner splits the property list on "," and each property on its
// first "=", and it decodes %0D, %0A, %3A, %2C and %25.
func TestEscapeProperty(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain", "plain"},
		{"100%", "100%25"},
		{"a\r\nb", "a%0D%0Ab"},
		{"GHSA-1: title", "GHSA-1%3A title"},
		{"a,b", "a%2Cb"},
		{"%3A", "%253A"}, // the escape character is escaped first
	}
	for _, c := range cases {
		if got := escapeProperty(c.in); got != c.want {
			t.Errorf("escapeProperty(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// The runner decodes %0D, %0A and %25 in the message. It does not
// decode %3A there, so escaping a colon in the data would show up
// literally in the rendered annotation.
func TestEscapeData(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain", "plain"},
		{"100%", "100%25"},
		{"a\r\nb", "a%0D%0Ab"},
		{"GHSA-1: title", "GHSA-1: title"},
		{"%0A", "%250A"},
	}
	for _, c := range cases {
		if got := escapeData(c.in); got != c.want {
			t.Errorf("escapeData(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// A reason comes from a third party. It must not be able to start a
// second workflow command.
func TestCraftedReasonCannotInjectACommand(t *testing.T) {
	s := &scanner.Summary{
		Findings: []scanner.Finding{{
			Workflow: ".github/workflows/ci.yml",
			Severity: "HIGH",
			Category: "vulnerable",
			Reason:   "benign\n::error file=evil.yml,title=pwn::injected",
			Fix:      "do not trust me",
		}},
	}

	out := Annotations(s)

	// The newline is escaped, so the whole annotation stays one line
	// and the injected text stays inside the message.
	if strings.Contains(out, "\n::") {
		t.Errorf("output contains a command after a line break: %q", out)
	}
	if n := countCommands(out); n != 1 {
		t.Errorf("got %d commands, want 1: %q", n, out)
	}
	if !strings.Contains(out, "%0A::error") {
		t.Errorf("the crafted text should be escaped inside the message: %q", out)
	}
}

// A crafted category must not be able to forge a property.
func TestCraftedTitleCannotInjectAProperty(t *testing.T) {
	s := &scanner.Summary{
		Findings: []scanner.Finding{{
			Workflow: ".github/workflows/ci.yml",
			Severity: "CRITICAL",
			Category: "malicious,file=evil.yml",
			Reason:   "r",
		}},
	}

	out := Annotations(s)
	c, ok := parseCommand(strings.TrimRight(out, "\n"))
	if !ok {
		t.Fatalf("output is not a workflow command: %q", out)
	}
	if len(c.props) != 2 {
		t.Errorf("got %d properties, want 2: %v", len(c.props), c.props)
	}
	if c.props["file"] != ".github/workflows/ci.yml" {
		t.Errorf("file property = %q — the crafted category forged one", c.props["file"])
	}
	if c.props["title"] != "CRITICAL malicious%2Cfile=evil.yml" {
		t.Errorf("title property = %q", c.props["title"])
	}
}

func TestAnnotationsAreCappedAtTen(t *testing.T) {
	var findings []scanner.Finding
	for i := 0; i < 25; i++ {
		findings = append(findings, scanner.Finding{
			Repo:     "acme/beta",
			Workflow: ".github/workflows/ci.yml",
			Action:   "actions/checkout@v4",
			Severity: "HIGH",
			Category: "vulnerable",
			Reason:   "finding " + string(rune('a'+i)),
		})
	}
	s := &scanner.Summary{Findings: findings}

	out := Annotations(s)
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")

	if len(lines) != 11 {
		t.Fatalf("got %d lines, want 10 annotations + 1 notice: %q", len(lines), out)
	}
	if !strings.HasPrefix(lines[10], "::notice") {
		t.Errorf("last line is not the suppression notice: %q", lines[10])
	}
	if !strings.Contains(lines[10], "15 more findings were suppressed") {
		t.Errorf("the notice does not report how many were suppressed: %q", lines[10])
	}
	if n := countCommands(out); n != 11 {
		t.Errorf("got %d commands, want 11", n)
	}
}

func TestAnnotationsWithoutFindings(t *testing.T) {
	if got := Annotations(&scanner.Summary{}); got != "" {
		t.Errorf("got %q, want an empty string", got)
	}
	if got := Annotations(nil); got != "" {
		t.Errorf("got %q, want an empty string", got)
	}
}

func TestStepSummary(t *testing.T) {
	s := &scanner.Summary{
		Findings: []scanner.Finding{
			{
				Repo: "acme/beta", Workflow: ".github/workflows/ci.yml",
				Action: "tj-actions/changed-files@v41", Severity: "CRITICAL",
				Category: "malicious", Reason: "dumped runner memory to attacker C2",
			},
			{
				Repo: "acme/alpha", Workflow: ".github/workflows/deploy.yaml",
				Action: "tj-actions/changed-files@v41", Severity: "HIGH",
				Category: "malicious", Reason: "dumped runner memory to attacker C2",
			},
			{
				Repo: "acme/alpha", Workflow: ".github/workflows/ci.yml",
				Action: "actions/checkout@v1", Severity: "MEDIUM",
				Category: "vulnerable", Reason: "GHSA-aaaa: bad",
			},
		},
		Critical: 1, High: 1, Medium: 1, Low: 0,
		TotalRepos: 42, AffectedRepos: 2, ActionsChecked: 17,
		Target: "org/acme", ToolVersion: "v9.9.9",
	}

	out := StepSummary(s)

	for _, want := range []string{
		"| CRITICAL | 1 |",
		"| HIGH | 1 |",
		"| MEDIUM | 1 |",
		"| LOW | 0 |",
		"tj-actions/changed-files@v41", // the top action by blast radius
		".github/workflows/ci.yml",
		"dumped runner memory to attacker C2",
		"org/acme",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("step summary missing %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "### Top actions by blast radius") {
		t.Errorf("step summary has no blast radius table:\n%s", out)
	}
}

func TestStepSummaryReportsDegradedIntel(t *testing.T) {
	s := &scanner.Summary{
		Degraded:       true,
		DegradedReason: "ghsa: HTTP 500",
		Findings: []scanner.Finding{{
			Repo: "acme/beta", Workflow: ".github/workflows/ci.yml",
			Action: "actions/checkout@v1", Severity: "HIGH",
			Category: "vulnerable", Reason: "r",
		}},
	}
	out := StepSummary(s)
	if !strings.Contains(out, "degraded") || !strings.Contains(out, "ghsa: HTTP 500") {
		t.Errorf("a degraded scan must say so in the summary:\n%s", out)
	}
}

func TestStepSummaryWithoutFindings(t *testing.T) {
	out := StepSummary(&scanner.Summary{TotalRepos: 3})
	if !strings.Contains(out, "No findings") {
		t.Errorf("an empty scan must say so:\n%s", out)
	}
}

// countCommands counts the workflow commands in the output the way the
// runner does: every line is parsed on its own, and only a line that
// starts with "::" is a command.
func countCommands(out string) int {
	n := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimLeft(line, " \t"), "::") {
			n++
		}
	}
	return n
}

// command is one parsed workflow command.
type command struct {
	name  string
	props map[string]string
	data  string
}

// parseCommand parses a workflow command the way the runner does: the
// command name, the comma-separated properties, and the data after the
// second "::".
func parseCommand(line string) (command, bool) {
	if !strings.HasPrefix(line, "::") {
		return command{}, false
	}
	end := strings.Index(line[2:], "::")
	if end < 0 {
		return command{}, false
	}
	end += 2
	info, data := line[2:end], line[end+2:]
	c := command{data: data}
	if i := strings.IndexByte(info, ' '); i >= 0 {
		c.name = info[:i]
		for _, p := range strings.Split(info[i+1:], ",") {
			if k, v, ok := strings.Cut(p, "="); ok {
				if c.props == nil {
					c.props = map[string]string{}
				}
				c.props[k] = v
			}
		}
	} else {
		c.name = info
	}
	return c, true
}
