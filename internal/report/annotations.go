package report

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/krishnaduttPanchagnula/actionscan/internal/scanner"
)

// maxAnnotations is the number of annotations GitHub renders per step.
// It is a platform limit, not a taste decision: the rest of the
// findings are summarised in one notice instead of being silently
// dropped.
const maxAnnotations = 10

// summaryFindingLimit is how many findings the step summary lists. The
// summary is rendered in a browser tab, so it stays short.
const summaryFindingLimit = 10

// topActionLimit is how many actions the blast-radius table lists.
const topActionLimit = 5

// Annotations renders findings as GitHub Actions workflow commands
// (::error / ::warning / ::notice) so they appear inline on the pull
// request.
//
// GitHub renders at most 10 annotations per step, so only the first
// 10 are emitted; the rest are summarised in one final notice.
func Annotations(s *scanner.Summary) string {
	if s == nil || len(s.Findings) == 0 {
		return ""
	}
	findings := sortedFindings(s.Findings)

	var b strings.Builder
	for i, f := range findings {
		if i >= maxAnnotations {
			break
		}
		b.WriteString(annotation(f))
		b.WriteString("\n")
	}
	if n := len(findings) - maxAnnotations; n > 0 {
		fmt.Fprintf(&b, "::notice title=actionscan::%d more findings were suppressed: GitHub renders at most %d annotations per step. See the job summary for the full list.\n",
			n, maxAnnotations)
	}
	return b.String()
}

// StepSummary renders a markdown summary for $GITHUB_STEP_SUMMARY.
func StepSummary(s *scanner.Summary) string {
	if s == nil {
		return ""
	}
	var b strings.Builder

	findings := sortedFindings(s.Findings)
	counts := countSeverities(findings)

	fmt.Fprintf(&b, "## actionscan — %d finding(s) in %d of %d repos\n\n",
		len(findings), s.AffectedRepos, s.TotalRepos)

	var meta []string
	if s.Target != "" {
		meta = append(meta, "`"+mdCode(s.Target)+"`")
	}
	if !s.ScannedAt.IsZero() {
		meta = append(meta, "scanned "+s.ScannedAt.UTC().Format(time.RFC3339))
	}
	if s.ActionsChecked > 0 {
		meta = append(meta, fmt.Sprintf("%d action(s) checked", s.ActionsChecked))
	}
	if s.ToolVersion != "" {
		meta = append(meta, "actionscan "+s.ToolVersion)
	}
	if len(meta) > 0 {
		b.WriteString(strings.Join(meta, " · "))
		b.WriteString("\n\n")
	}

	// A degraded load is a gap in what was checked, and it has to be
	// visible where the numbers are read.
	if s.Degraded {
		fmt.Fprintf(&b, "> ⚠ Threat intel degraded: %s — this scan may be missing findings.\n\n",
			mdText(s.DegradedReason))
	}
	if s.IncompleteReason != "" {
		fmt.Fprintf(&b, "> ⚠ Scan incomplete: %s\n\n", mdText(s.IncompleteReason))
	}

	if len(findings) == 0 {
		b.WriteString("No findings. Every action reference that was checked is clean.\n")
		return b.String()
	}

	b.WriteString("| Severity | Count |\n| --- | ---: |\n")
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		fmt.Fprintf(&b, "| %s | %d |\n", sev, counts[sev])
	}
	b.WriteString("\n")

	if top := topActions(findings); len(top) > 0 {
		b.WriteString("### Top actions by blast radius\n\n")
		b.WriteString("| Action | Findings | Repos | Workflows |\n| --- | ---: | ---: | ---: |\n")
		for _, a := range top {
			fmt.Fprintf(&b, "| `%s` | %d | %d | %d |\n", mdCode(a.action), a.findings, a.repos, a.workflows)
		}
		b.WriteString("\n")
	}

	b.WriteString("### Findings\n\n")
	b.WriteString("| Severity | Workflow | Action | Reason |\n| --- | --- | --- | --- |\n")
	for i, f := range findings {
		if i >= summaryFindingLimit {
			break
		}
		fmt.Fprintf(&b, "| %s | `%s` | `%s` | %s |\n",
			sevLabel(f.Severity), mdCode(f.Workflow), mdCode(f.Action), mdText(f.Reason))
	}
	if n := len(findings) - summaryFindingLimit; n > 0 {
		fmt.Fprintf(&b, "\n%d more finding(s) not shown. See the JSON report for the full list.\n", n)
	}
	return b.String()
}

// ── annotations ─────────────────────────────────────────────────────────

// annotation renders one finding as a workflow command.
//
// The shape is fixed by GitHub: "::error file={path},title={title}::{message}".
// There is no line= property: scanner.Finding carries no line number, and
// pointing the reader at the wrong line is worse than pointing at none.
func annotation(f scanner.Finding) string {
	var props []string
	if f.Workflow != "" {
		props = append(props, "file="+escapeProperty(f.Workflow))
	}
	props = append(props, "title="+escapeProperty(annotationTitle(f)))
	return "::" + commandFor(f.Severity) + " " + strings.Join(props, ",") + "::" + escapeData(annotationMessage(f))
}

// commandFor maps a severity onto a workflow command.
func commandFor(severity string) string {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	}
	return "notice"
}

// annotationTitle is the annotation title: the severity and the category.
func annotationTitle(f scanner.Finding) string {
	sev := strings.ToUpper(strings.TrimSpace(f.Severity))
	if sev == "" {
		sev = "UNKNOWN"
	}
	category := strings.ToLower(strings.TrimSpace(f.Category))
	if category == "" {
		return sev
	}
	return sev + " " + category
}

// annotationMessage is the annotation body: the reason, with the fix on
// a second line.
func annotationMessage(f scanner.Finding) string {
	reason := strings.TrimSpace(f.Reason)
	fix := strings.TrimSpace(f.Fix)
	switch {
	case reason == "":
		return fix
	case fix == "":
		return reason
	}
	return reason + "\n" + fix
}

// escapeProperty escapes a workflow-command property value.
//
// The runner splits the property list on "," and each property on its
// first "=", and it decodes %0D, %0A, %3A, %2C and %25. A colon or a
// comma in a value would otherwise forge a new property — and a
// property is not what decides whether a line is a command, so this is
// the boundary a crafted advisory title has to cross.
func escapeProperty(s string) string {
	s = strings.ReplaceAll(s, "%", "%25") // first: % is the escape character
	s = strings.ReplaceAll(s, "\r", "%0D")
	s = strings.ReplaceAll(s, "\n", "%0A")
	s = strings.ReplaceAll(s, ":", "%3A")
	s = strings.ReplaceAll(s, ",", "%2C")
	return s
}

// escapeData escapes a workflow-command message.
//
// The runner decodes %0D, %0A and %25 in the message. A raw newline
// would end the command line, and every line is parsed on its own — so
// a crafted reason that ends with a newline could start a second
// command. Escaping the newline removes the injection point; the
// message is still rendered with its line break.
func escapeData(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	s = strings.ReplaceAll(s, "\n", "%0A")
	return s
}

// ── helpers ─────────────────────────────────────────────────────────────

// sortedFindings returns the findings most severe first.
//
// The summary's own order is not trusted: the annotations have to show
// the worst findings even when the scan was built by something other
// than ScanAll.
func sortedFindings(findings []scanner.Finding) []scanner.Finding {
	out := append([]scanner.Finding(nil), findings...)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if ra, rb := severityRank(a.Severity), severityRank(b.Severity); ra != rb {
			return ra > rb
		}
		if a.Workflow != b.Workflow {
			return a.Workflow < b.Workflow
		}
		if a.Action != b.Action {
			return a.Action < b.Action
		}
		return a.Reason < b.Reason
	})
	return out
}

// severityRank orders the severities, most severe first.
func severityRank(severity string) int {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	}
	return 0
}

// countSeverities counts the findings per severity.
//
// The counts are computed from the findings, so the table always
// matches the rows underneath it.
func countSeverities(findings []scanner.Finding) map[string]int {
	counts := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
	for _, f := range findings {
		counts[strings.ToUpper(strings.TrimSpace(f.Severity))]++
	}
	return counts
}

// sevLabel is the severity as it appears in a table cell.
func sevLabel(severity string) string {
	s := strings.ToUpper(strings.TrimSpace(severity))
	if s == "" {
		return "UNKNOWN"
	}
	return s
}

// actionBlast is one action and how far it reaches.
type actionBlast struct {
	action    string
	findings  int
	repos     int
	workflows int
}

// topActions returns the actions that reach the most places, the
// "blast radius" of a compromised action: the same bad reference in
// ten workflows is one problem with ten landing places.
func topActions(findings []scanner.Finding) []actionBlast {
	type agg struct {
		action    string
		findings  int
		repos     map[string]bool
		workflows map[string]bool
	}
	byAction := map[string]*agg{}
	for _, f := range findings {
		a, ok := byAction[f.Action]
		if !ok {
			a = &agg{action: f.Action, repos: map[string]bool{}, workflows: map[string]bool{}}
			byAction[f.Action] = a
		}
		a.findings++
		a.repos[f.Repo] = true
		a.workflows[f.Repo+"|"+f.Workflow] = true
	}
	out := make([]actionBlast, 0, len(byAction))
	for _, a := range byAction {
		out = append(out, actionBlast{
			action:    a.action,
			findings:  a.findings,
			repos:     len(a.repos),
			workflows: len(a.workflows),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].findings != out[j].findings {
			return out[i].findings > out[j].findings
		}
		if out[i].repos != out[j].repos {
			return out[i].repos > out[j].repos
		}
		return out[i].action < out[j].action
	})
	if len(out) > topActionLimit {
		out = out[:topActionLimit]
	}
	return out
}

// mdText prepares a value for a markdown table cell: one line, no pipe
// to break the table, no HTML to be interpreted.
func mdText(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

// mdCode prepares a value for a markdown code span.
func mdCode(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	return strings.ReplaceAll(s, "`", "'")
}
