package scanner

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// ── config ──────────────────────────────────────────────────────────────

// PolicyConfig is the parsed actionscan.yml.
//
// The scanner package owns the policy semantics, so the type lives here
// and internal/config is the thin YAML loader that fills it in. That
// keeps the dependency one-way (config -> scanner) and avoids a cycle.
//
// The file looks like this:
//
//	version: 1
//	ignore_actions:      # owner/repo, owner/repo/* or a glob
//	  - actions/checkout
//	deny_ignore:         # must never be skipped; ignoring one is an error
//	  - tj-actions/changed-files
//	ignore_rules:        # rule categories to drop entirely
//	  - outdated
//	severity_remap:      # by rule category or by advisory id
//	  outdated: LOW
//	  GHSA-mrrh-fwg8-r2c3: CRITICAL
//	persona: regular     # regular | pedantic | auditor
//	respect_inline_ignores: true
//
// The YAML tags are part of the file format, not an implementation
// detail: they are what makes an actionscan.yml readable.
type PolicyConfig struct {
	Version              int               `yaml:"version"`
	IgnoreActions        []string          `yaml:"ignore_actions"`
	DenyIgnore           []string          `yaml:"deny_ignore"`
	IgnoreRules          []string          `yaml:"ignore_rules"`
	SeverityRemap        map[string]string `yaml:"severity_remap"`
	Persona              string            `yaml:"persona"`
	RespectInlineIgnores bool              `yaml:"respect_inline_ignores"`
}

// Personas are the sensitivity profiles a scan can run under.
const (
	// PersonaRegular reports exactly what the rules produce.
	PersonaRegular = "regular"
	// PersonaPedantic adds a LOW finding for mutable version tags.
	PersonaPedantic = "pedantic"
	// PersonaAuditor adds a LOW finding for anything not pinned to a
	// full 40-character commit SHA.
	PersonaAuditor = "auditor"
)

// policyRuleCategories are the rule categories a finding can carry.
var policyRuleCategories = []string{"malicious", "vulnerable", "osv", "outdated", "unpinned"}

// policySeverities are the severities a finding can be reported with.
var policySeverities = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"}

// RuleCategories returns the rule categories an actionscan.yml may
// reference. It returns a copy: the caller cannot corrupt the list.
func RuleCategories() []string {
	out := append([]string(nil), policyRuleCategories...)
	sort.Strings(out)
	return out
}

// IsRuleCategory reports whether s names a known rule category. The
// comparison is case-insensitive.
func IsRuleCategory(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	for _, c := range policyRuleCategories {
		if s == c {
			return true
		}
	}
	return false
}

// UnmarshalYAML decodes the config and applies the one default that
// cannot be expressed by a plain bool: respect_inline_ignores is true
// unless the file says otherwise.
//
// A config built in Go (not loaded from YAML) keeps the zero value, so
// RespectInlineIgnores is false there — set it explicitly.
func (c *PolicyConfig) UnmarshalYAML(value *yaml.Node) error {
	type plain PolicyConfig
	var p plain
	if err := value.Decode(&p); err != nil {
		return err
	}
	var probe struct {
		RespectInlineIgnores *bool `yaml:"respect_inline_ignores"`
	}
	if err := value.Decode(&probe); err != nil {
		return err
	}
	*c = PolicyConfig(p)
	if probe.RespectInlineIgnores == nil {
		c.RespectInlineIgnores = true
	}
	return nil
}

// persona returns the configured persona, normalized. An unset persona
// is the regular one.
func (c *PolicyConfig) persona() string {
	if c == nil {
		return PersonaRegular
	}
	p := strings.ToLower(strings.TrimSpace(c.Persona))
	if p == "" {
		return PersonaRegular
	}
	return p
}

// Validate checks the config for mistakes that would silently change
// what a scan reports.
//
// It returns the first problem found, as a human-readable error: a
// config that does not validate is a config whose meaning is unknown,
// and applying half of it is worse than refusing to apply any of it.
func (c *PolicyConfig) Validate() error {
	if c == nil {
		return nil
	}
	if c.Version != 0 && c.Version != 1 {
		return fmt.Errorf("unsupported actionscan config version %d (supported: 1)", c.Version)
	}
	switch c.persona() {
	case PersonaRegular, PersonaPedantic, PersonaAuditor:
	default:
		return fmt.Errorf("unknown persona %q (want %s, %s or %s)",
			c.Persona, PersonaRegular, PersonaPedantic, PersonaAuditor)
	}
	for _, r := range c.IgnoreRules {
		if !IsRuleCategory(r) {
			return fmt.Errorf("unknown rule category %q in ignore_rules (want one of %s)",
				r, strings.Join(RuleCategories(), ", "))
		}
	}
	for _, ig := range c.IgnoreActions {
		for _, d := range c.DenyIgnore {
			if policyIgnoreConflicts(ig, d) {
				return fmt.Errorf("action %q is in both ignore_actions and deny_ignore: "+
					"an action that must never be skipped cannot be ignored", ig)
			}
		}
	}
	for _, k := range sortedKeys(c.SeverityRemap) {
		if !policyIsSeverity(c.SeverityRemap[k]) {
			return fmt.Errorf("invalid severity %q for severity_remap[%q] (want %s)",
				c.SeverityRemap[k], k, strings.Join(policySeverities, ", "))
		}
	}
	return nil
}

// sortedKeys returns the map keys in a stable order, so that a config
// with more than one problem always reports the same one first.
func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// policyIsSeverity reports whether s is one of the four reportable
// severities. The comparison is case-insensitive.
func policyIsSeverity(s string) bool {
	s = strings.ToUpper(strings.TrimSpace(s))
	for _, sev := range policySeverities {
		if s == sev {
			return true
		}
	}
	return false
}

// ── the policy ─────────────────────────────────────────────────────────

// ConfigPolicy is the Policy built from a PolicyConfig.
//
// It is immutable after construction: the scanner calls the Policy from
// several worker goroutines, so nothing here may be written to once
// NewPolicy has returned.
type ConfigPolicy struct {
	ignores []policyIgnorePattern
	denies  []policyIgnorePattern
	rules   map[string]bool
	remap   map[string]string
	persona string
	inline  bool
}

// NewPolicy builds a Policy from a parsed config.
//
// A nil config returns NoPolicy: no configuration is a valid state, and
// it means "report everything".
func NewPolicy(c *PolicyConfig) (Policy, error) {
	if c == nil {
		return NoPolicy, nil
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	p := &ConfigPolicy{
		rules:   map[string]bool{},
		remap:   map[string]string{},
		persona: c.persona(),
		inline:  c.RespectInlineIgnores,
	}
	for _, a := range c.IgnoreActions {
		p.ignores = append(p.ignores, compilePolicyIgnore(a))
	}
	for _, d := range c.DenyIgnore {
		p.denies = append(p.denies, compilePolicyIgnore(d))
	}
	for _, r := range c.IgnoreRules {
		p.rules[strings.ToLower(strings.TrimSpace(r))] = true
	}
	for k, v := range c.SeverityRemap {
		p.remap[strings.ToLower(strings.TrimSpace(k))] = strings.ToUpper(strings.TrimSpace(v))
	}
	return p, nil
}

// Suppress implements Policy.
//
// deny_ignore wins over everything: an action the user marked as
// "never skip" keeps its findings even when a rule category is ignored
// wholesale.
func (p *ConfigPolicy) Suppress(f Finding) bool {
	if p == nil {
		return false
	}
	target := policyActionTarget(f.Action)
	if p.denied(target) {
		return false
	}
	if p.ignored(target) {
		return true
	}
	return p.rules[strings.ToLower(strings.TrimSpace(f.Category))]
}

// Severity implements Policy. An advisory id is more specific than a
// rule category, so it wins when both are remapped.
func (p *ConfigPolicy) Severity(f Finding) string {
	if p == nil {
		return ""
	}
	if f.AdvisoryID != "" {
		if sev, ok := p.remap[strings.ToLower(strings.TrimSpace(f.AdvisoryID))]; ok {
			return sev
		}
	}
	if sev, ok := p.remap[strings.ToLower(strings.TrimSpace(f.Category))]; ok {
		return sev
	}
	return ""
}

// Persona returns the sensitivity profile the policy was built with.
func (p *ConfigPolicy) Persona() string {
	if p == nil {
		return PersonaRegular
	}
	return p.persona
}

// RespectInlineIgnores reports whether inline ignore comments are
// honoured. The policy itself cannot apply them (it never sees the
// line a finding came from) — the scan path uses SuppressInline and
// checks this flag.
func (p *ConfigPolicy) RespectInlineIgnores() bool {
	return p != nil && p.inline
}

// PersonaFindings implements PersonaPolicy.
func (p *ConfigPolicy) PersonaFindings(repo, workflow, job string, a ActionRef) []Finding {
	if p == nil {
		return nil
	}
	return policyPersonaFindings(p.persona, repo, workflow, job, a)
}

// ignored reports whether the action path is covered by ignore_actions.
func (p *ConfigPolicy) ignored(target string) bool {
	for _, pat := range p.ignores {
		if pat.match(target) {
			return true
		}
	}
	return false
}

// denied reports whether the action path is covered by deny_ignore.
func (p *ConfigPolicy) denied(target string) bool {
	for _, pat := range p.denies {
		if pat.match(target) {
			return true
		}
	}
	return false
}

// PersonaPolicy is a Policy that can also contribute findings of its
// own. A persona cannot be expressed as "suppress less": it adds
// findings, which the Policy interface has no way to say.
type PersonaPolicy interface {
	Policy
	PersonaFindings(repo, workflow, job string, a ActionRef) []Finding
	// RespectInlineIgnores reports whether inline `# actionscan: ignore`
	// comments in a workflow should be honoured.
	RespectInlineIgnores() bool
	// Persona is the name of the active sensitivity profile.
	Persona() string
}

// ── ignore matching ────────────────────────────────────────────────────

// policyIgnorePattern is one compiled entry of ignore_actions or
// deny_ignore.
type policyIgnorePattern struct {
	raw     string
	all     bool   // "*" — matches everything
	prefix  string // "owner/repo/*" — matches everything below the repo
	glob    string // "some-org/internal-*" — a path.Match pattern
	literal string // "owner/repo" — the repo and its sub-path actions
}

// compilePolicyIgnore compiles one ignore entry.
//
// Three forms are supported:
//
//	owner/repo      the repo, and any of its sub-path actions
//	owner/repo/*    everything below the repo, at any depth
//	some-org/*      a glob
//
// Matching is case-insensitive: GitHub owner and repository names are.
func compilePolicyIgnore(raw string) policyIgnorePattern {
	p := policyIgnorePattern{raw: raw}
	s := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case s == "*":
		p.all = true
	case strings.HasSuffix(s, "/*"):
		// A trailing "*" is a prefix match, not a path.Match pattern:
		// "owner/repo/*" must also cover "owner/repo/sub/path".
		p.prefix = strings.TrimSuffix(s, "*")
	case strings.ContainsAny(s, "*?["):
		p.glob = s
	default:
		p.literal = strings.TrimSuffix(s, "/")
	}
	return p
}

// match reports whether the action path is covered by the pattern.
func (p policyIgnorePattern) match(target string) bool {
	switch {
	case p.all:
		return true
	case p.prefix != "":
		return strings.HasPrefix(target, p.prefix)
	case p.glob != "":
		ok, err := path.Match(p.glob, target)
		return err == nil && ok
	case p.literal != "":
		return target == p.literal || strings.HasPrefix(target, p.literal+"/")
	default:
		return false
	}
}

// policyIgnoreConflicts reports whether an ignore entry covers a denied
// action. Both directions are checked: a glob that covers the denied
// action counts, and so does a denied glob the ignore entry covers.
func policyIgnoreConflicts(ignore, deny string) bool {
	ip := compilePolicyIgnore(ignore)
	dp := compilePolicyIgnore(deny)
	if ip.match(policyActionTarget(deny)) {
		return true
	}
	return dp.match(policyActionTarget(ignore))
}

// policyActionTarget reduces a `uses:` value to the path an ignore
// entry is matched against: no ref, lower-cased, no trailing slash.
func policyActionTarget(action string) string {
	a := strings.TrimSpace(action)
	if i := strings.Index(a, "@"); i >= 0 {
		a = a[:i]
	}
	return strings.ToLower(strings.TrimSuffix(a, "/"))
}

// ── personas ───────────────────────────────────────────────────────────

// PersonaFindings returns the extra findings the configured persona
// adds for one action usage. It is empty for the regular persona.
//
// The persona adds findings; it never removes them. Filtering is the
// Policy's job, and a persona that hid findings would be a persona
// nobody could reason about.
func (c *PolicyConfig) PersonaFindings(repo, workflow, job string, a ActionRef) []Finding {
	if c == nil {
		return nil
	}
	return policyPersonaFindings(c.persona(), repo, workflow, job, a)
}

// policyPersonaFindings implements the three sensitivity profiles.
func policyPersonaFindings(persona, repo, workflow, job string, a ActionRef) []Finding {
	if job == "" {
		job = a.Job
	}
	switch persona {
	case PersonaPedantic:
		// A floating tag is the pinning case people skip: it looks
		// pinned, but it can be moved.
		if !policyFloatingTag(a.Ref) {
			return nil
		}
		return []Finding{{
			Repo: repo, Workflow: workflow, Job: job,
			Action: a.Raw, Ref: a.Ref,
			Severity: "LOW", Category: "unpinned",
			Reason: fmt.Sprintf("Mutable tag %q — a tag can be moved to a different commit", a.Ref),
			Fix:    fmt.Sprintf("Pin %s to a full 40-character commit SHA", a.FullName),
		}}
	case PersonaAuditor:
		// Everything that is not a full commit SHA. Noisy by design:
		// the auditor persona is opt-in and its job is to be strict.
		if policyFullSHA(a.Ref) {
			return nil
		}
		reason := fmt.Sprintf("Not pinned to a full 40-character commit SHA (ref %q)", a.Ref)
		if a.Ref == "" {
			reason = "No ref pinned — mutable action reference"
		}
		return []Finding{{
			Repo: repo, Workflow: workflow, Job: job,
			Action: a.Raw, Ref: a.Ref,
			Severity: "LOW", Category: "unpinned",
			Reason: reason,
			Fix:    fmt.Sprintf("Pin %s to a full 40-character commit SHA", a.FullName),
		}}
	default:
		return nil
	}
}

// policyFullSHA reports whether ref is a full 40-character commit SHA.
func policyFullSHA(ref string) bool {
	if len(ref) != 40 {
		return false
	}
	for i := 0; i < len(ref); i++ {
		c := ref[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// policyExactVersion reports whether ref is a specific release version
// ("v4.2.2"). A specific version is not a floating tag, but it is also
// not a commit SHA.
func policyExactVersion(ref string) bool {
	s := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(ref)), "v")
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for i := 0; i < len(p); i++ {
			if p[i] < '0' || p[i] > '9' {
				return false
			}
		}
	}
	return true
}

// policyFloatingTag reports whether ref is a version tag that floats
// ("v4", "v4.2"): a tag that looks pinned but can be moved, and is not
// a specific release.
func policyFloatingTag(ref string) bool {
	ref = strings.TrimSpace(ref)
	if ref == "" || policyFullSHA(ref) || policyExactVersion(ref) {
		return false
	}
	if ref[0] == 'v' || ref[0] == 'V' {
		return len(ref) > 1 && ref[1] >= '0' && ref[1] <= '9'
	}
	return ref[0] >= '0' && ref[0] <= '9'
}

// ── inline ignores ─────────────────────────────────────────────────────

// InlineIgnore is one ignore directive found in a workflow file.
type InlineIgnore struct {
	Line   int      // 1-based line number
	Rules  []string // rule categories to ignore; empty = all
	Reason string
}

// inlineIgnoreRe matches the directive itself. The rule list and the
// reason that may follow are parsed separately, because the reason is
// free text and may contain anything.
var inlineIgnoreRe = regexp.MustCompile(`(?i)#\s*actionscan:\s*ignore\b`)

// ParseInlineIgnores finds the ignore directives in a workflow file and
// returns them keyed by line number.
//
// The supported forms are:
//
//	# actionscan: ignore                    suppress every finding
//	# actionscan: ignore[outdated]          suppress one rule category
//	# actionscan: ignore[outdated,unpinned] suppress several
//	# actionscan: ignore reason text        suppress every finding, with a reason
//
// The scan is line-based and does not know YAML: a directive inside a
// `run:` block is parsed like any other. Deciding what to do with it is
// the caller's job.
func ParseInlineIgnores(content []byte) map[int]InlineIgnore {
	out := map[int]InlineIgnore{}
	if len(content) == 0 {
		return out
	}
	for i, line := range strings.Split(string(content), "\n") {
		loc := inlineIgnoreRe.FindStringIndex(line)
		if loc == nil {
			continue
		}
		rest := strings.TrimSpace(line[loc[1]:])
		ig := InlineIgnore{Line: i + 1}
		if strings.HasPrefix(rest, "[") {
			end := strings.Index(rest, "]")
			if end < 0 {
				continue // malformed rule list — not a directive
			}
			ig.Rules = splitInlineRules(rest[1:end])
			rest = strings.TrimSpace(rest[end+1:])
		}
		ig.Reason = rest
		out[i+1] = ig
	}
	return out
}

// splitInlineRules parses the comma-separated rule list of a directive.
func splitInlineRules(s string) []string {
	var out []string
	for _, r := range strings.Split(s, ",") {
		r = strings.ToLower(strings.TrimSpace(r))
		if r != "" {
			out = append(out, r)
		}
	}
	return out
}

// SuppressInline reports whether a finding on the given line is
// suppressed by an inline ignore directive.
//
// The line number must come from the workflow file: the finding itself
// does not carry one, so the scan path has to pass it in.
func SuppressInline(ignores map[int]InlineIgnore, f Finding, line int) bool {
	if len(ignores) == 0 || line <= 0 {
		return false
	}
	ig, ok := ignores[line]
	if !ok {
		return false
	}
	if len(ig.Rules) == 0 {
		return true // no rule list — every finding on this line is ignored
	}
	category := strings.ToLower(strings.TrimSpace(f.Category))
	for _, r := range ig.Rules {
		if r == category {
			return true
		}
		if f.AdvisoryID != "" && strings.EqualFold(r, f.AdvisoryID) {
			return true
		}
	}
	return false
}
