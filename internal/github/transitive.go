package github

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/google/go-github/v62/github"
	"gopkg.in/yaml.v3"
)

// ── transitive dependency graph ─────────────────────────────────────────
//
// A workflow can call an action, that action can be a composite action
// whose own action.yml calls further actions, and a workflow can call a
// reusable workflow whose body calls further actions. Those edges are
// invisible to a scanner that only reads the top-level workflow files,
// and a compromised action three hops away is exactly the thing that
// matters.
//
// The budgets below are the ones documented by the only prior art in this
// space (scharf, ADR 004). They are not arbitrary: a dependency graph is
// attacker-controlled. A repository can nest composite actions arbitrarily
// deep and can ship a metadata file large enough to exhaust memory, so
// every unbounded dimension is a denial-of-service vector aimed at the
// scanner itself.
//
// The rule that makes the whole thing trustworthy: a traversal that ran
// out of budget is INCOMPLETE, never clean. A security tool that reports
// "clean" when it stopped early is worse than useless.

// TransitiveLimits bounds a transitive traversal.
//
// A non-positive field means "use the default", so the zero value is a
// usable configuration rather than a traversal that does nothing.
type TransitiveLimits struct {
	// MaxDepth is how many `uses:` hops may be followed from a
	// workflow. A reference written in the workflow itself is depth 1.
	MaxDepth int
	// MaxStructures is the number of YAML nodes, aliases and mapping
	// keys that may be parsed across the whole traversal.
	MaxStructures int
	// MaxMetadataBytes is the total size of the unique metadata files
	// read during the traversal.
	MaxMetadataBytes int64
	// MaxRequests is the number of GitHub API requests the traversal
	// may make.
	MaxRequests int
	// MaxResponseBytes is the largest single API response accepted.
	MaxResponseBytes int64
	// MaxFileBytes is the largest single metadata file accepted.
	MaxFileBytes int64
	// RequestTimeout is the per-request timeout.
	RequestTimeout time.Duration
}

// The documented defaults. See the table in ADR 004.
const (
	transitiveDepth         = 12
	transitiveStructures    = 5000
	transitiveMetadataBytes = 8 << 20
	transitiveRequests      = 500
	transitiveResponseBytes = 2 << 20
	transitiveFileBytes     = 1 << 20
	transitiveTimeout       = 15 * time.Second

	// maxTransitiveReasons is how many distinct reasons the result
	// lists before the rest are counted.
	maxTransitiveReasons = 8
)

// DefaultTransitiveLimits returns the documented defaults.
func DefaultTransitiveLimits() TransitiveLimits {
	return TransitiveLimits{
		MaxDepth:         transitiveDepth,
		MaxStructures:    transitiveStructures,
		MaxMetadataBytes: transitiveMetadataBytes,
		MaxRequests:      transitiveRequests,
		MaxResponseBytes: transitiveResponseBytes,
		MaxFileBytes:     transitiveFileBytes,
		RequestTimeout:   transitiveTimeout,
	}
}

// normalizeTransitiveLimits fills in the defaults for any limit that was
// left at zero, so a caller cannot accidentally configure a traversal
// that does nothing.
func normalizeTransitiveLimits(l TransitiveLimits) TransitiveLimits {
	d := DefaultTransitiveLimits()
	if l.MaxDepth <= 0 {
		l.MaxDepth = d.MaxDepth
	}
	if l.MaxStructures <= 0 {
		l.MaxStructures = d.MaxStructures
	}
	if l.MaxMetadataBytes <= 0 {
		l.MaxMetadataBytes = d.MaxMetadataBytes
	}
	if l.MaxRequests <= 0 {
		l.MaxRequests = d.MaxRequests
	}
	if l.MaxResponseBytes <= 0 {
		l.MaxResponseBytes = d.MaxResponseBytes
	}
	if l.MaxFileBytes <= 0 {
		l.MaxFileBytes = d.MaxFileBytes
	}
	if l.RequestTimeout <= 0 {
		l.RequestTimeout = d.RequestTimeout
	}
	return l
}

// TransitiveNode is one action reached during the traversal.
type TransitiveNode struct {
	Repo  string // "owner/repo"
	Path  string // sub-path within the repo, e.g. "action.yml" or ".github/workflows/ci.yml"
	Ref   string // the ref as written in the `uses:` line
	SHA   string // the commit the metadata was read at ("" when unresolved)
	Depth int    // 1 = referenced by the workflow itself
	Via   []string
	// Composite is true when the node was resolved from a composite
	// action.yml, Workflow when it was resolved from a reusable
	// workflow.
	Composite bool
	Workflow  bool
	// Cycle is true when the node repeats one of its own ancestors. The
	// graph is complete, it is just cyclic.
	Cycle bool
	// RootWorkflow and RootJob are the top-level workflow and job the
	// chain starts from.
	RootWorkflow string
	RootJob      string
}

// TransitiveResult is the outcome of a traversal.
type TransitiveResult struct {
	Nodes []TransitiveNode
	// Complete is false when the graph could not be resolved in full.
	// An incomplete graph is never clean.
	Complete bool
	// Reason explains why the traversal is incomplete; empty when it is
	// complete.
	Reason     string
	Requests   int
	Structures int
}

// Sentinel failures. Each one is a reason the traversal could not see
// everything it set out to see.
var (
	errTransitiveStructures    = errors.New("YAML structure budget exhausted")
	errTransitiveResponseBytes = errors.New("API response exceeds the size budget")
	errTransitiveFileBytes     = errors.New("metadata file exceeds the size budget")
	errTransitiveRequestBudget = errors.New("API request budget exhausted")
	errTransitiveMetaBudget    = errors.New("metadata byte budget exhausted")
)

// ResolveTransitive walks the dependency graph of a set of workflows.
//
// The traversal follows declarative `uses:` edges through composite
// actions and reusable workflows. Every remote reference is resolved to a
// full commit SHA before its metadata is read, because a tag can be moved
// between the moment a workflow is written and the moment it runs — and
// reading the file at the SHA is what makes the graph trustworthy.
//
// The result is honest about what it could not see: when a budget runs
// out, a file cannot be read, or a ref cannot be resolved, the result is
// INCOMPLETE (Complete == false) with the reason recorded.
//
// The error return is reserved for a failure that stopped the traversal
// from running at all (a cancelled context). Incompleteness is reported
// through the result rather than as an error, so a caller cannot mistake
// it for "nothing to do" and throw away the nodes that WERE resolved.
func (c *Client) ResolveTransitive(ctx context.Context, r Repo, workflows map[string][]byte, limits TransitiveLimits) (TransitiveResult, error) {
	limits = normalizeTransitiveLimits(limits)
	t := &transitiveTraversal{
		c:         c,
		limits:    limits,
		complete:  true,
		reasonSet: map[string]bool{},
		shaCache:  map[string]string{},
		expanded:  map[string]transitiveExpanded{},
		failed:    map[string]bool{},
	}

	// The roots: every reference written in the workflow files
	// themselves.
	var queue []transitiveEdge
	for _, p := range transitiveSortedPaths(workflows) {
		root, merge, err := t.parseYAML(workflows[p])
		if err != nil {
			t.fail("cannot parse workflow %s of %s: %v", p, r.FullName, err)
			continue
		}
		if merge {
			t.fail("YAML merge keys in workflow %s of %s are not resolved, so a `uses:` there may be missed",
				p, r.FullName)
		}
		for _, ref := range transitiveUsesInWorkflow(root) {
			queue = append(queue, transitiveEdge{
				owner: ref.owner, name: ref.name, repo: ref.repo,
				path: ref.path, ref: ref.ref, depth: 1,
				rootWorkflow: p, rootJob: ref.job,
			})
		}
	}

	for len(queue) > 0 && !t.stop {
		if err := ctx.Err(); err != nil {
			return t.result(), err
		}
		e := queue[0]
		queue = queue[1:]
		if e.depth > t.limits.MaxDepth {
			t.fail("depth budget of %d exhausted at %s", t.limits.MaxDepth, e.repo)
			continue
		}
		children := t.expand(ctx, e)
		queue = append(queue, children...)
	}

	return t.result(), nil
}

// ── traversal ───────────────────────────────────────────────────────────

type transitiveExpanded struct {
	composite bool
	workflow  bool
}

// transitiveEdge is one pending `uses:` edge.
type transitiveEdge struct {
	owner, name           string
	repo                  string // "owner/name"
	path                  string // file to read inside the repo
	ref                   string // the ref as written
	depth                 int
	chain                 []string // keys of the ancestors, root first
	rootWorkflow, rootJob string
}

type transitiveTraversal struct {
	c      *Client
	limits TransitiveLimits

	nodes       []TransitiveNode
	reasons     []string
	reasonSet   map[string]bool
	moreReasons int
	complete    bool
	stop        bool

	requests   int
	structures int
	metaBytes  int64

	shaCache map[string]string
	expanded map[string]transitiveExpanded
	failed   map[string]bool
}

func (t *transitiveTraversal) result() TransitiveResult {
	reason := strings.Join(t.reasons, "; ")
	if t.moreReasons > 0 {
		reason += fmt.Sprintf(" (and %d more reasons)", t.moreReasons)
	}
	return TransitiveResult{
		Nodes:      t.nodes,
		Complete:   t.complete,
		Reason:     reason,
		Requests:   t.requests,
		Structures: t.structures,
	}
}

// fail records why the traversal is incomplete.
func (t *transitiveTraversal) fail(format string, args ...any) {
	t.complete = false
	msg := fmt.Sprintf(format, args...)
	if t.reasonSet[msg] {
		return
	}
	t.reasonSet[msg] = true
	// A long list of reasons is unreadable: the first few say what
	// matters and the rest are counted.
	if len(t.reasons) < maxTransitiveReasons {
		t.reasons = append(t.reasons, msg)
		return
	}
	t.moreReasons++
}

// expand resolves one edge and returns the edges it leads to.
func (t *transitiveTraversal) expand(ctx context.Context, e transitiveEdge) []transitiveEdge {
	sha, err := t.resolveRef(ctx, e.owner, e.name, e.ref)
	if err != nil {
		t.fail("cannot resolve %s@%s to a commit: %v", e.repo, e.ref, err)
		return nil
	}

	key := e.repo + "|" + e.path + "|" + sha
	chain := make([]string, 0, len(e.chain)+1)
	chain = append(chain, e.chain...)
	chain = append(chain, key)

	node := TransitiveNode{
		Repo:         e.repo,
		Path:         e.path,
		Ref:          e.ref,
		SHA:          sha,
		Depth:        e.depth,
		Via:          transitiveVia(chain),
		RootWorkflow: e.rootWorkflow,
		RootJob:      e.rootJob,
	}
	for _, k := range e.chain {
		if k == key {
			node.Cycle = true
			break
		}
	}

	if prev, ok := t.expanded[key]; ok {
		// Already resolved elsewhere in the graph. The caller chain is
		// still recorded — an action reachable by two paths is worth
		// seeing twice — but the file is not read again.
		node.Composite, node.Workflow = prev.composite, prev.workflow
		t.nodes = append(t.nodes, node)
		return nil
	}
	if t.failed[key] {
		// Already tried and refused. The reason was recorded the first
		// time; the file is not fetched again.
		return nil
	}

	data, err := t.readFile(ctx, e, sha)
	if err != nil {
		t.fail("cannot read %s/%s@%s: %v", e.repo, e.path, e.ref, err)
		t.failed[key] = true
		// A global budget that ran out stops the whole traversal: the
		// rest of the graph is unknown, not clean.
		if errors.Is(err, errTransitiveMetaBudget) || errors.Is(err, errTransitiveRequestBudget) {
			t.stop = true
		}
		return nil
	}

	root, merge, err := t.parseYAML(data)
	if err != nil {
		t.fail("cannot parse %s/%s@%s: %v", e.repo, e.path, e.ref, err)
		t.failed[key] = true
		if errors.Is(err, errTransitiveStructures) {
			t.stop = true
		}
		return nil
	}
	if merge {
		t.fail("YAML merge keys in %s/%s@%s are not resolved, so a `uses:` there may be missed",
			e.repo, e.path, e.ref)
	}

	var refs []transitiveRef
	if transitiveIsWorkflowPath(e.path) {
		node.Workflow = true
		refs = transitiveUsesInWorkflow(root)
	} else {
		composite, crefs := transitiveUsesInComposite(root)
		node.Composite = composite
		refs = crefs
	}
	t.expanded[key] = transitiveExpanded{composite: node.Composite, workflow: node.Workflow}
	t.nodes = append(t.nodes, node)

	var children []transitiveEdge
	for _, ref := range refs {
		children = append(children, transitiveEdge{
			owner: ref.owner, name: ref.name, repo: ref.repo,
			path: ref.path, ref: ref.ref, depth: e.depth + 1,
			chain:        chain,
			rootWorkflow: e.rootWorkflow, rootJob: e.rootJob,
		})
	}
	return children
}

// resolveRef expands a ref to the full commit SHA the metadata is read
// at. A ref that is already a full SHA needs no lookup.
func (t *transitiveTraversal) resolveRef(ctx context.Context, owner, name, ref string) (string, error) {
	if ref == "" {
		return "", errors.New("no ref pinned")
	}
	if transitiveFullSHA(ref) {
		return ref, nil
	}
	key := owner + "/" + name + "@" + ref
	if sha, ok := t.shaCache[key]; ok {
		return sha, nil
	}
	raw, err := t.fetch(ctx, fmt.Sprintf("repos/%s/%s/commits/%s", owner, name, url.PathEscape(ref)))
	if err != nil {
		return "", err
	}
	var commit struct {
		SHA string `json:"sha"`
	}
	if err := json.Unmarshal(raw, &commit); err != nil {
		return "", fmt.Errorf("unexpected commit response: %w", err)
	}
	if len(commit.SHA) != 40 {
		return "", fmt.Errorf("ref did not resolve to a full commit SHA")
	}
	t.shaCache[key] = commit.SHA
	return commit.SHA, nil
}

// readFile reads one metadata file at a commit and charges it against
// the byte budget.
func (t *transitiveTraversal) readFile(ctx context.Context, e transitiveEdge, sha string) ([]byte, error) {
	paths := []string{e.path}
	if alt := transitiveAltPath(e.path); alt != "" {
		paths = append(paths, alt)
	}
	var err error
	for _, p := range paths {
		var data []byte
		data, err = t.readContent(ctx, e.owner, e.name, p, sha)
		if err == nil {
			t.metaBytes += int64(len(data))
			if t.metaBytes > t.limits.MaxMetadataBytes {
				return nil, errTransitiveMetaBudget
			}
			return data, nil
		}
		// Only a missing file justifies trying the other name; anything
		// else (too large, rate limited) is the answer.
		var errResp *github.ErrorResponse
		if !errors.As(err, &errResp) || errResp.Response == nil ||
			errResp.Response.StatusCode != 404 {
			return nil, err
		}
	}
	return nil, err
}

// readContent fetches one file through the contents API.
func (t *transitiveTraversal) readContent(ctx context.Context, owner, name, path, ref string) ([]byte, error) {
	u := fmt.Sprintf("repos/%s/%s/contents/%s?ref=%s", owner, name,
		transitiveEscapePath(path), url.QueryEscape(ref))
	raw, err := t.fetch(ctx, u)
	if err != nil {
		return nil, err
	}
	trimmed := bytes.TrimLeft(raw, " \t\r\n")
	if len(trimmed) > 0 && trimmed[0] == '[' {
		return nil, errors.New("path is a directory, not a file")
	}
	var file github.RepositoryContent
	if err := json.Unmarshal(raw, &file); err != nil {
		return nil, fmt.Errorf("unexpected contents response: %w", err)
	}
	// A symlink is not a regular file and is not read.
	if typ := file.GetType(); typ != "" && typ != "file" {
		return nil, fmt.Errorf("not a regular file (%s)", typ)
	}
	if enc := file.GetEncoding(); enc != "base64" {
		return nil, fmt.Errorf("unsupported content encoding %q", enc)
	}
	if file.Content == nil {
		return nil, errors.New("empty content")
	}
	if size := int64(file.GetSize()); size > t.limits.MaxFileBytes {
		return nil, errTransitiveFileBytes
	}
	// GitHub wraps base64 content at 60 chars with newlines; strip them
	// or decoding fails.
	stripped := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, *file.Content)
	data, err := base64.StdEncoding.DecodeString(stripped)
	if err != nil {
		return nil, fmt.Errorf("cannot decode content: %w", err)
	}
	if int64(len(data)) > t.limits.MaxFileBytes {
		return nil, errTransitiveFileBytes
	}
	return data, nil
}

// fetch performs one bounded API request.
func (t *transitiveTraversal) fetch(ctx context.Context, u string) ([]byte, error) {
	var body []byte
	err := withRetry(ctx, func() error {
		if t.requests >= t.limits.MaxRequests {
			return errTransitiveRequestBudget
		}
		t.requests++
		b, err := t.fetchOnce(ctx, u)
		if err != nil {
			return err
		}
		body = b
		return nil
	})
	return body, err
}

// fetchOnce performs a single request, refusing a response larger than
// the per-response budget instead of buffering it.
func (t *transitiveTraversal) fetchOnce(ctx context.Context, u string) ([]byte, error) {
	req, err := t.c.gh.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, t.limits.RequestTimeout)
	defer cancel()
	req = req.WithContext(ctx)

	resp, err := t.c.gh.Client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, github.CheckResponse(resp)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, t.limits.MaxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > t.limits.MaxResponseBytes {
		return nil, errTransitiveResponseBytes
	}
	return body, nil
}

// parseYAML parses a document and charges its structures against the
// budget. It also reports whether the document uses YAML merge keys,
// which the parser does not resolve.
//
// The structure budget is PER DOCUMENT. It exists to bound a single
// pathological file, not the whole traversal: charging every fetched
// file against one counter makes a repo with thirty ordinary actions
// exhaust the budget and report INCOMPLETE, which is worse than not
// scanning at all. The total work of a traversal is bounded separately
// by the request and byte budgets.
func (t *transitiveTraversal) parseYAML(data []byte) (root *yaml.Node, merge bool, err error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, false, fmt.Errorf("invalid YAML: %w", err)
	}
	root = transitiveDocRoot(&doc)
	stats, over := transitiveScan(root, 0)
	if over || stats.structures > t.limits.MaxStructures {
		return nil, false, errTransitiveStructures
	}
	t.structures += stats.structures
	return root, stats.merge, nil
}

// ── YAML helpers ────────────────────────────────────────────────────────

// transitiveDocRoot unwraps the document node to the mapping it holds.
func transitiveDocRoot(n *yaml.Node) *yaml.Node {
	if n == nil {
		return nil
	}
	if n.Kind == yaml.DocumentNode {
		if len(n.Content) == 0 {
			return nil
		}
		return n.Content[0]
	}
	return n
}

// transitiveFollow resolves an alias node to the node it points at.
//
// The YAML parser does not expand aliases when decoding into a node tree,
// so a `uses:` hidden behind one would otherwise be missed entirely.
func transitiveFollow(n *yaml.Node) *yaml.Node {
	for i := 0; n != nil && n.Kind == yaml.AliasNode && i < 16; i++ {
		n = n.Alias
	}
	return n
}

// transitiveMapValue returns the value node for key in a mapping node.
func transitiveMapValue(n *yaml.Node, key string) *yaml.Node {
	n = transitiveFollow(n)
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return transitiveFollow(n.Content[i+1])
		}
	}
	return nil
}

// transitiveScalarValue returns the resolved scalar of a node.
func transitiveScalarValue(n *yaml.Node) string {
	n = transitiveFollow(n)
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}

// transitiveYAMLStats is what one document cost.
type transitiveYAMLStats struct {
	structures int
	merge      bool
}

// transitiveScan counts the YAML structures of a document: every node,
// every alias and every mapping key.
func transitiveScan(n *yaml.Node, depth int) (transitiveYAMLStats, bool) {
	var st transitiveYAMLStats
	if n == nil {
		return st, false
	}
	if depth > 1000 {
		// Pathologically nested YAML: refuse rather than recurse.
		st.structures = 1 << 30
		return st, true
	}
	st.structures = 1
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == "<<" {
				st.merge = true
			}
		}
	}
	for _, child := range n.Content {
		s, over := transitiveScan(child, depth+1)
		st.structures += s.structures
		st.merge = st.merge || s.merge
		if over {
			return st, true
		}
	}
	return st, false
}

// ── reference extraction ────────────────────────────────────────────────

// transitiveRef is one `uses:` reference found in a document.
type transitiveRef struct {
	owner, name string
	repo        string // "owner/name"
	path        string // the file to read inside the repo
	ref         string
	job         string
}

// transitiveUsesInWorkflow returns the `uses:` references of a workflow
// file: job-level reusable workflow calls and step-level action calls.
func transitiveUsesInWorkflow(root *yaml.Node) []transitiveRef {
	var out []transitiveRef
	jobs := transitiveMapValue(root, "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		jobName := jobs.Content[i].Value
		job := jobs.Content[i+1]
		if job.Kind != yaml.MappingNode {
			continue
		}
		if ref, ok := transitiveParseUses(transitiveScalarValue(transitiveMapValue(job, "uses"))); ok {
			ref.job = jobName
			out = append(out, ref)
		}
		steps := transitiveMapValue(job, "steps")
		if steps == nil || steps.Kind != yaml.SequenceNode {
			continue
		}
		for _, step := range steps.Content {
			if step.Kind != yaml.MappingNode {
				continue
			}
			if ref, ok := transitiveParseUses(transitiveScalarValue(transitiveMapValue(step, "uses"))); ok {
				ref.job = jobName
				out = append(out, ref)
			}
		}
	}
	return out
}

// transitiveUsesInComposite returns the `uses:` references of a composite
// action, and whether the action is composite at all. A plain action
// (runs.using: node20 and friends) has no transitive references.
func transitiveUsesInComposite(root *yaml.Node) (bool, []transitiveRef) {
	runs := transitiveMapValue(root, "runs")
	if runs == nil {
		return false, nil
	}
	if strings.ToLower(transitiveScalarValue(transitiveMapValue(runs, "using"))) != "composite" {
		return false, nil
	}
	steps := transitiveMapValue(runs, "steps")
	if steps == nil || steps.Kind != yaml.SequenceNode {
		return true, nil
	}
	var out []transitiveRef
	for _, step := range steps.Content {
		if step.Kind != yaml.MappingNode {
			continue
		}
		if ref, ok := transitiveParseUses(transitiveScalarValue(transitiveMapValue(step, "uses"))); ok {
			out = append(out, ref)
		}
	}
	return true, out
}

// transitiveParseUses turns one raw `uses:` value into a reference, or
// reports that it is not a remote reference this traversal can follow.
func transitiveParseUses(raw string) (transitiveRef, bool) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return transitiveRef{}, false
	}
	if strings.Contains(v, "${{") {
		return transitiveRef{}, false // expression: the real ref is not known
	}
	if strings.HasPrefix(v, "./") {
		return transitiveRef{}, false // local action
	}
	if strings.HasPrefix(v, "$/") {
		return transitiveRef{}, false // self-repository syntax
	}
	if strings.HasPrefix(v, "docker://") {
		return transitiveRef{}, false // container image
	}

	name, ref := v, ""
	if at := strings.Index(v, "@"); at >= 0 {
		name = strings.TrimSpace(v[:at])
		ref = strings.TrimSpace(v[at+1:])
	}
	segs := strings.Split(name, "/")
	if len(segs) < 2 || segs[0] == "" || segs[1] == "" {
		return transitiveRef{}, false // not an "owner/repo" reference
	}
	sub := strings.Join(segs[2:], "/")
	path := "action.yml"
	switch {
	case sub == "":
	case transitiveIsWorkflowPath(sub):
		path = sub // reusable workflow
	default:
		path = sub + "/action.yml"
	}
	return transitiveRef{
		owner: segs[0], name: segs[1], repo: segs[0] + "/" + segs[1],
		path: path, ref: ref,
	}, true
}

// transitiveIsWorkflowPath reports whether a sub-path names a reusable
// workflow. GitHub only allows those under .github/workflows.
func transitiveIsWorkflowPath(p string) bool {
	return strings.HasPrefix(p, ".github/workflows/") &&
		(strings.HasSuffix(p, ".yml") || strings.HasSuffix(p, ".yaml"))
}

// transitiveAltPath returns the other accepted metadata file name for an
// action, or "" when there is none.
func transitiveAltPath(p string) string {
	if p == "action.yml" {
		return "action.yaml"
	}
	if strings.HasSuffix(p, "/action.yml") {
		return strings.TrimSuffix(p, "/action.yml") + "/action.yaml"
	}
	return ""
}

// transitiveEscapePath escapes each segment of a repository path.
func transitiveEscapePath(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/")
}

// transitiveVia turns a chain of node keys into the chain of repos.
func transitiveVia(chain []string) []string {
	out := make([]string, 0, len(chain))
	for _, k := range chain {
		if i := strings.Index(k, "|"); i > 0 {
			out = append(out, k[:i])
		}
	}
	return out
}

// transitiveFullSHA reports whether a ref is a full 40-char commit SHA.
func transitiveFullSHA(ref string) bool {
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

// transitiveSortedPaths returns the workflow paths in a stable order.
func transitiveSortedPaths(workflows map[string][]byte) []string {
	out := make([]string, 0, len(workflows))
	for p := range workflows {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
