package github

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/google/go-github/v62/github"
)

// ── provenance: is the pinned commit really the upstream's? ────────────
//
// Pinning an action to a commit SHA is only half of the advice. The SHA
// is trustworthy only while the upstream project still carries that
// commit. A tag that is moved, a branch that is force-pushed, or a
// commit pushed by someone with write access all point the pin at code
// the upstream project never contained — an "imposter commit".
//
// The test is ancestry: the commit a ref resolves to must be an
// ancestor of SOME ref the repository publishes — a branch or a tag.
// GitHub's compare endpoint answers that in one call.
//
// With base = the candidate commit and head = the published ref, the
// status means:
//
//	"ahead"      the published ref is ahead of the candidate, so the
//	             candidate IS on that ref's history → trusted
//	"identical"  the candidate IS that ref's head → trusted
//	"behind"     the candidate contains that ref's head but is not on
//	             it → not trusted by this ref
//	"diverged"   the candidate is unrelated to that ref (a force-pushed
//	             or orphan commit) → not trusted by this ref
//
// The direction was confirmed against the live API: comparing an
// ancestor commit as base with "main" as head returns "ahead", and the
// same comparison reversed returns "behind".
//
// Checking only the DEFAULT BRANCH would be wrong: a legitimate pin to
// a release commit is usually not on the default branch. tj-actions/
// auto-doc pins the commit behind tag v3.6.0, which is on the release
// line, not on main — and the default-branch test calls that an imposter.
// The candidate is therefore tested against every published ref, and
// the default branch is only the first (cheapest) one tried.

// Provenance is the result of verifying one action reference.
//
// Checked and Trusted are separate on purpose. Checked says the check
// ran at all; Trusted says the commit is still published by the
// upstream project. A ref that could not be checked is NOT untrusted —
// it is unknown, and the difference has to survive into the report.
type Provenance struct {
	Repo      string // "owner/repo"
	Ref       string // the ref as written in the workflow
	CommitSHA string // the commit the ref resolved to
	Trusted   bool   // the commit is still reachable from a published ref
	Reason    string // why it is not trusted, empty when it is
	Checked   bool   // the check actually ran (false = could not check)
}

// VerifyProvenance checks whether the commit a ref resolves to is
// still reachable from a ref the repository publishes.
//
// A ref that cannot be resolved, a repository whose refs cannot be read
// and a rate-limited API all yield Checked == false: the check could not
// run, so nothing is claimed about the pin. A successful check that
// finds the commit on no branch and no tag yields Checked == true,
// Trusted == false and a reason.
//
// The result is cached for the lifetime of the client (concurrent
// callers share one upstream request), like the other lookups in this
// package. A failed check is cached too: retrying a rate-limited API
// for every occurrence of the same ref would stall the scan.
func (c *Client) VerifyProvenance(ctx context.Context, actionRepo, ref string) Provenance {
	owner, name, ok := splitActionRepo(actionRepo)
	if !ok || ref == "" {
		return Provenance{
			Repo:   actionRepo,
			Ref:    ref,
			Reason: "could not check: malformed repository name or empty ref",
		}
	}

	key := "r:" + actionRepo + "@" + ref
	cache := c.provenanceCache()

	cache.mu.Lock()
	if p, ok := cache.results[key]; ok {
		cache.mu.Unlock()
		return p
	}
	if done, ok := cache.inflight[key]; ok {
		// Another worker is verifying the same ref — wait for it.
		cache.mu.Unlock()
		<-done
		cache.mu.Lock()
		p, ok := cache.results[key]
		cache.mu.Unlock()
		if ok {
			return p
		}
		return Provenance{
			Repo:   actionRepo,
			Ref:    ref,
			Reason: "could not check: the verification did not produce a result",
		}
	}
	done := make(chan struct{})
	cache.inflight[key] = done
	cache.mu.Unlock()

	p := c.verifyProvenance(ctx, owner, name, actionRepo, ref)

	cache.mu.Lock()
	cache.results[key] = p
	delete(cache.inflight, key)
	cache.mu.Unlock()
	close(done)
	return p
}

// verifyProvenance does the work of one check: resolve the ref, then ask
// GitHub whether the commit is still on any published ref.
func (c *Client) verifyProvenance(ctx context.Context, owner, name, actionRepo, ref string) Provenance {
	p := Provenance{Repo: actionRepo, Ref: ref}

	// 1. Resolve the ref to the commit it points at. GitHub resolves a
	//    tag to the commit it points at, so the same lookup serves a
	//    SHA and a tag.
	commit, _, err := func() (*github.RepositoryCommit, *github.Response, error) {
		var cm *github.RepositoryCommit
		var resp *github.Response
		err := withRetry(ctx, func() (err error) {
			cm, resp, err = c.gh.Repositories.GetCommit(ctx, owner, name, ref, nil)
			return err
		})
		return cm, resp, err
	}()
	if err != nil || commit == nil || len(commit.GetSHA()) != 40 {
		p.Reason = fmt.Sprintf("could not check: cannot resolve %s@%s to a commit: %s",
			actionRepo, ref, provenanceErrText(err))
		return p
	}
	p.CommitSHA = commit.GetSHA()

	// 2. The default branch is the cheapest and most common answer, so
	//    it is tried on its own first. A commit on the default branch
	//    costs one comparison and never pays for the full ref list.
	if branch, err := c.defaultBranch(ctx, owner, name); err == nil {
		cmp, cmpErr := c.compareCommits(ctx, owner, name, p.CommitSHA, branch)
		switch {
		case cmpErr == nil && (cmp == "ahead" || cmp == "identical"):
			p.Checked = true
			p.Trusted = true
			return p
		case cmpErr == nil && (cmp == "behind" || cmp == "diverged"):
			// Not on the default branch — fall through to the
			// other published refs, since a release commit is
			// legitimately off the default branch.
		}
	}

	// 3. The commit is off the default branch. Test it against every
	//    published ref: a release or maintenance-branch commit is
	//    legitimate, only an orphan is an imposter.
	refs, refsErr := c.publishedRefs(ctx, owner, name)
	if len(refs) == 0 {
		if refsErr != nil {
			p.Reason = fmt.Sprintf("could not check: cannot read the branches and tags of %s: %s",
				actionRepo, provenanceErrText(refsErr))
		} else {
			p.Reason = fmt.Sprintf("could not check: %s publishes no branches or tags to check against", actionRepo)
		}
		return p
	}

	// 4. Is the commit an ancestor of any of them?
	unknown := false
	for _, r := range refs {
		cmp, err := c.compareCommits(ctx, owner, name, p.CommitSHA, r.ref)
		if err != nil {
			// One ref that cannot be compared does not invalidate the
			// others; keep going.
			continue
		}
		switch cmp {
		case "ahead", "identical":
			p.Checked = true
			p.Trusted = true
			return p
		case "behind", "diverged":
			// Not this ref; try the next one.
		default:
			// An answer the tool does not understand is not a
			// verdict, and it must not become one below.
			unknown = true
		}
	}

	// An unrecognised status makes the whole check inconclusive: GitHub
	// answered, but not in a way this tool can interpret.
	if unknown {
		p.Reason = fmt.Sprintf(
			"could not check: GitHub returned an unexpected comparison status for %s against the branches and tags of %s",
			p.CommitSHA, actionRepo)
		return p
	}

	// No published ref carries the commit. If every comparison ran, the
	// commit is an imposter.
	if c.allRefsCompared(ctx, owner, name, p.CommitSHA, refs) {
		p.Checked = true
		p.Trusted = false
		p.Reason = fmt.Sprintf(
			"imposter commit: %s@%s resolves to %s, which is not reachable from any branch or tag of %s — the pin points at a commit the upstream project does not publish",
			actionRepo, ref, p.CommitSHA, actionRepo)
		return p
	}

	// Some refs could not be compared, so the check is inconclusive.
	p.Reason = fmt.Sprintf(
		"could not check: could not compare %s against every branch and tag of %s",
		p.CommitSHA, actionRepo)
	return p
}

// compareCommits asks GitHub how two commits relate.
func (c *Client) compareCommits(ctx context.Context, owner, name, base, head string) (string, error) {
	cmp, _, err := func() (*github.CommitsComparison, *github.Response, error) {
		var cc *github.CommitsComparison
		var resp *github.Response
		err := withRetry(ctx, func() (err error) {
			// per_page=1: the status is a top-level field, the commit
			// list is not needed, and a long history would otherwise
			// be downloaded for nothing.
			cc, resp, err = c.gh.Repositories.CompareCommits(ctx, owner, name,
				base, head, &github.ListOptions{PerPage: 1})
			return err
		})
		return cc, resp, err
	}()
	if err != nil {
		return "", err
	}
	if cmp == nil {
		return "", fmt.Errorf("no comparison result")
	}
	return cmp.GetStatus(), nil
}

// allRefsCompared reports whether every published ref could be compared.
// A ref that errors makes the check inconclusive rather than a verdict.
func (c *Client) allRefsCompared(ctx context.Context, owner, name, sha string, refs []provenanceRef) bool {
	for _, r := range refs {
		if _, err := c.compareCommits(ctx, owner, name, sha, r.ref); err != nil {
			return false
		}
	}
	return true
}

// defaultBranch returns the default branch of a repository. It is a
// stable property of the repository and every check of every ref in it
// needs it, so it is cached for the lifetime of the client.
func (c *Client) defaultBranch(ctx context.Context, owner, name string) (string, error) {
	key := "b:" + owner + "/" + name
	cache := c.provenanceCache()

	cache.mu.Lock()
	if b, ok := cache.branches[key]; ok {
		cache.mu.Unlock()
		return b, nil
	}
	if done, ok := cache.inflight[key]; ok {
		// Another worker is reading the same repository — wait for it.
		cache.mu.Unlock()
		<-done
		cache.mu.Lock()
		b, ok := cache.branches[key]
		cache.mu.Unlock()
		if !ok {
			return "", fmt.Errorf("the default branch of %s/%s could not be read", owner, name)
		}
		return b, nil
	}
	done := make(chan struct{})
	cache.inflight[key] = done
	cache.mu.Unlock()

	repo, _, err := func() (*github.Repository, *github.Response, error) {
		var r *github.Repository
		var resp *github.Response
		err := withRetry(ctx, func() (err error) {
			r, resp, err = c.gh.Repositories.Get(ctx, owner, name)
			return err
		})
		return r, resp, err
	}()
	branch := repo.GetDefaultBranch()
	if err == nil && branch == "" {
		err = fmt.Errorf("repository %s/%s has no default branch", owner, name)
	}
	if err == nil {
		cache.mu.Lock()
		cache.branches[key] = branch
		cache.mu.Unlock()
	}
	cache.mu.Lock()
	delete(cache.inflight, key)
	cache.mu.Unlock()
	close(done)
	if err != nil {
		return "", err
	}
	return branch, nil
}

// ── published refs ─────────────────────────────────────────────────────

// provenanceRef is one published ref of a repository.
type provenanceRef struct {
	// ref is what the compare endpoint takes: a branch name or a commit
	// SHA.
	ref string
	// kind is "branch" or "tag", for the message.
	kind string
	// primary marks the default branch, which is tried first.
	primary bool
}

// publishedRefs lists the branches and tags a repository publishes.
//
// It is the set a pinned commit has to be reachable from. A commit that
// is on no branch and no tag is an orphan — the shape a force-push or
// an unauthorized push leaves behind.
//
// The list is cached for the lifetime of the client: it changes rarely
// and every check of every ref in the repository needs it.
func (c *Client) publishedRefs(ctx context.Context, owner, name string) ([]provenanceRef, error) {
	key := "r:" + owner + "/" + name
	cache := c.provenanceCache()

	cache.mu.Lock()
	if refs, ok := cache.refs[key]; ok {
		cache.mu.Unlock()
		return refs, nil
	}
	if done, ok := cache.inflight[key]; ok {
		cache.mu.Unlock()
		<-done
		cache.mu.Lock()
		refs, ok := cache.refs[key]
		cache.mu.Unlock()
		if !ok {
			return nil, fmt.Errorf("the branches and tags of %s/%s could not be read", owner, name)
		}
		return refs, nil
	}
	done := make(chan struct{})
	cache.inflight[key] = done
	cache.mu.Unlock()

	defaultBranch, _ := c.defaultBranch(ctx, owner, name)
	branches, branchListErr := c.listBranches(ctx, owner, name)
	tags, tagListErr := c.listTags(ctx, owner, name)

	var refs []provenanceRef
	for _, b := range branches {
		refs = append(refs, provenanceRef{ref: b, kind: "branch", primary: b == defaultBranch})
	}
	for _, t := range tags {
		refs = append(refs, provenanceRef{ref: t, kind: "tag"})
	}
	// The default branch first: it is the cheapest and most common
	// answer, so the common case costs one comparison.
	sortProvenanceRefs(refs)

	var err error
	switch {
	case branchListErr != nil && tagListErr != nil:
		err = fmt.Errorf("%s; %s", provenanceErrText(branchListErr), provenanceErrText(tagListErr))
	case branchListErr != nil:
		err = errors.New(provenanceErrText(branchListErr))
	case tagListErr != nil:
		err = errors.New(provenanceErrText(tagListErr))
	}
	if err == nil && len(refs) == 0 {
		err = fmt.Errorf("no branches or tags")
	}

	cache.mu.Lock()
	if err == nil {
		cache.refs[key] = refs
	}
	delete(cache.inflight, key)
	cache.mu.Unlock()
	close(done)
	if err != nil {
		return nil, err
	}
	return refs, nil
}

// listBranches returns the names of a repository's branches.
func (c *Client) listBranches(ctx context.Context, owner, name string) ([]string, error) {
	branches, _, err := func() ([]*github.Branch, *github.Response, error) {
		var bs []*github.Branch
		var resp *github.Response
		err := withRetry(ctx, func() (err error) {
			bs, resp, err = c.gh.Repositories.ListBranches(ctx, owner, name,
				&github.BranchListOptions{ListOptions: github.ListOptions{PerPage: 100}})
			return err
		})
		return bs, resp, err
	}()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(branches))
	for _, b := range branches {
		if b.GetName() != "" {
			out = append(out, b.GetName())
		}
	}
	return out, nil
}

// listTags returns the commit SHAs a repository's tags point at.
//
// A tag is compared by commit SHA rather than by name: comparing
// against a tag name resolves the tag again, and a tag that has been
// moved would then make an imposter commit look like the tag's target.
func (c *Client) listTags(ctx context.Context, owner, name string) ([]string, error) {
	tags, _, err := func() ([]*github.RepositoryTag, *github.Response, error) {
		var ts []*github.RepositoryTag
		var resp *github.Response
		err := withRetry(ctx, func() (err error) {
			ts, resp, err = c.gh.Repositories.ListTags(ctx, owner, name,
				&github.ListOptions{PerPage: 100})
			return err
		})
		return ts, resp, err
	}()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		if sha := t.GetCommit().GetSHA(); sha != "" {
			out = append(out, sha)
		}
	}
	return out, nil
}

// sortProvenanceRefs puts the default branch first, then the rest in a
// stable order, so the cheapest comparison is tried first and the
// result does not depend on the API's ordering.
func sortProvenanceRefs(refs []provenanceRef) {
	sort.SliceStable(refs, func(i, j int) bool {
		if refs[i].primary != refs[j].primary {
			return refs[i].primary
		}
		if refs[i].kind != refs[j].kind {
			return refs[i].kind < refs[j].kind
		}
		return refs[i].ref < refs[j].ref
	})
}

// ── cache ──────────────────────────────────────────────────────────────

// provenanceCache is one client's memo of provenance lookups.
//
// The Client struct lives in client.go, which this change does not
// touch, so the memo is kept in a side table keyed by the client
// pointer. Every client gets its own namespace, so a result is never
// served to another client (or to another API host).
type provenanceCache struct {
	mu       sync.Mutex
	results  map[string]Provenance      // "r:owner/repo@ref" -> result
	branches map[string]string          // "b:owner/repo" -> default branch
	refs     map[string][]provenanceRef // "r:owner/repo" -> published refs
	inflight map[string]chan struct{}
}

// provenanceCaches maps a client to its cache.
var provenanceCaches sync.Map // *Client -> *provenanceCache

// provenanceCache returns the client's cache, creating it on first use.
func (c *Client) provenanceCache() *provenanceCache {
	v, _ := provenanceCaches.LoadOrStore(c, &provenanceCache{
		results:  map[string]Provenance{},
		branches: map[string]string{},
		refs:     map[string][]provenanceRef{},
		inflight: map[string]chan struct{}{},
	})
	return v.(*provenanceCache)
}

// ── helpers ────────────────────────────────────────────────────────────

// splitActionRepo splits "owner/repo" into its two halves.
func splitActionRepo(actionRepo string) (owner, name string, ok bool) {
	parts := strings.SplitN(actionRepo, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// provenanceErrText renders an API error as one short line.
func provenanceErrText(err error) string {
	if err == nil {
		return "unknown error"
	}
	s := strings.TrimSpace(err.Error())
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	return s
}
