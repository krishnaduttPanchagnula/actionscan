package github

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/go-github/v62/github"
	"golang.org/x/oauth2"
)

type Client struct {
	gh *github.Client

	latestMu       sync.Mutex
	latest         map[string]string
	latestInflight map[string]chan struct{}

	shaMu       sync.Mutex
	sha         map[string]string // "repo@shortsha" -> full 40-char sha ("" = unresolvable)
	shaInflight map[string]chan struct{}
}

func New(token string) *Client {
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	return &Client{
		gh:     github.NewClient(oauth2.NewClient(context.Background(), ts)),
		latest: map[string]string{},
		sha:    map[string]string{},
	}
}

// ── rate limits ────────────────────────────────────────────────────────
//
// An org-wide scan makes thousands of API calls. Without handling the
// limits, a 403 either aborts the whole run or silently drops repos.
// Both are worse than waiting.

// maxRetries bounds how many times a rate-limited call is retried.
const maxRetries = 3

// maxRetryWait caps a single wait, so a rate limit cannot stall a scan
// for an hour.
const maxRetryWait = 2 * time.Minute

// retry waits for a rate limit to reset and reports whether the caller
// should try again.
func retry(err error) (bool, time.Duration) {
	var rateErr *github.RateLimitError
	if errors.As(err, &rateErr) {
		wait := time.Until(rateErr.Rate.Reset.Time) + time.Second
		if wait < time.Second {
			wait = time.Second
		}
		return true, wait
	}
	var abuseErr *github.AbuseRateLimitError
	if errors.As(err, &abuseErr) {
		wait := 5 * time.Second
		if abuseErr.RetryAfter != nil {
			wait = *abuseErr.RetryAfter
		}
		return true, wait
	}
	// GitHub answers secondary rate limits with 429, which go-github
	// reports as a plain error response — not as a rate-limit type.
	// Treating it as fatal would abort a whole org scan over a pause.
	var errResp *github.ErrorResponse
	if errors.As(err, &errResp) && errResp.Response != nil {
		if errResp.Response.StatusCode == http.StatusTooManyRequests {
			wait := 5 * time.Second
			if v := errResp.Response.Header.Get("Retry-After"); v != "" {
				if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
					wait = time.Duration(secs) * time.Second
				}
			}
			return true, wait
		}
	}
	return false, 0
}

// withRetry runs fn, waiting out GitHub rate limits.
//
// The error is returned unchanged when it is not a rate limit, so
// callers keep their existing error handling.
func withRetry(ctx context.Context, fn func() error) error {
	var err error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		err = fn()
		if err == nil {
			return nil
		}
		ok, wait := retry(err)
		if !ok {
			return err
		}
		if attempt == maxRetries {
			return fmt.Errorf("rate limited after %d retries: %w", maxRetries, err)
		}
		if wait > maxRetryWait {
			wait = maxRetryWait
		}
		log.Printf("actionscan: rate limited, waiting %s before retrying", wait.Round(time.Second))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
	return err
}

type Repo struct {
	FullName      string
	Owner         string
	Name          string
	DefaultBranch string
	Private       bool
}

func (c *Client) ListRepos(ctx context.Context, org, user string) ([]Repo, error) {
	var repos []*github.Repository

	switch {
	case org != "":
		opts := &github.RepositoryListByOrgOptions{
			Type:        "all",
			ListOptions: github.ListOptions{PerPage: 100},
		}
		for {
			var page []*github.Repository
			var resp *github.Response
			err := withRetry(ctx, func() (err error) {
				page, resp, err = c.gh.Repositories.ListByOrg(ctx, org, opts)
				return err
			})
			if err != nil {
				return nil, err
			}
			repos = append(repos, page...)
			if resp.NextPage == 0 {
				break
			}
			opts.Page = resp.NextPage
		}
	case user != "":
		opts := &github.RepositoryListOptions{
			Type:        "owner",
			ListOptions: github.ListOptions{PerPage: 100},
		}
		for {
			var page []*github.Repository
			var resp *github.Response
			err := withRetry(ctx, func() (err error) {
				page, resp, err = c.gh.Repositories.List(ctx, user, opts)
				return err
			})
			if err != nil {
				return nil, err
			}
			repos = append(repos, page...)
			if resp.NextPage == 0 {
				break
			}
			opts.Page = resp.NextPage
		}
	default:
		opts := &github.RepositoryListOptions{
			Affiliation: "owner,collaborator,organization_member",
			ListOptions: github.ListOptions{PerPage: 100},
		}
		for {
			var page []*github.Repository
			var resp *github.Response
			err := withRetry(ctx, func() (err error) {
				page, resp, err = c.gh.Repositories.List(ctx, "", opts)
				return err
			})
			if err != nil {
				return nil, err
			}
			repos = append(repos, page...)
			if resp.NextPage == 0 {
				break
			}
			opts.Page = resp.NextPage
		}
	}

	var out []Repo
	for _, r := range repos {
		if r.GetFork() {
			continue
		}
		out = append(out, Repo{
			FullName:      r.GetFullName(),
			Owner:         r.GetOwner().GetLogin(),
			Name:          r.GetName(),
			DefaultBranch: r.GetDefaultBranch(),
			Private:       r.GetPrivate(),
		})
	}
	return out, nil
}

// ListWorkflows returns the workflow files of a repo keyed by their full
// path (".github/workflows/ci.yml") so two workflows with the same file
// name cannot collide and the report can show where a finding lives.
func (c *Client) ListWorkflows(ctx context.Context, r Repo) (map[string][]byte, error) {
	var tree *github.Tree
	err := withRetry(ctx, func() (err error) {
		tree, _, err = c.gh.Git.GetTree(ctx, r.Owner, r.Name, r.DefaultBranch, true)
		return err
	})
	if err != nil {
		return nil, err
	}
	// The trees API truncates at 100k entries / 7 MB. A truncated tree
	// hides workflows, so it must never look like "no workflows found".
	if tree.GetTruncated() {
		return nil, fmt.Errorf("repository %s is too large to scan completely: the git tree was truncated, so some workflows may be missing", r.FullName)
	}

	var files []string
	for _, e := range tree.Entries {
		p := e.GetPath()
		if strings.HasPrefix(p, ".github/workflows/") &&
			(strings.HasSuffix(p, ".yml") || strings.HasSuffix(p, ".yaml")) {
			files = append(files, p)
		}
	}
	sort.Strings(files)

	out := make(map[string][]byte, len(files))
	failed := 0
	for _, f := range files {
		var file *github.RepositoryContent
		err := withRetry(ctx, func() (err error) {
			file, _, _, err = c.gh.Repositories.GetContents(ctx, r.Owner, r.Name, f,
				&github.RepositoryContentGetOptions{Ref: r.DefaultBranch})
			return err
		})
		if err != nil {
			log.Printf("actionscan: %s: cannot read %s: %v", r.FullName, f, err)
			failed++
			continue
		}
		if file == nil {
			log.Printf("actionscan: %s: cannot read %s: empty response", r.FullName, f)
			failed++
			continue
		}
		if t := file.GetType(); t != "" && t != "file" {
			log.Printf("actionscan: %s: skipping %s: not a regular file (%s)", r.FullName, f, t)
			failed++
			continue
		}
		// Only base64 is decoded. "none" means the file was too large
		// for the contents API (or is a symlink) — there is nothing to
		// scan, so say so instead of pretending it was clean.
		if enc := file.GetEncoding(); enc != "base64" {
			log.Printf("actionscan: %s: skipping %s: unsupported content encoding %q", r.FullName, f, enc)
			failed++
			continue
		}
		// GitHub wraps base64 content at 60 chars with newlines; strip
		// them or decoding fails and the workflow is silently skipped.
		if file.Content == nil {
			log.Printf("actionscan: %s: skipping %s: empty content", r.FullName, f)
			failed++
			continue
		}
		raw := strings.Map(func(r rune) rune {
			if r == '\n' || r == '\r' {
				return -1
			}
			return r
		}, *file.Content)
		content, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			log.Printf("actionscan: %s: cannot decode %s: %v", r.FullName, f, err)
			failed++
			continue
		}
		out[f] = content
	}
	// Workflow files exist but none could be read: the repo was not
	// scanned, and saying otherwise would report a clean repo we never
	// looked at.
	if len(out) == 0 && len(files) > 0 {
		return nil, fmt.Errorf("repository %s has %d workflow file(s) but none could be read", r.FullName, len(files))
	}
	if failed > 0 {
		// Partially read: the findings from the readable files are
		// returned, but the repo is also reported as incomplete so it
		// never reads as fully scanned.
		return out, fmt.Errorf("repository %s: %d of %d workflow file(s) could not be read", r.FullName, failed, len(files))
	}
	return out, nil
}

// LatestTag returns the latest release tag for an action repo
// (in-memory cached; concurrent callers share one upstream request).
func (c *Client) LatestTag(ctx context.Context, actionRepo string) string {
	parts := strings.SplitN(actionRepo, "/", 2)
	if len(parts) != 2 {
		return ""
	}

	c.latestMu.Lock()
	if v, ok := c.latest[actionRepo]; ok {
		c.latestMu.Unlock()
		return v
	}
	if c.latestInflight == nil {
		c.latestInflight = map[string]chan struct{}{}
	}
	if done, ok := c.latestInflight[actionRepo]; ok {
		// Another worker is fetching this tag — wait for it.
		c.latestMu.Unlock()
		<-done
		c.latestMu.Lock()
		v := c.latest[actionRepo]
		c.latestMu.Unlock()
		return v
	}
	done := make(chan struct{})
	c.latestInflight[actionRepo] = done
	c.latestMu.Unlock()

	rel, _, err := func() (*github.RepositoryRelease, *github.Response, error) {
		var r *github.RepositoryRelease
		var resp *github.Response
		err := withRetry(ctx, func() (err error) {
			r, resp, err = c.gh.Repositories.GetLatestRelease(ctx, parts[0], parts[1])
			return err
		})
		return r, resp, err
	}()
	tag := ""
	if err == nil {
		tag = rel.GetTagName()
	}

	c.latestMu.Lock()
	c.latest[actionRepo] = tag
	delete(c.latestInflight, actionRepo)
	c.latestMu.Unlock()
	close(done)
	return tag
}

// ResolveSHA expands a short commit SHA to its full 40-char form
// (in-memory cached; concurrent callers share one upstream request).
// Returns "" when the SHA cannot be resolved so callers can fall back
// to generic advice.
func (c *Client) ResolveSHA(ctx context.Context, actionRepo, short string) string {
	parts := strings.SplitN(actionRepo, "/", 2)
	if len(parts) != 2 || short == "" {
		return ""
	}

	key := actionRepo + "@" + short
	c.shaMu.Lock()
	if v, ok := c.sha[key]; ok {
		c.shaMu.Unlock()
		return v
	}
	if c.shaInflight == nil {
		c.shaInflight = map[string]chan struct{}{}
	}
	if done, ok := c.shaInflight[key]; ok {
		// Another worker is resolving this SHA — wait for it.
		c.shaMu.Unlock()
		<-done
		c.shaMu.Lock()
		v := c.sha[key]
		c.shaMu.Unlock()
		return v
	}
	done := make(chan struct{})
	c.shaInflight[key] = done
	c.shaMu.Unlock()

	commit, _, err := func() (*github.RepositoryCommit, *github.Response, error) {
		var cm *github.RepositoryCommit
		var resp *github.Response
		err := withRetry(ctx, func() (err error) {
			cm, resp, err = c.gh.Repositories.GetCommit(ctx, parts[0], parts[1], short, nil)
			return err
		})
		return cm, resp, err
	}()
	full := ""
	if err == nil && commit != nil && len(commit.GetSHA()) == 40 {
		full = commit.GetSHA()
	}

	c.shaMu.Lock()
	c.sha[key] = full
	delete(c.shaInflight, key)
	c.shaMu.Unlock()
	close(done)
	return full
}
