package github

import (
	"context"
	"encoding/base64"
	"path"
	"strings"
	"sync"

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
			page, resp, err := c.gh.Repositories.ListByOrg(ctx, org, opts)
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
			page, resp, err := c.gh.Repositories.List(ctx, user, opts)
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
			page, resp, err := c.gh.Repositories.List(ctx, "", opts)
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

func (c *Client) ListWorkflows(ctx context.Context, r Repo) (map[string][]byte, error) {
	tree, _, err := c.gh.Git.GetTree(ctx, r.Owner, r.Name, r.DefaultBranch, true)
	if err != nil {
		return nil, err
	}

	var files []string
	for _, e := range tree.Entries {
		p := e.GetPath()
		if strings.HasPrefix(p, ".github/workflows/") &&
			(strings.HasSuffix(p, ".yml") || strings.HasSuffix(p, ".yaml")) {
			files = append(files, p)
		}
	}

	out := make(map[string][]byte)
	for _, f := range files {
		file, _, _, err := c.gh.Repositories.GetContents(ctx, r.Owner, r.Name, f,
			&github.RepositoryContentGetOptions{Ref: r.DefaultBranch})
		if err != nil || file == nil || file.Content == nil {
			continue
		}
		// GitHub wraps base64 content at 60 chars with newlines; strip
		// them or decoding fails and the workflow is silently skipped.
		raw := strings.Map(func(r rune) rune {
			if r == '\n' || r == '\r' {
				return -1
			}
			return r
		}, *file.Content)
		content, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			continue
		}
		out[path.Base(f)] = content
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

	rel, _, err := c.gh.Repositories.GetLatestRelease(ctx, parts[0], parts[1])
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

	commit, _, err := c.gh.Repositories.GetCommit(ctx, parts[0], parts[1], short, nil)
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
