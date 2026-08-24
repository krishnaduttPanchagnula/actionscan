package utils

import (
	"context"
	"fmt"

	"github.com/google/go-github/v89/github"
)

func ClientCreation() *github.Client {
	client, err := github.NewClient()
	if err != nil {
		fmt.Print(err)
	}

	return client
}

func ListAllOrgRepos(c *github.Client, ctx context.Context, orgName string) []*github.Repository {

	opts := &github.RepositoryListByOrgOptions{}
	repos, _, err := c.Repositories.ListByOrg(ctx, orgName, opts)
	if err != nil {
		fmt.Print(err)
	}
	return repos
}

func ListAllUserRepos(c *github.Client, ctx context.Context, username string) []*github.Repository {
	opts := &github.RepositoryListByUserOptions{}
	repos, _, err := c.Repositories.ListByUser(ctx, username, opts)

	if err != nil {
		fmt.Print(err)
	}
	return repos
}
