package main

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/krishnaduttPanchagnula/github-actions-vulnerability-scanner/utils"
)

func main() {
	client := utils.ClientCreation()
	ctx := context.Background()

	repos := utils.ListAllUserRepos(client, ctx, "krishnaduttPanchagnula")
	repourl := []string{}
	for _, repo := range repos {
		// fmt.Println(repo.CloneURL)
		repourl = append(repourl, *repo.CloneURL)
	}
	fmt.Println(repourl)
	baseDir := "./my-repos"
	os.MkdirAll(baseDir, os.ModePerm)

	for _, repoURL := range repourl {
		baseName := path.Base(repoURL)

		// 2. Remove the ".git" suffix (e.g., "AirIAM")
		repoName := strings.TrimSuffix(baseName, ".git")

		// 3. Join it with your base directory (e.g., "./my-repos/AirIAM")
		destPath := filepath.Join(baseDir, repoName)
		utils.CloneGitRepo(destPath, repoURL)
	}

}
