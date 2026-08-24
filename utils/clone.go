package utils

import (
	"fmt"
	"os"

	"github.com/go-git/go-git/v5"
)

func CloneGitRepo(path string, url string) {
	_, err := git.PlainClone(path, false, &git.CloneOptions{URL: url, Progress: os.Stdout})
	if err != nil {
		fmt.Println(err)
	}

}
