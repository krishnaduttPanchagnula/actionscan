package cmd

import (
	"github.com/krishnaduttPanchagnula/actionscan/internal/config"
	"github.com/krishnaduttPanchagnula/actionscan/internal/scanner"
)

// loadPolicyForTest loads a policy from a directory, without the
// flag plumbing the scan command does.
func loadPolicyForTest(dir string) (*scanner.PolicyConfig, error) {
	return config.LoadPolicy(dir)
}
