package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/krishnaduttPanchagnula/actionscan/internal/scanner"
	"gopkg.in/yaml.v3"
)

// PolicyConfig is the parsed actionscan.yml.
//
// It is an alias of scanner.PolicyConfig, not a second type: the scanner
// package owns the policy semantics (what an ignore entry matches, what
// a persona adds) and this package only loads the YAML. The alias gives
// one type with two names, so config.PolicyConfig and
// scanner.PolicyConfig are interchangeable and no import cycle exists —
// internal/scanner does not import internal/config.
type PolicyConfig = scanner.PolicyConfig

// PolicyFileNames are the accepted names of the policy file, in the
// order they are looked for.
var PolicyFileNames = []string{"actionscan.yml", "actionscan.yaml"}

// LoadPolicy reads an actionscan.yml from dir.
//
// A missing file is not an error: no config is a valid state, and a
// repository that has never heard of actionscan.yml must still scan.
// A malformed file IS an error — silently ignoring a config the user
// wrote would be the worst possible outcome.
//
// An empty dir means the current directory. The returned config is not
// validated; call Validate (or scanner.NewPolicy, which validates) before
// acting on it.
func LoadPolicy(dir string) (*PolicyConfig, error) {
	if dir == "" {
		dir = "."
	}
	for _, name := range PolicyFileNames {
		path := filepath.Join(dir, name)
		b, err := os.ReadFile(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		var c PolicyConfig
		if err := yaml.Unmarshal(b, &c); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		return &c, nil
	}
	return nil, nil
}
