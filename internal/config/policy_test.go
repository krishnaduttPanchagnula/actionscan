package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/krishnaduttPanchagnula/actionscan/internal/scanner"
)

const samplePolicy = `# actionscan.yml
version: 1
ignore_actions:
  - actions/checkout
  - some-org/internal-*
deny_ignore:
  - tj-actions/changed-files
ignore_rules:
  - outdated
severity_remap:
  outdated: LOW
  GHSA-mrrh-fwg8-r2c3: CRITICAL
persona: pedantic
`

// writePolicy writes a policy file into dir and returns the directory.
func writePolicy(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func TestLoadPolicyValid(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "actionscan.yml", samplePolicy)

	c, err := LoadPolicy(dir)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if c == nil {
		t.Fatal("LoadPolicy returned nil config for an existing file")
	}
	if c.Version != 1 {
		t.Errorf("version = %d, want 1", c.Version)
	}
	if len(c.IgnoreActions) != 2 || c.IgnoreActions[0] != "actions/checkout" {
		t.Errorf("ignore_actions = %v", c.IgnoreActions)
	}
	if len(c.DenyIgnore) != 1 || c.DenyIgnore[0] != "tj-actions/changed-files" {
		t.Errorf("deny_ignore = %v", c.DenyIgnore)
	}
	if len(c.IgnoreRules) != 1 || c.IgnoreRules[0] != "outdated" {
		t.Errorf("ignore_rules = %v", c.IgnoreRules)
	}
	if c.SeverityRemap["outdated"] != "LOW" || c.SeverityRemap["GHSA-mrrh-fwg8-r2c3"] != "CRITICAL" {
		t.Errorf("severity_remap = %v", c.SeverityRemap)
	}
	if c.Persona != "pedantic" {
		t.Errorf("persona = %q, want pedantic", c.Persona)
	}
	// Absent from the file: inline ignores are honoured by default.
	if !c.RespectInlineIgnores {
		t.Error("respect_inline_ignores = false, want true by default")
	}
}

func TestLoadPolicyYamlExtension(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "actionscan.yaml", samplePolicy)

	c, err := LoadPolicy(dir)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if c == nil || c.Version != 1 {
		t.Fatalf("LoadPolicy = %+v, want version 1", c)
	}
}

func TestLoadPolicyPrefersYml(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "actionscan.yml", "version: 1\npersona: regular\n")
	writePolicy(t, dir, "actionscan.yaml", "version: 1\npersona: auditor\n")

	c, err := LoadPolicy(dir)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if c.Persona != "regular" {
		t.Errorf("persona = %q, want regular (the .yml file wins)", c.Persona)
	}
}

func TestLoadPolicyMissing(t *testing.T) {
	c, err := LoadPolicy(t.TempDir())
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if c != nil {
		t.Errorf("LoadPolicy = %+v, want nil for a missing file", c)
	}
}

func TestLoadPolicyMalformed(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "actionscan.yml", "version: 1\nignore_actions: [actions/checkout\n")

	c, err := LoadPolicy(dir)
	if err == nil {
		t.Fatalf("LoadPolicy = %+v, want an error for a malformed file", c)
	}
	if c != nil {
		t.Errorf("LoadPolicy returned a config alongside the error: %+v", c)
	}
}

func TestLoadPolicyEmptyPathUsesCurrentDir(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "actionscan.yml", "version: 1\npersona: auditor\n")

	old, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })

	c, err := LoadPolicy("")
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if c == nil || c.Persona != "auditor" {
		t.Fatalf("LoadPolicy = %+v, want the config in the current directory", c)
	}
}

func TestLoadPolicyRespectInlineIgnoresCanBeDisabled(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "actionscan.yml", "version: 1\nrespect_inline_ignores: false\n")

	c, err := LoadPolicy(dir)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if c.RespectInlineIgnores {
		t.Error("respect_inline_ignores = true, want false when the file says so")
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     PolicyConfig
		wantErr string
	}{
		{
			name: "valid",
			cfg: PolicyConfig{
				Version:       1,
				IgnoreActions: []string{"actions/checkout"},
				DenyIgnore:    []string{"tj-actions/changed-files"},
				IgnoreRules:   []string{"outdated"},
				SeverityRemap: map[string]string{"outdated": "LOW"},
				Persona:       "pedantic",
			},
		},
		{
			name:    "unknown persona",
			cfg:     PolicyConfig{Persona: "paranoid"},
			wantErr: "unknown persona",
		},
		{
			name:    "unknown rule category",
			cfg:     PolicyConfig{IgnoreRules: []string{"yolo"}},
			wantErr: "unknown rule category",
		},
		{
			name:    "invalid severity",
			cfg:     PolicyConfig{SeverityRemap: map[string]string{"outdated": "SEVERE"}},
			wantErr: "invalid severity",
		},
		{
			name:    "ignore is also denied",
			cfg:     PolicyConfig{IgnoreActions: []string{"tj-actions/changed-files"}, DenyIgnore: []string{"tj-actions/changed-files"}},
			wantErr: "deny_ignore",
		},
		{
			name:    "ignore glob covers a denied action",
			cfg:     PolicyConfig{IgnoreActions: []string{"tj-actions/*"}, DenyIgnore: []string{"tj-actions/changed-files"}},
			wantErr: "deny_ignore",
		},
		{
			name:    "unsupported version",
			cfg:     PolicyConfig{Version: 99},
			wantErr: "version",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate = nil, want an error mentioning %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Validate error = %q, want it to mention %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidateAcceptsEmptyConfig(t *testing.T) {
	var c PolicyConfig
	if err := c.Validate(); err != nil {
		t.Errorf("Validate on an empty config: %v", err)
	}
}

func TestLoadedConfigBuildsAScannerPolicy(t *testing.T) {
	// config.PolicyConfig and scanner.PolicyConfig are the same type, so
	// the scanner can build a policy straight from a loaded config.
	dir := t.TempDir()
	writePolicy(t, dir, "actionscan.yml", samplePolicy)

	c, err := LoadPolicy(dir)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	p, err := scanner.NewPolicy(c)
	if err != nil {
		t.Fatalf("scanner.NewPolicy: %v", err)
	}
	if !p.Suppress(scanner.Finding{Action: "actions/checkout@v4", Category: "vulnerable"}) {
		t.Error("the ignored action was not suppressed")
	}
	if p.Suppress(scanner.Finding{Action: "tj-actions/changed-files@v41", Category: "malicious"}) {
		t.Error("the denied action was suppressed")
	}
	if sev := p.Severity(scanner.Finding{Category: "outdated"}); sev != "LOW" {
		t.Errorf("severity = %q, want LOW", sev)
	}
}
