package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/krishnaduttPanchagnula/actionscan/internal/scanner"
	"github.com/spf13/viper"
)

// ── expandEnv ──────────────────────────────────────────────────────────

func TestExpandEnv(t *testing.T) {
	t.Setenv("CMD_TOKEN", "secret-abc")

	tests := []struct{ in, want string }{
		{"${CMD_TOKEN}", "secret-abc"},
		{"literal", "literal"},
		{"", ""},
		{"${}", "${}"},                     // too short to be a reference
		{"x${CMD_TOKEN}", "x${CMD_TOKEN}"}, // only bare references expand
	}
	for _, tt := range tests {
		if got := expandEnv(tt.in); got != tt.want {
			t.Errorf("expandEnv(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// ── tokenOrEnv ─────────────────────────────────────────────────────────

// setTokenFlag simulates `--token ...` on the command line. Using the
// flag (rather than a viper override, which cannot be unset) keeps the
// global viper state clean for other tests.
func setTokenFlag(t *testing.T, value string) {
	t.Helper()
	f := rootCmd.PersistentFlags().Lookup("token")
	if err := f.Value.Set(value); err != nil {
		t.Fatal(err)
	}
	f.Changed = true
	t.Cleanup(func() {
		_ = f.Value.Set("")
		f.Changed = false
	})
}

func TestTokenOrEnv_ConfiguredTokenWins(t *testing.T) {
	setTokenFlag(t, "flag-token")
	t.Setenv("ACTIONSCAN_TOKEN", "env-should-lose")
	t.Setenv("GITHUB_TOKEN", "")

	if got := tokenOrEnv(); got != "flag-token" {
		t.Errorf("tokenOrEnv() = %q, want flag-token", got)
	}
}

func TestTokenOrEnv_DocumentedEnvVarWorks(t *testing.T) {
	// Regression: ACTIONSCAN_TOKEN is documented in the README and in the
	// CLI's own error message, but was previously ignored (viper only
	// auto-mapped ACTIONSCAN_GITHUB_TOKEN for the github.token key).
	t.Setenv("ACTIONSCAN_TOKEN", "from-actionscan-env")
	t.Setenv("GITHUB_TOKEN", "gh-should-lose")

	if got := tokenOrEnv(); got != "from-actionscan-env" {
		t.Errorf("tokenOrEnv() = %q, want from-actionscan-env", got)
	}
}

func TestTokenOrEnv_GitHubTokenFallback(t *testing.T) {
	t.Setenv("ACTIONSCAN_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "from-github-env")

	if got := tokenOrEnv(); got != "from-github-env" {
		t.Errorf("tokenOrEnv() = %q, want from-github-env", got)
	}
}

func TestTokenOrEnv_EmptyWhenNothingConfigured(t *testing.T) {
	t.Setenv("ACTIONSCAN_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")

	if got := tokenOrEnv(); got != "" {
		t.Errorf("tokenOrEnv() = %q, want empty", got)
	}
}

// ── initConfig wiring ──────────────────────────────────────────────────

func TestRootFlagsAreBoundToViper(t *testing.T) {
	// Guards the flag -> viper key mapping used throughout the CLI.
	bindings := map[string]string{
		"github.token":          "token",
		"github.org":            "org",
		"github.user":           "user",
		"scan.concurrency":      "concurrency",
		"scan.report_dir":       "out",
		"rules.cache_ttl_hours": "cache-ttl",
		"rules.skip_latest":     "no-latest",
		"rules.skip_osv":        "no-osv",
	}
	for key, flag := range bindings {
		if rootCmd.PersistentFlags().Lookup(flag) == nil {
			t.Errorf("flag %q not registered", flag)
		}
		if !viper.IsSet(key) && viper.Get(key) == nil {
			// Bound pflags are readable even when unset (default value).
			if viper.GetString(key) == "" && viper.GetInt(key) == 0 {
				t.Errorf("key %q does not read from flag %q", key, flag)
			}
		}
	}
}

func TestRootHelpMentionsSubcommands(t *testing.T) {
	for _, name := range []string{"scan", "serve"} {
		found := false
		for _, c := range rootCmd.Commands() {
			if c.Name() == name {
				found = true
			}
		}
		if !found {
			t.Errorf("subcommand %q not registered", name)
		}
	}
}

// ── loadSummary ────────────────────────────────────────────────────────

func TestLoadSummary_MissingReport(t *testing.T) {
	if _, err := loadSummary(t.TempDir()); err == nil {
		t.Fatal("missing report.json must return an error")
	}
}

func TestLoadSummary_ValidReport(t *testing.T) {
	dir := t.TempDir()
	body := `{
		"findings": [
			{"repo":"a/b","workflow":"ci.yml","action":"x@v1","ref":"v1",
			 "severity":"CRITICAL","category":"malicious","reason":"bad"}
		],
		"critical":1,"high":0,"medium":0,"low":0,"total_repos":7
	}`
	if err := os.WriteFile(filepath.Join(dir, "report.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	s, err := loadSummary(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.TotalRepos != 7 || s.Critical != 1 || len(s.Findings) != 1 {
		t.Errorf("summary = %+v", s)
	}
	if s.Findings[0].Repo != "a/b" || s.Findings[0].Severity != "CRITICAL" {
		t.Errorf("finding = %+v", s.Findings[0])
	}
}

func TestLoadSummary_CorruptReport(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "report.json"), []byte("{broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSummary(dir); err == nil {
		t.Fatal("corrupt report.json must return an error")
	}
}

// compile-time sanity: the default summary type used by serve/scan
// stays in sync with the scanner package.
var _ = scanner.Summary{}
