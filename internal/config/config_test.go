package config

import (
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
)

// resetViper isolates each test from viper's global state. The config
// package tests run in their own binary, so no cobra flag bindings are
// lost by resetting here.
func resetViper(t *testing.T) {
	t.Helper()
	viper.Reset()
	t.Cleanup(viper.Reset)
}

func TestGetInt(t *testing.T) {
	resetViper(t)

	if got := getInt("no.such.key", 8); got != 8 {
		t.Errorf("unset key = %d, want default 8", got)
	}

	viper.Set("some.int", 16)
	if got := getInt("some.int", 8); got != 16 {
		t.Errorf("configured 16 = %d, want 16", got)
	}

	// Regression: an explicit 0 must be honored, not replaced by the
	// default (the old implementation discarded every zero value).
	viper.Set("zero.int", 0)
	if got := getInt("zero.int", 8); got != 0 {
		t.Errorf("configured 0 = %d, want 0", got)
	}
}

func TestGetStr(t *testing.T) {
	resetViper(t)

	if got := getStr("no.such.key", "fallback"); got != "fallback" {
		t.Errorf("unset key = %q, want fallback", got)
	}

	viper.Set("some.str", "value")
	if got := getStr("some.str", "fallback"); got != "value" {
		t.Errorf("configured value = %q, want value", got)
	}

	// ${VAR} syntax expands from the environment.
	t.Setenv("MY_TOKEN", "env-secret")
	viper.Set("env.str", "${MY_TOKEN}")
	if got := getStr("env.str", ""); got != "env-secret" {
		t.Errorf("expanded = %q, want env-secret", got)
	}

	// A plain (non-${}) value passes through untouched.
	viper.Set("plain.str", "${NOT_CLOSED")
	if got := getStr("plain.str", ""); got != "${NOT_CLOSED" {
		t.Errorf("plain = %q, want unchanged", got)
	}
}

func TestGetBool(t *testing.T) {
	resetViper(t)

	if got := getBool("no.such.key", true); got != true {
		t.Errorf("unset key = %v, want default true", got)
	}
	if got := getBool("no.such.key", false); got != false {
		t.Errorf("unset key = %v, want default false", got)
	}

	viper.Set("flag.on", true)
	if got := getBool("flag.on", false); got != true {
		t.Errorf("configured true = %v, want true", got)
	}

	// Explicit false must beat the default.
	viper.Set("flag.off", false)
	if got := getBool("flag.off", true); got != false {
		t.Errorf("configured false = %v, want false", got)
	}
}

func TestExpandEnv(t *testing.T) {
	t.Setenv("EXPAND_ME", "expanded")
	tests := []struct{ in, want string }{
		{"${EXPAND_ME}", "expanded"},
		{"plain-token", "plain-token"},
		{"${}", "${}"},                         // too short to be a reference
		{"pre${EXPAND_ME}", "pre${EXPAND_ME}"}, // only bare references expand
		{"", ""},
	}
	for _, tt := range tests {
		if got := expandEnv(tt.in); got != tt.want {
			t.Errorf("expandEnv(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestLoadDefaults(t *testing.T) {
	resetViper(t)
	home := t.TempDir()
	t.Setenv("HOME", home)

	c := Load()

	if c.Server.Port != "8080" || c.Server.Mode != "release" {
		t.Errorf("server = %+v, want defaults", c.Server)
	}
	if c.Scan.Concurrency != 8 {
		t.Errorf("concurrency = %d, want 8", c.Scan.Concurrency)
	}
	if c.Scan.ReportDir != "./reports" {
		t.Errorf("report dir = %q", c.Scan.ReportDir)
	}
	if c.Rules.CacheTTLHours != 12 {
		t.Errorf("cache ttl = %d, want 12", c.Rules.CacheTTLHours)
	}
	if !c.Rules.FetchLatestTags || !c.Rules.UseOSV {
		t.Errorf("rule toggles = %+v, want both enabled", c.Rules)
	}
	// Empty cache_dir must default to ~/.actionscan.
	if want := filepath.Join(home, ".actionscan"); c.Rules.CacheDir != want {
		t.Errorf("cache dir = %q, want %q", c.Rules.CacheDir, want)
	}
}

func TestLoadZeroValuesAreHonored(t *testing.T) {
	resetViper(t)

	viper.Set("scan.concurrency", 0)
	viper.Set("rules.cache_ttl_hours", 0)

	c := Load()

	// Regression: explicit zeros previously fell back to 8/12.
	if c.Scan.Concurrency != 0 {
		t.Errorf("concurrency = %d, want 0", c.Scan.Concurrency)
	}
	if c.Rules.CacheTTLHours != 0 {
		t.Errorf("cache ttl = %d, want 0", c.Rules.CacheTTLHours)
	}
}

func TestLoadCustomValues(t *testing.T) {
	resetViper(t)

	viper.Set("server.port", "9999")
	viper.Set("server.mode", "debug")
	viper.Set("github.org", "acme")
	viper.Set("github.user", "alice")
	viper.Set("scan.concurrency", 32)
	viper.Set("scan.report_dir", "/tmp/out")
	viper.Set("rules.cache_ttl_hours", 24)
	viper.Set("rules.cache_dir", "/custom/cache")
	viper.Set("rules.fetch_latest_tags", false)
	viper.Set("rules.use_osv", false)

	c := Load()

	if c.Server.Port != "9999" || c.Server.Mode != "debug" {
		t.Errorf("server = %+v", c.Server)
	}
	if c.GitHub.Org != "acme" || c.GitHub.User != "alice" {
		t.Errorf("github = %+v", c.GitHub)
	}
	if c.Scan.Concurrency != 32 || c.Scan.ReportDir != "/tmp/out" {
		t.Errorf("scan = %+v", c.Scan)
	}
	if c.Rules.CacheTTLHours != 24 || c.Rules.CacheDir != "/custom/cache" {
		t.Errorf("rules = %+v", c.Rules)
	}
	if c.Rules.FetchLatestTags || c.Rules.UseOSV {
		t.Errorf("disabled toggles came back enabled: %+v", c.Rules)
	}
}
