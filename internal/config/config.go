package config

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	Server struct {
		Port string
		Mode string
	}
	GitHub struct {
		Token string
		Org   string
		User  string
	}
	Scan struct {
		Concurrency int
		ReportDir   string
	}
	Rules struct {
		CacheTTLHours   int
		CacheDir        string
		FetchLatestTags bool
		UseOSV          bool
	}
}

func Load() *Config {
	var c Config
	c.Server.Port = getStr("server.port", "8080")
	c.Server.Mode = getStr("server.mode", "release")
	c.GitHub.Token = getStr("github.token", "")
	c.GitHub.Org = getStr("github.org", "")
	c.GitHub.User = getStr("github.user", "")
	c.Scan.Concurrency = getInt("scan.concurrency", 8)
	c.Scan.ReportDir = getStr("scan.report_dir", "./reports")
	c.Rules.CacheTTLHours = getInt("rules.cache_ttl_hours", 12)
	c.Rules.CacheDir = getStr("rules.cache_dir", "")
	c.Rules.FetchLatestTags = getBool("rules.fetch_latest_tags", true)
	c.Rules.UseOSV = getBool("rules.use_osv", true)

	if c.Rules.CacheDir == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			c.Rules.CacheDir = filepath.Join(home, ".actionscan")
		} else {
			c.Rules.CacheDir = "."
		}
	}
	return &c
}

func expandEnv(s string) string {
	if len(s) > 3 && strings.HasPrefix(s, "${") && strings.HasSuffix(s, "}") {
		return os.Getenv(s[2 : len(s)-1])
	}
	return s
}

func getStr(key, def string) string {
	v := viper.GetString(key)
	if v == "" {
		return def
	}
	return expandEnv(v)
}

func getInt(key string, def int) int {
	if v := viper.GetInt(key); v != 0 {
		return v
	}
	return def
}

func getBool(key string, def bool) bool {
	if viper.IsSet(key) {
		return viper.GetBool(key)
	}
	return def
}
