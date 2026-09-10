package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "actionscan",
	Short: "Scan GitHub repos for vulnerable & outdated Actions",
	Long: `actionscan scans all repos for a user or org, extracts every
GitHub Action referenced in workflows, and checks them against live
feeds: StepSecurity compromised-actions, GitHub Security Advisories
(GHSA), OSV.dev, and latest-release tags.

Reports are generated as HTML, CSV, and JSON.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: ./config.yaml)")
	rootCmd.PersistentFlags().String("token", "", "GitHub token (env: ACTIONSCAN_TOKEN or GITHUB_TOKEN)")
	rootCmd.PersistentFlags().String("org", "", "GitHub org to scan")
	rootCmd.PersistentFlags().String("user", "", "GitHub user to scan")
	rootCmd.PersistentFlags().Int("concurrency", 8, "parallel repo workers")
	rootCmd.PersistentFlags().String("out", "./reports", "output directory for reports")
	rootCmd.PersistentFlags().Int("cache-ttl", 12, "rules cache TTL in hours")
	rootCmd.PersistentFlags().Bool("no-latest", false, "skip live latest-tag lookups")
	rootCmd.PersistentFlags().Bool("no-osv", false, "skip OSV.dev queries")

	_ = viper.BindPFlag("github.token", rootCmd.PersistentFlags().Lookup("token"))
	_ = viper.BindPFlag("github.org", rootCmd.PersistentFlags().Lookup("org"))
	_ = viper.BindPFlag("github.user", rootCmd.PersistentFlags().Lookup("user"))
	_ = viper.BindPFlag("scan.concurrency", rootCmd.PersistentFlags().Lookup("concurrency"))
	_ = viper.BindPFlag("scan.report_dir", rootCmd.PersistentFlags().Lookup("out"))
	_ = viper.BindPFlag("rules.cache_ttl_hours", rootCmd.PersistentFlags().Lookup("cache-ttl"))
	_ = viper.BindPFlag("rules.skip_latest", rootCmd.PersistentFlags().Lookup("no-latest"))
	_ = viper.BindPFlag("rules.skip_osv", rootCmd.PersistentFlags().Lookup("no-osv"))
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
		viper.AddConfigPath(".")
		viper.AddConfigPath("$HOME/.actionscan")
	}

	viper.SetEnvPrefix("ACTIONSCAN")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	viper.SetDefault("server.port", "8080")
	viper.SetDefault("server.mode", "release")
	viper.SetDefault("scan.concurrency", 8)
	viper.SetDefault("scan.report_dir", "./reports")
	viper.SetDefault("rules.cache_ttl_hours", 12)
	viper.SetDefault("rules.fetch_latest_tags", true)
	viper.SetDefault("rules.use_osv", true)

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok && cfgFile != "" {
			fmt.Fprintln(os.Stderr, "config error:", err)
			os.Exit(1)
		}
	}
}

func tokenOrEnv() string {
	t := expandEnv(viper.GetString("github.token"))
	if t == "" {
		t = os.Getenv("GITHUB_TOKEN")
	}
	return t
}

func expandEnv(s string) string {
	if len(s) > 3 && strings.HasPrefix(s, "${") && strings.HasSuffix(s, "}") {
		return os.Getenv(s[2 : len(s)-1])
	}
	return s
}
