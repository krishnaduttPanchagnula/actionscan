package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/krishnaduttPanchagnula/actionscan/internal/config"
	"github.com/krishnaduttPanchagnula/actionscan/internal/github"
	"github.com/krishnaduttPanchagnula/actionscan/internal/report"
	"github.com/krishnaduttPanchagnula/actionscan/internal/rules"
	"github.com/krishnaduttPanchagnula/actionscan/internal/scanner"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan repos and generate HTML + CSV + JSON reports",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := config.Load()
		token := tokenOrEnv()
		if token == "" {
			return fmt.Errorf("no token: use --token, ACTIONSCAN_TOKEN, or GITHUB_TOKEN")
		}

		ctx := context.Background()

		ttl := time.Duration(cfg.Rules.CacheTTLHours) * time.Hour
		noLatest, _ := cmd.Flags().GetBool("no-latest")
		noOSV, _ := cmd.Flags().GetBool("no-osv")

		opts := rules.LoadOptions{
			CacheDir:    cfg.Rules.CacheDir,
			TTL:         ttl,
			Token:       token,
			UseOSV:      cfg.Rules.UseOSV && !noOSV,
			FetchLatest: cfg.Rules.FetchLatestTags && !noLatest,
		}

		fmt.Println("Loading vulnerability rules (StepSecurity + GHSA + OSV)…")
		rs, err := rules.Load(ctx, opts)
		if err != nil {
			fmt.Printf("⚠ %v — using what we could fetch\n", err)
		}
		fmt.Printf("Rules loaded from: %v (cached %s)\n",
			rs.Sources, rs.LoadedAt.Format(time.RFC3339))

		s := &scanner.Scanner{
			Client:  github.New(token),
			RuleSet: rs,
		}

		if cfg.GitHub.Org == "" && cfg.GitHub.User == "" {
			fmt.Println("No org/user given — scanning repos of authenticated user…")
		}

		fmt.Printf("Listing repos (org=%q user=%q)…\n", cfg.GitHub.Org, cfg.GitHub.User)
		repos, err := s.Client.ListRepos(ctx, cfg.GitHub.Org, cfg.GitHub.User)
		if err != nil {
			return fmt.Errorf("listing repos: %w", err)
		}
		fmt.Printf("Found %d repos. Scanning with %d workers…\n", len(repos), cfg.Scan.Concurrency)

		summary := s.ScanAll(ctx, repos, cfg.Scan.Concurrency)

		if err := os.MkdirAll(cfg.Scan.ReportDir, 0o755); err != nil {
			return err
		}

		htmlPath, err := report.HTML(summary, cfg.Scan.ReportDir)
		if err != nil {
			return fmt.Errorf("writing html: %w", err)
		}
		csvPath, err := report.CSV(summary, cfg.Scan.ReportDir)
		if err != nil {
			return fmt.Errorf("writing csv: %w", err)
		}
		jsonPath, err := report.JSON(summary, cfg.Scan.ReportDir)
		if err != nil {
			return fmt.Errorf("writing json: %w", err)
		}

		fmt.Printf("\nDone. %d findings across %d repos:\n", len(summary.Findings), summary.TotalRepos)
		fmt.Printf("  CRITICAL: %d  HIGH: %d  MEDIUM: %d  LOW: %d\n",
			summary.Critical, summary.High, summary.Medium, summary.Low)
		fmt.Printf("Reports:\n  HTML: %s\n  CSV:  %s\n  JSON: %s\n", htmlPath, csvPath, jsonPath)
		fmt.Printf("View:   actionscan serve --port 8080\n")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
}
