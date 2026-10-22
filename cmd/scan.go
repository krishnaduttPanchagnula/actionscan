package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
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
	Short: "Scan repos and generate HTML + CSV + JSON + SARIF reports",
	// A missing token is a usage error, not a crash: printing the whole
	// usage block on top of it buries the message.
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := config.Load()
		token := tokenOrEnv()
		if token == "" {
			return fmt.Errorf("no token: use --token, ACTIONSCAN_TOKEN, or GITHUB_TOKEN")
		}

		// Ctrl-C cancels the scan instead of killing the process, so a
		// partial scan still produces a report.
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		ttl := time.Duration(cfg.Rules.CacheTTLHours) * time.Hour
		noLatest, _ := cmd.Flags().GetBool("no-latest")
		noOSV, _ := cmd.Flags().GetBool("no-osv")

		opts := rules.LoadOptions{
			CacheDir:         cfg.Rules.CacheDir,
			TTL:              ttl,
			Token:            token,
			UseOSV:           cfg.Rules.UseOSV && !noOSV,
			FetchLatest:      cfg.Rules.FetchLatestTags && !noLatest,
			MaliciousFeedURL: cfg.Rules.MaliciousFeedURL,
		}

		fmt.Fprintln(os.Stderr, "Loading vulnerability rules (GHSA + OSV + compromised-action feeds)…")
		rs, err := rules.Load(ctx, opts)
		if err != nil {
			// A cancelled context means the operator interrupted the
			// scan — continuing would produce a report from a dead
			// context. An unreachable feed is different: the scan
			// continues with what could be fetched.
			if ctx.Err() != nil {
				return fmt.Errorf("scan cancelled: %w", ctx.Err())
			}
			fmt.Fprintf(os.Stderr, "⚠ %v — using what we could fetch\n", err)
		}
		fmt.Fprintf(os.Stderr, "Rules loaded from: %v (as of %s)\n",
			rs.Sources, rs.LoadedAt.Format(time.RFC3339))
		if rs.Degraded {
			fmt.Fprintf(os.Stderr, "⚠ Threat intel degraded: %s — this report may be missing findings\n",
				rs.DegradedReason)
		}

		ghClient := github.New(token)
		s := &scanner.Scanner{
			Client:  ghClient,
			RuleSet: rs,
		}

		target := scanTarget(cfg.GitHub.Org, cfg.GitHub.User)
		if cfg.GitHub.Org == "" && cfg.GitHub.User == "" {
			fmt.Fprintln(os.Stderr, "No org/user given — scanning repos of the authenticated user…")
		}

		fmt.Fprintf(os.Stderr, "Listing repos (org=%q user=%q)…\n", cfg.GitHub.Org, cfg.GitHub.User)
		repos, err := ghClient.ListRepos(ctx, cfg.GitHub.Org, cfg.GitHub.User)
		if err != nil {
			return fmt.Errorf("listing repos: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Found %d repos. Scanning with %d workers…\n", len(repos), cfg.Scan.Concurrency)

		summary := s.ScanAll(ctx, repos, cfg.Scan.Concurrency)
		summary.Target = target
		summary.ToolVersion = Version

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
		sarifPath, err := report.SARIF(summary, cfg.Scan.ReportDir)
		if err != nil {
			return fmt.Errorf("writing sarif: %w", err)
		}

		fmt.Fprintf(os.Stderr, "\nDone. %d findings in %d of %d repos (%d actions checked):\n",
			len(summary.Findings), summary.AffectedRepos, summary.TotalRepos, summary.ActionsChecked)
		fmt.Fprintf(os.Stderr, "  CRITICAL: %d  HIGH: %d  MEDIUM: %d  LOW: %d\n",
			summary.Critical, summary.High, summary.Medium, summary.Low)
		if n := len(summary.UnreadableRepos); n > 0 {
			fmt.Fprintf(os.Stderr, "  ⚠ %d repos could NOT be read (not scanned — not clean):\n", n)
			for _, r := range summary.UnreadableRepos {
				fmt.Fprintf(os.Stderr, "      %s\n", r)
			}
		}
		fmt.Fprintf(os.Stderr, "Reports:\n  HTML:  %s\n  CSV:   %s\n  JSON:  %s\n  SARIF: %s\n",
			htmlPath, csvPath, jsonPath, sarifPath)
		fmt.Fprintln(os.Stderr, "View:  actionscan serve --port 8080")

		// CI gating: exit non-zero when findings reach the threshold.
		failOn, _ := cmd.Flags().GetString("fail-on")
		if code, fail := exitCode(summary, failOn); fail {
			switch code {
			case 2:
				fmt.Fprintf(os.Stderr, "\nFailing: the scan could not be completed reliably (degraded threat intel) — refusing to pass the %s gate.\n", failOn)
			default:
				fmt.Fprintf(os.Stderr, "\nFailing: findings at or above %s severity.\n", failOn)
			}
			os.Exit(code)
		}
		return nil
	},
}

// scanTarget is the human name of what was scanned.
func scanTarget(org, user string) string {
	switch {
	case org != "":
		return "org/" + org
	case user != "":
		return "user/" + user
	}
	return "authenticated user"
}

// exitCode returns the process exit code when the scan must fail CI.
//
// A degraded scan (a threat feed was unreachable, so the ruleset was
// partial) must not pass a gate: the scan could not see the findings it
// was asked to look for. It exits 2 to distinguish "findings" from
// "could not check".
func exitCode(s *scanner.Summary, failOn string) (int, bool) {
	level := strings.ToLower(strings.TrimSpace(failOn))
	switch level {
	case "", "none":
		return 0, false
	case "critical", "high", "medium", "low":
	default:
		// An unknown threshold is a typo in a CI config: fail loudly
		// rather than silently disabling the gate.
		return 2, true
	}
	if s.Degraded {
		return 2, true
	}
	switch level {
	case "critical":
		if s.Critical > 0 {
			return 1, true
		}
	case "high":
		if s.Critical > 0 || s.High > 0 {
			return 1, true
		}
	case "medium":
		if s.Critical > 0 || s.High > 0 || s.Medium > 0 {
			return 1, true
		}
	case "low":
		if s.Critical+s.High+s.Medium+s.Low > 0 {
			return 1, true
		}
	}
	return 0, false
}

func init() {
	scanCmd.Flags().String("fail-on", "none",
		"exit non-zero when findings reach this severity: none|critical|high|medium|low")
	rootCmd.AddCommand(scanCmd)
}
