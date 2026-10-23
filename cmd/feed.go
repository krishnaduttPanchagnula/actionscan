package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/krishnaduttPanchagnula/actionscan/internal/config"
	"github.com/krishnaduttPanchagnula/actionscan/internal/feed"
	"github.com/krishnaduttPanchagnula/actionscan/internal/rules"
	"github.com/spf13/cobra"
)

var feedCmd = &cobra.Command{
	Use:   "feed",
	Short: "Print the public actionscan threat feed as JSON",
	Long: `Print the public actionscan threat feed: the set of known-compromised
and known-vulnerable GitHub Actions, with the affected version ranges.

The feed is what actionscan itself checks against. It is published so
other tools can consume the same intelligence instead of re-implementing
it — no account, no API key, no rate limit.

The output is deterministic: the same rules produce byte-identical JSON
apart from "generated_at", so the feed can be diffed and cached.`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := config.Load()
		token := tokenOrEnv()

		ttl := time.Duration(cfg.Rules.CacheTTLHours) * time.Hour
		opts := rules.LoadOptions{
			CacheDir:         cfg.Rules.CacheDir,
			TTL:              ttl,
			Token:            token,
			UseOSV:           false, // the feed is about actions, not OSV queries
			FetchLatest:      false,
			MaliciousFeedURL: cfg.Rules.MaliciousFeedURL,
		}

		rs, err := rules.Load(context.Background(), opts)
		if err != nil {
			// A degraded feed is still worth publishing — the document
			// says it is degraded, so a consumer can decide.
			fmt.Fprintf(os.Stderr, "⚠ %v — publishing a degraded feed\n", err)
		}

		f := feed.Build(rs)
		var b []byte
		if stable, _ := cmd.Flags().GetString("stable"); stable != "" {
			ts, err := time.Parse(time.RFC3339, stable)
			if err != nil {
				return fmt.Errorf("--stable must be an RFC3339 timestamp: %w", err)
			}
			b, err = f.MarshalStable(ts)
			if err != nil {
				return err
			}
		} else {
			b, err = f.Marshal()
			if err != nil {
				return err
			}
		}

		out, _ := cmd.Flags().GetString("out")
		if out == "" || out == "-" {
			_, err := os.Stdout.Write(b)
			return err
		}
		if err := os.WriteFile(out, b, 0o644); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Wrote %d entries to %s\n", len(f.Entries), out)
		return nil
	},
}

func init() {
	feedCmd.Flags().String("out", "", "write the feed to this file (default: stdout)")
	feedCmd.Flags().String("stable", "",
		"pin generated_at to this RFC3339 timestamp for a reproducible feed")
	rootCmd.AddCommand(feedCmd)
}
