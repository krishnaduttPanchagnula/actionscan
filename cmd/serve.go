package cmd

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/krishnaduttPanchagnula/actionscan/internal/scanner"
	"github.com/krishnaduttPanchagnula/actionscan/web"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var serveCmd = &cobra.Command{
	Use:          "serve",
	Short:        "Serve the HTML report + CSV/JSON/SARIF downloads",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		outDir := viper.GetString("scan.report_dir")
		mode := viper.GetString("server.mode")

		port, _ := cmd.Flags().GetString("port")
		if port == "" {
			port = viper.GetString("server.port")
		}
		host, _ := cmd.Flags().GetString("host")
		if host == "" {
			host = viper.GetString("server.host")
		}

		gin.SetMode(mode)
		r := gin.Default()

		// The dashboard is embedded in the binary — a released binary
		// must not depend on the working directory.
		tmpl := template.Must(template.New("report.html").Parse(web.TemplateHTML()))
		r.SetHTMLTemplate(tmpl)

		summary, err := loadSummary(outDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "⚠ No report in %s (run `actionscan scan` first): %v\n", outDir, err)
		}

		// The summary is re-read on request so a rescan shows up without
		// a restart. It is written by one request goroutine and read by
		// others, so it needs a lock.
		var mu sync.RWMutex
		current := func() *scanner.Summary {
			mu.RLock()
			defer mu.RUnlock()
			return summary
		}

		r.GET("/", func(c *gin.Context) {
			// Re-read the report so a rescan shows up without a restart.
			if s, err := loadSummary(outDir); err == nil {
				mu.Lock()
				summary = s
				mu.Unlock()
			}
			s := current()
			if s == nil {
				c.String(http.StatusNotFound, "No report yet — run `actionscan scan` first.")
				return
			}
			c.HTML(http.StatusOK, "report.html", templateData(s))
		})

		r.GET("/report.csv", func(c *gin.Context) {
			c.FileAttachment(filepath.Join(outDir, "report.csv"), "actionscan-report.csv")
		})
		r.GET("/report.json", func(c *gin.Context) {
			c.FileAttachment(filepath.Join(outDir, "report.json"), "actionscan-report.json")
		})
		r.GET("/report.sarif", func(c *gin.Context) {
			c.FileAttachment(filepath.Join(outDir, "report.sarif"), "actionscan-report.sarif")
		})

		api := r.Group("/api")
		{
			api.GET("/status", func(c *gin.Context) {
				s := current()
				if s == nil {
					c.JSON(http.StatusOK, gin.H{"report_available": false})
					return
				}
				c.JSON(http.StatusOK, gin.H{
					"report_available": true,
					"total_repos":      s.TotalRepos,
					"findings":         s.Total(),
					"degraded":         s.Degraded,
				})
			})
			api.GET("/findings", func(c *gin.Context) {
				s := current()
				if s == nil {
					c.JSON(http.StatusNotFound, gin.H{"error": "run `actionscan scan` first"})
					return
				}
				c.JSON(http.StatusOK, s)
			})
		}

		addr := host + ":" + port
		fmt.Fprintf(os.Stderr, "Serving reports on http://%s\n", addr)
		return r.Run(addr)
	},
}

func loadSummary(dir string) (*scanner.Summary, error) {
	b, err := os.ReadFile(filepath.Join(dir, "report.json"))
	if err != nil {
		return nil, err
	}
	var s scanner.Summary
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// templateData adapts a summary to the shape web/template.html expects:
// promoted summary fields at the top level ({{.Critical}}, {{range
// .Findings}}), exactly like report.HTML. Passing the summary under a
// named key instead renders an empty page.
func templateData(s *scanner.Summary) struct {
	*scanner.Summary
	Empty           bool
	NewFingerprints map[string]bool
	TransitiveRows  [][]string
} {
	return struct {
		*scanner.Summary
		Empty           bool
		NewFingerprints map[string]bool
		TransitiveRows  [][]string
	}{s, len(s.Findings) == 0, nil, nil}
}

func init() {
	serveCmd.Flags().String("port", "", "port override (default from config)")
	serveCmd.Flags().String("host", "", "host to bind (default 127.0.0.1)")
	rootCmd.AddCommand(serveCmd)
}
