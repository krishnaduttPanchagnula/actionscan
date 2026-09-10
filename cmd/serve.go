package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
	"github.com/krishnaduttPanchagnula/actionscan/internal/scanner"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Serve the HTML report + CSV download via web page",
	RunE: func(cmd *cobra.Command, args []string) error {
		outDir := viper.GetString("scan.report_dir")
		mode := viper.GetString("server.mode")

		port, _ := cmd.Flags().GetString("port")
		if port == "" {
			port = viper.GetString("server.port")
		}

		gin.SetMode(mode)
		r := gin.Default()

		summary, err := loadSummary(outDir)
		if err != nil {
			fmt.Printf("⚠ No report in %s (run `actionscan scan` first): %v\n", outDir, err)
		}

		r.LoadHTMLGlob("web/*.html")

		r.GET("/", func(c *gin.Context) {
			if summary == nil {
				c.String(http.StatusNotFound, "No report yet — run `actionscan scan` first.")
				return
			}
			c.HTML(http.StatusOK, "template.html", gin.H{
				"Summary": summary,
				"Empty":   len(summary.Findings) == 0,
			})
		})

		r.GET("/report.csv", func(c *gin.Context) {
			c.FileAttachment(filepath.Join(outDir, "report.csv"), "actionscan-report.csv")
		})
		r.GET("/report.json", func(c *gin.Context) {
			c.FileAttachment(filepath.Join(outDir, "report.json"), "actionscan-report.json")
		})

		api := r.Group("/api")
		{
			api.GET("/status", func(c *gin.Context) {
				if summary == nil {
					c.JSON(http.StatusOK, gin.H{"report_available": false})
					return
				}
				c.JSON(http.StatusOK, gin.H{
					"report_available": true,
					"total_repos":      summary.TotalRepos,
					"findings":         len(summary.Findings),
				})
			})
			api.GET("/findings", func(c *gin.Context) {
				if summary == nil {
					c.JSON(http.StatusNotFound, gin.H{"error": "run `actionscan scan` first"})
					return
				}
				c.JSON(http.StatusOK, summary)
			})
		}

		fmt.Printf("Serving reports on http://localhost:%s\n", port)
		return r.Run(":" + port)
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

func init() {
	serveCmd.Flags().String("port", "", "port override (default from config)")
	rootCmd.AddCommand(serveCmd)
}
