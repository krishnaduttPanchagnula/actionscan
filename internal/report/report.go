package report

import (
	"encoding/csv"
	"encoding/json"
	"html/template"
	"os"
	"path/filepath"

	"github.com/krishnaduttPanchagnula/actionscan/internal/scanner"
)

func HTML(s *scanner.Summary, dir string) (string, error) {
	tmpl, err := template.ParseFiles("web/template.html")
	if err != nil {
		return "", err
	}
	p := filepath.Join(dir, "report.html")
	f, err := os.Create(p)
	if err != nil {
		return "", err
	}
	defer f.Close()

	data := struct {
		*scanner.Summary
		Empty bool
	}{s, len(s.Findings) == 0}

	return p, tmpl.Execute(f, data)
}

func CSV(s *scanner.Summary, dir string) (string, error) {
	p := filepath.Join(dir, "report.csv")
	f, err := os.Create(p)
	if err != nil {
		return "", err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	w.Write([]string{"repo", "workflow", "action", "ref", "severity", "category", "reason"})
	for _, fi := range s.Findings {
		w.Write([]string{fi.Repo, fi.Workflow, fi.Action, fi.Ref, fi.Severity, fi.Category, fi.Reason})
	}
	w.Flush()
	return p, w.Error()
}

func JSON(s *scanner.Summary, dir string) (string, error) {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return "", err
	}
	p := filepath.Join(dir, "report.json")
	return p, os.WriteFile(p, b, 0o644)
}
