// Package web holds the HTML dashboard template.
//
// The template is embedded in the binary so a released actionscan can
// render its report from any working directory — reading it from disk
// made every published binary fail at the last step of a scan.
package web

import _ "embed"

//go:embed template.html
var templateHTML string

// TemplateHTML is the dashboard template source.
func TemplateHTML() string { return templateHTML }
