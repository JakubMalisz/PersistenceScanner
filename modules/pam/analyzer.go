package pam

import (
	"PersistenceScanner/internal/core"
	"regexp"
)

type Analyzer struct {
	Rules []core.DetectionRule
}

func (a *Analyzer) GetPaths() []string {
	return []string{
		"/etc/pam.d",
		"/etc/pam.conf",
	}
}

func (a *Analyzer) Analyze(file *core.FileData) ([]core.Alert, error) {
	entries, err := Content(file.Path)
	if err != nil {
		return nil, err
	}

	var allAlerts []core.Alert

	for _, entry := range entries {
		line := "Type: " + entry.Type + " | Control: " + entry.Control + " | Module: " + entry.Module

		if entry.Args != "" {
			line += " | Args: " + entry.Args
		}

		for _, rule := range a.Rules {
			match, err := regexp.MatchString(rule.Pattern, line)
			if err == nil && match {
				alert := core.Alert{
					FilePath:    file.Path,
					Pattern:     line,
					Description: rule.Description,
					Severity:    rule.Severity,
				}
				allAlerts = append(allAlerts, alert)
			}
		}

	}

	return allAlerts, nil
}
