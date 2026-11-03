package udev

import (
	"PersistenceScanner/internal/core"
	"regexp"
)

type Analyzer struct {
	Rules []core.DetectionRule
}

func (a *Analyzer) GetPaths() []string {
	return []string{
		"/etc/udev/rules.d/*.rules",
		"/run/udev/rules.d/*.rules",
		"/lib/udev/rules.d/*.rules",
		"/usr/lib/udev/rules.d/*.rules",
	}
}

func (a *Analyzer) Analyze(file *core.FileData) ([]core.Alert, error) {
	specs, err := Content(file.Path)
	if err != nil {
		return nil, err
	}

	var allAlerts []core.Alert
	for _, entry := range specs.Commands {
		var extraInfo string
		switch entry.Directive {
		case "RUN":
			extraInfo = "Udev Persistence via Direct Action Directive (RUN)"
		case "PROGRAM":
			extraInfo = "Udev Stealth Execution via Condition Evaluation (PROGRAM)"
		case "IMPORT{program}":
			extraInfo = "Udev Evasion Technique via Environment Import Directive (IMPORT)"
		default:
			extraInfo = "Udev Execution via " + entry.Directive
		}

		for _, rule := range a.Rules {
			match, err := regexp.MatchString(rule.Pattern, entry.Command)
			if err == nil && match {
				entryAlert := core.Alert{
					FilePath:    file.Path,
					Pattern:     entry.Command,
					Description: rule.Description,
					Severity:    rule.Severity,
					ExtraInfo:   extraInfo,
				}
				allAlerts = append(allAlerts, entryAlert)
			}
		}
	}
	return allAlerts, nil
}
