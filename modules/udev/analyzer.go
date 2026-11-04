package udev

import (
	"PersistenceScanner/internal/core"
	"regexp"
	"strings"
)

type Analyzer struct {
	Rules []core.DetectionRule
}

func (a *Analyzer) GetPaths() []string {
	return []string{
		"/etc/udev/rules.d",
		"/run/udev/rules.d",
		"/lib/udev/rules.d",
		"/usr/lib/udev/rules.d",
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
		switch {
		case entry.Directive == "RUN":
			extraInfo = "Udev Persistence via Direct Action Directive (RUN)"
		case entry.Directive == "PROGRAM":
			extraInfo = "Udev Stealth Execution via Condition Evaluation (PROGRAM)"
		case strings.HasPrefix(entry.Directive, "IMPORT"):
			extraInfo = "Udev Evasion Technique via Environment Import Directive (" + entry.Directive + ")"
		case strings.HasPrefix(entry.Directive, "ENV{"):
			extraInfo = "Udev Macro Evasion via Environment Variable (" + entry.Directive + ")"
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
