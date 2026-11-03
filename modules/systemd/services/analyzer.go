package services

import (
	"PersistenceScanner/internal/core"
	"regexp"
)

type Analyzer struct {
	Rules []core.DetectionRule
}

func (a *Analyzer) GetPaths() []string {
	return []string{
		"/etc/systemd/system",
		"/run/systemd/system",
		"/lib/systemd/system",
		"/usr/lib/systemd/system",
	}
}

func (a *Analyzer) Analyze(file *core.FileData) ([]core.Alert, error) {

	getFieldValues := func(specs ServiceSpecs, fieldName string) []string {
		switch fieldName {
		case "ExecStart":
			return specs.ExecStart
		case "ExecStartPre":
			return specs.ExecStartPre
		case "ExecStartPost":
			return specs.ExecStartPost
		case "EnvFiles":
			return specs.EnvFiles
		default:
			return nil
		}
	}

	buildAlert := func(specs ServiceSpecs, fieldName string) ([]core.Alert, error) {
		var fileAlerts []core.Alert
		for _, rule := range a.Rules {

			commands := getFieldValues(specs, fieldName)

			for _, command := range commands {
				match, err := regexp.MatchString(rule.Pattern, command)
				if err == nil && match {
					commandAlert := core.Alert{
						FilePath:    file.Path,
						Pattern:     command,
						Description: rule.Description,
						Severity:    rule.Severity,
					}
					fileAlerts = append(fileAlerts, commandAlert)
				}
			}
		}

		return fileAlerts, nil
	}

	var allAlerts []core.Alert

	specs, err := Content(file.Path)
	if err != nil {
		return nil, err
	}

	fieldsToCheck := []string{"ExecStart", "ExecStartPre", "ExecStartPost", "EnvFiles"}
	for _, field := range fieldsToCheck {
		fieldAlerts, err := buildAlert(*specs, field)
		if err != nil {
			return nil, err
		}
		allAlerts = append(allAlerts, fieldAlerts...)
	}

	return allAlerts, nil
}
