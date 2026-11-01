package pam
import (

	"strings"
	"PersistenceScanner/internal/core"
	"regexp"
)



type Analyzer struct {
	Rules []core.DetectionRule
}


func (a *Analyzer) GetPaths() []string{
	return []string{
		"/etc/pam.d",
		"/etc/pam.conf",
	} 
}

func (a *Analyzer) Analyze(file *core.FileData) ([]core.Alert, error){
	entries, err := Content(file.Path)
	if err != nil{
		return nil, err
	}

	
	var allAlerts []core.Alert
	
	for _, entry := range entries{
		extraInfo := "Type: " + entry.Type + " | Control: " + entry.Control + " | Module: " + entry.Module + " | Args: " + entry.Args
		
		line := entry.Type + " " + entry.Control + " " + entry.Module
		if entry.Args != "" {
			line += " " + entry.Args
		}

		for _, rule := range a.Rules {
			match, err := regexp.MatchString(rule.Pattern, line)
			if err == nil && match {
				alert := core.Alert{
					FilePath:    file.Path,
					Description: rule.Description,
					Severity:    rule.Severity,
					ExtraInfo:   extraInfo,
				}
				allAlerts = append(allAlerts, alert)
			}
		}

		if strings.HasPrefix(entry.Module, "/") && (strings.Contains(entry.Module, "/tmp") || strings.Contains(entry.Module, "/dev/shm")) {
			pathAlert := core.Alert{
				FilePath:    file.Path,
				Description: "Execution from suspicious directory (/tmp or /dev/shm)",
				Severity:    "HIGH",
				ExtraInfo:   extraInfo,
			}
			allAlerts = append(allAlerts, pathAlert)
		}
	}

	return allAlerts, nil
}