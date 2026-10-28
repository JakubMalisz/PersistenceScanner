package cron
import (

	"strings"
	"PersistenceScanner/internal/core"
)

type Analyzer struct {
	Rules []core.DetectionRule
}


func (a *Analyzer) GetPaths() []string{
	return []string{
		"/etc/crontab",
		"/etc/cron.d",
		"/var/spool/cron",          
		"/var/spool/cron/crontabs",
	} 
}

func (a *Analyzer) Analyze(file *core.FileData) ([]core.Alert, error){

	specs, err := Content(file.Path)
	if err != nil{
		return nil, err
	}

	var targetUsers, schedules string
	if len(specs.Users) > 0{
		targetUsers = strings.Join(specs.Users, ", ")
	}

	if len(specs.Schedules) > 0{
		schedules = strings.Join(specs.Schedules ", ")
	}

	var allAlerts []core.Alert

	for _, rule := range a.Rules{
		
		for _, value := range specs.Variables{
			if strings.Contains(value, rule.Pattern){
				variableAlert := core.Alert{
					FilePath: file.Path,
					Pattern: rule.Pattern,
					Description: rule.Description,
					Severity: rule.Severity,
					ExtraInfo: "Schedules: " + schedules + "| Users: " + targetUsers,
				}
				allAlerts = append(fileAlerts, variableAlert)
			}
		}
	
		for _, command := range specs.Commands{
			if strings.Contains(command, rule.Pattern){
				commandAlert := core.Alert{
					FilePath: file.Path,
					Pattern: rule.Pattern,
					Description: rule.Description,
					Severity: rule.Severity,
					ExtraInfo: "Schedules: " + schedules + "| Users: " + targetUsers,
				}
				allAlerts = append(fileAlerts, commandAlert)
			}
		}

		for _, schedule := range specs.Schedules {
			if strings.Contains(schedule, rule.Pattern) {
				scheduleAlert := core.Alert{
					FilePath:    file.Path,
					Pattern:     rule.Pattern,
					Description: rule.Description,
					Severity:    rule.Severity,
					ExtraInfo:   "Users: " + targetUsers,
				}
				allAlerts = append(allAlerts, scheduleAlert)
			}
		}
		
	}
	
	return allAlerts, nil
}

