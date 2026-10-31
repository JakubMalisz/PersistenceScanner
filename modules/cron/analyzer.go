package cron
import (

	"strings"
	"PersistenceScanner/internal/core"
	"reflect"
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

		//Script paths
		"/etc/cron.hourly",
		"/etc/cron.daily",
		"/etc/cron.weekly",
		"/etc/cron.monthly",
	} 
}

func (a *Analyzer) Analyze(file *core.FileData) ([]core.Alert, error){

	specs, err := Content(file.Path)
	if err != nil{
		return nil, err
	}

	var allAlerts []core.Alert

	switch s := specs.(type) {
	
	case *CronSpecs:
		var targetUsers, schedules string
		if len(s.Users) > 0 {
			targetUsers = strings.Join(s.Users, ", ")
		}
		if len(s.Schedules) > 0 {
			schedules = strings.Join(s.Schedules, ", ")
		}

		for _, rule := range a.Rules {
			for _, value := range s.Variables {
				if strings.Contains(value, rule.Pattern) {
					variableAlert := core.Alert{
						FilePath:    file.Path,
						Pattern:     rule.Pattern,
						Description: rule.Description,
						Severity:    rule.Severity,
						ExtraInfo:   "Schedules: " + schedules + " | Users: " + targetUsers,
					}
					allAlerts = append(allAlerts, variableAlert)
				}
			}

			for _, command := range s.Commands {
				if strings.Contains(command, rule.Pattern) {
					commandAlert := core.Alert{
						FilePath:    file.Path,
						Pattern:     rule.Pattern,
						Description: rule.Description,
						Severity:    rule.Severity,
						ExtraInfo:   "Schedules: " + schedules + " | Users: " + targetUsers,
					}
					allAlerts = append(allAlerts, commandAlert)
				}
			}

			for _, schedule := range s.Schedules {
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

	case *CronScriptSpecs:
		for _, rule := range a.Rules {
			for _, command := range s.Commands {
				if strings.Contains(command, rule.Pattern) {
					commandAlert := core.Alert{
						FilePath:    file.Path,
						Pattern:     rule.Pattern,
						Description: rule.Description,
						Severity:    rule.Severity,
					}
					allAlerts = append(allAlerts, commandAlert)
				}
			}
		}
	}

	return allAlerts, nil
}

