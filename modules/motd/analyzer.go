package motd
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
		"/etc/update-motd.d",
	} 
}

func (a *Analyzer) Analyze(file *core.FileData) ([]core.Alert, error){

	specs, err := Content(file.Path)
	if err != nil{
		return nil, err
	}
	var allAlerts []core.Alert
	for _, rule := range a.Rules{

		for _, command := range specs.Commands{
			match, err := regexp.MatchString(rule.Pattern, command)
			if err == nil && match {
				commandAlert := core.Alert{
					FilePath: file.Path,
					Pattern: rule.Pattern,
					Description: rule.Description,
					Severity: rule.Severity,
					
				}
			allAlerts  = append(allAlerts, commandAlert)	
			}
		}
	}
	return allAlerts, nil

}	