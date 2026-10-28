package motd
import (

	"strings"
	"PersistenceScanner/internal/core"
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

	specs, err := Content(file)
	if err != nil{
		return nil, err
	}
	var allAlerts []core.Alert
	for _, rule := range Rules{

		for _, command := range specs.Commands{
			if strings.Contains(specs.Commands, rule.Pattern){
				commandAlert := core.Alert{
					FilePath: file.Path
					Pattern: rule.Pattern
					Description: rule.Description
					Severity: rule.Severity
					
				}
			allAlerts  = append(fileAlerts, commandAlert)	
			}
		}
	}
	return allAlerts, err

}	