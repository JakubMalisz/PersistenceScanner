package pam
import (

	"strings"
	"PersistenceScanner/internal/core"
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

func (a *Analyzer) Analyze(file *FileData) ([]core.Alert, error){
	entries, err := Content(file.Path)
	if err != nil{
		return nil, err
	}

	
	var allAlerts []core.Alert
	
	for _, entry := range entries{
		extraInfo := "Type: " + entry.Type + " | Control: " + entry.Control + " | Module: " + entry.Module + " | Args: " + entry.Args
		// Backdoor analysis
		if entry.Type == "auth" && entry.Module == "pam_permit.so"{
			backdoorAlert := core.Alert{
				FilePath: file.Path,
				Description: ""
				Severity: "CRITICAL",
				ExtraInfo: extraInfo
			}
			allAlerts = append(allAlerts, backdoorAlert)
		}
		// Args analysis
		if entry.Module == "pam_exec.so"{
			for _, rule := range Rules{
				if strings.Contains(entry.Args, rule.Pattern){
					commandAlert := core.Alert{
						FilePath: file.Path
						Description: rule.Description
						Severity: rule.Severity
						ExtraInfo: extraInfo
					}
					allAlerts = append(allAlerts, commandAlert)
				}
			}
		}
		// Path analysis
		if strings.HasPrefix(entry.Module, "/") && (strings.Contains(entry.Module, "/tmp") || strings.Contains(entry.Module, "/dev/shm")){
			pathAlert := core.Alert{
				FilePath: file.Path
				Description: ""
				Severity: "HIGH"
				ExtraInfo: extraInfo
			}
			allAlerts = append(allAlerts, pathAlert)
		}
	}

	return allAlerts, nil
}