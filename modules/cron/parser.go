package cron

import (
	
	"bufio"
	"os"
	"strings"
)

type CronSpecs struct {
	Variables map[string]string `json:"variables,omitempty"`
	Schedules []string `json:"schedules,omitempty"` 
	Users []string `json:"users,omitempty"`
	Commands []string `json:"commands,omitempty"`
}

func Content(path string) (*CronSpecs, error){
	file, err := os.Open(path)
	if err != nil{
		return nil, err
	}
	defer file.Close()



	specs := &CronSpecs{
		Variables: make(map[string]string),
	}
	scanner := bufio.NewScanner(file)

	isSystemCrontab = path == "/etc/crontab" || strings.Contains(path, "/etc/cron.d")

	for scanner.Scan(){
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 || strings.HasPrefix(line, "#"){
			continue
		}
		

		if strings.Contains(line, "=") && !strings.Contains(line, "@"){
			variableParts := strings.SplitN(line, "=", 2)
			if len(variableParts) == 2 && !strings.Contains(variableParts[0], " "){
				key := strings.TrimSpace(variableParts[0])
				value := strings.TrimSpace(variableParts[1])
				specs.Variables[key] = value
				continue
			}
		}

		parts := strings.Fields(line)
		if len(parts) < 2{
			continue
		}
		currentIndex := 0

		if strings.HasPrefix(parts[0], "@"){
			specs.Schedules = append(specs.Schedules, parts[0])
			currentIndex = 1
		} else if len(parts) >=6 {
			specs.Schedules = append(specs.Schedules, strings.Join(parts[0:5], " "))
			currentIndex = 5
		}

		if isSystemCrontab && len(parts) > currentIndex{
			specs.Users = append(specs.Users, parts[currentIndex])
			currentIndex++
		}
		
		if len(parts) > currentIndex{
			specs.Commands = append(specs.Commands, strings.Join(parts[currentIndex:], " "))
		}
	}
		
	if err := scanner.Err(); err != nil{
		return nil, err
	}
	return specs, nil
}
