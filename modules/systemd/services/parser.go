package services

import (
	
	"bufio"
	"os"
	"strings"
)

type ServiceSpecs struct {
	Type          string   `json:"type,omitempty"`
	ExecStart     []string   `json:"exec_start,omitempty"`
	ExecStartPre []string `json:"exec_start_pre,omitempty"`
	ExecStartPost []string `json:"exec_start_post,omitempty"`
	Restart       string   `json:"restart,omitempty"`
	EnvFiles      []string `json:"environmental_files,omitempty"`
}


func Content(path string) (*ServiceSpecs, error){
	file, err :=os.Open(path)
	if err != nil{
		return nil, err
	}
	defer file.Close()

	specs := &ServiceSpecs{}
	scanner := bufio.NewScanner(file)

	var buffer string
	 
	for scanner.Scan(){
		rawLine := strings.TrimSpace(scanner.Text())

		if len(rawLine) == 0 || strings.HasPrefix(rawLine, "#") || strings.HasPrefix(rawLine, ";") || strings.HasPrefix(rawLine, "[") {
			continue
		}
		
		if strings.HasSuffix(rawLine, "\\"){
			buffer += strings.TrimSuffix(rawLine, "\\") + " "
			continue

		}

		line := buffer + rawLine
		buffer = ""

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2{
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "Type":
			specs.Type = value
		case "ExecStart":
			specs.ExecStart = append(specs.ExecStart, value)
		case "ExecStartPre":
			specs.ExecStartPre = append(specs.ExecStartPre, value)
		case "ExecStartPost":
			specs.ExecStartPost = append(specs.ExecStartPost, value)
		case "Restart":
			specs.Restart = value 
		case "EnvironmentFile":
			specs.EnvFiles = append(specs.EnvFiles, value)
		}


	}
	if err := scanner.Err(); err != nil{
		return nil, err
	}

	return specs, nil

}