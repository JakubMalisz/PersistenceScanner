package pam

import (
	
	"bufio"
	"os"
	"strings"
)

type PamSpecs struct{
	Type: string `json:"type,omitempty"`
	Control: string `json:"control,omitempty"`
	Module: string `json:"module,omitempty"`
	Args: string `json:"args,omitempty"`
}

func Content(path string) ([]PamSpecs, error){
	file, err := os.Open(path)
	if err != nil{
		return nil, err
	}
	defer Close(file)

	var entries []PamSpecs
	scanner := bufio.NewScanner(file)

	for scanner.Scan(){
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 || strings.HasPrefix(line, "#"){
			continue
		}
		
		parts := strings.Fields(line)
		specs := PamSpecs{
			Type: parts[0],
			Control: parts[1],
			Module: parts[2],
		}
		if len(parts) > 3{
			specs.Args = strings.Join(parts[3:], " ")
		}
		entries = append(entries, specs)
	}
	
	if err := scanner.Err(); err != nil{
		return nil, err
	}
	return specs, nil
}