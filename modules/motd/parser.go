package motd

import (
	
	"bufio"
	"os"
	"strings"
)

type MotdSpecs struct{
	Commands []string `json:"commands,omitempty"`
}

func Content(path string) (*MotdSpecs, error){
	file, err := os.Open(path)
	if err != nil{
		return nil, err
	}
	defer file.Close()

	specs := &MotdSpecs{}
	scanner := bufio.NewScanner(file)

	for scanner.Scan(){
		line := strings.TrimSpace(scanner.Text())
		if len(line) != 0 && !strings.HasPrefix(line, "#"){
			specs.Commands = append(specs.Commands, line)
		} else{
			continue
		}

	}
	if err := scanner.Err(); err != nil{
		return nil, err
	}
	
	return specs, nil
}