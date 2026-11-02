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

	var buffer string

	for scanner.Scan(){
		rawLine := strings.TrimSpace(scanner.Text())
		if len(rawLine) != 0 && !strings.HasPrefix(rawLine, "#"){
			if strings.HasSuffix(rawLine, "\\"){
				buffer += strings.TrimSuffix(rawLine, "\\") + " "
				continue
			}

			line := buffer + rawLine
			buffer = ""

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