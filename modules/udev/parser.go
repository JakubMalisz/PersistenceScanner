package udev

import (
	"bufio"
	"os"
	"regexp"
	"strings"
)

type UdevSpecs struct {
	Commands []UdevCommands `json:"commands,omitempty"`
}

type UdevCommands struct {
	Directive string `json:"directive,omitempty"`
	Command   string `json:"command,omitempty"`
}

var runDirectiveRegex = regexp.MustCompile(`(IMPORT\{[^}]+\}|PROGRAM|RUN|ENV\{[^}]+\})\+?=\s*(?:"([^"]*)"|'([^']*)')`)

func Content(path string) (*UdevSpecs, error) {

	if !strings.HasSuffix(path, ".rules") {
		return &UdevSpecs{}, nil
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	specs := &UdevSpecs{}
	scanner := bufio.NewScanner(file)

	var buffer string

	for scanner.Scan() {
		rawLine := strings.TrimSpace(scanner.Text())

		if len(rawLine) == 0 || strings.HasPrefix(rawLine, "#") {
			continue
		}

		if strings.HasSuffix(rawLine, "\\") {
			buffer += strings.TrimSuffix(rawLine, "\\") + " "
			continue

		}

		line := buffer + rawLine
		buffer = ""

		matches := runDirectiveRegex.FindAllStringSubmatch(line, -1)
		for _, match := range matches {
			if len(match) >= 4 {
				command := match[2]
				if command == "" {
					command = match[3]
				}

				entry := UdevCommands{
					Directive: match[1],
					Command:   command,
				}
				specs.Commands = append(specs.Commands, entry)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return specs, nil
}
