package main

import (
	"fmt"
	"os"
	"PersistenceScanner/internal/core"
	"PersistenceScanner/internal/feed"
	"PersistenceScanner/scanner"
	"PersistenceScanner/modules/cron"
	"PersistenceScanner/modules/motd"
	"PersistenceScanner/modules/pam"
	"PersistenceScanner/modules/systemd/services"
)

const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Cyan   = "\033[36m"
	Bold   = "\033[1m"
)

func PickModule() string{
	
	for{
		fmt.Print("\n\n%s=== PScanner ===%s\n", Bold, Cyan, Reset)
		fmt.Printf("%s[1]%s Systemd Services Scan\n", Yellow, Reset)
		fmt.Printf("%s[2]%s Cron Scan\n", Yellow, Reset)
		fmt.Printf("%s[3]%s Motd Files Scan\n", Yellow, Reset)
		fmt.Printf("%s[4]%s PAM Modules Scan\n", Yellow, Reset)
		fmt.Printf("%s[0]%s Exit\n", Red, Reset)
		
		fmt.Printf("Pick scanning module: ")

		var moduleNumber int
		fmt.Scan(&moduleNumber)
		switch moduleNumber{
		case 1:
			return "services"
		case 2:
			return "cron"
		case 3:
			return "motd"
		case 4:
			return "pam"
		case 0:
			fmt.Printf("%s[+] Exiting...%s\n", Green, Reset)
			os.Exit(0)
		default:
			fmt.Printf("%s[-] Incorrect module. Try again.%s\n", Red, Reset)
			var discard string
			fmt.Scanln(&discard)
		}
	}
}


func main(){

	fmt.Println("[*] Fetching detection rules...")
	rulesURL := "https://raw.githubusercontent.com/JakubMalisz/PersistenceScanner/main/rules.json" 
	fetchedRules, err := feed.FetchRules(rulesURL)
	if err != nil {
		fmt.Printf("[-] Fetching error")
		os.Exit(1)
	}
	fmt.Println("[+] Detection rules fetched successfuly\n")	
	fmt.Printf("[*] Number of rules: %d\n", len(fetchedRules))

	for{
		selectedModule := PickModule()

		modulesRegistry := map[string]core.Analyzer{
			"services": &services.Analyzer{Rules: fetchedRules},
			"cron": &cron.Analyzer{Rules: fetchedRules},
			"motd": &motd.Analyzer{Rules: fetchedRules},
			"pam": &pam.Analyzer{Rules: fetchedRules},
		}
		analyzer := modulesRegistry[selectedModule]

		
		
		var paths []string
		paths = append(paths, analyzer.GetPaths()...)
		

		
		fmt.Println("[*] Scanning files...\n")
		filesChan := scanner.DirScan(paths)
		
		var output []core.Alert

		for file := range filesChan{
			alerts, err := analyzer.Analyze(&file)
			if err != nil{
				fmt.Println(err)
			}
			if len(alerts) > 0{
				output = append(output, alerts...)
			}
		}

		
		if len(output) > 0{
			fmt.Printf("\n%s%s[!] Persistence mechanisms detected:%s\n", Bold, Red, Reset)
			for _, alert := range output{
				fmt.Printf("%s[-] FILE:%s %s\n", Red, Reset, alert.FilePath)
			fmt.Printf("    %sSeverity:%s %s%s%s\n", Yellow, Reset, Bold, alert.Severity, Reset)
			fmt.Printf("    %sPattern:%s  %s\n", Cyan, Reset, alert.Pattern)
			fmt.Printf("    %sDescription:%s     %s\n", Cyan, Reset, alert.Description)
			fmt.Printf("    %sExtra:%s    %s\n", Cyan, Reset, alert.ExtraInfo)
			}
		} else{
			fmt.Printf("\n%s[+] No persistence mechanisms detected.%s\n", Green, Reset)
		}
	}
}
