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

func PickModule() string{
	
	for{
		fmt.Print("Pick scanning module:\n")
		fmt.Print("[1] Systemd Services Scan\n")
		fmt.Print("[2] Cron Scan\n")
		fmt.Print("[3] Motd Files Scan\n")
		fmt.Print("[4] PAM Modules Scan\n")
		fmt.Print("[0] Exit\n")
			
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
			fmt.Println("[+] Exiting...")
			os.Exit(0)
		default:
			fmt.Println("[-] Incorrect module")
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
			for _, alert := range output{
				fmt.Printf("[!] Persistence mechanisms detected:\n%+v\n", alert)
			}
		} else{
			fmt.Print("[*] No persistence mechanisms detected")
		}
	}
}
