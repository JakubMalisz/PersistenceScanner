package feed

import (

	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
	"PersistenceScanner/internal/core"

)

type GitHubRule struct{
	Indicator string `json:"indicator"`
	Description string `json:"description"`
	Severity string `json:"severity"`
}

func FetchRules(url string) ([]core.DetectionRule, error){
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil{
		return nil, fmt.Errorf("ERROR: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK{
		return nil, fmt.Errorf("ERROR: %v", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil{
		return nil, err
	}

	var ghRules []GitHubRule
	
	if err := json.Unmarshal(body, &ghRules);err != nil{
		return nil, err
	}

	var rules []core.DetectionRule
	for _, rule := range ghRules{
		rules = append(rules, core.DetectionRule{
			Pattern: rule.Indicator,
			Description: rule.Description,
			Severity: rule.Severity,
		})
	}
	return rules, nil
}