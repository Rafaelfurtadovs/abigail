package rules_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/Rafaelfurtadovs/abigail/internal/ruleengine"
	"github.com/Rafaelfurtadovs/abigail/rules"
)

func TestReferenceServiceCoverage(t *testing.T) {
	pack, err := ruleengine.Parse(rules.Default)
	if err != nil {
		t.Fatalf("embedded rules: %v", err)
	}
	data, err := os.ReadFile("coverage.json")
	if err != nil {
		t.Fatal(err)
	}
	var coverage struct {
		Counts struct {
			SubdominatorServices  int `json:"subdominator_services"`
			AbigailMappedServices int `json:"abigail_mapped_services"`
			AbigailRules          int `json:"abigail_rules"`
			ExcludedServices      int `json:"excluded_services"`
			UnmappedServices      int `json:"unmapped_services"`
		} `json:"counts"`
		Services []struct {
			UpstreamService string   `json:"upstream_service"`
			AbigailRuleID   string   `json:"abigail_rule_id"`
			AbigailStatus   string   `json:"abigail_status"`
			Decision        string   `json:"decision"`
			Notes           []string `json:"notes"`
		} `json:"services"`
	}
	if err := json.Unmarshal(data, &coverage); err != nil {
		t.Fatal(err)
	}
	if coverage.Counts.SubdominatorServices != 97 ||
		coverage.Counts.AbigailRules != len(pack.Rules) ||
		coverage.Counts.AbigailMappedServices+coverage.Counts.ExcludedServices != len(coverage.Services) ||
		coverage.Counts.UnmappedServices != 0 ||
		len(coverage.Services) != 97 {
		t.Fatalf("coverage counts disagree: %+v, rules=%d, mappings=%d", coverage.Counts, len(pack.Rules), len(coverage.Services))
	}
	rulesByID := make(map[string]string, len(pack.Rules))
	for _, rule := range pack.Rules {
		rulesByID[rule.ID] = rule.Status
	}
	seenRules := make(map[string]bool, len(coverage.Services))
	seenServices := make(map[string]bool, len(coverage.Services))
	excluded := 0
	for _, item := range coverage.Services {
		if item.UpstreamService == "" || seenServices[item.UpstreamService] {
			t.Fatalf("missing or duplicate upstream service %+v", item)
		}
		seenServices[item.UpstreamService] = true
		if item.Decision == "excluded" {
			if item.AbigailRuleID != "" || item.AbigailStatus != "excluded" || len(item.Notes) == 0 {
				t.Fatalf("excluded service needs a reason and no active rule: %+v", item)
			}
			excluded++
			continue
		}
		status, exists := rulesByID[item.AbigailRuleID]
		if item.Decision != "active" || item.AbigailRuleID == "" || !exists ||
			status != item.AbigailStatus || seenRules[item.AbigailRuleID] {
			t.Fatalf("invalid active coverage mapping %+v", item)
		}
		seenRules[item.AbigailRuleID] = true
	}
	if excluded != coverage.Counts.ExcludedServices || len(seenRules) != len(pack.Rules) || len(seenRules) != coverage.Counts.AbigailMappedServices {
		t.Fatalf("active and excluded coverage counts disagree: active=%d, excluded=%d", len(seenRules), excluded)
	}
}
