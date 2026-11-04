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
			UnmappedServices      int `json:"unmapped_services"`
		} `json:"counts"`
		Services []struct {
			UpstreamService string `json:"upstream_service"`
			AbigailRuleID   string `json:"abigail_rule_id"`
		} `json:"services"`
	}
	if err := json.Unmarshal(data, &coverage); err != nil {
		t.Fatal(err)
	}
	if coverage.Counts.SubdominatorServices != 97 || len(pack.Rules) < 97 ||
		coverage.Counts.AbigailRules != len(pack.Rules) ||
		coverage.Counts.AbigailMappedServices != len(coverage.Services) ||
		coverage.Counts.UnmappedServices != 0 ||
		len(coverage.Services) != 97 {
		t.Fatalf("coverage counts disagree: %+v, rules=%d, mappings=%d", coverage.Counts, len(pack.Rules), len(coverage.Services))
	}
	rulesByID := make(map[string]bool, len(pack.Rules))
	for _, rule := range pack.Rules {
		rulesByID[rule.ID] = true
	}
	seenRules := make(map[string]bool, len(coverage.Services))
	seenServices := make(map[string]bool, len(coverage.Services))
	for _, item := range coverage.Services {
		if item.UpstreamService == "" || item.AbigailRuleID == "" || !rulesByID[item.AbigailRuleID] {
			t.Fatalf("missing rule for upstream service %+v", item)
		}
		if seenServices[item.UpstreamService] || seenRules[item.AbigailRuleID] {
			t.Fatalf("duplicate coverage mapping %+v", item)
		}
		seenServices[item.UpstreamService] = true
		seenRules[item.AbigailRuleID] = true
	}
}
