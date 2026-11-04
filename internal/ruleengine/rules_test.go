package ruleengine

import (
	"testing"

	"github.com/Rafaelfurtadovs/abigail/rules"
)

func TestEmbeddedRulesParse(t *testing.T) {
	pack, err := Parse(rules.Default)
	if err != nil {
		t.Fatal(err)
	}
	if len(pack.Rules) < 40 {
		t.Fatalf("expected curated coverage, got %d rules", len(pack.Rules))
	}
}

func TestCNAMEBoundaryAndExactMatch(t *testing.T) {
	rule := Rule{CNAMESuffixes: []string{"example.com"}, CNAMEExact: []string{"fixed.other.test"}}
	for _, name := range []string{"example.com.", "sub.example.com.", "fixed.other.test."} {
		if got := MatchDNS(rule, []string{name}, nil, nil); len(got) != 1 {
			t.Errorf("expected %s to match, got %v", name, got)
		}
	}
	for _, name := range []string{"notexample.com", "example.com.attacker.test", "sub.fixed.other.test"} {
		if got := MatchDNS(rule, []string{name}, nil, nil); len(got) != 0 {
			t.Errorf("expected %s not to match, got %v", name, got)
		}
	}
}

func TestHTTPRequiresStatusAndBody(t *testing.T) {
	rule := Rule{HTTPStatuses: []int{404}, BodySubstrings: []string{"resource does not exist"}}
	for _, test := range []struct {
		status int
		body   string
		want   bool
	}{{404, "resource does not exist", true}, {200, "resource does not exist", false}, {404, "ordinary 404", false}} {
		_, got := MatchHTTP(rule, test.status, []byte(test.body))
		if got != test.want {
			t.Errorf("status %d body %q: got %v, want %v", test.status, test.body, got, test.want)
		}
	}
}
