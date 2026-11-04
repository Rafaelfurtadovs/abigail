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
		if got := MatchDNS(rule, []string{name}, nil, nil, nil); len(got) != 1 {
			t.Errorf("expected %s to match, got %v", name, got)
		}
	}
	for _, name := range []string{"notexample.com", "example.com.attacker.test", "sub.fixed.other.test"} {
		if got := MatchDNS(rule, []string{name}, nil, nil, nil); len(got) != 0 {
			t.Errorf("expected %s not to match, got %v", name, got)
		}
	}
}

func TestRegexAndNSMatching(t *testing.T) {
	rule := Rule{CNAMERegexes: []string{`^[^.]+-portal\.apigee\.net$`}, NSSuffixes: []string{"digitalocean.com"}}
	if got := MatchDNS(rule, []string{"customer-portal.apigee.net"}, nil, nil, nil); len(got) != 1 {
		t.Fatalf("expected CNAME regex match: %v", got)
	}
	if got := MatchDNS(rule, []string{"customer-portal.apigee.net.attacker.test"}, nil, nil, nil); len(got) != 0 {
		t.Fatalf("unexpected CNAME regex match: %v", got)
	}
	if got := MatchDNS(rule, nil, nil, nil, []string{"ns1.digitalocean.com"}); len(got) != 1 || got[0].Record != "NS" {
		t.Fatalf("expected NS match: %v", got)
	}
}

func TestBodyRegexAndStatusOnly(t *testing.T) {
	rule := Rule{BodyRegexes: []string{`(?i)no such app`}, HTTPStatuses: []int{404}}
	if _, ok := MatchHTTP(rule, 404, []byte("NO SUCH APP")); !ok {
		t.Fatal("expected regex body match")
	}
	if _, ok := MatchHTTP(rule, 200, []byte("NO SUCH APP")); ok {
		t.Fatal("status mismatch must fail")
	}
	onlyStatus := Rule{HTTPStatuses: []int{404}}
	if _, ok := MatchHTTP(onlyStatus, 404, nil); !ok {
		t.Fatal("expected status-only match")
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
