package scanner

import (
	"context"
	"testing"

	"github.com/Rafaelfurtadovs/abigail/internal/dnsprobe"
	"github.com/Rafaelfurtadovs/abigail/internal/httpprobe"
	"github.com/Rafaelfurtadovs/abigail/internal/ruleengine"
)

type fakeHTTP struct{ result httpprobe.Result }

func (f fakeHTTP) Fetch(context.Context, string) httpprobe.Result { return f.result }

func testRule() ruleengine.Rule {
	return ruleengine.Rule{ID: "provider", Service: "Provider", CNAMESuffixes: []string{"provider.test"}, BodySubstrings: []string{"unclaimed"}, Status: "vulnerable", Source: "https://example.test/rule"}
}

func TestCandidateRequiresDNSAndHTTP(t *testing.T) {
	tests := []struct {
		cname string
		body  string
		want  string
	}{{"site.provider.test", "unclaimed", "candidate"}, {"site.provider.test", "normal page", "clean"}, {"provider.test.attacker.test", "unclaimed", "clean"}}
	for _, tc := range tests {
		s := Scanner{Rules: []ruleengine.Rule{testRule()}, HTTP: fakeHTTP{httpprobe.Result{Status: 404, Body: []byte(tc.body)}},
			Resolve: func(context.Context, string, dnsprobe.Options) dnsprobe.Result {
				return dnsprobe.Result{CNAMEChain: []string{tc.cname}, ChainComplete: true}
			}}
		got := s.Scan(context.Background(), "sub.example.test")
		if got.Status != tc.want {
			t.Errorf("%s + %q: got %s, want %s", tc.cname, tc.body, got.Status, tc.want)
		}
	}
}

func TestNXDomainNeedsCompleteCNAMEChain(t *testing.T) {
	rule := testRule()
	rule.BodySubstrings = nil
	rule.TargetNXDomain = true
	for _, complete := range []bool{true, false} {
		s := Scanner{Rules: []ruleengine.Rule{rule}, Resolve: func(context.Context, string, dnsprobe.Options) dnsprobe.Result {
			return dnsprobe.Result{CNAMEChain: []string{"gone.provider.test"}, NXDomain: true, ChainComplete: complete}
		}}
		got := s.Scan(context.Background(), "sub.example.test")
		want := "unknown"
		if complete {
			want = "candidate"
		}
		if got.Status != want {
			t.Errorf("complete=%v: got %s, want %s", complete, got.Status, want)
		}
	}
}

func TestHTTPErrorIsUnknown(t *testing.T) {
	s := Scanner{Rules: []ruleengine.Rule{testRule()}, HTTP: fakeHTTP{httpprobe.Result{Error: "timeout"}},
		Resolve: func(context.Context, string, dnsprobe.Options) dnsprobe.Result {
			return dnsprobe.Result{CNAMEChain: []string{"gone.provider.test"}}
		}}
	got := s.Scan(context.Background(), "sub.example.test")
	if got.Status != "unknown" || len(got.Findings) != 0 {
		t.Fatalf("network failure must not become positive or clean: %+v", got)
	}
}
