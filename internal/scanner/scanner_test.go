package scanner

import (
	"context"
	"testing"

	"github.com/Rafaelfurtadovs/abigail/internal/dnsprobe"
	"github.com/Rafaelfurtadovs/abigail/internal/httpprobe"
	"github.com/Rafaelfurtadovs/abigail/internal/ruleengine"
	"github.com/Rafaelfurtadovs/abigail/internal/validation"
)

type fakeHTTP struct{ result httpprobe.Result }

func (f fakeHTTP) Fetch(context.Context, string) httpprobe.Result { return f.result }

type fakeHTTPAll struct{ results []httpprobe.Result }

func (f fakeHTTPAll) Fetch(context.Context, string) httpprobe.Result {
	panic("Fetch must not be called when FetchAll is available")
}
func (f fakeHTTPAll) FetchAll(context.Context, string) []httpprobe.Result { return f.results }

type fakeValidator struct {
	result  validation.Result
	called  int
	targets []string
}

func (f *fakeValidator) Validate(_ context.Context, _ string, targets []string) validation.Result {
	f.called++
	f.targets = append([]string(nil), targets...)
	return f.result
}

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

func TestVerifiedParentNSUnresolvedDelegationIsEdgeCase(t *testing.T) {
	rule := ruleengine.Rule{ID: "digital-ocean", Service: "Digital Ocean", NSSuffixes: []string{"digitalocean.com"}, TargetNXDomain: true, Status: "edge_case", Source: "https://example.test/rule"}
	s := Scanner{Rules: []ruleengine.Rule{rule}, IncludeEdgeCases: true, Resolve: func(context.Context, string, dnsprobe.Options) dnsprobe.Result {
		return dnsprobe.Result{NS: []string{"ns1.digitalocean.com"}, NSParentVerified: true, ChainComplete: false, Errors: []string{"CNAME lookup: SERVFAIL"}}
	}}
	got := s.Scan(context.Background(), "sub.example.test")
	if got.Status != "edge_case" || len(got.Findings) != 1 || !got.Findings[0].DelegationUnresolved || got.Findings[0].TargetNXDomain {
		t.Fatalf("expected lower-confidence unresolved delegation evidence: %+v", got)
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

func TestHTTPBothSchemes(t *testing.T) {
	for _, tc := range []struct {
		name      string
		responses []httpprobe.Result
		want      string
		wantURL   string
	}{
		{"HTTP only signature", []httpprobe.Result{{URL: "https://sub.example.test", Status: 404, Body: []byte("other")}, {URL: "http://sub.example.test", Status: 404, Body: []byte("unclaimed")}}, "candidate", "http://sub.example.test"},
		{"one scheme failed", []httpprobe.Result{{URL: "https://sub.example.test", Error: "timeout"}, {URL: "http://sub.example.test", Status: 200, Body: []byte("other")}}, "unknown", ""},
		{"same rule on both", []httpprobe.Result{{URL: "https://sub.example.test", Status: 404, Body: []byte("unclaimed")}, {URL: "http://sub.example.test", Status: 404, Body: []byte("unclaimed")}}, "candidate", "https://sub.example.test"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := Scanner{Rules: []ruleengine.Rule{testRule()}, HTTP: fakeHTTPAll{tc.responses}, Resolve: func(context.Context, string, dnsprobe.Options) dnsprobe.Result {
				return dnsprobe.Result{CNAMEChain: []string{"gone.provider.test"}, FinalName: "gone.provider.test", ChainComplete: true}
			}}
			got := s.Scan(context.Background(), "sub.example.test")
			if got.Status != tc.want || len(got.HTTPProbes) != len(tc.responses) {
				t.Fatalf("got %+v, want %s with %d probes", got, tc.want, len(tc.responses))
			}
			if tc.wantURL != "" && (len(got.Findings) != 1 || got.Findings[0].HTTPURL != tc.wantURL) {
				t.Fatalf("unexpected finding evidence: %+v", got.Findings)
			}
		})
	}
}

func TestDirectValidationStates(t *testing.T) {
	for _, tc := range []struct {
		state      validation.State
		wantStatus string
		findings   int
		dismissed  int
	}{
		{validation.Available, "validated", 1, 0},
		{validation.Unavailable, "dismissed", 0, 1},
		{validation.Unknown, "candidate", 1, 0},
		{validation.Unsupported, "candidate", 1, 0},
	} {
		validator := &fakeValidator{result: validation.Result{Provider: "Provider", State: tc.state, Target: "gone.provider.test"}}
		s := Scanner{
			Rules:     []ruleengine.Rule{testRule()},
			HTTP:      fakeHTTP{httpprobe.Result{Status: 404, Body: []byte("unclaimed")}},
			Validate:  true,
			Validator: validator,
			Resolve: func(context.Context, string, dnsprobe.Options) dnsprobe.Result {
				return dnsprobe.Result{CNAMEChain: []string{"gone.provider.test"}, FinalName: "gone.provider.test", ChainComplete: true}
			},
		}
		got := s.Scan(context.Background(), "sub.example.test")
		if got.Status != tc.wantStatus || len(got.Findings) != tc.findings || len(got.Dismissed) != tc.dismissed {
			t.Errorf("validation state %s: %+v", tc.state, got)
		}
		if validator.called != 1 || len(validator.targets) != 1 || validator.targets[0] != "gone.provider.test" {
			t.Errorf("validation state %s: unexpected calls: %+v", tc.state, validator)
		}
	}
}

func TestDirectValidationRequiresExactFinalTarget(t *testing.T) {
	for _, tc := range []struct {
		name          string
		chain         []string
		final         string
		complete      bool
		apiTarget     string
		wantCallCount int
	}{
		{"matched intermediate", []string{"gone.provider.test", "other.example.test"}, "other.example.test", true, "gone.provider.test", 0},
		{"incomplete chain", []string{"gone.provider.test"}, "gone.provider.test", false, "gone.provider.test", 0},
		{"API response mismatch", []string{"gone.provider.test"}, "gone.provider.test", true, "other.provider.test", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			validator := &fakeValidator{result: validation.Result{Provider: "Provider", State: validation.Unavailable, Target: tc.apiTarget}}
			s := Scanner{
				Rules: []ruleengine.Rule{testRule()}, HTTP: fakeHTTP{httpprobe.Result{Status: 404, Body: []byte("unclaimed")}},
				Validate: true, Validator: validator,
				Resolve: func(context.Context, string, dnsprobe.Options) dnsprobe.Result {
					return dnsprobe.Result{CNAMEChain: tc.chain, FinalName: tc.final, ChainComplete: tc.complete}
				},
			}
			got := s.Scan(context.Background(), "sub.example.test")
			if got.Status != "candidate" || len(got.Dismissed) != 0 || validator.called != tc.wantCallCount {
				t.Fatalf("must keep candidate when exact target is not proven: %+v, calls=%d", got, validator.called)
			}
			if got.Findings[0].Validation == nil || (got.Findings[0].Validation.State != validation.Unknown && got.Findings[0].Validation.State != validation.Unsupported) {
				t.Fatalf("expected inconclusive validation: %+v", got.Findings[0])
			}
		})
	}
}
