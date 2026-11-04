package discovery

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type fakeDNSResolver struct {
	mu      sync.Mutex
	queries []string
	lookup  func(string) ([]string, error)
	cname   func(string) (string, error)
}

func (f *fakeDNSResolver) LookupCNAME(_ context.Context, name string) (string, error) {
	if f.cname != nil {
		return f.cname(strings.TrimSuffix(name, "."))
	}
	return name, nil
}

func (f *fakeDNSResolver) LookupHost(_ context.Context, name string) ([]string, error) {
	f.mu.Lock()
	f.queries = append(f.queries, name)
	f.mu.Unlock()
	return f.lookup(strings.TrimSuffix(name, "."))
}

func (f *fakeDNSResolver) names() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.queries...)
}

func notFound() error { return &net.DNSError{Err: "no such host", IsNotFound: true} }

func TestBruteForceFindsChildNamesAndFiltersStableWildcard(t *testing.T) {
	resolver := &fakeDNSResolver{lookup: func(name string) ([]string, error) {
		switch {
		case strings.HasPrefix(name, "abigail-wildcard-"):
			return []string{"192.0.2.1", "2001:db8::1"}, nil
		case name == "ghost.example.com":
			return []string{"2001:db8::1", "192.0.2.1"}, nil
		case name == "real.example.com":
			return []string{"192.0.2.9"}, nil
		default:
			return nil, notFound()
		}
	}}
	hosts, err := BruteForce(context.Background(), "Example.COM.", resolver, []string{"ghost", "real", "REAL", "missing"}, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 || hosts[0] != "real.example.com" {
		t.Fatalf("unexpected hosts %q", hosts)
	}
	queries := resolver.names()
	if len(queries) != 5 { // two random probes plus three unique words
		t.Fatalf("unexpected query count %d: %q", len(queries), queries)
	}
	for _, query := range queries {
		if !strings.HasSuffix(query, ".") {
			t.Fatalf("DNS query must be absolute to avoid search suffixes: %q", query)
		}
	}
	if queries[0] == queries[1] || !strings.HasPrefix(queries[0], "abigail-wildcard-") || !strings.HasPrefix(queries[1], "abigail-wildcard-") {
		t.Fatalf("expected two distinct random probes: %q", queries[:2])
	}
}

func TestBruteForceRejectsUnsafeInputsWithoutDNS(t *testing.T) {
	resolver := &fakeDNSResolver{lookup: func(string) ([]string, error) {
		t.Fatal("DNS must not run for invalid input")
		return nil, nil
	}}
	for _, tc := range []struct {
		root        string
		words       []string
		concurrency int
	}{
		{"example.com.attacker.test/", []string{"www"}, 1},
		{"example.com", []string{"www.attacker.test"}, 1},
		{"example.com", []string{"-www"}, 1},
		{"example.com", []string{"www"}, 0},
		{"example.com", []string{"www"}, 65},
	} {
		if _, err := BruteForce(context.Background(), tc.root, resolver, tc.words, tc.concurrency); err == nil {
			t.Fatalf("expected invalid input error: %+v", tc)
		}
	}
	if len(resolver.names()) != 0 {
		t.Fatal("invalid input caused DNS lookups")
	}
}

func TestBruteForceStopsWhenWildcardIsInconsistent(t *testing.T) {
	probes := 0
	resolver := &fakeDNSResolver{lookup: func(name string) ([]string, error) {
		if !strings.HasPrefix(name, "abigail-wildcard-") {
			t.Fatalf("candidate should not be queried after inconsistent wildcard: %s", name)
		}
		probes++
		if probes == 1 {
			return []string{"192.0.2.1"}, nil
		}
		return []string{"192.0.2.2"}, nil
	}}
	if hosts, err := BruteForce(context.Background(), "example.com", resolver, []string{"www"}, 1); err == nil || len(hosts) != 0 {
		t.Fatalf("expected inconclusive wildcard, got %q, %v", hosts, err)
	}
	if probes != 2 {
		t.Fatalf("expected two probes, got %d", probes)
	}
}

func TestBruteForceReturnsPartialResultsWithDNSError(t *testing.T) {
	resolver := &fakeDNSResolver{lookup: func(name string) ([]string, error) {
		switch name {
		case "www.example.com":
			return []string{"192.0.2.10"}, nil
		case "api.example.com":
			return nil, errors.New("resolver unreachable")
		default:
			return nil, notFound()
		}
	}}
	hosts, err := BruteForce(context.Background(), "example.com", resolver, []string{"www", "api"}, 2)
	if err == nil || len(hosts) != 1 || hosts[0] != "www.example.com" {
		t.Fatalf("expected partial result with error, got %q, %v", hosts, err)
	}
}

func TestBruteForceKeepsCNAMEWhenAddressLookupFails(t *testing.T) {
	resolver := &fakeDNSResolver{
		lookup: func(name string) ([]string, error) {
			if name == "dangling.example.com" {
				return nil, errors.New("temporary address lookup failure")
			}
			return nil, notFound()
		},
		cname: func(name string) (string, error) {
			if name == "dangling.example.com" {
				return "missing.provider.test.", nil
			}
			return "", notFound()
		},
	}
	hosts, err := BruteForce(context.Background(), "example.com", resolver, []string{"dangling"}, 1)
	if err == nil || len(hosts) != 1 || hosts[0] != "dangling.example.com" {
		t.Fatalf("CNAME evidence must survive a transient address error: hosts=%q err=%v", hosts, err)
	}
}

func TestBruteForceFindsDanglingCNAMEAndFiltersWildcardCNAME(t *testing.T) {
	resolver := &fakeDNSResolver{
		lookup: func(name string) ([]string, error) { return nil, notFound() },
		cname: func(name string) (string, error) {
			switch {
			case strings.HasPrefix(name, "abigail-wildcard-"), name == "ghost.example.com":
				return "shared.provider.test.", nil
			case name == "dangling.example.com":
				return "missing.provider.test.", nil
			default:
				return "", notFound()
			}
		},
	}
	hosts, err := BruteForce(context.Background(), "example.com", resolver, []string{"ghost", "dangling"}, 2)
	if err != nil || len(hosts) != 1 || hosts[0] != "dangling.example.com" {
		t.Fatalf("expected only dangling alias: hosts=%q err=%v", hosts, err)
	}
}

func TestGoResolverExposesDanglingCNAME(t *testing.T) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{PacketConn: packet, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		name := request.Question[0].Name
		if name == "dangling.example.test." {
			response.Answer = []dns.RR{&dns.CNAME{
				Hdr:    dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
				Target: "missing.provider.test.",
			}}
		} else {
			response.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(response)
	})}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	resolverAddress := packet.LocalAddr().String()
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		dialer := net.Dialer{Timeout: time.Second}
		return dialer.DialContext(ctx, "udp", resolverAddress)
	}}
	hosts, err := BruteForce(context.Background(), "example.test", resolver, []string{"dangling"}, 1)
	if err != nil || len(hosts) != 1 || hosts[0] != "dangling.example.test" {
		t.Fatalf("Go resolver did not expose dangling CNAME: hosts=%q err=%v", hosts, err)
	}
}

func TestDefaultWordsAreBoundedAndValid(t *testing.T) {
	words := DefaultWords()
	if len(words) < 100 || len(words) > 200 {
		t.Fatalf("unexpected default wordlist length %d", len(words))
	}
	for _, word := range words {
		if !validBruteLabel(word) {
			t.Fatalf("invalid default word %q", word)
		}
	}
}
