package dnsprobe

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func startTestDNS(t *testing.T, handler dns.HandlerFunc) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{PacketConn: conn, Handler: handler}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	return conn.LocalAddr().String()
}

func answer(t *testing.T, writer dns.ResponseWriter, request *dns.Msg, records ...string) {
	t.Helper()
	response := new(dns.Msg)
	response.SetReply(request)
	response.Authoritative = true
	for _, record := range records {
		rr, err := dns.NewRR(record)
		if err != nil {
			t.Errorf("invalid fixture %q: %v", record, err)
			return
		}
		response.Answer = append(response.Answer, rr)
	}
	if err := writer.WriteMsg(response); err != nil {
		t.Errorf("write DNS answer: %v", err)
	}
}

func noData(t *testing.T, writer dns.ResponseWriter, request *dns.Msg) {
	t.Helper()
	response := new(dns.Msg)
	response.SetReply(request)
	response.Authoritative = true
	soa, err := dns.NewRR("example.test. 60 IN SOA ns.example.test. hostmaster.example.test. 1 3600 600 86400 60")
	if err != nil {
		t.Fatal(err)
	}
	response.Ns = append(response.Ns, soa)
	if err := writer.WriteMsg(response); err != nil {
		t.Errorf("write DNS answer: %v", err)
	}
}

func TestResolveDirectChainAndAddresses(t *testing.T) {
	server := startTestDNS(t, func(w dns.ResponseWriter, request *dns.Msg) {
		q := request.Question[0]
		switch {
		case q.Name == "a.example.test." && q.Qtype == dns.TypeCNAME:
			answer(t, w, request, "a.example.test. 60 IN CNAME b.example.test.")
		case q.Name == "b.example.test." && q.Qtype == dns.TypeCNAME:
			answer(t, w, request, "b.example.test. 60 IN CNAME c.example.test.")
		case q.Name == "c.example.test." && q.Qtype == dns.TypeA:
			answer(t, w, request, "c.example.test. 60 IN A 192.0.2.2", "c.example.test. 60 IN A 192.0.2.1", "c.example.test. 60 IN A 192.0.2.1")
		case q.Name == "c.example.test." && q.Qtype == dns.TypeAAAA:
			answer(t, w, request, "c.example.test. 60 IN AAAA 2001:db8::1")
		default:
			answer(t, w, request)
		}
	})

	result := Resolve(context.Background(), "A.Example.Test.", Options{Resolver: server, Timeout: time.Second})
	if result.Query != "a.example.test" || result.FinalName != "c.example.test" || !result.ChainComplete || result.NXDomain {
		t.Fatalf("unexpected DNS metadata: %+v", result)
	}
	if got := strings.Join(result.CNAMEChain, ","); got != "b.example.test,c.example.test" {
		t.Fatalf("unexpected CNAME chain: %s", got)
	}
	if got := strings.Join(result.A, ","); got != "192.0.2.1,192.0.2.2" {
		t.Fatalf("unexpected A records: %s", got)
	}
	if got := strings.Join(result.AAAA, ","); got != "2001:db8::1" {
		t.Fatalf("unexpected AAAA records: %s", got)
	}
	if len(result.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", result.Errors)
	}
}

func TestResolveDirectNXDomainAfterCNAME(t *testing.T) {
	server := startTestDNS(t, func(w dns.ResponseWriter, request *dns.Msg) {
		q := request.Question[0]
		if q.Name == "a.example.test." {
			answer(t, w, request, "a.example.test. 60 IN CNAME missing.example.test.")
			return
		}
		response := new(dns.Msg)
		response.SetRcode(request, dns.RcodeNameError)
		_ = w.WriteMsg(response)
	})

	result := Resolve(context.Background(), "a.example.test", Options{Resolver: server})
	if !result.NXDomain || result.FinalName != "missing.example.test" || len(result.Errors) != 0 {
		t.Fatalf("unexpected NXDOMAIN result: %+v", result)
	}
}

func TestResolveDirectNoDataIsNotNXDomain(t *testing.T) {
	server := startTestDNS(t, func(w dns.ResponseWriter, request *dns.Msg) {
		noData(t, w, request)
	})
	result := Resolve(context.Background(), "empty.example.test", Options{Resolver: server})
	if result.NXDomain || !result.ChainComplete || len(result.Errors) != 0 || len(result.A) != 0 || len(result.AAAA) != 0 {
		t.Fatalf("NOERROR without addresses must not become NXDOMAIN: %+v", result)
	}
}

func TestResolveDirectLoop(t *testing.T) {
	server := startTestDNS(t, func(w dns.ResponseWriter, request *dns.Msg) {
		q := request.Question[0]
		if q.Name == "a.example.test." {
			answer(t, w, request, "a.example.test. 60 IN CNAME b.example.test.")
		} else {
			answer(t, w, request, "b.example.test. 60 IN CNAME a.example.test.")
		}
	})
	result := Resolve(context.Background(), "a.example.test", Options{Resolver: server})
	if len(result.Errors) != 1 || !strings.Contains(result.Errors[0], "loop") {
		t.Fatalf("expected loop error, got %+v", result)
	}
}

func TestResolveSystemUsesConfiguredResolver(t *testing.T) {
	server := startTestDNS(t, func(w dns.ResponseWriter, request *dns.Msg) {
		q := request.Question[0]
		switch q.Qtype {
		case dns.TypeA:
			answer(t, w, request, "site.example.test. 60 IN A 192.0.2.3")
		default:
			noData(t, w, request)
		}
	})
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "udp", server)
		},
	}
	result := Resolve(context.Background(), "site.example.test", Options{SystemResolver: resolver, Timeout: time.Second})
	if result.NXDomain || result.ChainComplete || len(result.Errors) != 0 || len(result.A) != 1 || result.A[0] != "192.0.2.3" {
		t.Fatalf("unexpected system result: %+v", result)
	}
}

func TestResolveCanceledContext(t *testing.T) {
	server := startTestDNS(t, func(w dns.ResponseWriter, request *dns.Msg) {
		answer(t, w, request)
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := Resolve(ctx, "a.example.test", Options{Resolver: server})
	if len(result.Errors) == 0 {
		t.Fatalf("expected cancellation error, got %+v", result)
	}
}
