package dnsprobe

import (
	"testing"

	"github.com/miekg/dns"
)

func TestAuthoritativeSOARequiresExactParent(t *testing.T) {
	response := new(dns.Msg)
	response.Rcode = dns.RcodeSuccess
	soa, err := dns.NewRR("example.test. 60 IN SOA ns.example.test. hostmaster.example.test. 1 3600 600 86400 60")
	if err != nil {
		t.Fatal(err)
	}
	response.Answer = []dns.RR{soa}
	if authoritativeSOA(response, "example.test") {
		t.Fatal("non-authoritative SOA must be rejected")
	}
	response.Authoritative = true
	if authoritativeSOA(response, "other.example.test") {
		t.Fatal("SOA for another zone must be rejected")
	}
	if !authoritativeSOA(response, "example.test") {
		t.Fatal("authoritative exact-parent SOA must be accepted")
	}
}
