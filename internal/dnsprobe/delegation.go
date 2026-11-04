package dnsprobe

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// exactNSRecords accepts only NS records owned by the queried name. A parent
// zone's ordinary authority NS records must not be mistaken for a delegation.
func exactNSRecords(response *dns.Msg, name string) []string {
	var nameservers []string
	if response == nil || response.Rcode != dns.RcodeSuccess {
		return nameservers
	}
	for _, section := range [][]dns.RR{response.Answer, response.Ns} {
		for _, answer := range section {
			if record, ok := answer.(*dns.NS); ok && normalizeName(record.Hdr.Name) == name {
				nameservers = append(nameservers, normalizeName(record.Ns))
			}
		}
	}
	return sortedUnique(nameservers)
}

// recoverParentNS is a bounded fallback for lame/dangling NS delegations.
// It first discovers the nearest parent zone's NS through the configured
// recursive resolver, then verifies that a candidate IP answers SOA for that
// parent authoritatively. Only then does it accept the child's exact-owner NS
// delegation from that parent's answer or authority section.
func recoverParentNS(parentCtx context.Context, result *Result, recursiveServers []string, opts Options) {
	ctx, cancel := context.WithTimeout(parentCtx, 8*time.Second)
	defer cancel()
	port := opts.authoritativePort
	if port == "" {
		port = "53"
	}
	for _, parent := range parentZoneCandidates(result.Query) {
		parentResponse, err := exchange(ctx, parent, dns.TypeNS, recursiveServers, opts.Timeout)
		if err != nil {
			continue
		}
		parentNS := exactNSRecords(parentResponse, parent)
		for i, nsName := range parentNS {
			if i == 2 { // Two independent parent authorities are enough for a bounded probe.
				break
			}
			addresses := nameserverIPs(ctx, nsName, recursiveServers, opts.Timeout)
			for j, ip := range addresses {
				if j == 2 {
					break
				}
				authority := []string{net.JoinHostPort(ip, port)}
				soa, err := exchangeWithRD(ctx, parent, dns.TypeSOA, authority, opts.Timeout, false)
				if err != nil || !authoritativeSOA(soa, parent) {
					continue
				}
				delegation, err := exchangeWithRD(ctx, result.Query, dns.TypeNS, authority, opts.Timeout, false)
				if err != nil {
					continue
				}
				if records := exactNSRecords(delegation, result.Query); len(records) > 0 {
					result.NS = records
					result.NSParentVerified = true
					result.Warnings = append(result.Warnings, "NS delegation recovered from a verified parent authority")
					return
				}
			}
		}
	}
}

func parentZoneCandidates(name string) []string {
	labels := strings.Split(name, ".")
	var candidates []string
	for i := 1; i < len(labels)-1 && len(candidates) < 4; i++ {
		candidates = append(candidates, strings.Join(labels[i:], "."))
	}
	return candidates
}

func nameserverIPs(ctx context.Context, name string, recursiveServers []string, timeout time.Duration) []string {
	var addresses []string
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		response, err := exchange(ctx, name, qtype, recursiveServers, timeout)
		if err != nil || response.Rcode != dns.RcodeSuccess {
			continue
		}
		for _, answer := range response.Answer {
			if normalizeName(answer.Header().Name) != name {
				continue
			}
			switch record := answer.(type) {
			case *dns.A:
				if qtype == dns.TypeA {
					addresses = append(addresses, record.A.String())
				}
			case *dns.AAAA:
				if qtype == dns.TypeAAAA {
					addresses = append(addresses, record.AAAA.String())
				}
			}
		}
	}
	return sortedUnique(addresses)
}

func authoritativeSOA(response *dns.Msg, name string) bool {
	if response == nil || response.Rcode != dns.RcodeSuccess || !response.Authoritative {
		return false
	}
	for _, answer := range response.Answer {
		if _, ok := answer.(*dns.SOA); ok && normalizeName(answer.Header().Name) == name {
			return true
		}
	}
	return false
}
