// Package dnsprobe resolves a hostname while retaining the DNS evidence needed
// by takeover checks. It never writes DNS records or attempts to claim a name.
package dnsprobe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	defaultMaxDepth = 12
	defaultTimeout  = 5 * time.Second
	maxAnswers      = 256
)

// Options controls resolution. An empty Resolver uses the Go system resolver,
// which is preferable on macOS networks with VPN or split DNS. A specified
// Resolver uses direct DNS queries and preserves each CNAME hop.
type Options struct {
	Resolver string
	MaxDepth int
	Timeout  time.Duration

	// SystemResolver is intended for deterministic tests. Nil uses
	// net.DefaultResolver. It is ignored when Resolver is set.
	SystemResolver *net.Resolver
}

// Result contains normalized DNS facts. CNAMEChain lists CNAME targets in
// resolution order; it does not include Query. In system mode, the operating
// system may expose only the final canonical name, so ChainComplete is false.
type Result struct {
	Query         string   `json:"query"`
	CNAMEChain    []string `json:"cname_chain,omitempty"`
	A             []string `json:"a,omitempty"`
	AAAA          []string `json:"aaaa,omitempty"`
	FinalName     string   `json:"final_name"`
	NXDomain      bool     `json:"nxdomain"`
	ChainComplete bool     `json:"chain_complete"`
	Errors        []string `json:"errors,omitempty"`
}

// Resolve resolves one hostname. It returns partial evidence and explanatory
// errors when DNS fails; callers must not interpret an errored result as safe.
func Resolve(ctx context.Context, hostname string, opts Options) Result {
	name := normalizeName(hostname)
	result := Result{Query: name, FinalName: name, CNAMEChain: []string{}, A: []string{}, AAAA: []string{}, Errors: []string{}}
	if name == "" {
		result.Errors = append(result.Errors, "empty hostname")
		return result
	}
	if _, ok := dns.IsDomainName(dns.Fqdn(name)); !ok {
		result.Errors = append(result.Errors, "invalid hostname")
		return result
	}
	if ctx == nil {
		result.Errors = append(result.Errors, "nil context")
		return result
	}
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = defaultMaxDepth
	}
	if opts.Timeout <= 0 {
		opts.Timeout = defaultTimeout
	}
	if opts.Resolver == "" {
		return resolveSystem(ctx, result, opts)
	}
	result.ChainComplete = true
	address, err := resolverAddress(opts.Resolver)
	if err != nil {
		result.Errors = append(result.Errors, err.Error())
		return result
	}
	return resolveDirect(ctx, result, address, opts)
}

func resolveSystem(parent context.Context, result Result, opts Options) Result {
	resolver := opts.SystemResolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	ctx, cancel := context.WithTimeout(parent, opts.Timeout)
	defer cancel()

	canonical, err := resolver.LookupCNAME(ctx, result.Query)
	if err != nil {
		if isNotFound(err) {
			// net.Resolver does not expose the DNS response code. Its
			// IsNotFound value can represent NXDOMAIN or no relevant RR.
			result.Errors = append(result.Errors, "name not found by system resolver; NXDOMAIN versus missing record is unknown")
		} else {
			result.Errors = append(result.Errors, fmt.Sprintf("CNAME lookup: %v", err))
		}
		return result
	}
	canonical = normalizeName(canonical)
	if canonical != "" && canonical != result.Query {
		result.CNAMEChain = append(result.CNAMEChain, canonical)
		result.FinalName = canonical
	}

	// LookupNetIP may return a not-found error for a missing address family;
	// that is not evidence of NXDOMAIN if the canonical name resolved.
	for _, family := range []struct {
		network string
		out     *[]string
	}{{"ip4", &result.A}, {"ip6", &result.AAAA}} {
		ips, err := resolver.LookupNetIP(ctx, family.network, result.FinalName)
		if err != nil {
			if !isNotFound(err) {
				result.Errors = append(result.Errors, fmt.Sprintf("%s lookup: %v", family.network, err))
			}
			continue
		}
		if len(ips) > maxAnswers {
			result.Errors = append(result.Errors, fmt.Sprintf("%s lookup exceeded %d answers", family.network, maxAnswers))
			continue
		}
		for _, ip := range ips {
			*family.out = append(*family.out, ip.String())
		}
		*family.out = sortedUnique(*family.out)
	}
	return result
}

func resolveDirect(ctx context.Context, result Result, server string, opts Options) Result {
	current := result.Query
	visited := map[string]struct{}{current: {}}
	for depth := 0; depth <= opts.MaxDepth; depth++ {
		response, err := exchange(ctx, current, dns.TypeCNAME, server, opts.Timeout)
		if err != nil {
			result.ChainComplete = false
			result.Errors = append(result.Errors, fmt.Sprintf("CNAME lookup for %s: %v", current, err))
			return result
		}
		if response.Rcode == dns.RcodeNameError {
			result.NXDomain = true
			result.FinalName = current
			return result
		}
		targets := make([]string, 0, 1)
		for _, answer := range response.Answer {
			record, ok := answer.(*dns.CNAME)
			if ok && normalizeName(record.Hdr.Name) == current {
				targets = append(targets, normalizeName(record.Target))
			}
		}
		if len(targets) == 0 {
			result.FinalName = current
			resolveAddresses(ctx, &result, current, server, opts.Timeout)
			return result
		}
		sort.Strings(targets)
		if len(targets) > 1 && targets[0] != targets[len(targets)-1] {
			result.ChainComplete = false
			result.Errors = append(result.Errors, fmt.Sprintf("conflicting CNAME targets for %s", current))
			return result
		}
		next := targets[0]
		if next == "" {
			result.ChainComplete = false
			result.Errors = append(result.Errors, fmt.Sprintf("empty CNAME target for %s", current))
			return result
		}
		if depth == opts.MaxDepth {
			result.ChainComplete = false
			result.Errors = append(result.Errors, fmt.Sprintf("CNAME chain exceeded maximum depth %d", opts.MaxDepth))
			return result
		}
		if _, exists := visited[next]; exists {
			result.ChainComplete = false
			result.Errors = append(result.Errors, fmt.Sprintf("CNAME loop at %s", next))
			return result
		}
		visited[next] = struct{}{}
		result.CNAMEChain = append(result.CNAMEChain, next)
		result.FinalName = next
		current = next
	}
	return result // The loop always returns from one of the branches above.
}

func resolveAddresses(ctx context.Context, result *Result, name, server string, timeout time.Duration) {
	for _, question := range []struct {
		qtype uint16
		label string
		out   *[]string
	}{{dns.TypeA, "A", &result.A}, {dns.TypeAAAA, "AAAA", &result.AAAA}} {
		response, err := exchange(ctx, name, question.qtype, server, timeout)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s lookup for %s: %v", question.label, name, err))
			continue
		}
		if response.Rcode == dns.RcodeNameError {
			// The preceding CNAME query returned NOERROR. Treat this
			// disagreement as unstable DNS rather than takeover evidence.
			result.Errors = append(result.Errors, fmt.Sprintf("%s lookup for %s returned NXDOMAIN after CNAME NOERROR", question.label, name))
			continue
		}
		for _, answer := range response.Answer {
			if normalizeName(answer.Header().Name) != name {
				continue
			}
			switch record := answer.(type) {
			case *dns.A:
				if question.qtype == dns.TypeA {
					*question.out = append(*question.out, record.A.String())
				}
			case *dns.AAAA:
				if question.qtype == dns.TypeAAAA {
					*question.out = append(*question.out, record.AAAA.String())
				}
			}
		}
		*question.out = sortedUnique(*question.out)
	}
}

func exchange(ctx context.Context, name string, qtype uint16, server string, timeout time.Duration) (*dns.Msg, error) {
	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn(name), qtype)
	query.SetEdns0(1232, false)
	client := &dns.Client{Net: "udp", Timeout: timeout}
	response, _, err := client.ExchangeContext(ctx, query, server)
	if err != nil {
		return nil, err
	}
	if response == nil {
		return nil, errors.New("empty DNS response")
	}
	if response.Truncated {
		client.Net = "tcp"
		response, _, err = client.ExchangeContext(ctx, query, server)
		if err != nil {
			return nil, err
		}
		if response == nil || response.Truncated {
			return nil, errors.New("incomplete TCP DNS response")
		}
	}
	if len(response.Answer) > maxAnswers {
		return nil, fmt.Errorf("DNS response exceeded %d answers", maxAnswers)
	}
	if response.Rcode != dns.RcodeSuccess && response.Rcode != dns.RcodeNameError {
		return nil, fmt.Errorf("DNS response: %s", dns.RcodeToString[response.Rcode])
	}
	return response, nil
}

func resolverAddress(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("empty DNS resolver")
	}
	if host, port, err := net.SplitHostPort(value); err == nil {
		if host == "" || port == "" {
			return "", errors.New("invalid DNS resolver address")
		}
		return value, nil
	}
	return net.JoinHostPort(strings.Trim(value, "[]"), "53"), nil
}

func normalizeName(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

func sortedUnique(values []string) []string {
	sort.Strings(values)
	out := values[:0]
	for _, value := range values {
		if len(out) == 0 || out[len(out)-1] != value {
			out = append(out, value)
		}
	}
	return out
}

func isNotFound(err error) bool {
	var dnsError *net.DNSError
	return errors.As(err, &dnsError) && dnsError.IsNotFound
}
