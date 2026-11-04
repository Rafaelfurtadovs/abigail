package discovery

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	maxBruteConcurrency = 64
	lookupTimeout       = 5 * time.Second
)

// DNSResolver is the DNS lookup needed for optional wordlist discovery.
// *net.Resolver implements it. Looking up CNAMEs separately is essential:
// LookupHost alone loses dangling aliases whose targets have no address.
type DNSResolver interface {
	LookupHost(context.Context, string) ([]string, error)
	LookupCNAME(context.Context, string) (string, error)
}

// DefaultWords returns a small, fixed wordlist. Brute-force discovery is
// opt-in because each word generates a DNS lookup against the target zone.
func DefaultWords() []string {
	return strings.Fields(`www api app admin auth login sso id accounts account portal dashboard
	mail webmail mx smtp imap pop ftp sftp ssh vpn remote gateway bastion
	dev development test testing qa uat stage staging preprod prod production
	beta alpha demo sandbox preview canary lab labs internal intranet intranet2
	status health monitor monitoring metrics prometheus grafana kibana logs log
	cdn static assets images img media files file download downloads upload uploads
	docs documentation help support faq blog news forum community wiki
	shop store checkout payment payments billing invoice invoices pay
	mobile m mapi mobile-api graphql rest v1 v2 v3 api2 api-dev
	git gitlab github ci cd jenkins build deploy registry artifacts packages
	db database mysql postgres redis mongo elasticsearch search cache queue
	ns ns1 ns2 ns3 dns dns1 dns2 ldap ad dc proxy edge lb loadbalancer
	office corp corporate workspace work admin-dev admin-stage admin-test
	partner partners client clients customer customers crm erp cms
	old legacy backup backups archive temp tmp new landing site web
	secure security mailer email smtp2 relay click tracking analytics events
	calendar meet video chat bot automation webhook webhooks jobs worker workers`)
}

// BruteForce resolves one-label wordlist candidates under root. Two random
// probes first identify deterministic wildcard DNS answers; candidates with
// the same addresses or CNAME target are excluded. An inconsistent answer makes the
// result inconclusive rather than flooding the caller with false discoveries.
func BruteForce(ctx context.Context, root string, resolver DNSResolver, words []string, concurrency int) ([]string, error) {
	root, err := validBruteRoot(root)
	if err != nil {
		return nil, err
	}
	if ctx == nil || resolver == nil {
		return nil, errors.New("brute-force discovery requires a context and DNS resolver")
	}
	if concurrency < 1 || concurrency > maxBruteConcurrency {
		return nil, fmt.Errorf("brute-force concurrency must be between 1 and %d", maxBruteConcurrency)
	}
	if len(words) == 0 {
		words = DefaultWords()
	}
	candidates := make([]string, 0, len(words))
	seen := make(map[string]bool, len(words))
	for _, raw := range words {
		word := strings.ToLower(strings.TrimSpace(raw))
		if !validBruteLabel(word) {
			return nil, fmt.Errorf("invalid brute-force word %q", raw)
		}
		if seen[word] {
			continue
		}
		seen[word] = true
		candidates = append(candidates, word+"."+root)
	}
	if len(candidates) == 0 {
		return []string{}, nil
	}

	wildcard, err := probeWildcard(ctx, root, resolver)
	if err != nil {
		return nil, err
	}

	type result struct {
		name   string
		record dnsRecord
		err    error
	}
	jobs := make(chan string)
	results := make(chan result, concurrency)
	var workers sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for name := range jobs {
				record, err := lookupRecord(ctx, resolver, name)
				select {
				case results <- result{name: name, record: record, err: err}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, name := range candidates {
			select {
			case jobs <- name:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { workers.Wait(); close(results) }()

	var hosts []string
	var failures int
	var firstErr error
	for item := range results {
		if item.err != nil {
			failures++
			if firstErr == nil {
				firstErr = item.err
			}
		}
		if !item.record.exists() || matchesWildcard(item.record, wildcard) {
			continue
		}
		hosts = append(hosts, item.name)
	}
	sort.Strings(hosts)
	if err := ctx.Err(); err != nil {
		return hosts, err
	}
	if failures > 0 {
		return hosts, fmt.Errorf("%d/%d DNS candidate lookups failed (first error: %w)", failures, len(candidates), firstErr)
	}
	return hosts, nil
}

type dnsRecord struct {
	ips   []string
	cname string
}

func (r dnsRecord) exists() bool { return len(r.ips) > 0 || r.cname != "" }

func probeWildcard(ctx context.Context, root string, resolver DNSResolver) (dnsRecord, error) {
	var probes [2]dnsRecord
	for i := range probes {
		var random [12]byte
		if _, err := rand.Read(random[:]); err != nil {
			return dnsRecord{}, fmt.Errorf("generate wildcard probe: %w", err)
		}
		name := "abigail-wildcard-" + hex.EncodeToString(random[:]) + "." + root
		record, err := lookupRecord(ctx, resolver, name)
		if err != nil {
			return dnsRecord{}, fmt.Errorf("wildcard DNS probe failed: %w", err)
		}
		probes[i] = record
	}
	if !probes[0].exists() && !probes[1].exists() {
		return dnsRecord{}, nil
	}
	if !probes[0].exists() || !probes[1].exists() ||
		probes[0].cname != probes[1].cname || !sameOrEmptyIPs(probes[0].ips, probes[1].ips) {
		return dnsRecord{}, errors.New("inconsistent wildcard DNS responses; wordlist results are inconclusive")
	}
	return probes[0], nil
}

func lookupRecord(ctx context.Context, resolver DNSResolver, name string) (dnsRecord, error) {
	queryCtx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	// The final dot prevents the OS resolver from appending enterprise search
	// domains and attributing an unrelated internal answer to this candidate.
	absoluteName := name + "."
	cname, cnameErr := resolver.LookupCNAME(queryCtx, absoluteName)
	if cnameErr != nil && !isDNSNotFound(cnameErr) {
		return dnsRecord{}, fmt.Errorf("CNAME lookup for %s: %w", name, cnameErr)
	}
	cname = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(cname)), ".")
	if cname == name {
		cname = ""
	}
	values, err := resolver.LookupHost(queryCtx, absoluteName)
	if err != nil {
		if isDNSNotFound(err) {
			return dnsRecord{cname: cname}, nil
		}
		return dnsRecord{cname: cname}, fmt.Errorf("address lookup for %s: %w", name, err)
	}
	seen := make(map[string]bool, len(values))
	var ips []string
	for _, value := range values {
		ip := net.ParseIP(value)
		if ip == nil {
			return dnsRecord{}, fmt.Errorf("DNS lookup for %s returned invalid address %q", name, value)
		}
		canonical := ip.String()
		if !seen[canonical] {
			seen[canonical] = true
			ips = append(ips, canonical)
		}
	}
	sort.Strings(ips)
	return dnsRecord{ips: ips, cname: cname}, nil
}

func isDNSNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

func matchesWildcard(candidate, wildcard dnsRecord) bool {
	if !wildcard.exists() {
		return false
	}
	if candidate.cname != "" {
		return wildcard.cname != "" && candidate.cname == wildcard.cname
	}
	return len(wildcard.ips) > 0 && sameIPs(candidate.ips, wildcard.ips)
}

func sameOrEmptyIPs(a, b []string) bool {
	return len(a) == 0 && len(b) == 0 || sameIPs(a, b)
}

func sameIPs(a, b []string) bool {
	if len(a) == 0 || len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func validBruteRoot(raw string) (string, error) {
	root := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if len(root) < 3 || len(root) > 253 || !strings.Contains(root, ".") {
		return "", fmt.Errorf("invalid discovery root %q", raw)
	}
	for _, label := range strings.Split(root, ".") {
		if !validBruteLabel(label) {
			return "", fmt.Errorf("invalid discovery root %q", raw)
		}
	}
	return root, nil
}

func validBruteLabel(label string) bool {
	if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, r := range label {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-') {
			return false
		}
	}
	return true
}
