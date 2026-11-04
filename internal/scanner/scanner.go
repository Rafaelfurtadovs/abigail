package scanner

import (
	"context"
	"sort"
	"strings"

	"github.com/Rafaelfurtadovs/abigail/internal/dnsprobe"
	"github.com/Rafaelfurtadovs/abigail/internal/httpprobe"
	"github.com/Rafaelfurtadovs/abigail/internal/ruleengine"
)

// A finding means that recorded evidence matches a rule. It is not proof that
// an attacker can claim the target resource.
type Finding struct {
	RuleID          string                `json:"rule_id"`
	Service         string                `json:"service"`
	Verdict         string                `json:"verdict"`
	DNS             []ruleengine.DNSMatch `json:"dns"`
	HTTPStatus      int                   `json:"http_status,omitempty"`
	HTTPURL         string                `json:"http_url,omitempty"`
	BodyFingerprint string                `json:"body_fingerprint,omitempty"`
	TargetNXDomain  bool                  `json:"target_nxdomain,omitempty"`
	Source          string                `json:"source"`
}

type Result struct {
	Domain   string          `json:"domain"`
	Status   string          `json:"status"` // candidate, edge_case, clean, or unknown
	DNS      dnsprobe.Result `json:"dns"`
	HTTP     *HTTPInfo       `json:"http,omitempty"`
	Findings []Finding       `json:"findings"`
	Errors   []string        `json:"errors,omitempty"`
}

type HTTPInfo struct {
	URL       string `json:"url,omitempty"`
	Status    int    `json:"status,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
	Error     string `json:"error,omitempty"`
}

type HTTPFetcher interface {
	Fetch(context.Context, string) httpprobe.Result
}

type Scanner struct {
	Rules            []ruleengine.Rule
	DNSOptions       dnsprobe.Options
	HTTP             HTTPFetcher
	IncludeEdgeCases bool
	Resolve          func(context.Context, string, dnsprobe.Options) dnsprobe.Result
}

func (s Scanner) Scan(ctx context.Context, domain string) Result {
	result := Result{Domain: domain, Findings: []Finding{}}
	resolve := s.Resolve
	if resolve == nil {
		resolve = dnsprobe.Resolve
	}
	result.DNS = resolve(ctx, domain, s.DNSOptions)
	result.Errors = append(result.Errors, result.DNS.Errors...)
	if result.DNS.NXDomain && !result.DNS.ChainComplete {
		result.Errors = append(result.Errors, "system DNS did not expose whether NXDOMAIN followed a CNAME; use --resolver for full chain evidence")
	}

	type candidate struct {
		rule  ruleengine.Rule
		match []ruleengine.DNSMatch
	}
	var httpCandidates []candidate
	for _, rule := range s.Rules {
		if rule.Status == "edge_case" && !s.IncludeEdgeCases {
			continue
		}
		matches := ruleengine.MatchDNS(rule, result.DNS.CNAMEChain, result.DNS.A, result.DNS.AAAA)
		if len(matches) == 0 {
			continue
		}
		if rule.TargetNXDomain {
			// Only a full, explicit CNAME chain can attribute an NXDOMAIN to
			// the provider's target. A missing original hostname is not enough.
			if result.DNS.ChainComplete && len(result.DNS.CNAMEChain) > 0 && result.DNS.NXDomain {
				result.Findings = append(result.Findings, finding(rule, matches, httpprobe.Result{}, ""))
			}
			continue
		}
		httpCandidates = append(httpCandidates, candidate{rule: rule, match: matches})
	}

	if len(httpCandidates) > 0 {
		if s.HTTP == nil {
			result.Errors = append(result.Errors, "HTTP probe is not configured")
		} else {
			response := s.HTTP.Fetch(ctx, domain)
			result.HTTP = &HTTPInfo{URL: response.URL, Status: response.Status, Truncated: response.Truncated, Error: response.Error}
			if response.Error != "" {
				result.Errors = append(result.Errors, "HTTP probe: "+response.Error)
			} else {
				for _, item := range httpCandidates {
					if fragment, ok := ruleengine.MatchHTTP(item.rule, response.Status, response.Body); ok {
						result.Findings = append(result.Findings, finding(item.rule, item.match, response, fragment))
					}
				}
				if response.Truncated && len(result.Findings) == 0 {
					result.Errors = append(result.Errors, "HTTP body exceeded probe limit before a fingerprint was found")
				}
				if response.Status >= 300 && response.Status < 400 && len(result.Findings) == 0 {
					result.Errors = append(result.Errors, "HTTP redirect was not followed")
				}
			}
		}
	}

	sort.Slice(result.Findings, func(i, j int) bool { return result.Findings[i].RuleID < result.Findings[j].RuleID })
	result.Status = "clean"
	if len(result.Errors) > 0 {
		result.Status = "unknown"
	}
	for _, item := range result.Findings {
		if item.Verdict == "candidate" {
			result.Status = "candidate"
			break
		}
		if result.Status != "candidate" {
			result.Status = "edge_case"
		}
	}
	return result
}

func finding(rule ruleengine.Rule, matches []ruleengine.DNSMatch, response httpprobe.Result, fragment string) Finding {
	verdict := "candidate"
	if rule.Status == "edge_case" {
		verdict = "edge_case"
	}
	return Finding{
		RuleID:          rule.ID,
		Service:         rule.Service,
		Verdict:         verdict,
		DNS:             uniqueMatches(matches),
		HTTPStatus:      response.Status,
		HTTPURL:         response.URL,
		BodyFingerprint: fragment,
		TargetNXDomain:  rule.TargetNXDomain,
		Source:          rule.Source,
	}
}

func uniqueMatches(input []ruleengine.DNSMatch) []ruleengine.DNSMatch {
	seen := map[string]bool{}
	out := make([]ruleengine.DNSMatch, 0, len(input))
	for _, match := range input {
		key := match.Record + ":" + strings.ToLower(match.Value)
		if !seen[key] {
			seen[key] = true
			out = append(out, match)
		}
	}
	return out
}
