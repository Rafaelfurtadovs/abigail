package scanner

import (
	"context"
	"sort"
	"strings"

	"github.com/Rafaelfurtadovs/abigail/internal/dnsprobe"
	"github.com/Rafaelfurtadovs/abigail/internal/httpprobe"
	"github.com/Rafaelfurtadovs/abigail/internal/ruleengine"
	"github.com/Rafaelfurtadovs/abigail/internal/validation"
)

// A finding means that recorded evidence matches a rule. It is not proof that
// an attacker can claim the target resource.
type Finding struct {
	RuleID               string                `json:"rule_id"`
	Service              string                `json:"service"`
	Verdict              string                `json:"verdict"`
	DNS                  []ruleengine.DNSMatch `json:"dns"`
	HTTPStatus           int                   `json:"http_status,omitempty"`
	HTTPURL              string                `json:"http_url,omitempty"`
	BodyFingerprint      string                `json:"body_fingerprint,omitempty"`
	TargetNXDomain       bool                  `json:"target_nxdomain,omitempty"`
	DelegationUnresolved bool                  `json:"delegation_unresolved,omitempty"`
	Validation           *validation.Result    `json:"validation,omitempty"`
	Source               string                `json:"source"`
}

type Result struct {
	Domain     string          `json:"domain"`
	Status     string          `json:"status"` // validated, candidate, edge_case, dismissed, clean, or unknown
	DNS        dnsprobe.Result `json:"dns"`
	HTTP       *HTTPInfo       `json:"http,omitempty"`
	HTTPProbes []HTTPInfo      `json:"http_probes,omitempty"`
	Findings   []Finding       `json:"findings"`
	Dismissed  []Finding       `json:"dismissed,omitempty"`
	Errors     []string        `json:"errors,omitempty"`
}

type HTTPInfo struct {
	URL       string `json:"url,omitempty"`
	Status    int    `json:"status,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
	Charset   string `json:"charset,omitempty"`
	Error     string `json:"error,omitempty"`
}

type HTTPFetcher interface {
	Fetch(context.Context, string) httpprobe.Result
}

type multiHTTPFetcher interface {
	FetchAll(context.Context, string) []httpprobe.Result
}

// Validator checks provider-side name availability after a signature matches.
// Unknown and unsupported checks never upgrade or dismiss a finding.
type Validator interface {
	Validate(context.Context, string, []string) validation.Result
}

type Scanner struct {
	Rules            []ruleengine.Rule
	DNSOptions       dnsprobe.Options
	HTTP             HTTPFetcher
	Validator        Validator
	Validate         bool
	IncludeEdgeCases bool
	Resolve          func(context.Context, string, dnsprobe.Options) dnsprobe.Result
}

func (s Scanner) Scan(ctx context.Context, domain string) Result {
	result := Result{Domain: domain, Findings: []Finding{}}
	resolve := s.Resolve
	if resolve == nil {
		resolve = dnsprobe.Resolve
	}
	dnsOptions := s.DNSOptions
	for _, rule := range s.Rules {
		if (len(rule.NSExact) > 0 || len(rule.NSSuffixes) > 0) && (s.IncludeEdgeCases || rule.Status != "edge_case") {
			dnsOptions.CheckNS = true
			break
		}
	}
	result.DNS = resolve(ctx, domain, dnsOptions)
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
		matches := ruleengine.MatchDNS(rule, result.DNS.CNAMEChain, result.DNS.A, result.DNS.AAAA, result.DNS.NS)
		if len(matches) == 0 {
			continue
		}
		if rule.TargetNXDomain {
			// Only a full, explicit CNAME chain can attribute an NXDOMAIN to
			// the provider's target. A missing original hostname is not enough.
			if result.DNS.ChainComplete && result.DNS.NXDomain && hasFinalTargetMatch(matches, result.DNS.FinalName, result.DNS.Query) {
				s.addFinding(ctx, &result, finding(rule, matches, httpprobe.Result{}, ""))
			} else if rule.Status == "edge_case" && result.DNS.NSParentVerified && !result.DNS.ChainComplete && hasNSMatch(matches) {
				// A verified parent delegation to provider NS plus a failed
				// child lookup is an unresolved delegation, not NXDOMAIN.
				item := finding(rule, matches, httpprobe.Result{}, "")
				item.TargetNXDomain = false
				item.DelegationUnresolved = true
				s.addFinding(ctx, &result, item)
			}
			continue
		}
		httpCandidates = append(httpCandidates, candidate{rule: rule, match: matches})
	}

	if len(httpCandidates) > 0 {
		if s.HTTP == nil {
			result.Errors = append(result.Errors, "HTTP probe is not configured")
		} else {
			var responses []httpprobe.Result
			if multi, ok := s.HTTP.(multiHTTPFetcher); ok {
				responses = multi.FetchAll(ctx, domain)
			} else {
				responses = []httpprobe.Result{s.HTTP.Fetch(ctx, domain)}
			}
			if len(responses) == 0 {
				result.Errors = append(result.Errors, "HTTP probe returned no responses")
			}
			var probeErrors []string
			matchedRules := make(map[string]bool, len(httpCandidates))
			for _, response := range responses {
				info := HTTPInfo{URL: response.URL, Status: response.Status, Truncated: response.Truncated, Charset: response.Charset, Error: response.Error}
				result.HTTPProbes = append(result.HTTPProbes, info)
				if result.HTTP == nil {
					copy := info
					result.HTTP = &copy
				}
				if response.Error != "" {
					probeErrors = append(probeErrors, "HTTP probe "+response.URL+": "+response.Error)
					continue
				}
				for _, item := range httpCandidates {
					if matchedRules[item.rule.ID] {
						continue
					}
					if fragment, ok := ruleengine.MatchHTTP(item.rule, response.Status, response.Body); ok {
						matchedRules[item.rule.ID] = true
						copy := info
						result.HTTP = &copy
						s.addFinding(ctx, &result, finding(item.rule, item.match, response, fragment))
					}
				}
				if response.Truncated {
					probeErrors = append(probeErrors, "HTTP body exceeded probe limit at "+response.URL)
				}
				if response.Status >= 300 && response.Status < 400 {
					probeErrors = append(probeErrors, "HTTP redirect was not followed at "+response.URL)
				}
			}
			if len(result.Findings) == 0 && len(result.Dismissed) == 0 {
				result.Errors = append(result.Errors, probeErrors...)
			}
		}
	}

	sort.Slice(result.Findings, func(i, j int) bool { return result.Findings[i].RuleID < result.Findings[j].RuleID })
	result.Status = "clean"
	if len(result.Dismissed) > 0 {
		result.Status = "dismissed"
	}
	if len(result.Errors) > 0 {
		result.Status = "unknown"
	}
	for _, item := range result.Findings {
		if item.Verdict == "validated" {
			result.Status = "validated"
			break
		}
		if item.Verdict == "candidate" {
			result.Status = "candidate"
			continue
		}
		if result.Status != "candidate" && result.Status != "validated" {
			result.Status = "edge_case"
		}
	}
	return result
}

func hasFinalTargetMatch(matches []ruleengine.DNSMatch, finalName, query string) bool {
	for _, match := range matches {
		if (match.Record == "CNAME" && normalizeTarget(match.Value) == normalizeTarget(finalName)) ||
			(match.Record == "NS" && normalizeTarget(finalName) == normalizeTarget(query)) {
			return true
		}
	}
	return false
}

func hasNSMatch(matches []ruleengine.DNSMatch) bool {
	for _, match := range matches {
		if match.Record == "NS" {
			return true
		}
	}
	return false
}

func (s Scanner) addFinding(ctx context.Context, result *Result, item Finding) {
	if !s.Validate {
		result.Findings = append(result.Findings, item)
		return
	}
	var check validation.Result
	if s.Validator == nil {
		check = validation.Result{Provider: item.Service, State: validation.Unsupported, Reason: "no direct validator is configured"}
	} else if !result.DNS.ChainComplete {
		check = validation.Result{Provider: item.Service, State: validation.Unknown, Reason: "full CNAME chain is unavailable for exact-target validation"}
	} else {
		final := normalizeTarget(result.DNS.FinalName)
		var matchedFinal bool
		for _, match := range item.DNS {
			if match.Record == "CNAME" && normalizeTarget(match.Value) == final {
				matchedFinal = true
				break
			}
		}
		if !matchedFinal {
			check = validation.Result{Provider: item.Service, State: validation.Unsupported, Reason: "rule did not match the final CNAME target"}
		} else {
			check = s.Validator.Validate(ctx, item.RuleID, []string{final})
			if (check.State == validation.Available || check.State == validation.Unavailable) && normalizeTarget(check.Target) != final {
				check = validation.Result{Provider: item.Service, State: validation.Unknown, Target: final, Reason: "provider API response did not validate the exact final CNAME target"}
			}
		}
	}
	item.Validation = &check
	if check.State == validation.Unavailable {
		result.Dismissed = append(result.Dismissed, item)
		return
	}
	if check.State == validation.Available && item.Verdict == "candidate" {
		item.Verdict = "validated"
	}
	result.Findings = append(result.Findings, item)
}

func normalizeTarget(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
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
