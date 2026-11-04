package ruleengine

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
)

// Pack is a versioned, local rule set. Rules are data, never executable code.
type Pack struct {
	SchemaVersion int    `json:"schema_version"`
	Rules         []Rule `json:"rules"`
}

type Rule struct {
	ID             string   `json:"id"`
	Service        string   `json:"service"`
	CNAMESuffixes  []string `json:"cname_suffixes"`
	CNAMEExact     []string `json:"cname_exact"`
	ARecords       []string `json:"a_records"`
	AAAARecords    []string `json:"aaaa_records"`
	HTTPStatuses   []int    `json:"http_statuses"`
	BodySubstrings []string `json:"body_substrings"`
	TargetNXDomain bool     `json:"target_nxdomain"`
	Status         string   `json:"status"`
	Source         string   `json:"source"`
}

type DNSMatch struct {
	Record string `json:"record"`
	Value  string `json:"value"`
}

func Parse(data []byte) (Pack, error) {
	var pack Pack
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&pack); err != nil {
		return Pack{}, fmt.Errorf("parse rules: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return Pack{}, errors.New("rules contain trailing data")
	}
	if pack.SchemaVersion != 1 {
		return Pack{}, fmt.Errorf("unsupported rules schema version %d", pack.SchemaVersion)
	}
	if len(pack.Rules) == 0 {
		return Pack{}, errors.New("rule set is empty")
	}
	seen := make(map[string]bool, len(pack.Rules))
	for i, rule := range pack.Rules {
		if err := validate(rule); err != nil {
			return Pack{}, fmt.Errorf("rule %d: %w", i+1, err)
		}
		if seen[rule.ID] {
			return Pack{}, fmt.Errorf("duplicate rule id %q", rule.ID)
		}
		seen[rule.ID] = true
	}
	return pack, nil
}

func validate(rule Rule) error {
	if rule.ID == "" || rule.Service == "" || rule.Source == "" {
		return errors.New("id, service and source are required")
	}
	if rule.Status != "vulnerable" && rule.Status != "edge_case" {
		return fmt.Errorf("%s: status must be vulnerable or edge_case", rule.ID)
	}
	if len(rule.CNAMESuffixes)+len(rule.CNAMEExact)+len(rule.ARecords)+len(rule.AAAARecords) == 0 {
		return fmt.Errorf("%s: at least one DNS matcher is required", rule.ID)
	}
	if rule.TargetNXDomain {
		if len(rule.HTTPStatuses)+len(rule.BodySubstrings) != 0 {
			return fmt.Errorf("%s: NXDOMAIN and HTTP evidence modes must be separate rules", rule.ID)
		}
	} else if len(rule.BodySubstrings) == 0 {
		return fmt.Errorf("%s: HTTP rules need a body fingerprint", rule.ID)
	}
	for _, suffix := range rule.CNAMESuffixes {
		if suffix == "" || strings.HasPrefix(suffix, ".") || strings.HasSuffix(suffix, ".") {
			return fmt.Errorf("%s: invalid CNAME suffix %q", rule.ID, suffix)
		}
	}
	for _, status := range rule.HTTPStatuses {
		if status < 100 || status > 599 {
			return fmt.Errorf("%s: invalid HTTP status %d", rule.ID, status)
		}
	}
	return nil
}

// MatchDNS requires an exact DNS label boundary. It never treats an arbitrary
// substring such as example.com.attacker.test as a match for example.com.
func MatchDNS(rule Rule, cnames, ipv4, ipv6 []string) []DNSMatch {
	var matches []DNSMatch
	for _, raw := range cnames {
		value := strings.TrimSuffix(strings.ToLower(raw), ".")
		for _, exact := range rule.CNAMEExact {
			if value == strings.ToLower(exact) {
				matches = append(matches, DNSMatch{Record: "CNAME", Value: raw})
				break
			}
		}
		for _, suffix := range rule.CNAMESuffixes {
			suffix = strings.ToLower(suffix)
			if value == suffix || strings.HasSuffix(value, "."+suffix) {
				matches = append(matches, DNSMatch{Record: "CNAME", Value: raw})
				break
			}
		}
	}
	for _, item := range []struct {
		record string
		values []string
		rules  []string
	}{{"A", ipv4, rule.ARecords}, {"AAAA", ipv6, rule.AAAARecords}} {
		for _, raw := range item.values {
			ip := net.ParseIP(raw)
			for _, candidate := range item.rules {
				if ip != nil && ip.Equal(net.ParseIP(candidate)) {
					matches = append(matches, DNSMatch{Record: item.record, Value: raw})
					break
				}
			}
		}
	}
	return matches
}

// MatchHTTP requires both the status and a case-sensitive body fingerprint
// when a rule specifies both. Redirects are not followed by the HTTP probe.
func MatchHTTP(rule Rule, status int, body []byte) (string, bool) {
	if rule.TargetNXDomain {
		return "", false
	}
	if len(rule.HTTPStatuses) > 0 {
		found := false
		for _, expected := range rule.HTTPStatuses {
			if status == expected {
				found = true
				break
			}
		}
		if !found {
			return "", false
		}
	}
	for _, fingerprint := range rule.BodySubstrings {
		if fingerprint != "" && bytes.Contains(body, []byte(fingerprint)) {
			return fingerprint, true
		}
	}
	return "", false
}
