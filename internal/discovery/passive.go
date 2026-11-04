// Package discovery collects candidate hostnames from passive certificate
// indexes. A certificate name is historical evidence, not proof that a DNS
// name currently exists or belongs to the queried organization.
package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

const (
	maxResponseBytes = 16 << 20
	maxNames         = 20000
	sourceTimeout    = 30 * time.Second
)

// QueryCRTSh searches the public crt.sh certificate index for names under
// root. Callers should expose source errors instead of interpreting an empty
// result as a complete inventory.
func QueryCRTSh(ctx context.Context, root string, client *http.Client) ([]string, error) {
	root, err := normalizeRoot(root)
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		return nil, errors.New("crt.sh: context is required")
	}
	query := url.Values{"q": {"%." + root}, "output": {"json"}}
	endpoint := "https://crt.sh/?" + query.Encode()
	ctx, cancel := withSourceTimeout(ctx, client)
	defer cancel()
	body, err := getSourceBody(ctx, client, endpoint, "application/json", "", "")
	if err != nil {
		return nil, fmt.Errorf("crt.sh: %w", err)
	}
	var entries []struct {
		NameValue  string `json:"name_value"`
		CommonName string `json:"common_name"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("crt.sh: decode JSON: %w", err)
	}
	hosts := make(map[string]bool)
	for _, entry := range entries {
		for _, raw := range strings.Fields(entry.NameValue + "\n" + entry.CommonName) {
			if name, ok := normalizeChild(raw, root); ok {
				hosts[name] = true
				if len(hosts) > maxNames {
					return sortedHosts(hosts), fmt.Errorf("crt.sh: more than %d unique hostnames", maxNames)
				}
			}
		}
	}
	return sortedHosts(hosts), nil
}

// QueryCRTName reads crt.name's historical subdomain index. Its API accepts
// only a registrable apex domain and has a per-IP daily query allowance.
func QueryCRTName(ctx context.Context, root string, client *http.Client) ([]string, error) {
	root, err := normalizeRoot(root)
	if err != nil {
		return nil, err
	}
	apex, err := publicsuffix.EffectiveTLDPlusOne(root)
	if err != nil || apex != root {
		return nil, fmt.Errorf("crt.name: %q must be a registrable apex domain", root)
	}
	if ctx == nil {
		return nil, errors.New("crt.name: context is required")
	}
	ctx, cancel := withSourceTimeout(ctx, client)
	defer cancel()
	query := url.Values{"apex": {root}, "format": {"json"}}
	endpoint := "https://crt.name/v1/search?" + query.Encode()
	body, err := getSourceBody(ctx, client, endpoint, "application/json", "", "")
	if err != nil {
		return nil, fmt.Errorf("crt.name: %w", err)
	}
	if trimmed := bytes.TrimSpace(body); len(trimmed) == 0 || trimmed[0] != '[' {
		return nil, errors.New("crt.name: expected JSON array")
	}
	var entries []struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("crt.name: decode JSON: %w", err)
	}
	hosts := make(map[string]bool)
	for _, entry := range entries {
		if entry.Sub == "" {
			return sortedHosts(hosts), errors.New("crt.name: missing subdomain in response")
		}
		if name, ok := normalizeChild(entry.Sub, root); ok {
			hosts[name] = true
			if len(hosts) > maxNames {
				return sortedHosts(hosts), fmt.Errorf("crt.name: more than %d unique hostnames", maxNames)
			}
		}
	}
	return sortedHosts(hosts), nil
}

// QueryCertSpotter reads the CT Search API's unexpired issuance pages. The
// unauthenticated API has a limited allowance; CERTSPOTTER_API_KEY can provide
// a bearer token for an account with a higher allowance.
func QueryCertSpotter(ctx context.Context, root string, client *http.Client) ([]string, error) {
	root, err := normalizeRoot(root)
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		return nil, errors.New("Cert Spotter: context is required")
	}
	ctx, cancel := withSourceTimeout(ctx, client)
	defer cancel()
	hosts := make(map[string]bool)
	seenAfter := make(map[string]bool)
	after := ""
	key := os.Getenv("CERTSPOTTER_API_KEY")
	// The API starts with its oldest issuances. Stopping at a fixed page count
	// would systematically omit the most recently discovered names.
	for {
		if err := ctx.Err(); err != nil {
			return sortedHosts(hosts), fmt.Errorf("Cert Spotter: pagination incomplete: %w", err)
		}
		query := url.Values{
			"domain":             {root},
			"include_subdomains": {"true"},
			"expand":             {"dns_names"},
		}
		if after != "" {
			query.Set("after", after)
		}
		endpoint := "https://api.certspotter.com/v1/issuances?" + query.Encode()
		auth := ""
		if key != "" {
			auth = "Bearer " + key
		}
		body, err := getSourceBody(ctx, client, endpoint, "application/json", "Authorization", auth)
		if err != nil {
			return sortedHosts(hosts), fmt.Errorf("Cert Spotter: %w", err)
		}
		var entries []struct {
			ID       string   `json:"id"`
			DNSNames []string `json:"dns_names"`
		}
		if err := json.Unmarshal(body, &entries); err != nil {
			return sortedHosts(hosts), fmt.Errorf("Cert Spotter: decode JSON: %w", err)
		}
		if len(entries) == 0 {
			return sortedHosts(hosts), nil
		}
		for _, entry := range entries {
			for _, raw := range entry.DNSNames {
				if name, ok := normalizeChild(raw, root); ok {
					if !hosts[name] && len(hosts) >= maxNames {
						return sortedHosts(hosts), fmt.Errorf("Cert Spotter: more than %d unique hostnames", maxNames)
					}
					hosts[name] = true
				}
			}
		}
		next := entries[len(entries)-1].ID
		if next == "" || next == after || seenAfter[next] {
			return sortedHosts(hosts), errors.New("Cert Spotter: pagination did not advance")
		}
		seenAfter[next] = true
		after = next
	}
}

// QueryHackerTarget reads the public Host Search API's hostname,IP rows. The
// free service limits queries and results; a full result page is reported as
// potentially truncated rather than as a complete inventory.
func QueryHackerTarget(ctx context.Context, root string, client *http.Client) ([]string, error) {
	root, err := normalizeRoot(root)
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		return nil, errors.New("HackerTarget: context is required")
	}
	ctx, cancel := withSourceTimeout(ctx, client)
	defer cancel()
	query := url.Values{"q": {root}}
	endpoint := "https://api.hackertarget.com/hostsearch/?" + query.Encode()
	key := os.Getenv("HACKERTARGET_API_KEY")
	body, err := getSourceBody(ctx, client, endpoint, "text/plain", "X-API-Key", key)
	if err != nil {
		return nil, fmt.Errorf("HackerTarget: %w", err)
	}
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return nil, errors.New("HackerTarget: empty response")
	}
	if strings.EqualFold(trimmed, "no records found") {
		return []string{}, nil
	}
	if strings.HasPrefix(strings.ToLower(trimmed), "error") {
		message := strings.SplitN(trimmed, "\n", 2)[0]
		if len(message) > 200 {
			message = message[:200]
		}
		return nil, fmt.Errorf("HackerTarget: %s", message)
	}
	hosts := make(map[string]bool)
	rows := 0
	for _, line := range strings.Split(trimmed, "\n") {
		parts := strings.Split(strings.TrimSpace(line), ",")
		if len(parts) != 2 || net.ParseIP(strings.TrimSpace(parts[1])) == nil {
			return sortedHosts(hosts), errors.New("HackerTarget: unexpected response row")
		}
		rows++
		if name, ok := normalizeChild(parts[0], root); ok {
			hosts[name] = true
		}
	}
	if key == "" && rows >= 50 {
		return sortedHosts(hosts), errors.New("HackerTarget: free response reached 50 rows and may be truncated")
	}
	return sortedHosts(hosts), nil
}

func withSourceTimeout(ctx context.Context, client *http.Client) (context.Context, context.CancelFunc) {
	if _, hasDeadline := ctx.Deadline(); hasDeadline {
		return context.WithCancel(ctx)
	}
	if client != nil && client.Timeout > 0 {
		return context.WithTimeout(ctx, client.Timeout)
	}
	return context.WithTimeout(ctx, sourceTimeout)
}

func getSourceBody(ctx context.Context, supplied *http.Client, endpoint, accept, authHeader, apiKey string) ([]byte, error) {
	client := http.Client{}
	if supplied != nil {
		client = *supplied
	}
	// A redirect could forward an API key to a different host. Treat it as a
	// source error instead, including when no key is configured.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", accept)
	request.Header.Set("User-Agent", "Abigail subdomain discovery")
	if authHeader != "" && apiKey != "" {
		request.Header.Set(authHeader, apiKey)
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxResponseBytes {
		return nil, fmt.Errorf("response exceeds %d bytes", maxResponseBytes)
	}
	return body, nil
}

func normalizeRoot(raw string) (string, error) {
	name, ok := normalizeName(raw)
	if !ok || !strings.Contains(name, ".") || net.ParseIP(name) != nil {
		return "", fmt.Errorf("invalid discovery domain %q", raw)
	}
	return name, nil
}

func normalizeChild(raw, root string) (string, bool) {
	name, ok := normalizeName(raw)
	if !ok || !strings.HasSuffix(name, "."+root) {
		return "", false
	}
	return name, true
}

func normalizeName(raw string) (string, bool) {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if len(name) == 0 || len(name) > 253 {
		return "", false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, ch := range label {
			if !((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-') {
				return "", false
			}
		}
	}
	return name, true
}

func sortedHosts(values map[string]bool) []string {
	hosts := make([]string, 0, len(values))
	for host := range values {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	return hosts
}
