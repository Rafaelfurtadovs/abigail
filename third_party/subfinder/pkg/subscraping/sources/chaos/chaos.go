// Package chaos logic
package chaos

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Rafaelfurtadovs/abigail/third_party/subfinder/pkg/subscraping"
)

// Source is the passive scraping agent
type Source struct {
	mu      sync.Mutex
	stats   subscraping.Statistics
	apiKeys []string
}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	s.mu.Lock()
	apiKeys := s.apiKeys
	s.mu.Unlock()

	go func() {
		var stats subscraping.Statistics
		defer func(startTime time.Time) {
			stats.TimeTaken = time.Since(startTime)
			s.mu.Lock()
			s.stats = stats
			s.mu.Unlock()
			close(results)
		}(time.Now())

		randomApiKey := subscraping.PickRandom(apiKeys, s.Name())
		if randomApiKey == "" {
			stats.Skipped = true
			return
		}

		stats.Requests++
		endpoint := "https://dns.projectdiscovery.io/dns/" + url.PathEscape(domain) + "/subdomains"
		response, err := session.Get(ctx, endpoint, "", map[string]string{"Authorization": randomApiKey})
		if response != nil {
			defer session.DiscardHTTPResponse(response)
		}
		if err != nil {
			stats.Errors++
			select {
			case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}:
			case <-ctx.Done():
			}
			return
		}
		var payload struct {
			Domain     string   `json:"domain"`
			Subdomains []string `json:"subdomains"`
		}
		if err := json.NewDecoder(response.Body).Decode(&payload); err != nil || !strings.EqualFold(payload.Domain, domain) {
			stats.Errors++
			if err == nil {
				err = fmt.Errorf("Chaos returned data for an unexpected domain")
			}
			select {
			case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("decode Chaos response: %w", err)}:
			case <-ctx.Done():
			}
			return
		}
		for _, subdomain := range payload.Subdomains {
			if session.MaxResults > 0 && stats.Results >= session.MaxResults {
				return
			}
			if subdomain == "" {
				continue
			}
			select {
			case <-ctx.Done():
				return
			case results <- subscraping.Result{
				Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain + "." + domain,
			}:
			}
			stats.Results++
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "chaos"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) HasRecursiveSupport() bool {
	return false
}

func (s *Source) KeyRequirement() subscraping.KeyRequirement {
	return subscraping.RequiredKey
}

func (s *Source) NeedsKey() bool {
	return s.KeyRequirement() == subscraping.RequiredKey
}

func (s *Source) AddApiKeys(keys []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.apiKeys = slices.Clone(keys)
}

// Statistics returns a snapshot of the most recently completed run.
func (s *Source) Statistics() subscraping.Statistics {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}
