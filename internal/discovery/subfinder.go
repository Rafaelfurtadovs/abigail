package discovery

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/Rafaelfurtadovs/abigail/third_party/subfinder/pkg/runner"
	"github.com/Rafaelfurtadovs/abigail/third_party/subfinder/pkg/subscraping"
	"github.com/projectdiscovery/goflags"
)

// subfinderEnumerator is the small part of Subfinder's SDK needed by Abigail.
// Keeping it behind an interface lets the adapter be tested without network
// requests or a user's provider credentials.
type subfinderEnumerator interface {
	EnumerateSingleDomainWithCtx(context.Context, string, []io.Writer) (map[string]map[string]struct{}, error)
	GetStatistics() map[string]subscraping.Statistics
	StartSharedRateLimiter(context.Context) (func() error, error)
}

// SubfinderEngine reuses one provider configuration and one rate-limit budget
// across a sequential list of root domains.
type SubfinderEngine struct {
	client   subfinderEnumerator
	close    func() error
	maxHosts int
}

// QuerySubfinder is a convenience wrapper for one root. Use
// NewSubfinderEngine for a list so provider budgets survive between roots.
func QuerySubfinder(ctx context.Context, root, providerConfig string, maxHosts int) ([]string, error) {
	return querySubfinder(ctx, root, providerConfig, maxHosts, func(options *runner.Options) (subfinderEnumerator, error) {
		return runner.NewRunner(options)
	})
}

func querySubfinder(ctx context.Context, root, providerConfig string, maxHosts int, newRunner func(*runner.Options) (subfinderEnumerator, error)) ([]string, error) {
	root, err := normalizeRoot(root)
	if err != nil {
		return nil, err
	}
	engine, err := newSubfinderEngine(ctx, providerConfig, maxHosts, newRunner)
	if err != nil {
		return nil, err
	}
	names, queryErr := engine.Query(ctx, root)
	return names, errors.Join(queryErr, engine.Close())
}

// NewSubfinderEngine uses the embedded engine's default passive sources.
// Empty providerConfig uses Abigail's provider-config.yaml location;
// SOURCE_API_KEY environment variables are also supported. Wildcard/DNS
// filtering stays off because takeover checks need dangling CNAME evidence.
func NewSubfinderEngine(ctx context.Context, providerConfig string, maxHosts int) (*SubfinderEngine, error) {
	return newSubfinderEngine(ctx, providerConfig, maxHosts, func(options *runner.Options) (subfinderEnumerator, error) {
		return runner.NewRunner(options)
	})
}

func newSubfinderEngine(ctx context.Context, providerConfig string, maxHosts int, newRunner func(*runner.Options) (subfinderEnumerator, error)) (*SubfinderEngine, error) {
	if ctx == nil {
		return nil, errors.New("passive discovery requires a context")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("passive discovery: %w", err)
	}
	if maxHosts < 1 {
		return nil, errors.New("passive discovery requires a positive host limit")
	}
	if providerConfig != "" {
		info, err := os.Stat(providerConfig)
		if err != nil {
			return nil, fmt.Errorf("provider config %q: %w", providerConfig, err)
		}
		if info.IsDir() {
			return nil, fmt.Errorf("provider config %q is a directory", providerConfig)
		}
	}
	// The Subfinder CLI installs these provider limits in ParseOptions; SDK
	// callers must supply them themselves. Keep the effective CLI defaults for
	// all default sources used by Abigail.
	var rateLimits goflags.RateLimitMap
	for _, limit := range []string{
		"github=83/m", "fullhunt=60/m", "pugrecon=10/s", "hackertarget=2/s",
		"securitytrails=2/s", "shodan=1/s", "virustotal=4/m",
		"waybackarchive=15/m", "whoisxmlapi=50/s", "sitedossier=8/m",
		"netlas=1/s", "hudsonrock=5/s", "urlscan=1/s",
	} {
		if err := rateLimits.Set(limit); err != nil {
			return nil, fmt.Errorf("invalid provider rate limit %q: %w", limit, err)
		}
	}

	// The SDK's "active" option resolves names and can discard dangling
	// records relevant to takeover detection, so leave it disabled.
	client, err := newRunner(&runner.Options{
		Threads:             10,
		Timeout:             30,
		MaxEnumerationTime:  10,
		RateLimits:          rateLimits,
		ProviderConfig:      providerConfig,
		MaxResults:          maxHosts,
		MaxResponseBodySize: 32 << 20,
		DisableUpdateCheck:  true,
	})
	if err != nil {
		return nil, fmt.Errorf("initialize passive sources: %w", err)
	}
	closeLimiter, err := client.StartSharedRateLimiter(ctx)
	if err != nil {
		return nil, fmt.Errorf("initialize provider rate limits: %w", err)
	}
	return &SubfinderEngine{client: client, close: closeLimiter, maxHosts: maxHosts}, nil
}

// Close releases the shared provider rate limiter after the final root.
func (e *SubfinderEngine) Close() error {
	if e == nil || e.close == nil {
		return nil
	}
	return e.close()
}

// Query enumerates one root. Call sequentially; a Runner and its source
// statistics are not safe to use concurrently for independent roots.
func (e *SubfinderEngine) Query(ctx context.Context, root string) ([]string, error) {
	if e == nil || e.client == nil {
		return nil, errors.New("passive discovery is not initialized")
	}
	if ctx == nil {
		return nil, errors.New("passive discovery requires a context")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("passive discovery: %w", err)
	}
	root, err := normalizeRoot(root)
	if err != nil {
		return nil, err
	}
	// The source map is returned directly by the SDK. No output writer is needed.
	results, runErr := e.client.EnumerateSingleDomainWithCtx(ctx, root, nil)
	hosts := make(map[string]bool, len(results))
	for raw := range results {
		if name, ok := normalizeChild(raw, root); ok {
			hosts[name] = true
		}
	}
	names := sortedHosts(hosts)
	if runErr != nil {
		return names, fmt.Errorf("enumerate passive sources: %w", runErr)
	}
	if err := ctx.Err(); err != nil {
		return names, fmt.Errorf("passive discovery: %w", err)
	}

	// The runner logs individual source errors but exposes only counts here.
	// Surface those counts alongside any partial results instead of implying a
	// complete search when a provider was unavailable or rate limited.
	var failed []string
	for source, stats := range e.client.GetStatistics() {
		if stats.Errors > 0 && !stats.Skipped {
			failed = append(failed, fmt.Sprintf("%s (%d)", source, stats.Errors))
		}
		if stats.Results >= e.maxHosts {
			failed = append(failed, fmt.Sprintf("%s reached the per-source result limit (%d)", source, e.maxHosts))
		}
	}
	if len(failed) > 0 {
		sort.Strings(failed)
		return names, fmt.Errorf("source errors: %s", strings.Join(failed, ", "))
	}
	return names, nil
}
