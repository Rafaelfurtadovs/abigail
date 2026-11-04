package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Rafaelfurtadovs/abigail/internal/discovery"
	fileutil "github.com/projectdiscovery/utils/file"
	"gopkg.in/yaml.v3"
)

func validateProviderConfig(path string) error {
	reader, err := fileutil.SubstituteConfigFromEnvVars(path)
	if err != nil {
		return fmt.Errorf("read %q: %w", path, err)
	}
	var keys map[string][]string
	if err := yaml.NewDecoder(reader).Decode(&keys); err != nil || keys == nil {
		// YAML unmarshalling errors may echo the invalid scalar, which could be
		// a provider secret. Keep credentials out of CLI and CI logs.
		return errors.New("expected YAML mapping from source names to key lists")
	}
	return nil
}

type namedDiscoverySource struct {
	name string
	run  func(context.Context, string) ([]string, error)
}

func writeDiscovered(w io.Writer, names []string, format string) error {
	if format == "jsonl" {
		encoder := json.NewEncoder(w)
		for _, name := range names {
			if err := encoder.Encode(struct {
				Domain string `json:"domain"`
				Status string `json:"status"`
			}{Domain: name, Status: "discovered"}); err != nil {
				return err
			}
		}
		return nil
	}
	for _, name := range names {
		if _, err := fmt.Fprintln(w, name); err != nil {
			return err
		}
	}
	return nil
}

// discoverDomains gathers candidates, then lets the ordinary scanner check
// each one. The supplied roots are scanned too, but discover-only prints only
// child names, matching the expectation of a subdomain enumerator.
func discoverDomains(ctx context.Context, roots []string, cfg config, stderr io.Writer) ([]string, []string, error) {
	var sources []namedDiscoverySource
	if cfg.nativeDiscovery {
		client := &http.Client{
			Timeout: min(cfg.discoveryTimeout, 30*time.Second),
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		sources = []namedDiscoverySource{
			{name: "crt.sh", run: func(ctx context.Context, root string) ([]string, error) {
				return discovery.QueryCRTSh(ctx, root, client)
			}},
			{name: "crt.name", run: func(ctx context.Context, root string) ([]string, error) {
				return discovery.QueryCRTName(ctx, root, client)
			}},
			{name: "Cert Spotter", run: func(ctx context.Context, root string) ([]string, error) {
				return discovery.QueryCertSpotter(ctx, root, client)
			}},
			{name: "HackerTarget", run: func(ctx context.Context, root string) ([]string, error) {
				return discovery.QueryHackerTarget(ctx, root, client)
			}},
		}
	} else {
		engine, err := discovery.NewSubfinderEngine(ctx, cfg.providerConfig, cfg.maxHosts)
		if err != nil {
			return nil, nil, err
		}
		defer func() {
			if err := engine.Close(); err != nil {
				fmt.Fprintf(stderr, "warning: close Subfinder discovery: %v\n", err)
			}
		}()
		sources = []namedDiscoverySource{{name: "Subfinder passive sources", run: engine.Query}}
	}
	if cfg.brute {
		concurrency := min(cfg.concurrency, 16)
		sources = append(sources, namedDiscoverySource{name: "DNS wordlist", run: func(ctx context.Context, root string) ([]string, error) {
			bruteCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
			defer cancel()
			return discovery.BruteForce(bruteCtx, root, net.DefaultResolver, discovery.DefaultWords(), concurrency)
		}})
	}
	return discoverWithSources(ctx, roots, cfg, stderr, sources)
}

func discoverWithSources(ctx context.Context, roots []string, cfg config, stderr io.Writer, sources []namedDiscoverySource) ([]string, []string, error) {
	if len(sources) == 0 {
		return nil, nil, errors.New("no discovery sources are configured")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	all := make(map[string]bool, len(roots))
	for _, root := range roots {
		all[root] = true
	}
	if len(all) > cfg.maxHosts {
		return nil, nil, fmt.Errorf("%d roots exceed --max-hosts=%d", len(all), cfg.maxHosts)
	}
	children := make(map[string]bool)
	for _, root := range roots {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		type reply struct {
			name  string
			hosts []string
			err   error
		}
		results := make(chan reply, len(sources))
		for _, source := range sources {
			go func(source namedDiscoverySource) {
				sourceCtx := ctx
				stop := func() {}
				if cfg.discoveryTimeout > 0 {
					sourceCtx, stop = context.WithTimeout(ctx, cfg.discoveryTimeout)
				}
				defer stop()
				hosts, err := source.run(sourceCtx, root)
				results <- reply{name: source.name, hosts: hosts, err: err}
			}(source)
		}
		var successful int
		var failures []string
		var foundForRoot int
		for range sources {
			item := <-results
			if item.err != nil {
				failures = append(failures, fmt.Sprintf("%s: %v", item.name, item.err))
			}
			var validFromSource int
			for _, raw := range item.hosts {
				name, err := normalizeDomain(raw)
				if err != nil || !strings.HasSuffix(name, "."+root) {
					continue
				}
				validFromSource++
				if !all[name] {
					all[name] = true
					foundForRoot++
				}
				children[name] = true
				if len(all) > cfg.maxHosts {
					return nil, nil, fmt.Errorf("discovered more than --max-hosts=%d; raise the limit to continue", cfg.maxHosts)
				}
			}
			if item.err == nil || validFromSource > 0 {
				successful++
			}
		}
		if successful == 0 {
			return nil, nil, fmt.Errorf("%s: all discovery sources failed (%s)", root, strings.Join(failures, "; "))
		}
		for _, failure := range failures {
			fmt.Fprintf(stderr, "warning: discovery for %s: %s\n", root, failure)
		}
		fmt.Fprintf(stderr, "Discovered %d new subdomains for %s\n", foundForRoot, root)
	}
	for _, root := range roots {
		delete(children, root)
	}
	domains := make([]string, 0, len(all))
	for domain := range all {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	discovered := make([]string, 0, len(children))
	for domain := range children {
		discovered = append(discovered, domain)
	}
	sort.Strings(discovered)
	if cfg.discoverOnly {
		fmt.Fprintf(stderr, "Discovered %d unique subdomains across %d roots\n", len(discovered), len(roots))
	} else {
		fmt.Fprintf(stderr, "Discovered %d unique subdomains across %d roots; scanning %d hostnames\n", len(discovered), len(roots), len(domains))
	}
	return domains, discovered, nil
}
