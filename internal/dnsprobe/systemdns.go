package dnsprobe

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const systemDNSCacheTTL = 30 * time.Second

type systemDNSConfig struct {
	platform     string
	macResolvers []macDNSResolver
	linuxServers []string
	reason       string
}

type cachedSystemDNS struct {
	mu       sync.Mutex
	loadedAt time.Time
	config   systemDNSConfig
}

var osDNSCache cachedSystemDNS

func (c *cachedSystemDNS) get(ctx context.Context, now time.Time, load func(context.Context) systemDNSConfig) systemDNSConfig {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.loadedAt.IsZero() && !now.Before(c.loadedAt) && now.Sub(c.loadedAt) < systemDNSCacheTTL {
		return c.config
	}
	config := load(ctx)
	// A canceled caller must not poison the shared cache for the next scan.
	if ctx.Err() == nil {
		c.config = config
		c.loadedAt = now
	}
	return config
}

// systemDNSServers returns the route to a name only when the local OS
// configuration identifies it without guessing. An empty result instructs
// callers to use the system API and mark the CNAME chain incomplete.
func systemDNSServers(ctx context.Context, name string) ([]string, string) {
	config := osDNSCache.get(ctx, time.Now(), readSystemDNSConfig)
	if config.reason != "" {
		return nil, config.reason
	}
	switch config.platform {
	case "darwin":
		return selectMacResolvers(name, config.macResolvers)
	case "linux":
		return port53Addresses(config.linuxServers), ""
	default:
		return nil, "system DNS route unavailable on this platform"
	}
}

func readSystemDNSConfig(ctx context.Context) systemDNSConfig {
	switch runtime.GOOS {
	case "darwin":
		inspectCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		output, err := exec.CommandContext(inspectCtx, "/usr/sbin/scutil", "--dns").Output()
		if err != nil {
			return systemDNSConfig{platform: "darwin", reason: fmt.Sprintf("could not inspect macOS DNS routing: %v", err)}
		}
		return systemDNSConfig{platform: "darwin", macResolvers: parseScutilDNS(string(output))}
	case "linux":
		data, err := os.ReadFile("/etc/resolv.conf")
		if err != nil {
			return systemDNSConfig{platform: "linux", reason: fmt.Sprintf("could not read system DNS configuration: %v", err)}
		}
		linkTarget, _ := os.Readlink("/etc/resolv.conf")
		nss, _ := os.ReadFile("/etc/nsswitch.conf")
		if systemdRouteHidden(string(data), linkTarget, string(nss)) {
			return systemDNSConfig{platform: "linux", reason: "systemd-resolved may route this name by link; use the system resolver or specify --resolver"}
		}
		servers := parseResolvConfNameservers(string(data))
		if len(servers) == 0 {
			return systemDNSConfig{platform: "linux", reason: "system DNS configuration has no usable nameserver"}
		}
		return systemDNSConfig{platform: "linux", linuxServers: servers}
	default:
		return systemDNSConfig{reason: "system DNS route unavailable on this platform"}
	}
}

func systemdRouteHidden(config, linkTarget, nss string) bool {
	// The non-stub systemd-resolved file aggregates DNS servers without the
	// per-link routing domains. Its order is not a faithful query route.
	if strings.Contains(linkTarget, "systemd/resolve/resolv.conf") && !strings.Contains(linkTarget, "stub-resolv.conf") {
		return true
	}
	// nss-resolve can also apply per-link routing when resolv.conf has real
	// upstreams. A loopback stub, if configured, retains that policy.
	if allLoopbackServers(config) {
		return false
	}
	for _, line := range strings.Split(string(nss), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if strings.HasPrefix(line, "hosts:") {
			for _, field := range strings.Fields(strings.TrimPrefix(line, "hosts:")) {
				if field == "resolve" {
					return true
				}
			}
		}
	}
	return false
}

func allLoopbackServers(config string) bool {
	servers := parseResolvConfNameservers(config)
	if len(servers) == 0 {
		return false
	}
	for _, server := range servers {
		if ip := net.ParseIP(server); ip == nil || !ip.IsLoopback() {
			return false
		}
	}
	return true
}

func selectResolvConfServers(config string) ([]string, string) {
	servers := parseResolvConfNameservers(config)
	if len(servers) == 0 {
		return nil, "system DNS configuration has no usable nameserver"
	}
	return port53Addresses(servers), ""
}

func parseResolvConfNameservers(config string) []string {
	var servers []string
	seen := map[string]bool{}
	scanner := bufio.NewScanner(strings.NewReader(config))
	for scanner.Scan() {
		line := strings.TrimSpace(strings.SplitN(scanner.Text(), "#", 2)[0])
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		server := fields[1]
		if net.ParseIP(server) == nil || seen[server] {
			continue
		}
		seen[server] = true
		servers = append(servers, server)
		if len(servers) == 6 {
			break
		}
	}
	return servers
}

type macDNSResolver struct {
	domain      string
	nameservers []string
	order       int
	scoped      bool
}

func selectMacDNSServers(name, output string) ([]string, string) {
	return selectMacResolvers(name, parseScutilDNS(output))
}

func selectMacResolvers(name string, resolvers []macDNSResolver) ([]string, string) {
	var selected *macDNSResolver
	bestMatch := -1
	ambiguous := false
	for i := range resolvers {
		resolver := &resolvers[i]
		if resolver.scoped || len(resolver.nameservers) == 0 || !matchesDomain(name, resolver.domain) {
			continue
		}
		matchLength := len(resolver.domain)
		if matchLength > bestMatch {
			selected, bestMatch, ambiguous = resolver, matchLength, false
		} else if matchLength == bestMatch {
			if resolver.order < selected.order {
				selected, ambiguous = resolver, false
			} else if resolver.order == selected.order && !sameServers(resolver.nameservers, selected.nameservers) {
				ambiguous = true
			}
		}
	}
	if selected == nil {
		return nil, "macOS DNS configuration has no unscoped route for this name"
	}
	for _, resolver := range resolvers {
		if resolver.scoped && resolver.domain != "" && matchesDomain(name, resolver.domain) && len(resolver.domain) >= bestMatch {
			return nil, "macOS DNS route is interface-scoped; the selected interface is unknown"
		}
	}
	if ambiguous {
		return nil, "macOS DNS configuration has conflicting equally preferred routes"
	}
	return port53Addresses(selected.nameservers), ""
}

func parseScutilDNS(output string) []macDNSResolver {
	var resolvers []macDNSResolver
	scopedSection := false
	var current *macDNSResolver
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "DNS configuration (for scoped queries)") {
			scopedSection = true
			current = nil
			continue
		}
		if line == "DNS configuration" {
			scopedSection = false
			current = nil
			continue
		}
		if strings.HasPrefix(line, "resolver #") {
			resolvers = append(resolvers, macDNSResolver{order: int(^uint(0) >> 1), scoped: scopedSection})
			current = &resolvers[len(resolvers)-1]
			continue
		}
		if current == nil {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		switch {
		case key == "domain":
			current.domain = normalizeName(value)
		case strings.HasPrefix(key, "nameserver["):
			server := strings.TrimSpace(value)
			ipPart := strings.SplitN(server, "%", 2)[0]
			if net.ParseIP(ipPart) != nil {
				current.nameservers = append(current.nameservers, server)
			}
		case key == "order":
			if order, err := strconv.Atoi(value); err == nil {
				current.order = order
			}
		case key == "flags":
			current.scoped = current.scoped || strings.Contains(value, "Scoped")
		}
	}
	return resolvers
}

func matchesDomain(name, domain string) bool {
	return domain == "" || name == domain || strings.HasSuffix(name, "."+domain)
}

func sameServers(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func port53Addresses(servers []string) []string {
	addresses := make([]string, 0, len(servers))
	for _, server := range servers {
		addresses = append(addresses, net.JoinHostPort(server, "53"))
	}
	return addresses
}
