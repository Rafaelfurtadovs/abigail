package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDiscoverWithSourcesCombinesChildrenAndRoots(t *testing.T) {
	sources := []namedDiscoverySource{
		{name: "first", run: func(context.Context, string) ([]string, error) {
			return []string{"API.Example.com", "deep.api.example.com", "*.example.com", "example.com", "api.example.com.attacker.test"}, nil
		}},
		{name: "second", run: func(context.Context, string) ([]string, error) {
			return []string{"api.example.com", "mail.example.com"}, nil
		}},
	}
	var stderr bytes.Buffer
	domains, children, err := discoverWithSources(context.Background(), []string{"example.com"}, config{maxHosts: 10}, &stderr, sources)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"api.example.com", "deep.api.example.com", "example.com", "mail.example.com"}; !reflect.DeepEqual(domains, want) {
		t.Fatalf("scan domains = %q, want %q", domains, want)
	}
	if want := []string{"api.example.com", "deep.api.example.com", "mail.example.com"}; !reflect.DeepEqual(children, want) {
		t.Fatalf("discovered children = %q, want %q", children, want)
	}
	if !strings.Contains(stderr.String(), "Discovered 3 unique subdomains") || !strings.Contains(stderr.String(), "scanning 4 hostnames") {
		t.Fatalf("missing discovery summary: %q", stderr.String())
	}
}

func TestDiscoverWithSourcesSurfacesPartialAndTotalFailure(t *testing.T) {
	failed := namedDiscoverySource{name: "failed", run: func(context.Context, string) ([]string, error) {
		return nil, errors.New("rate limited")
	}}
	partial := namedDiscoverySource{name: "partial", run: func(context.Context, string) ([]string, error) {
		return []string{"api.example.com"}, errors.New("later page failed")
	}}
	var stderr bytes.Buffer
	_, children, err := discoverWithSources(context.Background(), []string{"example.com"}, config{maxHosts: 10}, &stderr, []namedDiscoverySource{failed, partial})
	if err != nil || !reflect.DeepEqual(children, []string{"api.example.com"}) || !strings.Contains(stderr.String(), "warning:") {
		t.Fatalf("partial discovery lost evidence or warning: children=%q, err=%v, stderr=%q", children, err, stderr.String())
	}
	_, _, err = discoverWithSources(context.Background(), []string{"example.com"}, config{maxHosts: 10}, &stderr, []namedDiscoverySource{failed})
	if err == nil || !strings.Contains(err.Error(), "all discovery sources failed") {
		t.Fatalf("total source failure must stop scan: %v", err)
	}
	invalidPartial := namedDiscoverySource{name: "invalid", run: func(context.Context, string) ([]string, error) {
		return []string{"api.example.com.attacker.test"}, errors.New("bad page")
	}}
	_, _, err = discoverWithSources(context.Background(), []string{"example.com"}, config{maxHosts: 10}, &stderr, []namedDiscoverySource{invalidPartial})
	if err == nil {
		t.Fatal("invalid out-of-scope partial names must not conceal total failure")
	}
}

func TestDiscoverWithSourcesHonorsHostLimit(t *testing.T) {
	source := namedDiscoverySource{name: "source", run: func(context.Context, string) ([]string, error) {
		return []string{"a.example.com", "b.example.com"}, nil
	}}
	_, _, err := discoverWithSources(context.Background(), []string{"example.com"}, config{maxHosts: 2}, &bytes.Buffer{}, []namedDiscoverySource{source})
	if err == nil || !strings.Contains(err.Error(), "--max-hosts") {
		t.Fatalf("expected explicit host limit error, got %v", err)
	}
}

func TestIncompatibleDiscoveryFlagsFailBeforeNetwork(t *testing.T) {
	for _, extra := range []string{"--brute", "--discover-only", "--native-discovery"} {
		var stdout, stderr bytes.Buffer
		code := run([]string{"scan", "-d", "example.com", "--no-discover", extra}, &stdout, &stderr)
		if code != 2 || !strings.Contains(stderr.String(), "cannot be combined") {
			t.Errorf("flags %s: code=%d, stderr=%q", extra, code, stderr.String())
		}
	}
}

func TestNativeDiscoveryRejectsSubfinderConfig(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "-d", "example.com", "--native-discovery", "--provider-config", "/does/not/exist/providers.yaml"}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "requires the Subfinder discovery engine") {
		t.Fatalf("code=%d, stderr=%q", code, stderr.String())
	}
}

func TestPublicSuffixDiscoveryFailsBeforeNetwork(t *testing.T) {
	for _, root := range []string{"com.br", "co.uk"} {
		var stdout, stderr bytes.Buffer
		code := run([]string{"scan", "-d", root, "--discover-only"}, &stdout, &stderr)
		if code != 2 || !strings.Contains(stderr.String(), "must be beneath a registrable domain") {
			t.Fatalf("root=%s, code=%d, stderr=%q", root, code, stderr.String())
		}
	}
}

func TestMissingProviderConfigFailsBeforeNetwork(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "-d", "example.com", "--provider-config", "/does/not/exist/providers.yaml"}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "provider config:") {
		t.Fatalf("code=%d, stderr=%q", code, stderr.String())
	}
}

func TestMalformedProviderConfigFailsWithoutLoggingSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "providers.yaml")
	if err := os.WriteFile(path, []byte("github: [very-secret-key\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "-d", "example.com", "--provider-config", path}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "expected YAML mapping") || strings.Contains(stderr.String(), "very-secret-key") {
		t.Fatalf("code=%d, stderr=%q", code, stderr.String())
	}
}

func TestMalformedEnvProviderConfigFailsBeforeNetwork(t *testing.T) {
	path := filepath.Join(t.TempDir(), "providers.yaml")
	if err := os.WriteFile(path, []byte("github: bad-value\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SUBFINDER_PROVIDER_CONFIG", path)
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "-d", "example.com"}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "expected YAML mapping") {
		t.Fatalf("code=%d, stderr=%q", code, stderr.String())
	}
}

func TestDiscoverOnlyRespectsOutputFormat(t *testing.T) {
	for _, tc := range []struct {
		format string
		want   string
	}{
		{"text", "api.example.com\n"},
		{"jsonl", "{\"domain\":\"api.example.com\",\"status\":\"discovered\"}\n"},
	} {
		var output bytes.Buffer
		if err := writeDiscovered(&output, []string{"api.example.com"}, tc.format); err != nil {
			t.Fatal(err)
		}
		if output.String() != tc.want {
			t.Fatalf("format=%s: got %q, want %q", tc.format, output.String(), tc.want)
		}
	}
}
