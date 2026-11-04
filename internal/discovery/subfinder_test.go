package discovery

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/Rafaelfurtadovs/abigail/third_party/subfinder/pkg/runner"
	"github.com/Rafaelfurtadovs/abigail/third_party/subfinder/pkg/subscraping"
)

type fakeSubfinderEnumerator struct {
	results map[string]map[string]struct{}
	stats   map[string]subscraping.Statistics
	err     error
	root    string
	runs    int
	starts  int
	closes  int
}

func (f *fakeSubfinderEnumerator) EnumerateSingleDomainWithCtx(_ context.Context, root string, _ []io.Writer) (map[string]map[string]struct{}, error) {
	f.root = root
	f.runs++
	return f.results, f.err
}

func (f *fakeSubfinderEnumerator) GetStatistics() map[string]subscraping.Statistics {
	return f.stats
}

func (f *fakeSubfinderEnumerator) StartSharedRateLimiter(context.Context) (func() error, error) {
	f.starts++
	return func() error {
		f.closes++
		return nil
	}, nil
}

func TestQuerySubfinderUsesPassiveSourcesAndFiltersCandidates(t *testing.T) {
	fake := &fakeSubfinderEnumerator{results: map[string]map[string]struct{}{
		"API.EXAMPLE.COM":                  {"crtname": {}},
		"z.example.com":                    {"crtsh": {}},
		"*.example.com":                    {"crtsh": {}},
		"bad.example.com.attacker.invalid": {"crtsh": {}},
		"example.com":                      {"crtsh": {}},
	}}
	var gotOptions *runner.Options
	names, err := querySubfinder(context.Background(), "Example.COM.", "", 10000, func(options *runner.Options) (subfinderEnumerator, error) {
		gotOptions = options
		return fake, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(names, ","); got != "api.example.com,z.example.com" {
		t.Fatalf("names = %q", got)
	}
	if fake.root != "example.com" || gotOptions == nil || gotOptions.RemoveWildcard || gotOptions.All || gotOptions.Timeout != 30 || gotOptions.MaxEnumerationTime != 10 || gotOptions.MaxResults != 10000 || gotOptions.MaxResponseBodySize != 32<<20 {
		t.Fatalf("unexpected SDK invocation: root=%q, options=%+v", fake.root, gotOptions)
	}
	if got := strings.Join(gotOptions.ExcludeSources, ","); got != "" {
		t.Fatalf("default Subfinder source set unexpectedly restricted: %q", got)
	}
	if limit := gotOptions.RateLimits.AsMap()["urlscan"]; limit.MaxCount != 1 {
		t.Fatalf("missing Subfinder CLI provider limit for urlscan: %+v", limit)
	}
	if limit := gotOptions.RateLimits.AsMap()["hackertarget"]; limit.MaxCount != 2 {
		t.Fatalf("missing Subfinder CLI provider limit for hackertarget: %+v", limit)
	}
}

func TestQuerySubfinderReportsSourceErrorsWithPartialResults(t *testing.T) {
	fake := &fakeSubfinderEnumerator{
		results: map[string]map[string]struct{}{"api.example.com": {"crtname": {}}},
		stats: map[string]subscraping.Statistics{
			"crtname": {Results: 1},
			"urlscan": {Errors: 2},
		},
	}
	names, err := querySubfinder(context.Background(), "example.com", "", 10000, func(*runner.Options) (subfinderEnumerator, error) { return fake, nil })
	if len(names) != 1 || names[0] != "api.example.com" || err == nil || !strings.Contains(err.Error(), "urlscan (2)") {
		t.Fatalf("names=%v, error=%v", names, err)
	}
}

func TestQuerySubfinderRejectsCanceledContextAndMissingConfig(t *testing.T) {
	called := false
	factory := func(*runner.Options) (subfinderEnumerator, error) {
		called = true
		return &fakeSubfinderEnumerator{}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := querySubfinder(ctx, "example.com", "", 10000, factory)
	if !errors.Is(err, context.Canceled) || called {
		t.Fatalf("canceled context: error=%v, factory called=%t", err, called)
	}
	_, err = querySubfinder(context.Background(), "example.com", "/does/not/exist/subfinder.yaml", 10000, factory)
	if err == nil || called {
		t.Fatalf("missing config: error=%v, factory called=%t", err, called)
	}
}

func TestSubfinderEngineReusesRunnerAcrossRoots(t *testing.T) {
	fake := &fakeSubfinderEnumerator{results: map[string]map[string]struct{}{"api.example.com": {"crtname": {}}}}
	var created int
	engine, err := newSubfinderEngine(context.Background(), "", 10000, func(*runner.Options) (subfinderEnumerator, error) {
		created++
		return fake, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := engine.Query(context.Background(), "example.com"); err != nil {
			t.Fatal(err)
		}
	}
	if err := engine.Close(); err != nil {
		t.Fatal(err)
	}
	if created != 1 || fake.starts != 1 || fake.runs != 2 || fake.closes != 1 {
		t.Fatalf("runner was not shared: created=%d starts=%d runs=%d closes=%d", created, fake.starts, fake.runs, fake.closes)
	}
}
