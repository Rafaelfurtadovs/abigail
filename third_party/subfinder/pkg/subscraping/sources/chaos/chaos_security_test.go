package chaos

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Rafaelfurtadovs/abigail/third_party/subfinder/pkg/subscraping"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

type allowRequests struct{}

func (allowRequests) Wait(context.Context, string) error { return nil }

func TestChaosUsesSessionClientWithAuthorization(t *testing.T) {
	var calls int
	session := &subscraping.Session{
		Client: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			calls++
			if request.URL.Scheme != "https" || request.URL.Host != "dns.projectdiscovery.io" || request.URL.Path != "/dns/example.com/subdomains" {
				t.Errorf("unexpected Chaos URL: %s", request.URL)
			}
			if got := request.Header.Get("Authorization"); got != "test-key" {
				t.Errorf("Chaos Authorization = %q", got)
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"domain":"example.com","subdomains":["www","deep.api"]}`)), Header: make(http.Header), Request: request}, nil
		})},
		RequestLimiter: allowRequests{},
		MaxResults:     10,
	}
	source := &Source{}
	source.AddApiKeys([]string{"test-key"})
	ctx := context.WithValue(context.Background(), subscraping.CtxSourceArg, "chaos")
	var names []string
	for result := range source.Run(ctx, "example.com", session) {
		if result.Type == subscraping.Error {
			t.Fatal(result.Error)
		}
		names = append(names, result.Value)
	}
	if calls != 1 || strings.Join(names, ",") != "www.example.com,deep.api.example.com" {
		t.Fatalf("calls=%d names=%q", calls, names)
	}
	stats := source.Statistics()
	if stats.Requests != 1 || stats.Results != 2 || stats.Errors != 0 {
		t.Fatalf("unexpected Chaos stats: %+v", stats)
	}
}

func TestChaosStatusErrorDoesNotExposeKey(t *testing.T) {
	session := &subscraping.Session{
		Client: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 429, Body: io.NopCloser(strings.NewReader("test-key")), Header: make(http.Header), Request: request}, nil
		})},
		RequestLimiter: allowRequests{},
	}
	source := &Source{}
	source.AddApiKeys([]string{"test-key"})
	ctx := context.WithValue(context.Background(), subscraping.CtxSourceArg, "chaos")
	var resultError error
	for result := range source.Run(ctx, "example.com", session) {
		if result.Type == subscraping.Error {
			resultError = result.Error
		}
	}
	if resultError == nil || strings.Contains(resultError.Error(), "test-key") || source.Statistics().Errors != 1 {
		t.Fatalf("unsafe or missing Chaos status error: %v stats=%+v", resultError, source.Statistics())
	}
}

func TestChaosCanceledContextStopsBeforeTransport(t *testing.T) {
	var calls int
	session := &subscraping.Session{
		Client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			return nil, nil
		})},
		RequestLimiter: allowRequests{},
	}
	source := &Source{}
	source.AddApiKeys([]string{"test-key"})
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), subscraping.CtxSourceArg, "chaos"))
	cancel()
	done := make(chan struct{})
	go func() {
		for range source.Run(ctx, "example.com", session) {
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Chaos source did not stop after cancellation")
	}
	if calls != 0 {
		t.Fatalf("Chaos made %d network requests after cancellation", calls)
	}
}
