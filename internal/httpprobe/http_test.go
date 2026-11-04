package httpprobe

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestFetchAllPreservesBothSchemeResponses(t *testing.T) {
	probe := New(time.Second, DefaultMaxBody)
	defer probe.Close()
	probe.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		status, body := http.StatusNotFound, "ordinary HTTPS page"
		if request.URL.Scheme == "http" {
			status, body = http.StatusOK, "provider fingerprint"
		}
		return &http.Response{
			StatusCode: status,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(body)),
		}, nil
	})
	results := probe.FetchAll(context.Background(), "sub.example.test")
	if len(results) != 2 || results[0].URL != "https://sub.example.test" ||
		results[0].Status != http.StatusNotFound ||
		results[1].URL != "http://sub.example.test" ||
		results[1].Status != http.StatusOK ||
		string(results[1].Body) != "provider fingerprint" {
		t.Fatalf("expected distinct HTTPS and HTTP evidence: %+v", results)
	}
}

func TestFetchAllRetainsSecondSchemeAfterFirstFails(t *testing.T) {
	probe := New(time.Second, DefaultMaxBody)
	defer probe.Close()
	probe.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Scheme == "https" {
			return nil, errors.New("TLS unavailable")
		}
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("provider fingerprint")),
		}, nil
	})
	results := probe.FetchAll(context.Background(), "sub.example.test")
	if len(results) != 2 || results[0].Error == "" || results[1].Error != "" ||
		string(results[1].Body) != "provider fingerprint" {
		t.Fatalf("first scheme failure must not mask second response: %+v", results)
	}
}

func TestRejectsInvalidTLSCertificate(t *testing.T) {
	var handled atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		handled.Add(1)
		w.Write([]byte("provider fingerprint"))
	}))
	defer server.Close()
	probe := New(time.Second, DefaultMaxBody)
	defer probe.Close()
	result := probe.Fetch(context.Background(), strings.TrimPrefix(server.URL, "https://"))
	if handled.Load() != 0 || strings.Contains(string(result.Body), "provider fingerprint") {
		t.Fatalf("untrusted TLS response must not count as HTTP evidence: %+v", result)
	}
}

func TestDoesNotFollowRedirects(t *testing.T) {
	var followed atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/destination" {
			followed.Add(1)
			return
		}
		http.Redirect(w, r, "/destination", http.StatusFound)
	}))
	defer server.Close()
	probe := New(time.Second, DefaultMaxBody)
	defer probe.Close()
	result := probe.Fetch(context.Background(), strings.TrimPrefix(server.URL, "http://"))
	if result.Error != "" || result.Status != http.StatusFound || followed.Load() != 0 {
		t.Fatalf("redirect must remain unvisited: %+v, followed=%d", result, followed.Load())
	}
}

func TestBodyLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(strings.Repeat("a", 100)))
	}))
	defer server.Close()
	probe := New(time.Second, 16)
	defer probe.Close()
	result := probe.Fetch(context.Background(), strings.TrimPrefix(server.URL, "http://"))
	if result.Error != "" || !result.Truncated || len(result.Body) != 16 {
		t.Fatalf("expected bounded response body: %+v", result)
	}
}

func TestDecodesDeclaredLegacyCharset(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=windows-1251")
		w.Write([]byte{0xC4, 0xEE, 0xEC, 0xE5, 0xED}) // Домен
	}))
	defer server.Close()
	probe := New(time.Second, DefaultMaxBody)
	defer probe.Close()
	result := probe.Fetch(context.Background(), strings.TrimPrefix(server.URL, "http://"))
	if result.Error != "" || string(result.Body) != "Домен" {
		t.Fatalf("expected decoded Cyrillic body: %+v", result)
	}
}
