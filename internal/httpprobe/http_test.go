package httpprobe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

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
