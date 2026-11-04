package subscraping

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

type failingTransport func(*http.Request) (*http.Response, error)

func (fn failingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func TestSessionRejectsUntrustedTLSAndRedactsNetworkError(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "unexpected success")
	}))
	defer server.Close()
	server.Config.ErrorLog = log.New(io.Discard, "", 0)

	session, err := NewSession("example.com", "", nil, 5)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	request, err := http.NewRequest(http.MethodGet, server.URL+"/?apikey=very-secret-key", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := httpRequestWrapper(session.Client, request, 0)
	if response != nil {
		_ = response.Body.Close()
	}
	var unknownAuthority x509.UnknownAuthorityError
	if !errors.As(err, &unknownAuthority) {
		t.Fatalf("expected certificate verification failure, got %v", err)
	}
	if strings.Contains(err.Error(), "very-secret-key") {
		t.Fatalf("network error exposed query API key: %v", err)
	}
}

func TestSessionDoesNotForwardCredentialsAcrossOrigins(t *testing.T) {
	var targetHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		t.Errorf("redirect reached another origin with Authorization=%q", r.Header.Get("Authorization"))
	}))
	defer target.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/collect", http.StatusFound)
	}))
	defer origin.Close()

	session, err := NewSession("example.com", "", nil, 5)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	request, err := http.NewRequest(http.MethodGet, origin.URL+"/?apikey=very-secret-key", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer very-secret-key")
	response, err := httpRequestWrapper(session.Client, request, 0)
	if response == nil || response.StatusCode != http.StatusFound || err == nil {
		t.Fatalf("expected blocked redirect response, got response=%v err=%v", response, err)
	}
	_ = response.Body.Close()
	if targetHits.Load() != 0 {
		t.Fatalf("cross-origin redirect sent %d requests", targetHits.Load())
	}
	if strings.Contains(err.Error(), "very-secret-key") {
		t.Fatalf("redirect error exposed query API key: %v", err)
	}
}

func TestSourceHTTPStatusAndParseErrorsDoNotExposeQueryKeys(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, "very-secret-key")
	}))
	defer server.Close()
	session, err := NewSession("example.com", "", nil, 5)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	request, err := http.NewRequest(http.MethodGet, server.URL+"/?apikey=very-secret-key", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := httpRequestWrapper(session.Client, request, 0)
	if response == nil || response.StatusCode != http.StatusTooManyRequests || err == nil {
		t.Fatalf("expected 429 response and error, got response=%v err=%v", response, err)
	}
	_ = response.Body.Close()
	if strings.Contains(err.Error(), "very-secret-key") {
		t.Fatalf("status error exposed query API key: %v", err)
	}
	_, err = session.HTTPRequest(context.Background(), http.MethodGet, "://very-secret-key", "", nil, nil, BasicAuth{})
	if err == nil || strings.Contains(err.Error(), "very-secret-key") {
		t.Fatalf("parse error exposed malformed credential URL: %v", err)
	}
}

func TestTransportErrorCannotEchoSecretURL(t *testing.T) {
	secretCause := errors.New("transport saw very-secret-key")
	client := &http.Client{Transport: failingTransport(func(*http.Request) (*http.Response, error) {
		return nil, secretCause
	})}
	request, err := http.NewRequest(http.MethodGet, "https://provider.example/?apikey=very-secret-key", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = httpRequestWrapper(client, request, 0)
	if err == nil || strings.Contains(err.Error(), "very-secret-key") || !errors.Is(err, secretCause) {
		t.Fatalf("unsafe or opaque transport error: %v", err)
	}
}
