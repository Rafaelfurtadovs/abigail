package httpprobe

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/html/charset"
)

const DefaultMaxBody = 512 * 1024

type Result struct {
	URL       string `json:"url,omitempty"`
	Status    int    `json:"status,omitempty"`
	Body      []byte `json:"-"`
	Truncated bool   `json:"truncated,omitempty"`
	Charset   string `json:"charset,omitempty"`
	Error     string `json:"error,omitempty"`
}

type Prober struct {
	client  *http.Client
	maxBody int64
}

// New keeps TLS certificate validation enabled and does not follow redirects.
// The HTTP client may be replaced in unit tests with an in-memory transport.
func New(timeout time.Duration, maxBody int64) *Prober {
	if maxBody <= 0 {
		maxBody = DefaultMaxBody
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = (&net.Dialer{Timeout: timeout}).DialContext
	transport.ResponseHeaderTimeout = timeout
	transport.MaxResponseHeaderBytes = 64 * 1024
	return &Prober{
		client: &http.Client{
			Transport: transport,
			Timeout:   timeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		maxBody: maxBody,
	}
}

func (p *Prober) Close() { p.client.CloseIdleConnections() }

// FetchAll probes both schemes in a stable order. Each request is bounded by
// the client's timeout, and an error on one scheme does not hide the other's
// response. The caller decides which response supports a provider rule.
func (p *Prober) FetchAll(ctx context.Context, domain string) []Result {
	results := make([]Result, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		results[0] = p.fetchURL(ctx, "https://"+domain)
	}()
	go func() {
		defer wg.Done()
		results[1] = p.fetchURL(ctx, "http://"+domain)
	}()
	wg.Wait()
	return results
}

// Fetch retains the original single-response behavior for callers that only
// need a preferred scheme.
func (p *Prober) Fetch(ctx context.Context, domain string) Result {
	https := p.fetchURL(ctx, "https://"+domain)
	if https.Error == "" || ctx.Err() != nil {
		return https
	}
	httpResult := p.fetchURL(ctx, "http://"+domain)
	if httpResult.Error == "" {
		return httpResult
	}
	httpResult.Error = fmt.Sprintf("HTTPS: %s; HTTP: %s", https.Error, httpResult.Error)
	return httpResult
}

func (p *Prober) fetchURL(ctx context.Context, address string) Result {
	result := Result{URL: address}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	request.Header.Set("User-Agent", "abigail (+https://github.com/Rafaelfurtadovs/abigail)")
	response, err := p.client.Do(request)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer response.Body.Close()
	result.Status = response.StatusCode
	body, err := io.ReadAll(io.LimitReader(response.Body, p.maxBody+1))
	if err != nil {
		result.Error = err.Error()
		return result
	}
	if int64(len(body)) > p.maxBody {
		result.Truncated = true
		body = body[:p.maxBody]
	}
	encoding, name, _ := charset.DetermineEncoding(body, response.Header.Get("Content-Type"))
	decoded, err := encoding.NewDecoder().Bytes(body)
	if err != nil {
		result.Error = "unable to decode HTTP response body"
		return result
	}
	result.Charset = name
	result.Body = decoded
	return result
}
