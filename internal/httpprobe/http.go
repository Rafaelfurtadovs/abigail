package httpprobe

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

const DefaultMaxBody = 512 * 1024

type Result struct {
	URL       string `json:"url,omitempty"`
	Status    int    `json:"status,omitempty"`
	Body      []byte `json:"-"`
	Truncated bool   `json:"truncated,omitempty"`
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
	request.Header.Set("User-Agent", "abigail/0.1 (+https://github.com/Rafaelfurtadovs/abigail)")
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
	result.Body = body
	return result
}
