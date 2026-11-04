package subscraping

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/corpix/uarand"
	"github.com/projectdiscovery/ratelimit"

	"github.com/projectdiscovery/gologger"
)

// limitedResponseBody wraps a response body so that at most maxSize bytes can
// be read from it, while still closing the underlying body (so no
// connection/body leak). It is applied centrally so every source inherits the
// cap regardless of how it consumes the body (io.ReadAll, json.Decoder,
// bufio.Scanner, etc.).
type limitedResponseBody struct {
	io.Reader // io.LimitReader over the original body
	io.Closer // the original body's Close
}

// sourceTransportError preserves errors.Is/As without exposing an upstream
// error string that may contain a URL with an API key in its query or path.
type sourceTransportError struct{ cause error }

func (e sourceTransportError) Error() string { return "source HTTP request failed" }
func (e sourceTransportError) Unwrap() error { return e.cause }

// LimitResponseBody caps response.Body at maxSize bytes in place when maxSize
// is greater than zero. A maxSize of 0 or less leaves the body unchanged
// (unlimited; the default). It preserves the original body's Close.
// Exported so sources that (rarely) issue a raw client.Do — bypassing the
// session's httpRequestWrapper — can opt into the same protection.
func LimitResponseBody(response *http.Response, maxSize int64) {
	if response == nil || response.Body == nil || maxSize <= 0 {
		return
	}
	response.Body = &limitedResponseBody{
		Reader: io.LimitReader(response.Body, maxSize),
		Closer: response.Body,
	}
}

// NewSession creates a new session object for a domain
func NewSession(domain string, proxy string, multiRateLimiter *ratelimit.MultiLimiter, timeout int) (*Session, error) {
	Transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
		DialContext: (&net.Dialer{
			Timeout: time.Duration(timeout) * time.Second,
		}).DialContext,
	}

	// Add proxy
	if proxy != "" {
		proxyURL, _ := url.Parse(proxy)
		if proxyURL == nil {
			// Log warning but continue anyway
			gologger.Warning().Msgf("Invalid proxy provided: %s", proxy)
		} else {
			Transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	client := &http.Client{
		Transport: Transport,
		Timeout:   time.Duration(timeout) * time.Second,
		CheckRedirect: func(next *http.Request, previous []*http.Request) error {
			// A provider may put an API key in a header or URL. Do not forward
			// credentials to another origin, or downgrade HTTPS to HTTP.
			if len(previous) == 0 || next.URL.Scheme != previous[0].URL.Scheme ||
				!strings.EqualFold(next.URL.Host, previous[0].URL.Host) {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	session := &Session{Client: client, Timeout: timeout}

	// Initiate rate limit instance
	session.MultiRateLimiter = multiRateLimiter

	// Create a new extractor object for the current domain
	extractor, err := NewSubdomainExtractor(domain)
	session.Extractor = extractor

	return session, err
}

// Get makes a GET request to a URL with extended parameters
func (s *Session) Get(ctx context.Context, getURL, cookies string, headers map[string]string) (*http.Response, error) {
	return s.HTTPRequest(ctx, http.MethodGet, getURL, cookies, headers, nil, BasicAuth{})
}

// SimpleGet makes a simple GET request to a URL
func (s *Session) SimpleGet(ctx context.Context, getURL string) (*http.Response, error) {
	return s.HTTPRequest(ctx, http.MethodGet, getURL, "", map[string]string{}, nil, BasicAuth{})
}

// Post makes a POST request to a URL with extended parameters
func (s *Session) Post(ctx context.Context, postURL, cookies string, headers map[string]string, body io.Reader) (*http.Response, error) {
	return s.HTTPRequest(ctx, http.MethodPost, postURL, cookies, headers, body, BasicAuth{})
}

// SimplePost makes a simple POST request to a URL
func (s *Session) SimplePost(ctx context.Context, postURL, contentType string, body io.Reader) (*http.Response, error) {
	return s.HTTPRequest(ctx, http.MethodPost, postURL, "", map[string]string{"Content-Type": contentType}, body, BasicAuth{})
}

// HTTPRequest makes any HTTP request to a URL with extended parameters
func (s *Session) HTTPRequest(ctx context.Context, method, requestURL, cookies string, headers map[string]string, body io.Reader, basicAuth BasicAuth) (*http.Response, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, requestURL, body)
	if err != nil {
		// The parser error can contain a credential-bearing URL.
		return nil, errors.New("invalid source request URL")
	}

	req.Header.Set("User-Agent", uarand.GetRandom())
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en")

	if basicAuth.Username != "" || basicAuth.Password != "" {
		req.SetBasicAuth(basicAuth.Username, basicAuth.Password)
	}

	if cookies != "" {
		req.Header.Set("Cookie", cookies)
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	sourceName := ctx.Value(CtxSourceArg).(string)

	var mrlErr error
	if s.RequestLimiter != nil {
		mrlErr = s.RequestLimiter.Wait(ctx, sourceName)
	} else {
		mrlErr = s.MultiRateLimiter.Take(sourceName)
	}

	if mrlErr != nil {
		return nil, mrlErr
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return httpRequestWrapper(s.Client, req, s.MaxResponseBodySize)
}

// DiscardHTTPResponse discards the response content by demand
func (s *Session) DiscardHTTPResponse(response *http.Response) {
	if response == nil {
		return
	}
	// Close regardless of how draining went. Returning early on a drain error
	// used to leak the connection in exactly the case this helper exists to
	// handle, and every source now reaches it through a defer.
	defer func() {
		if closeErr := response.Body.Close(); closeErr != nil {
			gologger.Warning().Msgf("Could not close response body: %s\n", closeErr)
		}
	}()
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		gologger.Warning().Msgf("Could not discard response body: %s\n", err)
	}
}

// Close the session
func (s *Session) Close() {
	if s.MultiRateLimiter != nil {
		s.MultiRateLimiter.Stop()
	}

	s.Client.CloseIdleConnections()
}

func httpRequestWrapper(client *http.Client, request *http.Request, maxResponseBodySize int64) (*http.Response, error) {
	response, err := client.Do(request)
	if err != nil {
		// http.Client wraps transport errors in url.Error, whose Error() prints
		// credential-bearing URLs. Keep the cause for errors.Is/As but never
		// include its string form in provider logs or returned messages.
		return nil, sourceTransportError{cause: err}
	}

	// Optionally cap the untrusted response body centrally so every source
	// inherits the same bound when enabled.
	LimitResponseBody(response, maxResponseBodySize)

	if response.StatusCode != http.StatusOK {
		// Neither the URL nor response body is safe to log: both may echo keys.
		return response, fmt.Errorf("unexpected status code %d from source", response.StatusCode)
	}
	return response, nil
}
