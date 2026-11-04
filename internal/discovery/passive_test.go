package discovery

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestCRTShFiltersNamesAndEscapesQuery(t *testing.T) {
	var calls int
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.URL.Host != "crt.sh" || request.URL.Query().Get("q") != "%.example.com" ||
			request.URL.Query().Get("output") != "json" {
			t.Fatalf("unexpected crt.sh request: %s", request.URL)
		}
		return jsonResponse(200, `[
			{"name_value":"API.EXAMPLE.COM\n*.example.com\nbadexample.com\nfoo.example.com.attacker.test\nbar.api.example.com\nbad_name.example.com\napi.example.com.",
			 "common_name":"www.example.com"},
			{"name_value":"api.example.com\nEXAMPLE.COM\n-evil.example.com"}
		]`), nil
	})}
	hosts, err := QueryCRTSh(context.Background(), "Example.COM.", client)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"api.example.com", "bar.api.example.com", "www.example.com"}
	if strings.Join(hosts, ",") != strings.Join(want, ",") || calls != 1 {
		t.Fatalf("got hosts=%v calls=%d, want %v and 1", hosts, calls, want)
	}
}

func TestCRTNameFiltersNamesAndEscapesQuery(t *testing.T) {
	var calls int
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.URL.Scheme != "https" || request.URL.Host != "crt.name" ||
			request.URL.Path != "/v1/search" || request.URL.Query().Get("apex") != "example.com" ||
			request.URL.Query().Get("format") != "json" || len(request.URL.Query()) != 2 {
			t.Fatalf("unexpected crt.name request: %s", request.URL)
		}
		return jsonResponse(200, `[
			{"sub":"API.EXAMPLE.COM"},
			{"sub":"bar.api.example.com"},
			{"sub":"api.example.com."},
			{"sub":"*.example.com"},
			{"sub":"example.com"},
			{"sub":"foo.example.com.attacker.test"},
			{"sub":"bad_name.example.com"},
			{"sub":"-bad.example.com"}
		]`), nil
	})}
	hosts, err := QueryCRTName(context.Background(), "Example.COM.", client)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"api.example.com", "bar.api.example.com"}
	if strings.Join(hosts, ",") != strings.Join(want, ",") || calls != 1 {
		t.Fatalf("got hosts=%v calls=%d, want %v and 1", hosts, calls, want)
	}
}

func TestCRTNameSurfacesSourceErrors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"rate limit", 429, `{"error":"limit reached"}`},
		{"malformed JSON", 200, `[{"sub":`},
		{"wrong schema", 200, `{"results":[]}`},
		{"missing subdomain", 200, `[{"sub":"a.example.com"},{}]`},
		{"oversized body", 200, strings.Repeat("x", maxResponseBytes+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return jsonResponse(tc.status, tc.body), nil
			})}
			hosts, err := QueryCRTName(context.Background(), "example.com", client)
			if err == nil {
				t.Fatal("source error must be visible")
			}
			if tc.name == "missing subdomain" && (len(hosts) != 1 || hosts[0] != "a.example.com") {
				t.Fatalf("expected partial names, got hosts=%v err=%v", hosts, err)
			}
		})
	}
}

func TestCRTNameRequiresApexWithoutRequest(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("non-apex domain must not cause a request")
		return nil, errors.New("unreachable")
	})}
	for _, root := range []string{"www.example.com", "example.com.attacker.test/", "*.example.com", "localhost", "192.0.2.1"} {
		if _, err := QueryCRTName(context.Background(), root, client); err == nil {
			t.Errorf("crt.name accepted invalid or non-apex root %q", root)
		}
	}
}

func TestSourceRespectsCallerTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		deadline, ok := request.Context().Deadline()
		if !ok || time.Until(deadline) < 35*time.Second {
			t.Fatalf("caller 40s deadline was shortened: deadline=%v, hasDeadline=%v", deadline, ok)
		}
		return jsonResponse(200, `[]`), nil
	})}
	if _, err := QueryCRTName(ctx, "example.com", client); err != nil {
		t.Fatal(err)
	}

	withClientTimeout, stop := withSourceTimeout(context.Background(), &http.Client{Timeout: 40 * time.Second})
	defer stop()
	clientDeadline, ok := withClientTimeout.Deadline()
	if !ok || time.Until(clientDeadline) < 35*time.Second {
		t.Fatalf("source deadline should use the client's 40s timeout, got %v", clientDeadline)
	}

	withDefaultTimeout, stop := withSourceTimeout(context.Background(), nil)
	defer stop()
	deadline, ok := withDefaultTimeout.Deadline()
	remaining := time.Until(deadline)
	if !ok || remaining < 25*time.Second || remaining > sourceTimeout {
		t.Fatalf("expected default %s timeout, deadline=%v, hasDeadline=%v", sourceTimeout, deadline, ok)
	}
}

func TestCertSpotterPaginatesAndFilters(t *testing.T) {
	t.Setenv("CERTSPOTTER_API_KEY", "test-key")
	var calls int
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		query := request.URL.Query()
		if request.URL.Host != "api.certspotter.com" || query.Get("domain") != "example.com" ||
			query.Get("include_subdomains") != "true" || query.Get("expand") != "dns_names" ||
			request.Header.Get("Authorization") != "Bearer test-key" {
			t.Fatalf("unexpected Cert Spotter request: %s, Authorization=%q", request.URL, request.Header.Get("Authorization"))
		}
		switch query.Get("after") {
		case "":
			return jsonResponse(200, `[{"id":"first","dns_names":["A.example.com","*.example.com","example.com","a.example.com.attacker.test"]}]`), nil
		case "first":
			return jsonResponse(200, `[{"id":"second","dns_names":["b.a.example.com","A.example.com"]}]`), nil
		case "second":
			return jsonResponse(200, "[]"), nil
		default:
			t.Fatalf("unexpected pagination after=%q", query.Get("after"))
			return nil, nil
		}
	})}
	hosts, err := QueryCertSpotter(context.Background(), "example.com", client)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a.example.com", "b.a.example.com"}
	if strings.Join(hosts, ",") != strings.Join(want, ",") || calls != 3 {
		t.Fatalf("got hosts=%v calls=%d, want %v and 3", hosts, calls, want)
	}
}

func TestCertSpotterReturnsPartialOnRateLimit(t *testing.T) {
	t.Setenv("CERTSPOTTER_API_KEY", "")
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Query().Get("after") == "" {
			return jsonResponse(200, `[{"id":"first","dns_names":["a.example.com"]}]`), nil
		}
		return jsonResponse(429, `{"code":"rate_limited"}`), nil
	})}
	hosts, err := QueryCertSpotter(context.Background(), "example.com", client)
	if len(hosts) != 1 || hosts[0] != "a.example.com" || err == nil || !strings.Contains(err.Error(), "429") {
		t.Fatalf("expected partial names and 429 error, got hosts=%v err=%v", hosts, err)
	}
}

func TestCertSpotterReadsPastFivePages(t *testing.T) {
	t.Setenv("CERTSPOTTER_API_KEY", "")
	var calls int
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if calls == 8 {
			if request.URL.Query().Get("after") != "page-7" {
				t.Fatalf("unexpected final pagination cursor: %s", request.URL)
			}
			return jsonResponse(200, `[]`), nil
		}
		if request.URL.Query().Get("after") != cursorForPage(calls-1) {
			t.Fatalf("unexpected cursor on page %d: %s", calls, request.URL)
		}
		return jsonResponse(200, fmt.Sprintf(`[{"id":"page-%d","dns_names":["host-%d.example.com"]}]`, calls, calls)), nil
	})}
	hosts, err := QueryCertSpotter(context.Background(), "example.com", client)
	if len(hosts) != 7 || err != nil || calls != 8 {
		t.Fatalf("expected all seven pages, got hosts=%v err=%v calls=%d", hosts, err, calls)
	}
}

func cursorForPage(page int) string {
	if page == 0 {
		return ""
	}
	return fmt.Sprintf("page-%d", page)
}

func TestCertSpotterReturnsPartialOnDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls int
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if calls == 7 {
			cancel()
			return nil, request.Context().Err()
		}
		return jsonResponse(200, fmt.Sprintf(`[{"id":"page-%d","dns_names":["host-%d.example.com"]}]`, calls, calls)), nil
	})}
	hosts, err := QueryCertSpotter(ctx, "example.com", client)
	if len(hosts) != 6 || err == nil || !errors.Is(err, context.Canceled) || calls != 7 {
		t.Fatalf("expected six partial names and cancellation error, got hosts=%v err=%v calls=%d", hosts, err, calls)
	}
}

func TestCertSpotterNeverForwardsKeyOnRedirect(t *testing.T) {
	t.Setenv("CERTSPOTTER_API_KEY", "secret-key")
	var calls int
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.URL.Host != "api.certspotter.com" {
			t.Fatalf("redirected to unrelated host %q", request.URL.Host)
		}
		response := jsonResponse(302, "")
		response.Header.Set("Location", "https://other.example/elsewhere")
		return response, nil
	})}
	if _, err := QueryCertSpotter(context.Background(), "example.com", client); err == nil || calls != 1 {
		t.Fatalf("redirect must fail without second request: err=%v calls=%d", err, calls)
	}
}

func TestHackerTargetFiltersHostIPRows(t *testing.T) {
	t.Setenv("HACKERTARGET_API_KEY", "test-key")
	var calls int
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.URL.Host != "api.hackertarget.com" || request.URL.Query().Get("q") != "example.com" ||
			request.Header.Get("X-API-Key") != "test-key" {
			t.Fatalf("unexpected HackerTarget request: %s", request.URL)
		}
		return jsonResponse(200, "API.EXAMPLE.COM,192.0.2.1\nb.api.example.com,2001:db8::1\n"+
			"api.example.com,192.0.2.1\n*.example.com,192.0.2.1\n"+
			"api.example.com.attacker.test,192.0.2.1\nexample.com,192.0.2.1\n"), nil
	})}
	hosts, err := QueryHackerTarget(context.Background(), "Example.COM.", client)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"api.example.com", "b.api.example.com"}
	if strings.Join(hosts, ",") != strings.Join(want, ",") || calls != 1 {
		t.Fatalf("got hosts=%v calls=%d, want %v and 1", hosts, calls, want)
	}
}

func TestHackerTargetSurfacesTextErrorsAndTruncation(t *testing.T) {
	t.Setenv("HACKERTARGET_API_KEY", "")
	for _, response := range []string{"error check your api limits", "unstructured text", "api.example.com,not-an-ip"} {
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return jsonResponse(200, response), nil
		})}
		if _, err := QueryHackerTarget(context.Background(), "example.com", client); err == nil {
			t.Errorf("accepted invalid response %q", response)
		}
	}
	var rows []string
	for i := 0; i < 50; i++ {
		rows = append(rows, fmt.Sprintf("host-%d.example.com,192.0.2.1", i))
	}
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return jsonResponse(200, strings.Join(rows, "\n")), nil
	})}
	hosts, err := QueryHackerTarget(context.Background(), "example.com", client)
	if len(hosts) != 50 || err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("full free page needs partial+error, got hosts=%d err=%v", len(hosts), err)
	}
}

func TestHackerTargetNoRecordsAndHTTPError(t *testing.T) {
	for _, tc := range []struct {
		status  int
		body    string
		wantErr bool
	}{
		{200, "No records found", false},
		{429, "quota exceeded", true},
	} {
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return jsonResponse(tc.status, tc.body), nil
		})}
		hosts, err := QueryHackerTarget(context.Background(), "example.com", client)
		if len(hosts) != 0 || (err != nil) != tc.wantErr {
			t.Errorf("status=%d: hosts=%v err=%v", tc.status, hosts, err)
		}
	}
}

func TestSourcesRejectMalformedAndUnrelatedResponses(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		code int
	}{
		{"malformed JSON", "{", 200},
		{"server error", "upstream failed", 502},
		{"redirect", "", 302},
		{"oversized body", strings.Repeat("x", maxResponseBytes+1), 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				response := jsonResponse(tc.code, tc.body)
				if tc.code == 302 {
					response.Header.Set("Location", "https://other.example/elsewhere")
				}
				return response, nil
			})}
			if _, err := QueryCRTSh(context.Background(), "example.com", client); err == nil {
				t.Fatal("crt.sh failure must be visible")
			}
			if _, err := QueryCertSpotter(context.Background(), "example.com", client); err == nil {
				t.Fatal("Cert Spotter failure must be visible")
			}
		})
	}
}

func TestSourcesValidateRootBeforeRequest(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid root must not cause a request")
		return nil, errors.New("unreachable")
	})}
	for _, root := range []string{"example.com.attacker.test/", "*.example.com", "localhost", "192.0.2.1", "foo..example.com"} {
		if _, err := QueryCRTSh(context.Background(), root, client); err == nil {
			t.Errorf("crt.sh accepted invalid root %q", root)
		}
		if _, err := QueryCertSpotter(context.Background(), root, client); err == nil {
			t.Errorf("Cert Spotter accepted invalid root %q", root)
		}
	}
}
