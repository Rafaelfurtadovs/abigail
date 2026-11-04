package azure

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Rafaelfurtadovs/abigail/internal/validation"
)

const subscription = "00000000-0000-0000-0000-000000000000"

type fakeToken struct {
	calls int
	err   error
}

func (f *fakeToken) Token(context.Context) (string, error) {
	f.calls++
	if f.err != nil {
		return "", f.err
	}
	return "test-token", nil
}

func TestTargetParsingIsStrict(t *testing.T) {
	tests := []struct {
		input string
		name  string
	}{
		{"MyApp.azurewebsites.net.", "myapp"},
		{"myapp.scm.privatelink.azurewebsites.net", "myapp"},
		{"myprofile.trafficmanager.net", "myprofile"},
		{"azurewebsites.net", ""},
		{"myapp.azurewebsites.net.attacker.test", ""},
		{"nested.myprofile.trafficmanager.net", ""},
		{"foo.evil.azurewebsites.net", ""},
	}
	for _, tc := range tests {
		got := targets([]string{tc.input})
		if tc.name == "" && len(got) != 0 {
			t.Errorf("%q unexpectedly matched: %+v", tc.input, got)
		} else if tc.name != "" && (len(got) != 1 || got[0].name != tc.name) {
			t.Errorf("%q: got %+v, want name %q", tc.input, got, tc.name)
		}
	}
}

func TestUnsupportedAndMissingSubscriptionNeverAuthenticate(t *testing.T) {
	token := &fakeToken{}
	unsupported := Validate(context.Background(), []string{"example.com"}, Options{SubscriptionID: subscription, TokenProvider: token})
	if unsupported.State != validation.Unsupported {
		t.Fatalf("unsupported target: %+v", unsupported)
	}
	missing := Validate(context.Background(), []string{"app.azurewebsites.net"}, Options{TokenProvider: token})
	if missing.State != validation.Unknown || token.calls != 0 {
		t.Fatalf("missing subscription should be inconclusive without auth: %+v, calls %d", missing, token.calls)
	}
}

func TestAppServiceAvailabilityRequest(t *testing.T) {
	token := &fakeToken{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/subscriptions/"+subscription+"/providers/Microsoft.Web/checknameavailability" || r.URL.Query().Get("api-version") != "2025-03-01" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("missing token: %q", r.Header.Get("Authorization"))
		}
		var body struct {
			Name string `json:"name"`
			Type string `json:"type"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body.Name != "testapp" || body.Type != "Microsoft.Web/sites" {
			t.Errorf("unexpected body: %+v", body)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"nameAvailable":true}`))
	}))
	defer server.Close()
	result := Validate(context.Background(), []string{"testapp.azurewebsites.net", "testapp.privatelink.azurewebsites.net"}, Options{
		SubscriptionID: subscription, TokenProvider: token, HTTPClient: server.Client(), endpoint: server.URL,
	})
	if result.State != validation.Available || result.Target != "testapp.azurewebsites.net" || token.calls != 1 {
		t.Fatalf("expected available result with deduplicated target: %+v, token calls=%d", result, token.calls)
	}
}

func TestTrafficManagerUnavailableAndInvalid(t *testing.T) {
	for _, reason := range []string{"AlreadyExists", "Invalid"} {
		t.Run(reason, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/subscriptions/"+subscription+"/providers/Microsoft.Network/checkTrafficManagerNameAvailabilityV2" || r.URL.Query().Get("api-version") != "2022-04-01" {
					t.Errorf("wrong API path: %s", r.URL)
				}
				var body struct {
					Name string `json:"name"`
					Type string `json:"type"`
				}
				json.NewDecoder(r.Body).Decode(&body)
				if body.Name != "profile" || body.Type != "microsoft.network/trafficmanagerprofiles" {
					t.Errorf("wrong request body: %+v", body)
				}
				w.Write([]byte(`{"nameAvailable":false,"reason":"` + reason + `"}`))
			}))
			defer server.Close()
			result := Validate(context.Background(), []string{"profile.trafficmanager.net"}, Options{SubscriptionID: subscription, TokenProvider: &fakeToken{}, HTTPClient: server.Client(), endpoint: server.URL})
			if result.State != validation.Unavailable {
				t.Fatalf("expected unavailable: %+v", result)
			}
			if reason == "Invalid" && !strings.Contains(result.Reason, "invalid") {
				t.Fatalf("expected invalid reason: %+v", result)
			}
		})
	}
}

func TestAPIErrorAndMissingFieldRemainUnknown(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   string
	}{{"forbidden", http.StatusForbidden, `{}`}, {"missing field", http.StatusOK, `{}`}, {"invalid JSON", http.StatusOK, `{`}, {"wrong name", http.StatusOK, `{"nameAvailable":false,"name":"other"}`}} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				w.Write([]byte(test.body))
			}))
			defer server.Close()
			result := Validate(context.Background(), []string{"app.azurewebsites.net"}, Options{SubscriptionID: subscription, TokenProvider: &fakeToken{}, HTTPClient: server.Client(), endpoint: server.URL})
			if result.State != validation.Unknown {
				t.Fatalf("API error must be inconclusive: %+v", result)
			}
		})
	}
}

func TestMixedUnavailableAndAPIFailureIsUnknown(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "Microsoft.Web") {
			w.Write([]byte(`{"nameAvailable":false,"reason":"AlreadyExists"}`))
			return
		}
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()
	result := Validate(context.Background(), []string{"app.azurewebsites.net", "profile.trafficmanager.net"}, Options{
		SubscriptionID: subscription, TokenProvider: &fakeToken{}, HTTPClient: server.Client(), endpoint: server.URL,
	})
	if result.State != validation.Unknown {
		t.Fatalf("second uncertain target must not be suppressed: %+v", result)
	}
}
