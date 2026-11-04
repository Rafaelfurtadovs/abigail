// Package azure checks Azure resource-name availability without creating a
// resource. It only runs when the caller explicitly requests validation.
package azure

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Rafaelfurtadovs/abigail/internal/validation"
)

const (
	provider = "Microsoft Azure"
	armScope = "https://management.azure.com/.default"
	armURL   = "https://management.azure.com"
)

// TokenProvider allows callers and tests to supply a token without starting
// an interactive authentication flow. A nil provider uses Azure's default
// noninteractive credential chain only after a supported target is found.
type TokenProvider interface {
	Token(context.Context) (string, error)
}

type Options struct {
	SubscriptionID string
	TokenProvider  TokenProvider
	HTTPClient     *http.Client

	// endpoint is intentionally private: production validation always uses ARM.
	endpoint string
}

type resource struct {
	target string
	name   string
	path   string
	typeID string
}

var credentialCache struct {
	once sync.Once
	cred *azidentity.DefaultAzureCredential
	err  error
}

type defaultTokenProvider struct{}

func (defaultTokenProvider) Token(ctx context.Context) (string, error) {
	credentialCache.once.Do(func() {
		credentialCache.cred, credentialCache.err = azidentity.NewDefaultAzureCredential(nil)
	})
	if credentialCache.err != nil {
		return "", credentialCache.err
	}
	token, err := credentialCache.cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{armScope}})
	if err != nil {
		return "", err
	}
	return token.Token, nil
}

// Validate checks App Service and Traffic Manager names in the supplied CNAME
// chain. It never issues a resource creation request. For multiple distinct
// targets, an available name wins; ambiguous mixed results stay unknown.
func Validate(ctx context.Context, cnames []string, opts Options) validation.Result {
	resources := targets(cnames)
	if len(resources) == 0 {
		return validation.Result{Provider: provider, State: validation.Unsupported, Reason: "no supported Azure CNAME target"}
	}
	if !validSubscriptionID(opts.SubscriptionID) {
		return validation.Result{Provider: provider, State: validation.Unknown, Reason: "a valid Azure subscription ID is required"}
	}
	if ctx == nil {
		return validation.Result{Provider: provider, State: validation.Unknown, Reason: "validation context is required"}
	}
	providerToken := opts.TokenProvider
	if providerToken == nil {
		providerToken = defaultTokenProvider{}
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	endpoint := opts.endpoint
	if endpoint == "" {
		endpoint = armURL
	}
	// A failed token request is inconclusive; no Azure API call is attempted.
	token, err := providerToken.Token(ctx)
	if err != nil || token == "" {
		return validation.Result{Provider: provider, State: validation.Unknown, Reason: "Azure authentication unavailable"}
	}
	var unavailable *validation.Result
	var unknown *validation.Result
	for _, resource := range resources {
		result := check(ctx, client, endpoint, opts.SubscriptionID, token, resource)
		switch result.State {
		case validation.Available:
			return result
		case validation.Unavailable:
			unavailable = &result
		default:
			unknown = &result
		}
	}
	if unknown != nil {
		return *unknown
	}
	if unavailable != nil {
		return *unavailable
	}
	return validation.Result{Provider: provider, State: validation.Unknown, Reason: "no Azure name was checked"}
}

func targets(cnames []string) []resource {
	seen := map[string]bool{}
	var output []resource
	for _, raw := range cnames {
		target := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
		var r resource
		switch {
		case strings.HasSuffix(target, ".azurewebsites.net"):
			prefix := strings.TrimSuffix(target, ".azurewebsites.net")
			parts := strings.Split(prefix, ".")
			if len(parts) < 1 || len(parts) > 3 || !validLabel(parts[0]) {
				continue
			}
			if (len(parts) == 2 && parts[1] != "scm" && parts[1] != "privatelink") ||
				(len(parts) == 3 && (parts[1] != "scm" || parts[2] != "privatelink")) {
				continue
			}
			r = resource{target: target, name: parts[0], path: "/providers/Microsoft.Web/checknameavailability?api-version=2025-03-01", typeID: "Microsoft.Web/sites"}
		case strings.HasSuffix(target, ".trafficmanager.net"):
			prefix := strings.TrimSuffix(target, ".trafficmanager.net")
			if !validLabel(prefix) {
				continue
			}
			r = resource{target: target, name: prefix, path: "/providers/Microsoft.Network/checkTrafficManagerNameAvailabilityV2?api-version=2022-04-01", typeID: "microsoft.network/trafficmanagerprofiles"}
		default:
			continue
		}
		key := r.typeID + ":" + r.name
		if !seen[key] {
			seen[key] = true
			output = append(output, r)
		}
	}
	return output
}

func validLabel(label string) bool {
	if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, ch := range label {
		if !((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-') {
			return false
		}
	}
	return true
}

func validSubscriptionID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for i, ch := range id {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if ch != '-' {
				return false
			}
			continue
		}
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
			return false
		}
	}
	return true
}

func check(ctx context.Context, client *http.Client, endpoint, subscriptionID, token string, r resource) validation.Result {
	result := validation.Result{Provider: provider, State: validation.Unknown, Target: r.target}
	body, err := json.Marshal(struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}{Name: r.name, Type: r.typeID})
	if err != nil {
		result.Reason = "failed to encode Azure request"
		return result
	}
	address := strings.TrimRight(endpoint, "/") + "/subscriptions/" + url.PathEscape(subscriptionID) + r.path
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, address, bytes.NewReader(body))
	if err != nil {
		result.Reason = "failed to construct Azure request"
		return result
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		result.Reason = "Azure availability request failed: " + err.Error()
		return result
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		result.Reason = fmt.Sprintf("Azure availability API returned HTTP %d", response.StatusCode)
		return result
	}
	limited := io.LimitReader(response.Body, 16*1024+1)
	data, err := io.ReadAll(limited)
	if err != nil || len(data) > 16*1024 {
		result.Reason = "Azure availability response was incomplete or oversized"
		return result
	}
	var payload struct {
		NameAvailable *bool  `json:"nameAvailable"`
		Name          string `json:"name"`
		Reason        string `json:"reason"`
	}
	if err := json.Unmarshal(data, &payload); err != nil || payload.NameAvailable == nil {
		result.Reason = "Azure availability response lacked a valid nameAvailable field"
		return result
	}
	if payload.Name != "" && !strings.EqualFold(payload.Name, r.name) {
		result.Reason = "Azure availability response referred to a different resource name"
		return result
	}
	if *payload.NameAvailable {
		result.State = validation.Available
		result.Reason = "Azure reports the resource name is available"
	} else {
		result.State = validation.Unavailable
		if strings.EqualFold(payload.Reason, "Invalid") {
			result.Reason = "Azure reports the resource name is invalid"
		} else {
			result.Reason = "Azure reports the resource name is unavailable"
		}
	}
	return result
}

// Compile-time assertion that the default token provider has the mockable API.
var _ TokenProvider = defaultTokenProvider{}
