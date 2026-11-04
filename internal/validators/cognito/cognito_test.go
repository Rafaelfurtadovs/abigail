package cognito

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Rafaelfurtadovs/abigail/internal/validation"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
)

type fakeClient struct {
	response *cognitoidentityprovider.DescribeUserPoolDomainOutput
	err      error
	prefix   string
	calls    int
}

func (f *fakeClient) DescribeUserPoolDomain(_ context.Context, input *cognitoidentityprovider.DescribeUserPoolDomainInput, _ ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.DescribeUserPoolDomainOutput, error) {
	f.calls++
	f.prefix = aws.ToString(input.Domain)
	return f.response, f.err
}

func TestParseTargetsAcceptsOnlyDocumentedPrefixDomains(t *testing.T) {
	for _, tc := range []struct {
		name       string
		wantPrefix string
		wantRegion string
	}{
		{"My-App.auth.us-east-1.amazoncognito.com.", "my-app", "us-east-1"},
		{"a.auth-fips.us-gov-west-1.amazoncognito.com", "a", "us-gov-west-1"},
		{"foo.amazoncognito.com", "", ""},
		{"foo.auth.amazoncognito.com", "", ""},
		{"foo.auth.us-east-1.amazoncognito.com.attacker.test", "", ""},
		{"nested.foo.auth.us-east-1.amazoncognito.com", "", ""},
		{"-foo.auth.us-east-1.amazoncognito.com", "", ""},
		{strings.Repeat("x", 64) + ".auth.us-east-1.amazoncognito.com", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			targets, _ := parseTargets([]string{tc.name})
			if tc.wantPrefix == "" {
				if len(targets) != 0 {
					t.Fatalf("unexpected target %+v", targets)
				}
				return
			}
			if len(targets) != 1 || targets[0].prefix != tc.wantPrefix || targets[0].region != tc.wantRegion {
				t.Fatalf("unexpected targets %+v", targets)
			}
		})
	}
}

func TestUnsupportedTargetDoesNotLoadCredentials(t *testing.T) {
	called := false
	got := Validate(context.Background(), []string{"foo.amazoncognito.com"}, Options{Factory: func(context.Context, string) (API, error) {
		called = true
		return nil, errors.New("must not run")
	}})
	if got.State != validation.Unsupported || called {
		t.Fatalf("unsupported target should not trigger AWS: %+v, called=%t", got, called)
	}
}

func TestExactExistingPrefixIsUnavailable(t *testing.T) {
	client := &fakeClient{response: &cognitoidentityprovider.DescribeUserPoolDomainOutput{
		DomainDescription: &types.DomainDescriptionType{Domain: aws.String("my-app")},
	}}
	got := Validate(context.Background(), []string{"My-App.auth.eu-west-1.amazoncognito.com."}, Options{
		Factory: func(_ context.Context, region string) (API, error) {
			if region != "eu-west-1" {
				t.Fatalf("wrong region %q", region)
			}
			return client, nil
		},
	})
	if got.State != validation.Unavailable || got.Target != "my-app.auth.eu-west-1.amazoncognito.com" || client.calls != 1 || client.prefix != "my-app" {
		t.Fatalf("expected exact existing prefix: %+v, client=%+v", got, client)
	}
}

func TestMissingOrInconclusiveNeverReportsAvailableOrUnavailable(t *testing.T) {
	for _, tc := range []struct {
		name     string
		response *cognitoidentityprovider.DescribeUserPoolDomainOutput
		err      error
	}{
		{"not found", nil, &types.ResourceNotFoundException{Message: aws.String("not found")}},
		{"access denied", nil, errors.New("access denied")},
		{"empty response", nil, nil},
		{"missing description", &cognitoidentityprovider.DescribeUserPoolDomainOutput{}, nil},
		{"different prefix", &cognitoidentityprovider.DescribeUserPoolDomainOutput{DomainDescription: &types.DomainDescriptionType{Domain: aws.String("other")}}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &fakeClient{response: tc.response, err: tc.err}
			got := Validate(context.Background(), []string{"my-app.auth.eu-west-1.amazoncognito.com"}, Options{
				Factory: func(context.Context, string) (API, error) { return client, nil },
			})
			if got.State != validation.Unknown || client.calls != 1 {
				t.Fatalf("inconclusive API result must remain unknown: %+v, client=%+v", got, client)
			}
		})
	}
}

func TestMixedSupportedAndUnsupportedNeverDismisses(t *testing.T) {
	client := &fakeClient{response: &cognitoidentityprovider.DescribeUserPoolDomainOutput{
		DomainDescription: &types.DomainDescriptionType{Domain: aws.String("my-app")},
	}}
	got := Validate(context.Background(), []string{"my-app.auth.eu-west-1.amazoncognito.com", "foo.amazoncognito.com"}, Options{
		Factory: func(context.Context, string) (API, error) { return client, nil },
	})
	if got.State != validation.Unknown || client.calls != 1 {
		t.Fatalf("mixed targets must stay inconclusive: %+v, client=%+v", got, client)
	}
}
