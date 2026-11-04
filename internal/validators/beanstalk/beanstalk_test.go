package beanstalk

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Rafaelfurtadovs/abigail/internal/validation"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk"
)

type fakeClient struct {
	response *elasticbeanstalk.CheckDNSAvailabilityOutput
	err      error
	prefix   string
	called   int
}

func (f *fakeClient) CheckDNSAvailability(_ context.Context, input *elasticbeanstalk.CheckDNSAvailabilityInput, _ ...func(*elasticbeanstalk.Options)) (*elasticbeanstalk.CheckDNSAvailabilityOutput, error) {
	f.called++
	f.prefix = aws.ToString(input.CNAMEPrefix)
	return f.response, f.err
}

func TestRegionalAvailabilityRequiresExactReturnedCNAME(t *testing.T) {
	for _, tc := range []struct {
		name      string
		available bool
		returned  string
		want      validation.State
	}{
		{"available", true, "myapp.us-east-1.elasticbeanstalk.com", validation.Available},
		{"unavailable", false, "myapp.us-east-1.elasticbeanstalk.com", validation.Unavailable},
		{"different target", true, "other.us-east-1.elasticbeanstalk.com", validation.Unknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &fakeClient{response: &elasticbeanstalk.CheckDNSAvailabilityOutput{
				Available: aws.Bool(tc.available), FullyQualifiedCNAME: aws.String(tc.returned),
			}}
			got := Validate(context.Background(), []string{"MYAPP.US-EAST-1.ELASTICBEANSTALK.COM."}, Options{
				Factory: func(_ context.Context, region string) (API, error) {
					if region != "us-east-1" {
						t.Fatalf("unexpected region %q", region)
					}
					return client, nil
				},
			})
			if got.State != tc.want || client.called != 1 || client.prefix != "myapp" {
				t.Fatalf("got %+v, calls=%d prefix=%q", got, client.called, client.prefix)
			}
		})
	}
}

func TestUnsupportedAliasesNeverCallAWS(t *testing.T) {
	for _, name := range []string{
		"myapp.elasticbeanstalk.com",                      // legacy format; no region
		"myapp.bx7dx222kw.us-east-2.elasticbeanstalk.com", // generated alias
		"myapp.us-east-1.elasticbeanstalk.com.evil.test",
		"a.us-east-1.elasticbeanstalk.com", // prefix too short
	} {
		called := false
		got := Validate(context.Background(), []string{name}, Options{Factory: func(context.Context, string) (API, error) {
			called = true
			return nil, errors.New("should not be called")
		}})
		if got.State != validation.Unsupported || called {
			t.Errorf("%s: got %+v, called=%t", name, got, called)
		}
	}
}

func TestAPIFailureIsUnknown(t *testing.T) {
	client := &fakeClient{err: errors.New("access denied")}
	got := Validate(context.Background(), []string{"myapp.eu-west-1.elasticbeanstalk.com"}, Options{
		Factory: func(context.Context, string) (API, error) { return client, nil },
	})
	if got.State != validation.Unknown || !strings.Contains(got.Reason, "access denied") {
		t.Fatalf("got %+v", got)
	}
}

func TestIncompleteAPIResponseIsUnknown(t *testing.T) {
	client := &fakeClient{response: &elasticbeanstalk.CheckDNSAvailabilityOutput{Available: aws.Bool(true)}}
	got := Validate(context.Background(), []string{"myapp.eu-west-1.elasticbeanstalk.com"}, Options{
		Factory: func(context.Context, string) (API, error) { return client, nil },
	})
	if got.State != validation.Unknown {
		t.Fatalf("got %+v", got)
	}
}

func TestUncertainTargetPreventsFalseUnavailableConclusion(t *testing.T) {
	client := &fakeClient{response: &elasticbeanstalk.CheckDNSAvailabilityOutput{
		Available: aws.Bool(false), FullyQualifiedCNAME: aws.String("myapp.eu-west-1.elasticbeanstalk.com"),
	}}
	got := Validate(context.Background(), []string{
		"myapp.eu-west-1.elasticbeanstalk.com",
		"other.eu-west-1.elasticbeanstalk.com",
	}, Options{Factory: func(context.Context, string) (API, error) { return client, nil }})
	if got.State != validation.Unknown { // The fake returns myapp for other, so its identity is unknown.
		t.Fatalf("got %+v", got)
	}
}
