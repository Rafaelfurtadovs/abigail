// Package cognito performs an opt-in, read-only existence check for Amazon
// Cognito user-pool prefix domains. Absence is inconclusive, not proof that a
// domain can be claimed.
package cognito

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/Rafaelfurtadovs/abigail/internal/validation"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
)

const provider = "Amazon Cognito"

// Amazon Cognito's documented prefix-domain shape is
// <prefix>.auth.<region>.amazoncognito.com. The auth-fips parent is also
// documented. A broad *.amazoncognito.com match would misidentify unrelated
// names as claimable user-pool prefixes.
var prefixDomain = regexp.MustCompile(`^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\.auth(?:-fips)?\.([a-z]{2}(?:-[a-z0-9]+)+-[0-9]+)\.amazoncognito\.com$`)

// API is the read-only part of the Cognito SDK needed by this validator.
type API interface {
	DescribeUserPoolDomain(context.Context, *cognitoidentityprovider.DescribeUserPoolDomainInput, ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.DescribeUserPoolDomainOutput, error)
}

type ClientFactory func(context.Context, string) (API, error)

type Options struct {
	// Factory is for tests or a supplied Cognito client. Nil uses the AWS
	// SDK default credential chain only when Validate checks a supported name.
	Factory ClientFactory
}

type target struct {
	name   string
	prefix string
	region string
}

// Validate confirms when a Cognito prefix domain is already assigned. It
// never creates a user pool or domain. ResourceNotFound and all API failures
// remain Unknown because this API does not certify name availability.
func Validate(ctx context.Context, cnames []string, opts Options) validation.Result {
	targets, unsupported := parseTargets(cnames)
	if len(targets) == 0 {
		return validation.Result{Provider: provider, State: validation.Unsupported, Reason: "no supported Cognito prefix-domain target"}
	}
	if ctx == nil {
		return validation.Result{Provider: provider, State: validation.Unknown, Reason: "validation context is required"}
	}
	factory := opts.Factory
	if factory == nil {
		factory = defaultClient
	}
	clients := make(map[string]API)
	var checked []string
	var uncertain []string
	if unsupported {
		uncertain = append(uncertain, "another Cognito CNAME has an unsupported shape")
	}
	for _, candidate := range targets {
		client := clients[candidate.region]
		if client == nil {
			var err error
			client, err = factory(ctx, candidate.region)
			if err != nil {
				uncertain = append(uncertain, fmt.Sprintf("%s: load AWS client: %v", candidate.name, err))
				continue
			}
			if client == nil {
				uncertain = append(uncertain, candidate.name+": AWS client factory returned no client")
				continue
			}
			clients[candidate.region] = client
		}
		response, err := client.DescribeUserPoolDomain(ctx, &cognitoidentityprovider.DescribeUserPoolDomainInput{
			Domain: aws.String(candidate.prefix),
		})
		if err != nil {
			var missing *types.ResourceNotFoundException
			if errors.As(err, &missing) {
				uncertain = append(uncertain, candidate.name+": AWS reports no existing domain; claimability is unverified")
			} else {
				uncertain = append(uncertain, fmt.Sprintf("%s: Cognito describe failed: %v", candidate.name, err))
			}
			continue
		}
		if response == nil || response.DomainDescription == nil || response.DomainDescription.Domain == nil {
			uncertain = append(uncertain, candidate.name+": incomplete Cognito domain response")
			continue
		}
		if normalize(*response.DomainDescription.Domain) != candidate.prefix {
			uncertain = append(uncertain, candidate.name+": Cognito response refers to a different prefix")
			continue
		}
		checked = append(checked, candidate.name)
	}
	if len(uncertain) > 0 {
		return validation.Result{Provider: provider, State: validation.Unknown, Reason: strings.Join(uncertain, "; ")}
	}
	if len(checked) > 0 {
		return validation.Result{
			Provider: provider,
			State:    validation.Unavailable,
			Target:   checked[0],
			Reason:   "AWS DescribeUserPoolDomain confirms the exact prefix is already assigned",
		}
	}
	return validation.Result{Provider: provider, State: validation.Unknown, Reason: "no Cognito domain was checked"}
}

func parseTargets(cnames []string) ([]target, bool) {
	seen := make(map[string]bool)
	var targets []target
	var unsupported bool
	for _, raw := range cnames {
		name := normalize(raw)
		if !strings.HasSuffix(name, ".amazoncognito.com") {
			continue
		}
		match := prefixDomain.FindStringSubmatch(name)
		if match == nil {
			unsupported = true
			continue
		}
		if !seen[name] {
			seen[name] = true
			targets = append(targets, target{name: name, prefix: match[1], region: match[2]})
		}
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].name < targets[j].name })
	return targets, unsupported
}

func normalize(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}

func defaultClient(ctx context.Context, region string) (API, error) {
	config, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, err
	}
	return cognitoidentityprovider.NewFromConfig(config), nil
}
