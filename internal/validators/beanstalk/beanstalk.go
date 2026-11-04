// Package beanstalk validates whether an Elastic Beanstalk regional CNAME is
// available according to AWS's read-only CheckDNSAvailability API.
package beanstalk

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/Rafaelfurtadovs/abigail/internal/validation"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk"
)

const provider = "AWS/Elastic Beanstalk"
const suffix = ".elasticbeanstalk.com"

var regionPattern = regexp.MustCompile(`^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$`)
var prefixPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)

// API is the small read-only part of the AWS SDK needed for validation.
type API interface {
	CheckDNSAvailability(context.Context, *elasticbeanstalk.CheckDNSAvailabilityInput, ...func(*elasticbeanstalk.Options)) (*elasticbeanstalk.CheckDNSAvailabilityOutput, error)
}

type ClientFactory func(context.Context, string) (API, error)

type Options struct {
	// Factory is for tests or a caller-supplied, credentialed AWS client.
	// Nil uses the AWS SDK default credential chain only when Validate is called.
	Factory ClientFactory
}

type target struct {
	name   string
	region string
	prefix string
}

// Validate checks each regional Elastic Beanstalk target and verifies that
// AWS's FullyQualifiedCNAME equals the exact DNS target before trusting its
// Available value. It never creates an environment or claims a name.
func Validate(ctx context.Context, cnames []string, opts Options) validation.Result {
	result := validation.Result{Provider: provider, State: validation.Unsupported}
	targets, unsupported := parseTargets(cnames)
	if len(targets) == 0 {
		if unsupported != "" {
			result.Reason = unsupported
		} else {
			result.Reason = "no regional Elastic Beanstalk CNAME target"
		}
		return result
	}

	factory := opts.Factory
	if factory == nil {
		factory = defaultClient
	}
	clients := make(map[string]API)
	var unavailable []string
	var unknown []string
	if unsupported != "" {
		unknown = append(unknown, unsupported)
	}
	for _, candidate := range targets {
		client := clients[candidate.region]
		if client == nil {
			var err error
			client, err = factory(ctx, candidate.region)
			if err != nil {
				unknown = append(unknown, fmt.Sprintf("%s: load AWS client: %v", candidate.name, err))
				continue
			}
			if client == nil {
				unknown = append(unknown, candidate.name+": AWS client factory returned no client")
				continue
			}
			clients[candidate.region] = client
		}
		response, err := client.CheckDNSAvailability(ctx, &elasticbeanstalk.CheckDNSAvailabilityInput{
			CNAMEPrefix: aws.String(candidate.prefix),
		})
		if err != nil {
			unknown = append(unknown, fmt.Sprintf("%s: AWS availability check failed: %v", candidate.name, err))
			continue
		}
		if response == nil || response.Available == nil || response.FullyQualifiedCNAME == nil {
			unknown = append(unknown, candidate.name+": incomplete AWS availability response")
			continue
		}
		returned := normalize(*response.FullyQualifiedCNAME)
		if returned != candidate.name {
			unknown = append(unknown, fmt.Sprintf("%s: AWS response refers to %s", candidate.name, returned))
			continue
		}
		if *response.Available {
			return validation.Result{
				Provider: provider,
				State:    validation.Available,
				Target:   candidate.name,
				Reason:   "AWS CheckDNSAvailability reports the exact CNAME is available",
			}
		}
		unavailable = append(unavailable, candidate.name)
	}
	if len(unknown) > 0 {
		return validation.Result{Provider: provider, State: validation.Unknown, Reason: strings.Join(unknown, "; ")}
	}
	if len(unavailable) > 0 {
		return validation.Result{
			Provider: provider,
			State:    validation.Unavailable,
			Target:   unavailable[0],
			Reason:   "AWS CheckDNSAvailability reports the exact CNAME is unavailable",
		}
	}
	return result
}

func parseTargets(cnames []string) ([]target, string) {
	seen := map[string]bool{}
	var targets []target
	var unsupported string
	for _, raw := range cnames {
		name := normalize(raw)
		if !strings.HasSuffix(name, suffix) {
			continue
		}
		prefix := strings.TrimSuffix(name, suffix)
		parts := strings.Split(prefix, ".")
		if len(parts) != 2 {
			unsupported = "legacy or generated Elastic Beanstalk aliases cannot be verified by CheckDNSAvailability"
			continue
		}
		region := parts[1]
		if !regionPattern.MatchString(region) || len(parts[0]) < 4 || len(parts[0]) > 63 || !prefixPattern.MatchString(parts[0]) {
			unsupported = "Elastic Beanstalk CNAME has an unsupported region or prefix"
			continue
		}
		if !seen[name] {
			seen[name] = true
			targets = append(targets, target{name: name, region: region, prefix: parts[0]})
		}
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].name < targets[j].name })
	return targets, unsupported
}

func normalize(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

func defaultClient(ctx context.Context, region string) (API, error) {
	config, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, err
	}
	return elasticbeanstalk.NewFromConfig(config), nil
}
