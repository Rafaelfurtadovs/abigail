// Package validators routes opt-in availability checks to provider APIs.
package validators

import (
	"context"

	"github.com/Rafaelfurtadovs/abigail/internal/validation"
	"github.com/Rafaelfurtadovs/abigail/internal/validators/azure"
	"github.com/Rafaelfurtadovs/abigail/internal/validators/beanstalk"
	"github.com/Rafaelfurtadovs/abigail/internal/validators/cognito"
)

type Router struct {
	AzureSubscriptionID string
}

func (r Router) Validate(ctx context.Context, ruleID string, cnames []string) validation.Result {
	switch ruleID {
	case "microsoft-azure":
		return azure.Validate(ctx, cnames, azure.Options{SubscriptionID: r.AzureSubscriptionID})
	case "aws-elastic-beanstalk":
		return beanstalk.Validate(ctx, cnames, beanstalk.Options{})
	case "amazon-cognito":
		return cognito.Validate(ctx, cnames, cognito.Options{})
	default:
		return validation.Result{Provider: ruleID, State: validation.Unsupported, Reason: "no direct provider API validator is available"}
	}
}
