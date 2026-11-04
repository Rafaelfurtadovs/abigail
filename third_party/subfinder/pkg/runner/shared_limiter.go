package runner

import (
	"context"
	"errors"
	"sync"
)

// StartSharedRateLimiter keeps provider request budgets across sequential
// domain enumerations. The upstream CLI creates one for a domain batch, but
// Abigail drives the single-domain SDK method for each input root.
func (r *Runner) StartSharedRateLimiter(ctx context.Context) (func() error, error) {
	if r.sharedRateLimiter != nil {
		return nil, errors.New("shared provider rate limiter is already started")
	}
	if ctx == nil {
		return nil, errors.New("shared provider rate limiter needs a context")
	}
	limiter, err := r.passiveAgent.NewRateLimiter(ctx, r.options.RateLimit, r.rateLimit)
	if err != nil {
		return nil, err
	}
	r.sharedRateLimiter = limiter
	var once sync.Once
	var closeErr error
	return func() error {
		once.Do(func() {
			r.sharedRateLimiter = nil
			closeErr = limiter.Close()
		})
		return closeErr
	}, nil
}
