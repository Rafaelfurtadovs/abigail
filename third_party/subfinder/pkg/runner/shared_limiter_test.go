package runner

import (
	"context"
	"testing"

	"github.com/Rafaelfurtadovs/abigail/third_party/subfinder/pkg/passive"
)

func TestSharedRateLimiterSurvivesSequentialQueries(t *testing.T) {
	r := &Runner{
		options:      &Options{},
		passiveAgent: passive.NewWithProviderConfig([]string{"crtname"}, nil, false, false, nil),
	}
	stop, err := r.StartSharedRateLimiter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	first := r.sharedRateLimiter
	if first == nil {
		t.Fatal("shared limiter was not installed")
	}
	if _, err := r.StartSharedRateLimiter(context.Background()); err == nil {
		t.Fatal("second initialization should fail")
	}
	if err := r.sharedRateLimiter.Wait(context.Background(), "crtname"); err != nil {
		t.Fatalf("first query budget: %v", err)
	}
	if err := r.sharedRateLimiter.Wait(context.Background(), "crtname"); err != nil {
		t.Fatalf("second query budget: %v", err)
	}
	if r.sharedRateLimiter != first {
		t.Fatal("provider limiter changed between queries")
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if r.sharedRateLimiter != nil {
		t.Fatal("provider limiter was not removed after close")
	}
	if err := stop(); err != nil {
		t.Fatal("repeated close should be harmless:", err)
	}
}
