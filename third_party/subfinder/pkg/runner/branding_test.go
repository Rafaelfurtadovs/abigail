package runner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfigPathsBelongToAbigail(t *testing.T) {
	if filepath.Base(configDir) != "abigail" {
		t.Fatalf("unexpected application config directory %q", configDir)
	}
	if path := os.Getenv("ABIGAIL_PROVIDER_CONFIG"); path != "" {
		if defaultProviderConfigLocation != path {
			t.Fatalf("provider config path = %q, want override %q", defaultProviderConfigLocation, path)
		}
	} else if want := filepath.Join(configDir, "provider-config.yaml"); defaultProviderConfigLocation != want {
		t.Fatalf("provider config path = %q, want %q", defaultProviderConfigLocation, want)
	}
	if path := os.Getenv("ABIGAIL_CONFIG"); path != "" {
		if defaultConfigLocation != path {
			t.Fatalf("config path = %q, want override %q", defaultConfigLocation, path)
		}
	} else if want := filepath.Join(configDir, "config.yaml"); defaultConfigLocation != want {
		t.Fatalf("config path = %q, want %q", defaultConfigLocation, want)
	}
}
