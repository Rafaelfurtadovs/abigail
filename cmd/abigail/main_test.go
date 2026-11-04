package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeDomain(t *testing.T) {
	name, err := normalizeDomain(" Sub.Example.COM. ")
	if err != nil || name != "sub.example.com" {
		t.Fatalf("normalization failed: %q, %v", name, err)
	}
	for _, input := range []string{"https://example.com", "example.com/path", "127.0.0.1", "-bad.example.com", "example.com.attacker.test:443"} {
		if _, err := normalizeDomain(input); err == nil {
			t.Errorf("expected %q to be rejected", input)
		}
	}
}

func TestInvalidInputDoesNotStartScan(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"scan", "-d", "https://example.com"}, &stdout, &stderr); code != 2 {
		t.Fatalf("invalid hostname exit code = %d", code)
	}
	if !strings.Contains(stderr.String(), "invalid hostname") {
		t.Fatalf("missing useful error: %q", stderr.String())
	}
}

func TestOutputFileIsReplacedOnlyOnCommit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "results.jsonl")
	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, commit := range []bool{false, true} {
		writer, finish, err := openOutput(path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte("new")); err != nil {
			t.Fatal(err)
		}
		if err := finish(commit); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		want := "old"
		if commit {
			want = "new"
		}
		if string(data) != want {
			t.Fatalf("commit=%v: got %q, want %q", commit, data, want)
		}
	}
}
