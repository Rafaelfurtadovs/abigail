package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Rafaelfurtadovs/abigail/internal/dnsprobe"
	"github.com/Rafaelfurtadovs/abigail/internal/httpprobe"
	"github.com/Rafaelfurtadovs/abigail/internal/ruleengine"
	"github.com/Rafaelfurtadovs/abigail/internal/scanner"
	"github.com/Rafaelfurtadovs/abigail/rules"
)

const version = "0.1.0"

type config struct {
	domain           string
	list             string
	output           string
	format           string
	rulesPath        string
	resolver         string
	concurrency      int
	rate             int
	timeout          time.Duration
	includeEdgeCases bool
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "--version" || args[0] == "version") {
		fmt.Fprintln(stdout, "abigail", version)
		return 0
	}
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		usage(stdout)
		return 0
	}
	if args[0] != "scan" {
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		usage(stderr)
		return 2
	}
	return scanCommand(args[1:], stdout, stderr)
}

func usage(w io.Writer) {
	fmt.Fprintln(w, `Abigail: evidence-based subdomain takeover detection

Usage:
  abigail scan -d sub.example.com [options]
  abigail scan -l domains.txt [options]
  abigail version

Use "abigail scan -h" for scan options.`)
}

func scanCommand(args []string, stdout, stderr io.Writer) int {
	cfg := config{}
	flags := flag.NewFlagSet("scan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&cfg.domain, "d", "", "one hostname to scan")
	flags.StringVar(&cfg.domain, "domain", "", "one hostname to scan")
	flags.StringVar(&cfg.list, "l", "", "file with one hostname per line; - reads stdin")
	flags.StringVar(&cfg.list, "list", "", "file with one hostname per line; - reads stdin")
	flags.StringVar(&cfg.output, "o", "", "write output to a file atomically")
	flags.StringVar(&cfg.output, "output", "", "write output to a file atomically")
	flags.StringVar(&cfg.format, "format", "text", "output format: text or jsonl")
	flags.StringVar(&cfg.rulesPath, "rules", "", "custom JSON rules file; default is embedded rules")
	flags.StringVar(&cfg.resolver, "resolver", "", "DNS resolver IP[:port] for full CNAME-chain checks")
	flags.IntVar(&cfg.concurrency, "concurrency", 20, "maximum domains checked in parallel (1-256)")
	flags.IntVar(&cfg.rate, "rate", 20, "maximum domains started per second; 0 disables pacing")
	flags.DurationVar(&cfg.timeout, "timeout", 5*time.Second, "timeout for individual DNS/HTTP requests")
	flags.BoolVar(&cfg.includeEdgeCases, "include-edge-cases", false, "include lower-confidence provider rules")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: abigail scan (-d hostname | -l file) [options]")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 || (cfg.domain == "") == (cfg.list == "") {
		fmt.Fprintln(stderr, "specify exactly one of -d or -l and no positional arguments")
		return 2
	}
	if cfg.format != "text" && cfg.format != "jsonl" {
		fmt.Fprintln(stderr, "--format must be text or jsonl")
		return 2
	}
	if cfg.concurrency < 1 || cfg.concurrency > 256 || cfg.rate < 0 || cfg.rate > 10000 || cfg.timeout <= 0 {
		fmt.Fprintln(stderr, "invalid concurrency, rate or timeout")
		return 2
	}

	var data []byte
	var err error
	if cfg.rulesPath == "" {
		data = rules.Default
	} else {
		data, err = os.ReadFile(cfg.rulesPath)
		if err != nil {
			fmt.Fprintf(stderr, "read rules: %v\n", err)
			return 2
		}
	}
	pack, err := ruleengine.Parse(data)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	domains, err := readDomains(cfg)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	output, finish, err := openOutput(cfg.output, stdout)
	if err != nil {
		fmt.Fprintf(stderr, "open output: %v\n", err)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	code, writeErr := execute(ctx, cfg, domains, pack, output, stderr)
	if err := finish(writeErr == nil && ctx.Err() == nil); err != nil && writeErr == nil {
		writeErr = err
	}
	if writeErr != nil {
		fmt.Fprintf(stderr, "write output: %v\n", writeErr)
		return 2
	}
	if ctx.Err() != nil {
		fmt.Fprintln(stderr, "scan interrupted")
		return 2
	}
	return code
}

func readDomains(cfg config) ([]string, error) {
	if cfg.domain != "" {
		name, err := normalizeDomain(cfg.domain)
		if err != nil {
			return nil, err
		}
		return []string{name}, nil
	}
	var reader io.Reader
	if cfg.list == "-" {
		reader = os.Stdin
	} else {
		file, err := os.Open(cfg.list)
		if err != nil {
			return nil, fmt.Errorf("open list: %w", err)
		}
		defer file.Close()
		reader = file
	}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	seen := map[string]bool{}
	var domains []string
	for line := 1; scanner.Scan(); line++ {
		value := strings.TrimSpace(scanner.Text())
		if value == "" || strings.HasPrefix(value, "#") {
			continue
		}
		name, err := normalizeDomain(value)
		if err != nil {
			return nil, fmt.Errorf("list line %d: %w", line, err)
		}
		if !seen[name] {
			seen[name] = true
			domains = append(domains, name)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read list: %w", err)
	}
	if len(domains) == 0 {
		return nil, errors.New("no hostnames to scan")
	}
	return domains, nil
}

func normalizeDomain(input string) (string, error) {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(input), "."))
	if len(name) == 0 || len(name) > 253 || net.ParseIP(name) != nil {
		return "", fmt.Errorf("invalid hostname %q", input)
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid hostname %q", input)
		}
		for _, ch := range label {
			if !((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-') {
				return "", fmt.Errorf("invalid hostname %q (use ASCII/Punycode hostnames)", input)
			}
		}
	}
	if !strings.Contains(name, ".") {
		return "", fmt.Errorf("invalid hostname %q (a fully qualified name is required)", input)
	}
	return name, nil
}

func openOutput(path string, stdout io.Writer) (io.Writer, func(bool) error, error) {
	if path == "" {
		return stdout, func(bool) error { return nil }, nil
	}
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, ".abigail-*.tmp")
	if err != nil {
		return nil, nil, err
	}
	return file, func(commit bool) error {
		if commit {
			if err := file.Sync(); err != nil {
				file.Close()
				os.Remove(file.Name())
				return err
			}
		}
		if err := file.Close(); err != nil {
			os.Remove(file.Name())
			return err
		}
		if !commit {
			return os.Remove(file.Name())
		}
		if err := os.Rename(file.Name(), path); err != nil {
			os.Remove(file.Name())
			return err
		}
		return nil
	}, nil
}

func execute(ctx context.Context, cfg config, domains []string, pack ruleengine.Pack, output, stderr io.Writer) (int, error) {
	probe := httpprobe.New(cfg.timeout, httpprobe.DefaultMaxBody)
	defer probe.Close()
	engine := scanner.Scanner{
		Rules:            pack.Rules,
		DNSOptions:       dnsprobe.Options{Resolver: cfg.resolver, MaxDepth: 12, Timeout: cfg.timeout},
		HTTP:             probe,
		IncludeEdgeCases: cfg.includeEdgeCases,
	}
	type job struct{ domain string }
	jobs := make(chan job)
	results := make(chan scanner.Result, cfg.concurrency)
	var workers sync.WaitGroup
	for range cfg.concurrency {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for item := range jobs {
				jobCtx, cancel := context.WithTimeout(ctx, cfg.timeout*3)
				result := engine.Scan(jobCtx, item.domain)
				cancel()
				select {
				case results <- result:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		if cfg.rate == 0 {
			for _, domain := range domains {
				select {
				case jobs <- job{domain}:
				case <-ctx.Done():
					return
				}
			}
			return
		}
		ticker := time.NewTicker(time.Second / time.Duration(cfg.rate))
		defer ticker.Stop()
		for _, domain := range domains {
			select {
			case <-ticker.C:
			case <-ctx.Done():
				return
			}
			select {
			case jobs <- job{domain}:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { workers.Wait(); close(results) }()

	counts := map[string]int{}
	var encoder *json.Encoder
	if cfg.format == "jsonl" {
		encoder = json.NewEncoder(output)
		encoder.SetEscapeHTML(false)
	}
	var writeErr error
	for result := range results {
		counts[result.Status]++
		if writeErr != nil {
			continue
		}
		if encoder != nil {
			writeErr = encoder.Encode(result)
		} else if result.Status == "unknown" {
			_, writeErr = fmt.Fprintf(output, "[unknown] %s: %s\n", result.Domain, strings.Join(result.Errors, "; "))
		} else {
			for _, finding := range result.Findings {
				_, writeErr = fmt.Fprintf(output, "[%s] %s %s (%s: %s)\n", finding.Verdict, result.Domain, finding.Service, finding.DNS[0].Record, finding.DNS[0].Value)
				if writeErr != nil {
					break
				}
			}
		}
	}
	fmt.Fprintf(stderr, "Scanned %d: %d candidate, %d edge case, %d unknown, %d no signature\n",
		len(domains), counts["candidate"], counts["edge_case"], counts["unknown"], counts["clean"])
	if writeErr != nil || counts["unknown"] > 0 {
		return 2, writeErr
	}
	if counts["candidate"]+counts["edge_case"] > 0 {
		return 1, nil
	}
	return 0, nil
}
