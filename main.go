package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"
)

var version = "1.1.0"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "help", "-h", "--help":
			printHelp()
			return
		case "version", "-version", "--version":
			fmt.Printf("hawkprobe %s\n", version)
			return
		case "rules":
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(builtinRules)
			return
		}
	}

	opts, err := parseFlags()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	rules, err := loadRules(opts.RuleFile, opts.Profile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "rules:", err)
		os.Exit(2)
	}
	targets, err := loadTargets(opts.Target, opts.ListFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	results := make([]scanResult, 0, len(targets))
	for _, target := range targets {
		results = append(results, scanTarget(opts, target, rules))
	}
	if err := outputResults(results, opts); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func parseFlags() (options, error) {
	var opts options
	flag.StringVar(&opts.ListFile, "list", "", "file containing targets")
	flag.StringVar(&opts.RuleFile, "rules", "", "custom JSON rule file")
	flag.StringVar(&opts.Profile, "profile", "default", "quick, default, or full")
	flag.IntVar(&opts.Concurrency, "c", 24, "concurrent requests per target")
	flag.DurationVar(&opts.Timeout, "timeout", 6*time.Second, "request timeout")
	flag.BoolVar(&opts.Insecure, "k", false, "allow invalid TLS certificates")
	flag.BoolVar(&opts.JSON, "json", false, "JSON output")
	flag.BoolVar(&opts.JSONL, "jsonl", false, "JSON Lines output")
	flag.StringVar(&opts.Output, "o", "", "write output to a file")
	flag.Var(&opts.Headers, "H", "custom header, repeatable: 'Name: value'")
	flag.StringVar(&opts.User, "user", "", "basic auth username")
	flag.StringVar(&opts.Pass, "pass", "", "basic auth password")
	flag.StringVar(&opts.Token, "token", "", "bearer token")
	flag.StringVar(&opts.Proxy, "proxy", "", "HTTP or SOCKS-compatible HTTP proxy URL")
	flag.IntVar(&opts.MaxRedirects, "max-redirects", 5, "maximum redirects")
	flag.BoolVar(&opts.NoRedirect, "no-redirect", false, "do not follow redirects")
	flag.StringVar(&opts.UserAgent, "ua", "", "custom User-Agent")
	flag.Usage = printHelp
	flag.Parse()

	if flag.NArg() > 1 {
		return opts, errors.New("only one positional target is allowed; use -list for more")
	}
	if flag.NArg() == 1 {
		opts.Target = flag.Arg(0)
	}
	if opts.Target == "" && opts.ListFile == "" {
		return opts, errors.New("one target or -list file is required")
	}
	if opts.Target != "" && opts.ListFile != "" {
		return opts, errors.New("use either a target or -list, not both")
	}
	if opts.Concurrency < 1 || opts.Concurrency > 256 {
		return opts, errors.New("concurrency must be between 1 and 256")
	}
	if opts.Timeout < time.Second {
		return opts, errors.New("timeout must be at least 1s")
	}
	if opts.MaxRedirects < 1 || opts.MaxRedirects > 20 {
		return opts, errors.New("max-redirects must be between 1 and 20")
	}
	if opts.JSON && opts.JSONL {
		return opts, errors.New("use either -json or -jsonl")
	}
	if opts.Profile != "quick" && opts.Profile != "default" && opts.Profile != "full" {
		return opts, errors.New("profile must be quick, default, or full")
	}
	if (opts.User == "") != (opts.Pass == "") {
		return opts, errors.New("basic auth requires both -user and -pass")
	}
	if opts.Token != "" && opts.User != "" {
		return opts, errors.New("use bearer token or basic auth, not both")
	}
	return opts, nil
}

func printHelp() {
	fmt.Println(`hawkprobe - fast web exposure scanner

usage:
  hawkprobe [options] <url>
  hawkprobe -list targets.txt [options]
  hawkprobe rules
  hawkprobe version

scan options:
  -profile string       quick, default, or full (default "default")
  -c int                concurrent requests per target (default 24)
  -timeout duration     request timeout (default 6s)
  -rules file.json      add custom rules
  -list targets.txt     scan targets from a file
  -H "Name: value"      add a request header; may be repeated
  -user string          basic auth username
  -pass string          basic auth password
  -token string         bearer token
  -proxy URL            proxy URL
  -ua string            custom User-Agent
  -no-redirect          do not follow redirects
  -max-redirects int    redirect limit (default 5)
  -k                    allow invalid TLS certificates

output:
  -json                 JSON output
  -jsonl                JSON Lines output
  -o file               write output to a file

examples:
  hawkprobe https://example.com
  hawkprobe -profile quick https://example.com
  hawkprobe -profile full -c 64 https://example.com
  hawkprobe -list targets.txt -jsonl -o results.jsonl
  hawkprobe -H "X-Test: 1" https://example.com
  hawkprobe -user admin -pass test https://lab.example
  hawkprobe -rules custom-rules.json https://lab.example
  hawkprobe rules`)
}
