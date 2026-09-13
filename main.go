package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

var version = "1.3.0-dev"

func main() {
	if handleCommand(os.Args[1:]) {
		return
	}
	opts, err := parseFlags()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	rules, err := loadRules(opts.RuleFile, opts.Mode)
	if err != nil {
		fmt.Fprintln(os.Stderr, "rules:", err)
		os.Exit(2)
	}
	rules = filterRulesForOptions(rules, opts)

	if opts.Wordlist != "" {
		wordRules, err := loadWordlistRules(opts.Wordlist, opts.Extensions)
		if err != nil {
			fmt.Fprintln(os.Stderr, "wordlist:", err)
			os.Exit(2)
		}
		rules = append(rules, filterRulesForOptions(wordRules, opts)...)
	}
	if opts.SecLists != "" {
		path, err := resolveSecListsWordlist(opts.SecLists, opts.SecListsRoot)
		if err != nil {
			fmt.Fprintln(os.Stderr, "seclists:", err)
			os.Exit(2)
		}
		wordRules, err := loadWordlistRules(path, opts.Extensions)
		if err != nil {
			fmt.Fprintln(os.Stderr, "seclists:", err)
			os.Exit(2)
		}
		rules = append(rules, filterRulesForOptions(wordRules, opts)...)
	}

	targets, err := loadInputTargets(opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	results := scanTargets(opts, targets, rules)
	if err := outputResults(results, opts); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if resultsMeetFailThreshold(results, opts.FailOn) {
		os.Exit(3)
	}
}

func handleCommand(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "help", "-h", "--help":
		printHelp()
		return true
	case "version", "-version", "--version":
		fmt.Printf("hawkprobe %s\n", version)
		return true
	case "seclists":
		printSecListsPresets()
		return true
	case "rules":
		if len(args) >= 3 && args[1] == "validate" {
			if err := validateRulesFile(args[2]); err != nil {
				fmt.Fprintln(os.Stderr, "invalid:", err)
				os.Exit(2)
			}
			fmt.Println("rules valid")
			return true
		}
		if len(args) >= 2 && args[1] == "list" {
			for _, r := range builtinRules {
				fmt.Printf("%-34s %-12s %-8s %s\n", r.ID, r.Category, r.Severity, r.Path)
			}
			return true
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(builtinRules)
		return true
	}
	return false
}

func parseFlags() (options, error) {
	var opts options
	fs := flag.NewFlagSet("hawkprobe", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var profileAlias string

	fs.StringVar(&opts.ListFile, "list", "", "file containing targets")
	fs.StringVar(&opts.NmapFile, "nmap", "", "import HTTP services from Nmap XML, grepable, or normal output")
	fs.BoolVar(&opts.ReadStdin, "stdin", false, "read targets from stdin")
	fs.StringVar(&opts.RuleFile, "rules", "", "custom JSON rule file")
	fs.StringVar(&opts.Mode, "mode", "default", "scan mode")
	fs.StringVar(&profileAlias, "profile", "", "deprecated alias for -mode")
	fs.IntVar(&opts.Concurrency, "c", 32, "concurrent requests per target")
	fs.IntVar(&opts.TargetConcurrency, "target-c", 4, "targets scanned concurrently")
	fs.IntVar(&opts.Rate, "rate", 0, "maximum requests per second per target; 0 is unlimited")
	fs.DurationVar(&opts.Timeout, "timeout", 6*time.Second, "request timeout")
	fs.BoolVar(&opts.Insecure, "k", false, "allow invalid TLS certificates")
	fs.BoolVar(&opts.JSON, "json", false, "JSON output")
	fs.BoolVar(&opts.JSONL, "jsonl", false, "JSON Lines output")
	fs.BoolVar(&opts.CSV, "csv", false, "CSV findings output")
	fs.BoolVar(&opts.SARIF, "sarif", false, "SARIF 2.1.0 output")
	fs.StringVar(&opts.Output, "o", "", "write output to a file")
	fs.Var(&opts.Headers, "H", "custom header, repeatable: 'Name: value'")
	fs.StringVar(&opts.User, "user", "", "basic auth username")
	fs.StringVar(&opts.Pass, "pass", "", "basic auth password")
	fs.StringVar(&opts.Token, "token", "", "bearer token")
	fs.StringVar(&opts.Proxy, "proxy", "", "HTTP proxy URL")
	fs.IntVar(&opts.MaxRedirects, "max-redirects", 5, "maximum redirects")
	fs.BoolVar(&opts.NoRedirect, "no-redirect", false, "do not follow redirects")
	fs.StringVar(&opts.UserAgent, "ua", "", "custom User-Agent")
	fs.StringVar(&opts.HostHeader, "host", "", "override HTTP Host header")
	fs.BoolVar(&opts.Verbose, "v", false, "show each rule check")
	fs.BoolVar(&opts.Evidence, "evidence", false, "show evidence and remediation")
	fs.BoolVar(&opts.Discover, "discover", false, "parse robots/sitemap and probe discovered paths")
	fs.StringVar(&opts.Wordlist, "wordlist", "", "optional path wordlist for content discovery")
	fs.StringVar(&opts.SecLists, "seclists", "", "SecLists preset, relative path, or wordlist path")
	fs.StringVar(&opts.SecListsRoot, "seclists-root", "", "SecLists installation root")
	fs.StringVar(&opts.Extensions, "ext", "", "comma-separated extensions for wordlist entries")
	fs.BoolVar(&opts.Progress, "progress", false, "show a progress bar on stderr")
	fs.StringVar(&opts.MinSeverity, "severity", "", "minimum severity: info, low, medium, high, critical")
	fs.StringVar(&opts.Category, "category", "", "only scan/report one category")
	fs.StringVar(&opts.IncludeTag, "include-tag", "", "only rules containing this tag")
	fs.StringVar(&opts.ExcludeTag, "exclude-tag", "", "exclude rules containing this tag")
	fs.StringVar(&opts.FailOn, "fail-on", "", "exit 3 when a finding at or above this severity is found")

	if err := fs.Parse(reorderArgs(os.Args[1:])); err != nil {
		return opts, err
	}
	if profileAlias != "" {
		opts.Mode = profileAlias
	}
	if fs.NArg() > 1 {
		return opts, errors.New("only one positional target is allowed; use -list, -nmap, or -stdin for more")
	}
	if fs.NArg() == 1 {
		opts.Target = fs.Arg(0)
	}
	if opts.Target == "" && opts.ListFile == "" && opts.NmapFile == "" && !opts.ReadStdin {
		return opts, errors.New("provide a target, -list, -nmap, or -stdin")
	}
	if opts.Concurrency < 1 || opts.Concurrency > 512 {
		return opts, errors.New("concurrency must be between 1 and 512")
	}
	if opts.TargetConcurrency < 1 || opts.TargetConcurrency > 64 {
		return opts, errors.New("target-c must be between 1 and 64")
	}
	if opts.Rate < 0 || opts.Rate > 10000 {
		return opts, errors.New("rate must be between 0 and 10000 requests/second")
	}
	if opts.Timeout < 500*time.Millisecond {
		return opts, errors.New("timeout must be at least 500ms")
	}
	if opts.MaxRedirects < 1 || opts.MaxRedirects > 20 {
		return opts, errors.New("max-redirects must be between 1 and 20")
	}
	formats := 0
	for _, enabled := range []bool{opts.JSON, opts.JSONL, opts.CSV, opts.SARIF} {
		if enabled {
			formats++
		}
	}
	if formats > 1 {
		return opts, errors.New("use only one of -json, -jsonl, -csv, or -sarif")
	}
	validModes := map[string]bool{"quick": true, "default": true, "full": true, "deep": true, "htb": true, "exposure": true, "admin": true, "api": true, "debug": true, "headers": true, "tls": true, "tech": true}
	opts.Mode = lower(opts.Mode)
	if !validModes[opts.Mode] {
		return opts, fmt.Errorf("unknown mode %q", opts.Mode)
	}
	if err := validateSeverityName(opts.MinSeverity); err != nil {
		return opts, err
	}
	if err := validateSeverityName(opts.FailOn); err != nil {
		return opts, err
	}
	if (opts.User == "") != (opts.Pass == "") {
		return opts, errors.New("basic auth requires both -user and -pass")
	}
	if opts.Token != "" && opts.User != "" {
		return opts, errors.New("use bearer token or basic auth, not both")
	}
	return opts, nil
}

func reorderArgs(args []string) []string {
	valueFlags := map[string]bool{
		"-list": true, "-nmap": true, "-rules": true, "-mode": true, "-profile": true, "-c": true,
		"-target-c": true, "-rate": true, "-timeout": true, "-o": true, "-H": true, "-user": true,
		"-pass": true, "-token": true, "-proxy": true, "-max-redirects": true, "-ua": true, "-host": true,
		"-wordlist": true, "-seclists": true, "-seclists-root": true, "-ext": true, "-severity": true,
		"-category": true, "-include-tag": true, "-exclude-tag": true, "-fail-on": true,
	}
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			name := a
			if eq := strings.IndexByte(a, '='); eq >= 0 {
				name = a[:eq]
			}
			if valueFlags[name] && !strings.Contains(a, "=") && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
		} else {
			positional = append(positional, a)
		}
	}
	return append(flags, positional...)
}

func scanTargets(opts options, targets []string, rules []rule) []scanResult {
	results := make([]scanResult, len(targets))
	workers := minInt(opts.TargetConcurrency, len(targets))
	if workers < 1 {
		return results
	}
	if opts.Progress && !opts.Verbose && !opts.JSON && !opts.JSONL && !opts.CSV && !opts.SARIF && len(rules) > 0 {
		opts.progress = newProgressTracker(len(targets) * len(rules))
		defer opts.progress.Finish()
	}
	type job struct {
		index  int
		target string
	}
	jobs := make(chan job)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				results[j.index] = scanTarget(opts, j.target, rules)
			}
		}()
	}
	for i, target := range targets {
		jobs <- job{i, target}
	}
	close(jobs)
	wg.Wait()
	return results
}

func printHelp() {
	fmt.Println(`hawkprobe - fast web exposure and misconfiguration scanner

usage:
  hawkprobe [options] <url>
  hawkprobe <url> [options]
  hawkprobe -list targets.txt [options]
  hawkprobe -nmap scan.xml [options]
  command-producing-urls | hawkprobe -stdin [options]
  hawkprobe rules list
  hawkprobe rules validate custom-rules.json
  hawkprobe seclists
  hawkprobe version

modes:
  quick       fast high-value checks
  default     balanced everyday scan
  full/deep   broad exposure and discovery scan
  htb         HTB/CTF-oriented discovery + exposure checks
  exposure    secrets, backups, VCS, configs and logs
  admin       admin/login/management surfaces
  api         API docs, Swagger/OpenAPI and GraphQL
  debug       diagnostics, Actuator, pprof and monitoring
  headers     headers, cookies, CORS and HTTP methods
  tls         TLS/certificate checks
  tech        technology fingerprinting

inputs / interoperability:
  -list file            targets from a text file
  -stdin                targets from stdin (works well with httpx pipelines)
  -nmap file            import web services from Nmap XML/-oG/normal output
  -wordlist file        discover paths from any wordlist
  -seclists preset      SecLists preset or relative/file path
  -seclists-root path   custom SecLists installation directory
  -ext php,txt,bak      expand extensionless wordlist entries

scan controls:
  -mode string          scan mode (default "default")
  -c int                concurrent requests per target (default 32)
  -target-c int         targets scanned concurrently (default 4)
  -rate int             per-target requests/sec; 0 is unlimited
  -timeout duration     request timeout (default 6s)
  -discover             parse robots/sitemap and probe discovered paths
  -progress             progress bar on stderr
  -v                    show each rule check
  -evidence             print evidence and remediation details
  -severity level       minimum finding/rule severity
  -category name        only one rule/finding category
  -include-tag tag      only rules with tag
  -exclude-tag tag      skip rules with tag
  -fail-on level        exit 3 if findings reach severity threshold
  -rules file.json      add custom rules
  -H "Name: value"      add a request header; repeatable
  -host string          override HTTP Host header
  -user/-pass           basic authentication
  -token string         bearer token
  -proxy URL            HTTP proxy URL
  -ua string            custom User-Agent
  -no-redirect          do not follow redirects
  -max-redirects int    redirect limit (default 5)
  -k                    allow invalid TLS certificates

output:
  -json                 JSON output
  -jsonl                JSON Lines output
  -csv                  CSV findings output
  -sarif                SARIF 2.1.0 output for security tooling
  -o file               write output to a file

examples:
  hawkprobe http://10.10.10.10 -mode htb -progress
  hawkprobe -nmap scan.xml -mode htb -target-c 8 -progress
  httpx -silent < hosts.txt | hawkprobe -stdin -mode exposure -severity high
  hawkprobe box.htb -mode htb -seclists raft-small -ext php,bak -c 64
  hawkprobe box.htb -seclists common -seclists-root ~/SecLists
  hawkprobe https://example.com -mode exposure -evidence -fail-on high
  hawkprobe -list targets.txt -sarif -o hawkprobe.sarif
  hawkprobe -list targets.txt -jsonl -o results.jsonl
  hawkprobe rules validate custom-rules.json`)
}
