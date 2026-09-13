package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
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
	if opts.SecList != "" {
		path, err := resolveSecList(opts.SecList)
		if err != nil {
			fmt.Fprintln(os.Stderr, "seclists:", err)
			os.Exit(2)
		}
		opts.Wordlist = path
	}
	if opts.Wordlist != "" {
		wordRules, err := loadWordlistRules(opts.Wordlist, opts.Extensions, opts.WordlistLimit)
		if err != nil {
			fmt.Fprintln(os.Stderr, "wordlist:", err)
			os.Exit(2)
		}
		rules = append(rules, wordRules...)
	}
	rules = filterRules(rules, opts)

	var targets []string
	if opts.InputFile != "" {
		targets, err = loadInputTargets(opts.InputFile, opts.InputFormat)
	} else {
		targets, err = loadTargets(opts.Target, opts.ListFile)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	results := scanTargets(opts, targets, rules)
	if err := outputResults(results, opts); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
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
	case "wordlists":
		printSecListAliases()
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
		if len(args) >= 2 && args[1] == "stats" {
			printRuleStats()
			return true
		}
		if len(args) >= 2 && args[1] == "list" {
			for _, r := range builtinRules {
				fmt.Printf("%-28s %-12s %-8s %s\n", r.ID, r.Category, r.Severity, r.Path)
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

func printRuleStats() {
	counts := ruleCategoryCounts(builtinRules)
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	fmt.Printf("%d built-in rules\n", len(builtinRules))
	for _, key := range keys {
		fmt.Printf("  %-14s %d\n", key, counts[key])
	}
}

func parseFlags() (options, error) {
	var opts options
	fs := flag.NewFlagSet("hawkprobe", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var profileAlias string
	var noProgress bool
	fs.StringVar(&opts.ListFile, "list", "", "plain file containing targets")
	fs.StringVar(&opts.InputFile, "input", "", "tool output or URL file ('-' for stdin)")
	fs.StringVar(&opts.InputFormat, "input-format", "auto", "auto, plain, nmap-xml, nmap-gnmap, httpx-jsonl, nuclei-jsonl, ferox-jsonl, ffuf-json")
	fs.StringVar(&opts.NmapFile, "nmap", "", "Nmap XML or grepable output (shortcut for -input)")
	fs.StringVar(&opts.RuleFile, "rules", "", "custom JSON rule file")
	fs.StringVar(&opts.Mode, "mode", "default", "scan mode")
	fs.StringVar(&profileAlias, "profile", "", "deprecated alias for -mode")
	fs.IntVar(&opts.Concurrency, "c", 32, "concurrent requests per target")
	fs.IntVar(&opts.TargetConcurrency, "target-c", 4, "targets scanned concurrently")
	fs.DurationVar(&opts.Timeout, "timeout", 6*time.Second, "request timeout")
	fs.BoolVar(&opts.Insecure, "k", false, "allow invalid TLS certificates")
	fs.BoolVar(&opts.JSON, "json", false, "legacy alias for -format json")
	fs.BoolVar(&opts.JSONL, "jsonl", false, "legacy alias for -format jsonl")
	fs.StringVar(&opts.OutputFormat, "format", "text", "text, json, jsonl, csv, md, or urls")
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
	fs.StringVar(&opts.Wordlist, "wordlist", "", "path wordlist for content discovery")
	fs.StringVar(&opts.SecList, "seclist", "", "SecLists alias; run 'hawkprobe wordlists'")
	fs.StringVar(&opts.Extensions, "ext", "", "comma-separated extensions for wordlist entries")
	fs.IntVar(&opts.WordlistLimit, "wordlist-limit", 50000, "maximum generated wordlist checks")
	fs.BoolVar(&opts.Progress, "progress", true, "show progress bar for single-target scans")
	fs.BoolVar(&noProgress, "no-progress", false, "disable progress bar")
	fs.BoolVar(&opts.Quiet, "q", false, "quiet output; print findings only")
	fs.StringVar(&opts.MinSeverity, "severity", "", "minimum rule severity: info, low, medium, high, critical")
	fs.StringVar(&opts.IncludeCategory, "include-category", "", "comma-separated rule categories to include")
	fs.StringVar(&opts.ExcludeCategory, "exclude-category", "", "comma-separated rule categories to exclude")
	if err := fs.Parse(reorderArgs(os.Args[1:])); err != nil {
		return opts, err
	}
	if profileAlias != "" {
		opts.Mode = profileAlias
	}
	if noProgress || opts.Quiet {
		opts.Progress = false
	}
	if fs.NArg() > 1 {
		return opts, errors.New("only one positional target is allowed; use -list or -input for more")
	}
	if fs.NArg() == 1 {
		opts.Target = fs.Arg(0)
	}
	if opts.NmapFile != "" {
		if opts.InputFile != "" {
			return opts, errors.New("use either -nmap or -input, not both")
		}
		opts.InputFile = opts.NmapFile
		if opts.InputFormat == "" || opts.InputFormat == "auto" {
			opts.InputFormat = "nmap"
		}
	}
	sources := 0
	for _, set := range []bool{opts.Target != "", opts.ListFile != "", opts.InputFile != ""} {
		if set { sources++ }
	}
	if sources != 1 {
		return opts, errors.New("provide exactly one target source: URL, -list, -input, or -nmap")
	}
	if opts.Wordlist != "" && opts.SecList != "" {
		return opts, errors.New("use either -wordlist or -seclist, not both")
	}
	if opts.Concurrency < 1 || opts.Concurrency > 512 {
		return opts, errors.New("concurrency must be between 1 and 512")
	}
	if opts.TargetConcurrency < 1 || opts.TargetConcurrency > 64 {
		return opts, errors.New("target-c must be between 1 and 64")
	}
	if opts.WordlistLimit < 1 || opts.WordlistLimit > 1000000 {
		return opts, errors.New("wordlist-limit must be between 1 and 1000000")
	}
	if opts.Timeout < 500*time.Millisecond {
		return opts, errors.New("timeout must be at least 500ms")
	}
	if opts.MaxRedirects < 1 || opts.MaxRedirects > 20 {
		return opts, errors.New("max-redirects must be between 1 and 20")
	}
	if opts.JSON && opts.JSONL {
		return opts, errors.New("use either -json or -jsonl")
	}
	if opts.JSON { opts.OutputFormat = "json" }
	if opts.JSONL { opts.OutputFormat = "jsonl" }
	opts.OutputFormat = lower(opts.OutputFormat)
	switch opts.OutputFormat {
	case "text", "json", "jsonl", "csv", "md", "markdown", "urls":
	default:
		return opts, fmt.Errorf("unknown output format %q", opts.OutputFormat)
	}
	validModes := map[string]bool{"quick": true, "default": true, "full": true, "deep": true, "htb": true, "exposure": true, "admin": true, "api": true, "debug": true, "headers": true, "tls": true, "tech": true}
	opts.Mode = lower(opts.Mode)
	if !validModes[opts.Mode] {
		return opts, fmt.Errorf("unknown mode %q", opts.Mode)
	}
	if opts.MinSeverity != "" {
		switch lower(opts.MinSeverity) {
		case "info", "low", "medium", "med", "high", "critical", "crit":
		default:
			return opts, fmt.Errorf("invalid severity %q", opts.MinSeverity)
		}
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
	valueFlags := map[string]bool{"-list": true, "-input": true, "-input-format": true, "-nmap": true, "-rules": true, "-mode": true, "-profile": true, "-c": true, "-target-c": true, "-timeout": true, "-format": true, "-o": true, "-H": true, "-user": true, "-pass": true, "-token": true, "-proxy": true, "-max-redirects": true, "-ua": true, "-host": true, "-wordlist": true, "-seclist": true, "-ext": true, "-wordlist-limit": true, "-severity": true, "-include-category": true, "-exclude-category": true}
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
	type job struct { index int; target string }
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
	for i, target := range targets { jobs <- job{i, target} }
	close(jobs)
	wg.Wait()
	return results
}

func printHelp() {
	fmt.Println(`HawkProbe - fast web exposure and misconfiguration scanner

USAGE
  hawkprobe [options] <url>
  hawkprobe -list targets.txt [options]
  hawkprobe -nmap scan.xml [options]
  hawkprobe -input results.jsonl -input-format httpx-jsonl [options]

MODES
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

DISCOVERY
  -wordlist file        use any text wordlist, including SecLists files
  -seclist alias        use an installed SecLists alias
  -ext php,txt,bak      expand extensionless wordlist entries
  -wordlist-limit int   maximum generated checks (default 50000)
  -discover             parse robots.txt/sitemaps and probe found paths

TOOL INPUT
  -nmap file            import Nmap XML or grepable output
  -input file           import tool output; use '-' for stdin
  -input-format string  auto, plain, nmap-xml, nmap-gnmap,
                        httpx-jsonl, nuclei-jsonl, ferox-jsonl, ffuf-json

SCAN CONTROL
  -mode string          scan mode (default "default")
  -c int                concurrent requests per target (default 32)
  -target-c int         targets scanned concurrently (default 4)
  -timeout duration     request timeout (default 6s)
  -severity string      minimum rule severity
  -include-category x   only selected comma-separated categories
  -exclude-category x   skip selected comma-separated categories
  -v                    show every rule check
  -progress             progress bar (default on for single target)
  -no-progress          disable progress bar
  -q                    findings-only output
  -evidence             print evidence and remediation

REQUESTS
  -H "Name: value"      custom header; repeatable
  -host string          override HTTP Host header
  -user/-pass           basic authentication
  -token string         bearer token
  -proxy URL            HTTP proxy URL
  -ua string            custom User-Agent
  -no-redirect          do not follow redirects
  -max-redirects int    redirect limit (default 5)
  -k                    allow invalid TLS certificates

OUTPUT
  -format string        text, json, jsonl, csv, md, urls
  -o file               write output to a file
  -json / -jsonl        compatibility aliases

UTILITIES
  hawkprobe rules list
  hawkprobe rules stats
  hawkprobe rules validate custom-rules.json
  hawkprobe wordlists
  hawkprobe version

EXAMPLES
  hawkprobe http://10.10.10.10 -mode htb
  hawkprobe box.htb -mode htb -seclist raft-small -ext php,bak
  hawkprobe -nmap scan.xml -mode htb -target-c 8
  httpx -json | hawkprobe -input - -input-format httpx-jsonl -mode exposure
  hawkprobe example.com -mode full -severity medium -evidence
  hawkprobe -list targets.txt -format jsonl -o results.jsonl`)
}
