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
	rules = filterRules(rules, opts.CategoryFilter, opts.TagFilter)

	if opts.Wordlist != "" {
		wordRules, err := loadWordlistRules(opts.Wordlist, opts.Extensions)
		if err != nil {
			fmt.Fprintln(os.Stderr, "wordlist:", err)
			os.Exit(2)
		}
		rules = append(rules, wordRules...)
	}

	targets, err := loadTargets(opts.Target, opts.ListFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	results := scanTargets(opts, targets, rules)
	results = filterResultSeverity(results, opts.MinSeverity)
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
	case "doctor":
		printDoctor()
		return true
	case "completion":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: hawkprobe completion bash|zsh|fish")
			os.Exit(2)
		}
		if err := printCompletion(args[1]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		return true
	case "wordlists":
		root := findSecListsRoot()
		if root == "" {
			fmt.Println("SecLists: not found (set SECLISTS_PATH or install SecLists)")
		} else {
			fmt.Println("SecLists:", root)
		}
		fmt.Println("presets:")
		for _, name := range secListsPresetNames() {
			fmt.Printf("  @%-13s %s\n", name, secListsPresets[name])
		}
		return true
	case "rules":
		if len(args) >= 2 && args[1] == "stats" {
			printRuleStats()
			return true
		}
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
				fmt.Printf("%-32s %-12s %-8s %s\n", r.ID, r.Category, r.Severity, r.Path)
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
	var nmapAlias string
	var secListsAlias string
	var stdinAlias bool

	fs.StringVar(&opts.ListFile, "list", "", "target file, stdin (-), Nmap output, or httpx JSONL")
	fs.StringVar(&nmapAlias, "nmap", "", "alias for -list with Nmap output")
	fs.BoolVar(&stdinAlias, "stdin", false, "alias for -list -")
	fs.StringVar(&opts.RuleFile, "rules", "", "custom JSON rule file")
	fs.StringVar(&opts.Mode, "mode", "default", "scan mode")
	fs.StringVar(&profileAlias, "profile", "", "deprecated alias for -mode")
	fs.StringVar(&opts.CategoryFilter, "category", "", "only scan comma-separated rule categories")
	fs.StringVar(&opts.TagFilter, "tag", "", "only scan rules matching comma-separated tags")
	fs.StringVar(&opts.MinSeverity, "severity", "", "only output findings at or above info/low/medium/high/critical")
	fs.StringVar(&opts.FailOn, "fail-on", "", "exit 3 when a finding reaches this severity")
	fs.IntVar(&opts.Concurrency, "c", 32, "concurrent requests per target")
	fs.IntVar(&opts.TargetConcurrency, "target-c", 4, "targets scanned concurrently")
	fs.IntVar(&opts.Rate, "rate", 0, "maximum requests per second per target (0 = unlimited)")
	fs.DurationVar(&opts.Timeout, "timeout", 6*time.Second, "request timeout")
	fs.BoolVar(&opts.Insecure, "k", false, "allow invalid TLS certificates")
	fs.BoolVar(&opts.JSON, "json", false, "JSON output")
	fs.BoolVar(&opts.JSONL, "jsonl", false, "JSON Lines output")
	fs.BoolVar(&opts.CSV, "csv", false, "CSV findings output")
	fs.BoolVar(&opts.SARIF, "sarif", false, "SARIF 2.1.0 output")
	fs.StringVar(&opts.Output, "o", "", "write output to a file")
	fs.StringVar(&opts.URLsOut, "urls-out", "", "write unique target/finding URLs for nuclei/httpx/ffuf pipelines")
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
	fs.StringVar(&opts.Wordlist, "wordlist", "", "wordlist path or SecLists preset such as @common")
	fs.StringVar(&secListsAlias, "seclists", "", "SecLists preset alias, e.g. common or dirs-medium")
	fs.StringVar(&opts.Extensions, "ext", "", "comma-separated extensions for wordlist entries")
	fs.BoolVar(&opts.NoProgress, "no-progress", false, "disable terminal progress bar")
	fs.BoolVar(&opts.NoColor, "no-color", false, "disable ANSI colors")
	fs.BoolVar(&opts.Quiet, "q", false, "only print findings and errors")

	if err := fs.Parse(reorderArgs(os.Args[1:])); err != nil {
		return opts, err
	}
	if profileAlias != "" {
		opts.Mode = profileAlias
	}
	if nmapAlias != "" {
		if opts.ListFile != "" {
			return opts, errors.New("use either -list or -nmap, not both")
		}
		opts.ListFile = nmapAlias
	}
	if stdinAlias {
		if opts.ListFile != "" {
			return opts, errors.New("use either -list/-nmap or -stdin, not both")
		}
		opts.ListFile = "-"
	}
	if secListsAlias != "" {
		if opts.Wordlist != "" {
			return opts, errors.New("use either -wordlist or -seclists, not both")
		}
		spec := strings.TrimSpace(secListsAlias)
		if !strings.HasPrefix(spec, "@") && !strings.HasPrefix(strings.ToLower(spec), "seclists:") && !strings.ContainsAny(spec, "/\\") {
			spec = "@" + spec
		}
		opts.Wordlist = spec
	}

	if fs.NArg() > 1 {
		return opts, errors.New("only one positional target is allowed; use -list for more")
	}
	if fs.NArg() == 1 {
		opts.Target = fs.Arg(0)
	}
	if opts.Target == "" && opts.ListFile == "" {
		return opts, errors.New("one target or -list/-nmap/-stdin input is required")
	}
	if opts.Target != "" && opts.ListFile != "" {
		return opts, errors.New("use either a target or list input, not both")
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
	if !validSeverityName(opts.MinSeverity) {
		return opts, fmt.Errorf("invalid severity %q", opts.MinSeverity)
	}
	if !validSeverityName(opts.FailOn) {
		return opts, fmt.Errorf("invalid fail-on severity %q", opts.FailOn)
	}

	validModes := map[string]bool{"quick": true, "default": true, "full": true, "deep": true, "htb": true, "exposure": true, "admin": true, "api": true, "debug": true, "headers": true, "tls": true, "tech": true}
	opts.Mode = lower(opts.Mode)
	if !validModes[opts.Mode] {
		return opts, fmt.Errorf("unknown mode %q", opts.Mode)
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
		"-list": true, "-nmap": true, "-rules": true, "-mode": true, "-profile": true,
		"-category": true, "-tag": true, "-severity": true, "-fail-on": true,
		"-c": true, "-target-c": true, "-rate": true, "-timeout": true,
		"-o": true, "-urls-out": true, "-H": true, "-user": true, "-pass": true,
		"-token": true, "-proxy": true, "-max-redirects": true, "-ua": true,
		"-host": true, "-wordlist": true, "-seclists": true, "-ext": true,
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
  hawkprobe -nmap scan.xml -mode htb
  command-producing-urls | hawkprobe -stdin -mode exposure
  hawkprobe rules list
  hawkprobe rules stats
  hawkprobe rules validate custom-rules.json
  hawkprobe wordlists
  hawkprobe doctor
  hawkprobe completion bash|zsh|fish
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

input:
  -list file           plain URLs/hosts, Nmap XML/-oG/normal output, or httpx JSONL
  -list -              read targets from stdin
  -nmap file           friendly alias for -list with Nmap output
  -stdin               friendly alias for -list -
  -wordlist file       path discovery wordlist
  -wordlist @common    auto-find a SecLists preset
  -seclists common     friendly alias for -wordlist @common
  -ext php,txt,bak     add extensions to extensionless wordlist entries

scan selection:
  -mode string          scan mode (default "default")
  -category list        only categories, e.g. cloud,devops,backup
  -tag list             only tags, e.g. htb,exposure
  -severity level       only output findings at/above a severity
  -fail-on level        exit 3 if a finding reaches a severity

scan options:
  -c int                concurrent requests per target (default 32)
  -target-c int         targets scanned concurrently (default 4)
  -rate int             requests/sec per target; 0 = unlimited
  -timeout duration     request timeout (default 6s)
  -discover             parse robots/sitemap and probe discovered paths
  -v                    show every rule check
  -evidence             show evidence and remediation
  -rules file.json      add custom rules
  -H "Name: value"      custom request header; repeatable
  -host string          override HTTP Host header
  -user/-pass           basic authentication
  -token string         bearer token
  -proxy URL            HTTP proxy URL
  -ua string            custom User-Agent
  -no-redirect          do not follow redirects
  -max-redirects int    redirect limit (default 5)
  -k                    allow invalid TLS certificates

terminal/output:
  -q                    only print findings and errors
  -no-progress          disable adaptive progress bar
  -no-color             disable ANSI colors
  -urls-out file        unique URLs for nuclei/httpx/ffuf chaining
  -json                 JSON output
  -jsonl                JSON Lines output
  -csv                  CSV findings output
  -sarif                SARIF 2.1.0 output
  -o file               write output to a file

examples:
  hawkprobe http://10.10.10.10 -mode htb
  hawkprobe box.htb:80 -mode htb -evidence
  hawkprobe -nmap scan.xml -mode htb -target-c 8
  httpx -l hosts.txt -silent | hawkprobe -stdin -mode exposure
  hawkprobe http://box.htb -mode htb -seclists common -ext php,bak
  hawkprobe http://box.htb -wordlist @dirs-medium -c 80 -rate 250
  hawkprobe https://app.lab -mode full -category cloud,devops
  hawkprobe https://app.lab -mode full -severity medium
  hawkprobe https://app.lab -mode exposure -fail-on high
  hawkprobe -list targets.txt -sarif -o hawkprobe.sarif
  hawkprobe -host internal.htb http://10.10.10.10 -mode htb
  hawkprobe https://app.lab -mode full -urls-out discovered.txt
  nuclei -l discovered.txt
  hawkprobe completion zsh
  hawkprobe rules validate custom-rules.json`)
}
