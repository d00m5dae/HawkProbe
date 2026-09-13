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
	case "doctor":
		printDoctor()
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
	fs.StringVar(&opts.ListFile, "list", "", "target file, stdin (-), Nmap XML/gnmap, or httpx JSONL")
	fs.StringVar(&opts.RuleFile, "rules", "", "custom JSON rule file")
	fs.StringVar(&opts.Mode, "mode", "default", "scan mode")
	fs.StringVar(&profileAlias, "profile", "", "deprecated alias for -mode")
	fs.IntVar(&opts.Concurrency, "c", 32, "concurrent requests per target")
	fs.IntVar(&opts.TargetConcurrency, "target-c", 4, "targets scanned concurrently")
	fs.DurationVar(&opts.Timeout, "timeout", 6*time.Second, "request timeout")
	fs.BoolVar(&opts.Insecure, "k", false, "allow invalid TLS certificates")
	fs.BoolVar(&opts.JSON, "json", false, "JSON output")
	fs.BoolVar(&opts.JSONL, "jsonl", false, "JSON Lines output")
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
	fs.StringVar(&opts.Wordlist, "wordlist", "", "wordlist path or SecLists preset such as @common")
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
	if fs.NArg() > 1 {
		return opts, errors.New("only one positional target is allowed; use -list for more")
	}
	if fs.NArg() == 1 {
		opts.Target = fs.Arg(0)
	}
	if opts.Target == "" && opts.ListFile == "" {
		return opts, errors.New("one target or -list input is required")
	}
	if opts.Target != "" && opts.ListFile != "" {
		return opts, errors.New("use either a target or -list, not both")
	}
	if opts.Concurrency < 1 || opts.Concurrency > 512 {
		return opts, errors.New("concurrency must be between 1 and 512")
	}
	if opts.TargetConcurrency < 1 || opts.TargetConcurrency > 64 {
		return opts, errors.New("target-c must be between 1 and 64")
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
	valueFlags := map[string]bool{"-list": true, "-rules": true, "-mode": true, "-profile": true, "-c": true, "-target-c": true, "-timeout": true, "-o": true, "-H": true, "-user": true, "-pass": true, "-token": true, "-proxy": true, "-max-redirects": true, "-ua": true, "-host": true, "-wordlist": true, "-ext": true}
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
  hawkprobe -list nmap.xml -mode htb
  nmap ... -oG - | hawkprobe -list - -mode htb
  hawkprobe rules list
  hawkprobe rules validate custom-rules.json
  hawkprobe wordlists
  hawkprobe doctor
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
  -list file           plain URLs/hosts, Nmap XML, Nmap -oG, or httpx JSONL
  -list -              read targets from stdin
  -wordlist file       path discovery wordlist
  -wordlist @common    auto-find a SecLists preset
  -ext php,txt,bak     add extensions to extensionless wordlist entries

scan options:
  -mode string          scan mode (default "default")
  -c int                concurrent requests per target (default 32)
  -target-c int         targets scanned concurrently (default 4)
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
  -json                 JSON output
  -jsonl                JSON Lines output
  -o file               write output to a file

examples:
  hawkprobe http://10.10.10.10 -mode htb
  hawkprobe box.htb:80 -mode htb -evidence
  hawkprobe -list scan.xml -mode htb -target-c 8
  httpx -l hosts.txt -json | hawkprobe -list - -mode exposure
  hawkprobe http://box.htb -mode htb -wordlist @common -ext php,bak
  hawkprobe http://box.htb -wordlist @dirs-medium -c 80
  hawkprobe -host internal.htb http://10.10.10.10 -mode htb
  hawkprobe rules validate custom-rules.json`)
}
