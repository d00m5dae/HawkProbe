package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type configProfile struct {
	Mode              string `json:"mode,omitempty"`
	Category          string `json:"category,omitempty"`
	Tag               string `json:"tag,omitempty"`
	Severity          string `json:"severity,omitempty"`
	FailOn            string `json:"fail-on,omitempty"`
	Concurrency       int    `json:"concurrency,omitempty"`
	TargetConcurrency int    `json:"target-concurrency,omitempty"`
	Rate              int    `json:"rate,omitempty"`
	Retries           int    `json:"retries,omitempty"`
	MaxRequests       int    `json:"max-requests,omitempty"`
	Timeout           string `json:"timeout,omitempty"`
	Wordlist          string `json:"wordlist,omitempty"`
	Extensions        string `json:"extensions,omitempty"`
	Discover          bool   `json:"discover,omitempty"`
	Insecure          bool   `json:"insecure,omitempty"`
	Suppressions      string `json:"suppressions,omitempty"`
	CustomRules       string `json:"custom-rules,omitempty"`
	AI                bool   `json:"ai,omitempty"`
	AIModel           string `json:"ai-model,omitempty"`
}

type configAI struct {
	Model string `json:"model,omitempty"`
	Host  string `json:"host,omitempty"`
}

type configData struct {
	Profiles map[string]configProfile `json:"profiles,omitempty"`
	AI       configAI                 `json:"ai,omitempty"`
}

func configPath() string {
	if p := os.Getenv("HAWKPROBE_CONFIG"); p != "" {
		return p
	}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "hawkprobe", "config.json")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".hawkprobe-config.json"
	}
	return filepath.Join(home, ".config", "hawkprobe", "config.json")
}

func loadConfig() (configData, error) {
	var cfg configData
	data, err := os.ReadFile(configPath())
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("read config: %w", err)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return cfg, nil
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse %s: %w", configPath(), err)
	}
	return cfg, nil
}

func saveConfig(cfg configData) error {
	path := configPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func validModesSet() map[string]bool {
	return map[string]bool{"quick": true, "default": true, "full": true, "deep": true, "htb": true, "exposure": true, "admin": true, "api": true, "debug": true, "headers": true, "tls": true, "tech": true}
}

func validateProfile(p configProfile) error {
	if p.Mode != "" && !validModesSet()[lower(p.Mode)] {
		return fmt.Errorf("invalid mode %q", p.Mode)
	}
	if p.Severity != "" && !validSeverityName(p.Severity) {
		return fmt.Errorf("invalid severity %q", p.Severity)
	}
	if p.FailOn != "" && !validSeverityName(p.FailOn) {
		return fmt.Errorf("invalid fail-on severity %q", p.FailOn)
	}
	if p.Timeout != "" {
		if _, err := time.ParseDuration(p.Timeout); err != nil {
			return fmt.Errorf("invalid timeout %q", p.Timeout)
		}
	}
	if p.Concurrency < 0 || p.Concurrency > 512 {
		return fmt.Errorf("concurrency must be between 0 and 512")
	}
	if p.TargetConcurrency < 0 || p.TargetConcurrency > 64 {
		return fmt.Errorf("target-concurrency must be between 0 and 64")
	}
	if p.Rate < 0 || p.Rate > 10000 {
		return fmt.Errorf("rate must be between 0 and 10000")
	}
	if p.Retries < 0 || p.Retries > 5 {
		return fmt.Errorf("retries must be between 0 and 5")
	}
	return nil
}

// applyProfile resolves -profile: a built-in mode name keeps the legacy
// alias behavior, otherwise the name must exist in the config file.
// Explicitly set CLI flags always win over profile values.
func applyProfile(opts *options, cfg configData, set map[string]bool) error {
	name := strings.TrimSpace(opts.Profile)
	if validModesSet()[lower(name)] {
		opts.Mode = lower(name)
		return nil
	}
	p, ok := cfg.Profiles[name]
	if !ok {
		return fmt.Errorf("unknown profile %q (not a built-in mode or config profile; run: hawkprobe config show)", name)
	}
	notSet := func(names ...string) bool {
		for _, n := range names {
			if set[n] {
				return false
			}
		}
		return true
	}
	if p.Mode != "" && notSet("mode") {
		if !validModesSet()[lower(p.Mode)] {
			return fmt.Errorf("profile %q has invalid mode %q", name, p.Mode)
		}
		opts.Mode = lower(p.Mode)
	}
	if p.Category != "" && notSet("category") {
		opts.CategoryFilter = p.Category
	}
	if p.Tag != "" && notSet("tag") {
		opts.TagFilter = p.Tag
	}
	if p.Severity != "" && notSet("severity") {
		if !validSeverityName(p.Severity) {
			return fmt.Errorf("profile %q has invalid severity %q", name, p.Severity)
		}
		opts.MinSeverity = p.Severity
	}
	if p.FailOn != "" && notSet("fail-on") {
		opts.FailOn = p.FailOn
	}
	if p.Concurrency > 0 && notSet("c") {
		opts.Concurrency = p.Concurrency
	}
	if p.TargetConcurrency > 0 && notSet("target-c") {
		opts.TargetConcurrency = p.TargetConcurrency
	}
	if p.Rate > 0 && notSet("rate") {
		opts.Rate = p.Rate
	}
	if p.Retries > 0 && notSet("retries") {
		opts.Retries = p.Retries
	}
	if p.MaxRequests > 0 && notSet("max-requests") {
		opts.MaxRequests = p.MaxRequests
	}
	if p.Timeout != "" && notSet("timeout") {
		d, err := time.ParseDuration(p.Timeout)
		if err != nil {
			return fmt.Errorf("profile %q has invalid timeout %q", name, p.Timeout)
		}
		opts.Timeout = d
	}
	if p.Wordlist != "" && notSet("wordlist", "seclists") {
		opts.Wordlist = p.Wordlist
	}
	if p.Extensions != "" && notSet("ext") {
		opts.Extensions = p.Extensions
	}
	if p.Discover && notSet("discover") {
		opts.Discover = true
	}
	if p.Insecure && notSet("k") {
		opts.Insecure = true
	}
	if p.Suppressions != "" && notSet("suppressions") {
		opts.Suppressions = p.Suppressions
	}
	if p.CustomRules != "" && notSet("custom-rules") {
		opts.CustomRules = p.CustomRules
	}
	if p.AI && notSet("ai") {
		opts.AI = true
	}
	if p.AIModel != "" && notSet("ai-model") {
		opts.AIModel = p.AIModel
	}
	return nil
}

func handleConfigCommand(args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: hawkprobe config path|show|set|rm\n  hawkprobe config set <name> '{\"mode\":\"htb\",\"rate\":100}'")
		os.Exit(2)
	}
	switch args[1] {
	case "path":
		fmt.Println(configPath())
	case "show":
		cfg, err := loadConfig()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		path := configPath()
		if _, err := os.Stat(path); err != nil {
			fmt.Printf("no config file at %s\n", path)
			fmt.Printf("create one with: hawkprobe config set <name> '{\"mode\":\"htb\",\"rate\":100}'\n")
			return
		}
		data, _ := json.MarshalIndent(cfg, "", "  ")
		fmt.Printf("# %s\n%s\n", path, string(data))
	case "set":
		if len(args) < 4 {
			fmt.Fprintln(os.Stderr, "usage: hawkprobe config set <name> '<json object>'")
			os.Exit(2)
		}
		name := args[2]
		var profile configProfile
		if err := json.Unmarshal([]byte(args[3]), &profile); err != nil {
			fmt.Fprintf(os.Stderr, "invalid profile JSON: %v\n", err)
			os.Exit(2)
		}
		if strings.TrimSpace(args[3]) == "null" {
			fmt.Fprintln(os.Stderr, "profile JSON must be an object, e.g. {\"mode\":\"htb\"}")
			os.Exit(2)
		}
		if err := validateProfile(profile); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		cfg, err := loadConfig()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if cfg.Profiles == nil {
			cfg.Profiles = map[string]configProfile{}
		}
		cfg.Profiles[name] = profile
		if err := saveConfig(cfg); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		fmt.Printf("saved profile %q to %s\n", name, configPath())
	case "rm":
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: hawkprobe config rm <name>")
			os.Exit(2)
		}
		cfg, err := loadConfig()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if _, ok := cfg.Profiles[args[2]]; !ok {
			fmt.Fprintf(os.Stderr, "profile %q not found\n", args[2])
			os.Exit(2)
		}
		delete(cfg.Profiles, args[2])
		if err := saveConfig(cfg); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		fmt.Printf("removed profile %q\n", args[2])
	default:
		fmt.Fprintln(os.Stderr, "usage: hawkprobe config path|show|set|rm")
		os.Exit(2)
	}
}
