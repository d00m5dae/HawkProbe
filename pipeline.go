package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func loadInputTargets(opts options) ([]string, error) {
	var raw []string
	if opts.Target != "" || opts.ListFile != "" {
		targets, err := loadTargets(opts.Target, opts.ListFile)
		if err != nil {
			return nil, err
		}
		raw = append(raw, targets...)
	}
	if opts.NmapFile != "" {
		targets, err := loadNmapTargets(opts.NmapFile)
		if err != nil {
			return nil, err
		}
		raw = append(raw, targets...)
	}
	if opts.ReadStdin {
		targets, err := loadTargetsFromReader(bufio.NewScanner(os.Stdin))
		if err != nil {
			return nil, err
		}
		raw = append(raw, targets...)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("provide a target, -list, -nmap, or -stdin")
	}
	return uniqueStrings(raw), nil
}

func loadTargetsFromReader(s *bufio.Scanner) ([]string, error) {
	seen := make(map[string]bool)
	var out []string
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		t, err := normalizeTarget(line)
		if err != nil {
			continue
		}
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out, s.Err()
}

func filterRulesForOptions(rules []rule, opts options) []rule {
	minimum := parseSeverity(opts.MinSeverity)
	out := make([]rule, 0, len(rules))
	for _, r := range rules {
		if opts.MinSeverity != "" && parseSeverity(r.Severity) < minimum {
			continue
		}
		if opts.Category != "" && !strings.EqualFold(r.Category, opts.Category) {
			continue
		}
		if opts.IncludeTag != "" && !hasTag(r.Tags, opts.IncludeTag) {
			continue
		}
		if opts.ExcludeTag != "" && hasTag(r.Tags, opts.ExcludeTag) {
			continue
		}
		out = append(out, r)
	}
	return out
}

func filterFindingsForOptions(findings []finding, opts options) []finding {
	if opts.MinSeverity == "" && opts.Category == "" {
		return findings
	}
	minimum := parseSeverity(opts.MinSeverity)
	out := findings[:0]
	for _, f := range findings {
		if opts.MinSeverity != "" && f.Severity < minimum {
			continue
		}
		if opts.Category != "" && f.Category != "" && !strings.EqualFold(f.Category, opts.Category) {
			continue
		}
		out = append(out, f)
	}
	return out
}

func validateSeverityName(value string) error {
	if value == "" {
		return nil
	}
	switch lower(value) {
	case "info", "low", "medium", "med", "high", "critical", "crit":
		return nil
	default:
		return fmt.Errorf("invalid severity %q", value)
	}
}

func resultsMeetFailThreshold(results []scanResult, threshold string) bool {
	if threshold == "" {
		return false
	}
	min := parseSeverity(threshold)
	for _, result := range results {
		for _, f := range result.Findings {
			if f.Severity >= min {
				return true
			}
		}
	}
	return false
}
