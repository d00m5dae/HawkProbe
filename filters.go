package main

import "strings"

func filterRules(rules []rule, opts options) []rule {
	min := parseSeverity(opts.MinSeverity)
	include := csvSet(opts.IncludeCategory)
	exclude := csvSet(opts.ExcludeCategory)
	out := make([]rule, 0, len(rules))
	for _, r := range rules {
		if opts.MinSeverity != "" && parseSeverity(r.Severity) < min {
			continue
		}
		category := lower(r.Category)
		if len(include) > 0 {
			if _, ok := include[category]; !ok {
				continue
			}
		}
		if _, ok := exclude[category]; ok {
			continue
		}
		out = append(out, r)
	}
	return out
}

func csvSet(raw string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, item := range strings.Split(raw, ",") {
		item = lower(item)
		if item != "" {
			out[item] = struct{}{}
		}
	}
	return out
}

func ruleCategoryCounts(rules []rule) map[string]int {
	out := make(map[string]int)
	for _, r := range rules {
		category := r.Category
		if category == "" {
			category = "general"
		}
		out[category]++
	}
	return out
}
