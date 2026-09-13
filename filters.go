package main

import (
	"fmt"
	"sort"
	"strings"
)

func filterRules(rules []rule, categories, tags string) []rule {
	categorySet := csvSet(categories)
	tagSet := csvSet(tags)
	if len(categorySet) == 0 && len(tagSet) == 0 {
		return rules
	}
	out := make([]rule, 0, len(rules))
	for _, r := range rules {
		if len(categorySet) > 0 {
			if _, ok := categorySet[lower(r.Category)]; !ok {
				continue
			}
		}
		if len(tagSet) > 0 && !ruleHasAnyTag(r, tagSet) {
			continue
		}
		out = append(out, r)
	}
	return out
}

func filterResultSeverity(results []scanResult, minimum string) []scanResult {
	minimum = lower(minimum)
	if minimum == "" || minimum == "info" {
		return results
	}
	threshold := parseSeverity(minimum)
	for i := range results {
		filtered := results[i].Findings[:0]
		for _, f := range results[i].Findings {
			if f.Severity >= threshold {
				filtered = append(filtered, f)
			}
		}
		results[i].Findings = filtered
	}
	return results
}

func validSeverityName(value string) bool {
	switch lower(value) {
	case "", "info", "low", "medium", "med", "high", "critical", "crit":
		return true
	default:
		return false
	}
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

func ruleHasAnyTag(r rule, wanted map[string]struct{}) bool {
	for _, tag := range r.Tags {
		if _, ok := wanted[lower(tag)]; ok {
			return true
		}
	}
	return false
}

func printRuleStats() {
	counts := map[string]int{}
	for _, r := range builtinRules {
		category := r.Category
		if category == "" {
			category = "general"
		}
		counts[category]++
	}
	categories := make([]string, 0, len(counts))
	for category := range counts {
		categories = append(categories, category)
	}
	sort.Strings(categories)
	fmt.Printf("%d built-in rules\n", len(builtinRules))
	for _, category := range categories {
		fmt.Printf("  %-14s %d\n", category, counts[category])
	}
}
