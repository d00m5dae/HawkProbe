package main

import (
	"fmt"
	"sort"
)

func printRuleStats() {
	categories := make(map[string]int)
	severities := make(map[string]int)
	for _, r := range builtinRules {
		categories[r.Category]++
		severities[r.Severity]++
	}
	fmt.Printf("built-in rules: %d\n\n", len(builtinRules))
	fmt.Println("by category:")
	for _, key := range sortedCountKeys(categories) {
		fmt.Printf("  %-14s %d\n", key, categories[key])
	}
	fmt.Println("\nby severity:")
	for _, key := range []string{"critical", "high", "medium", "low", "info"} {
		if severities[key] > 0 {
			fmt.Printf("  %-14s %d\n", key, severities[key])
		}
	}
}

func sortedCountKeys(values map[string]int) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
