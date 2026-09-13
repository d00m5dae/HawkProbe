package main

import (
	"fmt"
	"hash/fnv"
	"strings"
)

// The go command presents package files in lexical filename order, so this
// finalizer runs after the generated catalog has been appended.
func init() {
	ensureUniqueBuiltinRuleIDs(builtinRules)
}

func ensureUniqueBuiltinRuleIDs(rules []rule) {
	seen := make(map[string]struct{}, len(rules))
	for i := range rules {
		id := rules[i].ID
		if _, exists := seen[id]; !exists {
			seen[id] = struct{}{}
			continue
		}

		base := id + "-" + shortRuleID(rules[i])
		candidate := base
		for n := 2; ; n++ {
			if _, exists := seen[candidate]; !exists {
				break
			}
			candidate = fmt.Sprintf("%s-%d", base, n)
		}
		rules[i].ID = candidate
		seen[candidate] = struct{}{}
	}
}

func shortRuleID(r rule) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(strings.ToUpper(r.Method)))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(r.Path))
	return fmt.Sprintf("%08x", h.Sum32())
}
