package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var secListAliases = map[string]string{
	"common":           "Discovery/Web-Content/common.txt",
	"quickhits":        "Discovery/Web-Content/quickhits.txt",
	"raft-small":       "Discovery/Web-Content/raft-small-words.txt",
	"raft-medium":      "Discovery/Web-Content/raft-medium-words.txt",
	"raft-large":       "Discovery/Web-Content/raft-large-words.txt",
	"dirs-small":       "Discovery/Web-Content/directory-list-2.3-small.txt",
	"dirs-medium":      "Discovery/Web-Content/directory-list-2.3-medium.txt",
	"raft-small-dirs":  "Discovery/Web-Content/raft-small-directories.txt",
	"raft-medium-dirs": "Discovery/Web-Content/raft-medium-directories.txt",
	"raft-large-dirs":  "Discovery/Web-Content/raft-large-directories.txt",
}

func resolveSecList(alias string) (string, error) {
	alias = lower(alias)
	rel, ok := secListAliases[alias]
	if !ok {
		return "", fmt.Errorf("unknown SecLists alias %q (run 'hawkprobe wordlists')", alias)
	}
	for _, root := range secListRoots() {
		candidate := filepath.Join(root, filepath.FromSlash(rel))
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("SecLists %q was not found; install SecLists or set SECLISTS_PATH", alias)
}

func secListRoots() []string {
	var roots []string
	if root := strings.TrimSpace(os.Getenv("SECLISTS_PATH")); root != "" {
		roots = append(roots, root)
	}
	if home, err := os.UserHomeDir(); err == nil {
		roots = append(roots, filepath.Join(home, "SecLists"), filepath.Join(home, "seclists"))
	}
	roots = append(roots, "/usr/share/seclists", "/usr/share/SecLists", "/opt/SecLists", "/opt/seclists")
	seen := map[string]struct{}{}
	out := make([]string, 0, len(roots))
	for _, root := range roots {
		if _, ok := seen[root]; ok {
			continue
		}
		seen[root] = struct{}{}
		out = append(out, root)
	}
	return out
}

func printSecListAliases() {
	keys := make([]string, 0, len(secListAliases))
	for key := range secListAliases {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	fmt.Println("SecLists aliases:")
	for _, key := range keys {
		path, err := resolveSecList(key)
		if err == nil {
			fmt.Printf("  %-18s %s\n", key, path)
		} else {
			fmt.Printf("  %-18s %s (not found)\n", key, secListAliases[key])
		}
	}
	fmt.Println("\nSet SECLISTS_PATH if SecLists is installed somewhere else.")
}
