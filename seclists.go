package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var secListsPresets = map[string]string{
	"common":             "Discovery/Web-Content/common.txt",
	"raft-small":         "Discovery/Web-Content/raft-small-words.txt",
	"raft-medium":        "Discovery/Web-Content/raft-medium-words.txt",
	"raft-large":         "Discovery/Web-Content/raft-large-words.txt",
	"dirs-small":         "Discovery/Web-Content/raft-small-directories.txt",
	"dirs-medium":        "Discovery/Web-Content/raft-medium-directories.txt",
	"files-small":        "Discovery/Web-Content/raft-small-files.txt",
	"files-medium":       "Discovery/Web-Content/raft-medium-files.txt",
	"directory-list-2.3": "Discovery/Web-Content/directory-list-2.3-medium.txt",
}

func resolveSecListsWordlist(value, root string) (string, error) {
	if value == "" {
		return "", nil
	}
	if info, err := os.Stat(value); err == nil && !info.IsDir() {
		return value, nil
	}
	relative, ok := secListsPresets[lower(value)]
	if !ok {
		relative = strings.TrimLeft(value, "/")
	}
	for _, candidateRoot := range secListsRoots(root) {
		candidate := filepath.Join(candidateRoot, filepath.FromSlash(relative))
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("SecLists wordlist %q not found; set -seclists-root or SECLISTS_DIR", value)
}

func secListsRoots(explicit string) []string {
	var roots []string
	if explicit != "" {
		roots = append(roots, explicit)
	}
	if env := os.Getenv("SECLISTS_DIR"); env != "" {
		roots = append(roots, env)
	}
	if home, err := os.UserHomeDir(); err == nil {
		roots = append(roots, filepath.Join(home, "SecLists"), filepath.Join(home, "seclists"))
	}
	roots = append(roots, "/usr/share/seclists", "/usr/share/SecLists", "/opt/SecLists", "/opt/seclists")
	return uniqueStrings(roots)
}

func printSecListsPresets() {
	order := []string{"common", "raft-small", "raft-medium", "raft-large", "dirs-small", "dirs-medium", "files-small", "files-medium", "directory-list-2.3"}
	for _, name := range order {
		fmt.Printf("%-20s %s\n", name, secListsPresets[name])
	}
}
