package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var secListsPresets = map[string]string{
	"common":       "Discovery/Web-Content/common.txt",
	"quick":        "Discovery/Web-Content/common.txt",
	"combined":     "Discovery/Web-Content/combined_directories.txt",
	"dirs-small":   "Discovery/Web-Content/raft-small-directories.txt",
	"dirs-medium":  "Discovery/Web-Content/raft-medium-directories.txt",
	"dirs-large":   "Discovery/Web-Content/raft-large-directories.txt",
	"words-small":  "Discovery/Web-Content/raft-small-words.txt",
	"words-medium": "Discovery/Web-Content/raft-medium-words.txt",
	"words-large":  "Discovery/Web-Content/raft-large-words.txt",
	"files-small":  "Discovery/Web-Content/raft-small-files.txt",
	"files-medium": "Discovery/Web-Content/raft-medium-files.txt",
	"files-large":  "Discovery/Web-Content/raft-large-files.txt",
	"graphql":      "Discovery/Web-Content/graphql.txt",
	"mcp":          "Discovery/Web-Content/mcp-server.txt",
	"apache":       "Discovery/Web-Content/Apache.fuzz.txt",
}

func resolveWordlistSpec(spec string) (string, error) {
	spec = strings.TrimSpace(spec)
	if !strings.HasPrefix(spec, "@") && !strings.HasPrefix(strings.ToLower(spec), "seclists:") {
		return spec, nil
	}

	name := strings.TrimPrefix(spec, "@")
	name = strings.TrimPrefix(strings.ToLower(name), "seclists:")
	rel, ok := secListsPresets[name]
	if !ok {
		return "", fmt.Errorf("unknown SecLists preset %q; try @common, @dirs-small, @dirs-medium, @dirs-large, @combined, @graphql, or @mcp", name)
	}
	root := findSecListsRoot()
	if root == "" {
		return "", fmt.Errorf("SecLists not found; install it or set SECLISTS_PATH")
	}
	path := filepath.Join(root, filepath.FromSlash(rel))
	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("SecLists preset %q not found at %s", name, path)
	}
	return path, nil
}

func findSecListsRoot() string {
	var roots []string
	if env := strings.TrimSpace(os.Getenv("SECLISTS_PATH")); env != "" {
		roots = append(roots, env)
	}
	if home, err := os.UserHomeDir(); err == nil {
		roots = append(roots, filepath.Join(home, "SecLists"), filepath.Join(home, "seclists"))
	}
	roots = append(roots,
		"/usr/share/seclists",
		"/usr/local/share/seclists",
		"/opt/SecLists",
		"/opt/seclists",
	)
	for _, root := range roots {
		if info, err := os.Stat(root); err == nil && info.IsDir() {
			return root
		}
	}
	return ""
}

func secListsPresetNames() []string {
	names := make([]string, 0, len(secListsPresets))
	for name := range secListsPresets {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
