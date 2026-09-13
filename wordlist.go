package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

const maxWordlistRules = 250000

func loadWordlistRules(path, extensions string) ([]rule, error) {
	resolved, err := resolveWordlistSpec(path)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(resolved)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var exts []string
	for _, ext := range strings.Split(extensions, ",") {
		ext = strings.TrimSpace(strings.TrimPrefix(ext, "."))
		if ext != "" {
			exts = append(exts, ext)
		}
	}

	seen := make(map[string]bool)
	out := make([]rule, 0, 4096)
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" || strings.ContainsAny(p, " \t") {
			return
		}
		p = "/" + strings.TrimLeft(p, "/")
		if p == "/" || seen[p] || len(out) >= maxWordlistRules {
			return
		}
		seen[p] = true
		id := fmt.Sprintf("wordlist-%d", len(out)+1)
		out = append(out, normalizeRule(rule{
			ID:         id,
			Path:       p,
			Name:       "discovered endpoint",
			Severity:   "info",
			Category:   "discovery",
			Confidence: "medium",
			Statuses:   []int{200, 204, 301, 302, 307, 308, 401, 403},
			Profile:    "full",
			Tags:       []string{"htb", "discovery"},
		}))
	}

	s := bufio.NewScanner(f)
	buf := make([]byte, 64*1024)
	s.Buffer(buf, 4*1024*1024)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		add(line)
		if !strings.HasSuffix(line, "/") && !strings.Contains(lastPathPart(line), ".") {
			for _, ext := range exts {
				add(line + "." + ext)
			}
		}
		if len(out) >= maxWordlistRules {
			break
		}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func lastPathPart(path string) string {
	path = strings.TrimRight(path, "/")
	if i := strings.LastIndex(path, "/"); i >= 0 {
		return path[i+1:]
	}
	return path
}
