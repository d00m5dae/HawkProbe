package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func loadWordlistRules(path, extensions string, limits ...int) ([]rule, error) {
	limit := 50000
	if len(limits) > 0 && limits[0] > 0 {
		limit = limits[0]
	}
	f, err := os.Open(path)
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
	out := make([]rule, 0, minInt(limit, 4096))
	add := func(p string) {
		p = "/" + strings.TrimLeft(strings.TrimSpace(p), "/")
		if p == "/" || seen[p] || len(out) >= limit {
			return
		}
		seen[p] = true
		id := fmt.Sprintf("wordlist-%d", len(out)+1)
		out = append(out, normalizeRule(rule{ID: id, Path: p, Name: "wordlist endpoint", Severity: "info", Category: "discovery", Confidence: "medium", Statuses: []int{200, 301, 302, 307, 308, 401, 403}, Profile: "full", Tags: []string{"htb"}}))
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
		if len(out) >= limit {
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
