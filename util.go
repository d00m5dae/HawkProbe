package main

import (
	"bufio"
	"errors"
	"net/url"
	"os"
	"strings"
)

type headerList []string

func (h *headerList) String() string { return strings.Join(*h, ", ") }
func (h *headerList) Set(v string) error {
	if !strings.Contains(v, ":") {
		return errors.New("header must be 'Name: value'")
	}
	*h = append(*h, v)
	return nil
}

func normalizeTarget(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("empty target")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", errors.New("invalid target")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errors.New("target must use http or https")
	}
	u.Fragment = ""
	return strings.TrimRight(u.String(), "/"), nil
}

func loadTargets(single, listFile string) ([]string, error) {
	var raw []string
	if single != "" {
		raw = append(raw, single)
	}
	if listFile != "" {
		f, err := os.Open(listFile)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		s := bufio.NewScanner(f)
		for s.Scan() {
			line := strings.TrimSpace(s.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			raw = append(raw, line)
		}
		if err := s.Err(); err != nil {
			return nil, err
		}
	}
	if len(raw) == 0 {
		return nil, errors.New("one target or -list file is required")
	}
	seen := make(map[string]bool)
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		t, err := normalizeTarget(item)
		if err != nil {
			return nil, err
		}
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out, nil
}

func lower(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func containsAny(haystack string, needles []string) bool {
	if len(needles) == 0 {
		return true
	}
	h := strings.ToLower(haystack)
	for _, n := range needles {
		if strings.Contains(h, strings.ToLower(n)) {
			return true
		}
	}
	return false
}

func containsNone(haystack string, needles []string) bool {
	h := strings.ToLower(haystack)
	for _, n := range needles {
		if strings.Contains(h, strings.ToLower(n)) {
			return false
		}
	}
	return true
}

func statusAllowed(status int, allowed []int) bool {
	for _, code := range allowed {
		if status == code {
			return true
		}
	}
	return false
}
