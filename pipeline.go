package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
)

func writeResultURLs(results []scanResult, path string) error {
	seen := make(map[string]struct{})
	var urls []string
	add := func(value string) {
		if value == "" {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		urls = append(urls, value)
	}
	for _, result := range results {
		add(result.Target)
		for _, finding := range result.Findings {
			add(finding.URL)
		}
	}
	sort.Strings(urls)

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("urls-out: %w", err)
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, u := range urls {
		if _, err := fmt.Fprintln(w, u); err != nil {
			return err
		}
	}
	return w.Flush()
}
