package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
)

func sortFindings(findings []finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Severity == findings[j].Severity {
			if findings[i].Message == findings[j].Message {
				return findings[i].URL < findings[j].URL
			}
			return findings[i].Message < findings[j].Message
		}
		return findings[i].Severity > findings[j].Severity
	})
}

func outputResults(results []scanResult, opts options) error {
	var w io.Writer = os.Stdout
	var f *os.File
	if opts.Output != "" {
		var err error
		f, err = os.Create(opts.Output)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	if opts.JSONL {
		enc := json.NewEncoder(w)
		for _, r := range results {
			if err := enc.Encode(r); err != nil {
				return err
			}
		}
		return nil
	}
	if opts.JSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if len(results) == 1 {
			return enc.Encode(results[0])
		}
		return enc.Encode(results)
	}
	for i, r := range results {
		if i > 0 {
			fmt.Fprintln(w)
		}
		fmt.Fprintf(w, "%s", r.Target)
		if r.Status != "" {
			fmt.Fprintf(w, "  %s", r.Status)
		}
		fmt.Fprintln(w)
		if r.Error != "" {
			fmt.Fprintf(w, "[error] %s\n", r.Error)
			continue
		}
		if len(r.Findings) == 0 {
			fmt.Fprintln(w, "no findings")
		} else {
			for _, finding := range r.Findings {
				fmt.Fprintf(w, "%-6s %s", "["+finding.Level+"]", finding.Message)
				if finding.URL != "" && finding.URL != r.Target {
					fmt.Fprintf(w, "  %s", finding.URL)
				}
				fmt.Fprintln(w)
			}
		}
		fmt.Fprintf(w, "\n%d requests in %.2fs\n", r.Requests, float64(r.DurationMS)/1000)
	}
	return nil
}
