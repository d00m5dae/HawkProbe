package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

func sortFindings(findings []finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Severity == findings[j].Severity {
			if findings[i].Category == findings[j].Category {
				if findings[i].Message == findings[j].Message {
					return findings[i].URL < findings[j].URL
				}
				return findings[i].Message < findings[j].Message
			}
			return findings[i].Category < findings[j].Category
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

	switch opts.OutputFormat {
	case "jsonl":
		enc := json.NewEncoder(w)
		for _, r := range results {
			if err := enc.Encode(r); err != nil { return err }
		}
		return nil
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if len(results) == 1 { return enc.Encode(results[0]) }
		return enc.Encode(results)
	case "csv":
		return outputCSV(w, results)
	case "md", "markdown":
		return outputMarkdown(w, results)
	case "urls":
		return outputURLs(w, results)
	default:
		return outputText(w, results, opts)
	}
}

func outputText(w io.Writer, results []scanResult, opts options) error {
	for i, r := range results {
		if opts.Quiet {
			for _, finding := range r.Findings {
				fmt.Fprintf(w, "[%s] %s", finding.Level, finding.Message)
				if finding.URL != "" { fmt.Fprintf(w, "  %s", finding.URL) }
				fmt.Fprintln(w)
			}
			continue
		}
		if i > 0 { fmt.Fprintln(w) }
		fmt.Fprintf(w, "%s", r.Target)
		if r.Status != "" { fmt.Fprintf(w, "  %s", r.Status) }
		if r.Title != "" { fmt.Fprintf(w, "  %q", r.Title) }
		fmt.Fprintln(w)
		var meta []string
		if r.Server != "" { meta = append(meta, "server="+r.Server) }
		if r.ContentType != "" { meta = append(meta, "type="+r.ContentType) }
		if r.ContentLength > 0 { meta = append(meta, fmt.Sprintf("bytes=%d", r.ContentLength)) }
		if r.FinalURL != "" && r.FinalURL != r.Target { meta = append(meta, "final="+r.FinalURL) }
		if len(meta) > 0 { fmt.Fprintf(w, "  %s\n", strings.Join(meta, "  ")) }
		if r.Error != "" {
			fmt.Fprintf(w, "[error] %s\n", r.Error)
			continue
		}
		if len(r.Findings) == 0 {
			fmt.Fprintln(w, "no findings")
		} else {
			for _, finding := range r.Findings {
				prefix := "[" + finding.Level + "]"
				if finding.Category != "" {
					fmt.Fprintf(w, "%-6s %-13s %s", prefix, "["+finding.Category+"]", finding.Message)
				} else {
					fmt.Fprintf(w, "%-6s %s", prefix, finding.Message)
				}
				if finding.URL != "" && finding.URL != r.Target { fmt.Fprintf(w, "  %s", finding.URL) }
				fmt.Fprintln(w)
				if opts.Evidence && finding.Evidence != "" { fmt.Fprintf(w, "        evidence: %s\n", finding.Evidence) }
				if opts.Evidence && finding.Remediation != "" { fmt.Fprintf(w, "        fix: %s\n", finding.Remediation) }
			}
		}
		fmt.Fprintf(w, "\n%d rules checked, %d requests, %d findings, %d no-match, %d skipped in %.2fs\n", r.RulesChecked, r.Requests, len(r.Findings), r.NoMatch, r.Skipped, float64(r.DurationMS)/1000)
	}
	return nil
}

func outputCSV(w io.Writer, results []scanResult) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()
	if err := cw.Write([]string{"target", "status", "title", "server", "level", "category", "confidence", "rule", "message", "url", "evidence", "remediation"}); err != nil { return err }
	for _, r := range results {
		if len(r.Findings) == 0 {
			if err := cw.Write([]string{r.Target, r.Status, r.Title, r.Server, "", "", "", "", "", "", "", ""}); err != nil { return err }
			continue
		}
		for _, f := range r.Findings {
			if err := cw.Write([]string{r.Target, r.Status, r.Title, r.Server, f.Level, f.Category, f.Confidence, f.Rule, f.Message, f.URL, f.Evidence, f.Remediation}); err != nil { return err }
		}
	}
	return cw.Error()
}

func outputMarkdown(w io.Writer, results []scanResult) error {
	fmt.Fprintln(w, "| Target | Level | Category | Finding | URL |")
	fmt.Fprintln(w, "|---|---|---|---|---|")
	for _, r := range results {
		for _, f := range r.Findings {
			fmt.Fprintf(w, "| %s | %s | %s | %s | %s |\n", mdEscape(r.Target), mdEscape(f.Level), mdEscape(f.Category), mdEscape(f.Message), mdEscape(f.URL))
		}
	}
	return nil
}

func outputURLs(w io.Writer, results []scanResult) error {
	seen := map[string]struct{}{}
	for _, r := range results {
		for _, f := range r.Findings {
			u := f.URL
			if u == "" { u = r.Target }
			if _, ok := seen[u]; ok { continue }
			seen[u] = struct{}{}
			fmt.Fprintln(w, u)
		}
	}
	return nil
}

func mdEscape(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}
