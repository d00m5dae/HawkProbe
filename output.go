package main

import (
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
	if opts.URLsOut != "" {
		if err := writeResultURLs(results, opts.URLsOut); err != nil {
			return err
		}
	}

	if opts.Bundle != "" {
		return writeBundle(opts.Bundle, results)
	}

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

	if opts.SARIF {
		return outputSARIF(w, results)
	}
	if opts.CSV {
		return outputCSV(w, results)
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
	if opts.HTML {
		return outputHTML(w, results)
	}
	if opts.Markdown {
		return outputMarkdown(w, results)
	}

	useColor := colorEnabled(opts, w)
	if opts.Quiet {
		return outputQuiet(w, results, useColor)
	}

	for i, r := range results {
		if i > 0 {
			fmt.Fprintln(w)
		}
		header := r.Target
		if r.Status != "" {
			header += "  " + r.Status
		}
		fmt.Fprintln(w, colorize(useColor, ansiBold+ansiCyan, header))
		if r.Error != "" {
			fmt.Fprintf(w, "%s %s\n", colorize(useColor, ansiRed, "[error]"), r.Error)
			continue
		}
		if len(r.Findings) == 0 {
			line := colorize(useColor, ansiDim, "no findings")
			if r.Suppressed > 0 {
				line += colorize(useColor, ansiDim, fmt.Sprintf(" (%d suppressed)", r.Suppressed))
			}
			fmt.Fprintln(w, line)
		} else {
			printGroupedFindings(w, r, useColor, opts.Evidence)
		}
		if r.AISummary != "" {
			printWrappedLine(w, colorize(useColor, ansiDim, "ai: ")+r.AISummary)
		}
		summary := fmt.Sprintf("%d rules · %d requests · %d findings · %d clean · %d skipped · %.2fs", r.RulesChecked, r.Requests, len(r.Findings), r.NoMatch, r.Skipped, float64(r.DurationMS)/1000)
		if r.Suppressed > 0 {
			summary += fmt.Sprintf(" · %d suppressed", r.Suppressed)
		}
		fmt.Fprintf(w, "\n%s\n", colorize(useColor, ansiDim, summary))
	}
	printOverallSummary(w, results, useColor)
	return nil
}

func printGroupedFindings(w io.Writer, r scanResult, useColor, evidence bool) {
	byCategory := map[string][]finding{}
	var order []string
	uncategorized := []finding{}
	for _, finding := range r.Findings {
		if finding.Category == "" {
			uncategorized = append(uncategorized, finding)
			continue
		}
		if _, ok := byCategory[finding.Category]; !ok {
			order = append(order, finding.Category)
		}
		byCategory[finding.Category] = append(byCategory[finding.Category], finding)
	}
	for _, finding := range uncategorized {
		printFindingLine(w, finding, useColor, "", r.Target, evidence)
	}
	for _, category := range order {
		count := len(byCategory[category])
		fmt.Fprintf(w, "  %s%s\n", colorize(useColor, ansiBold, category), colorize(useColor, ansiDim, fmt.Sprintf(" (%d)", count)))
		for _, finding := range byCategory[category] {
			printFindingLine(w, finding, useColor, "  ", r.Target, evidence)
		}
	}
}

func printFindingLine(w io.Writer, finding finding, useColor bool, indent, target string, evidence bool) {
	prefix := colorize(useColor, severityColor(finding.Severity), "["+finding.Level+"]")
	if finding.Category != "" {
		category := colorize(useColor, ansiDim, "["+finding.Category+"]")
		fmt.Fprintf(w, "%s%-15s %-20s %s", indent, prefix, category, finding.Message)
	} else {
		fmt.Fprintf(w, "%s%-15s %s", indent, prefix, finding.Message)
	}
	if finding.URL != "" && finding.URL != target {
		fmt.Fprintf(w, "  %s", finding.URL)
	}
	fmt.Fprintln(w)
	if evidence && finding.Evidence != "" {
		fmt.Fprintf(w, "%s      %s %s\n", indent, colorize(useColor, ansiDim, "evidence:"), finding.Evidence)
	}
	if evidence && finding.Remediation != "" {
		fmt.Fprintf(w, "%s      %s %s\n", indent, colorize(useColor, ansiDim, "fix:"), finding.Remediation)
	}
}

func printOverallSummary(w io.Writer, results []scanResult, useColor bool) {
	if len(results) < 2 {
		return
	}
	counts := map[severity]int{}
	findings := 0
	errors := 0
	totalMS := int64(0)
	for _, r := range results {
		totalMS += r.DurationMS
		if r.Error != "" {
			errors++
		}
		for _, f := range r.Findings {
			counts[f.Severity]++
			findings++
		}
	}
	var parts []string
	for _, sev := range []severity{critical, high, medium, low, info} {
		if n := counts[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev.String()))
		}
	}
	line := fmt.Sprintf("%d targets · %d findings", len(results), findings)
	if len(parts) > 0 {
		line += " (" + strings.Join(parts, ", ") + ")"
	}
	if errors > 0 {
		line += fmt.Sprintf(" · %d errors", errors)
	}
	line += fmt.Sprintf(" · %.1fs total", float64(totalMS)/1000)
	fmt.Fprintln(w)
	fmt.Fprintln(w, colorize(useColor, ansiDim, strings.Repeat("─", 40)))
	fmt.Fprintln(w, colorize(useColor, ansiBold, line))
}

func printWrappedLine(w io.Writer, line string) {
	fmt.Fprintf(w, "%s\n", line)
}

func outputQuiet(w io.Writer, results []scanResult, useColor bool) error {
	for _, r := range results {
		if r.Error != "" {
			fmt.Fprintf(w, "%s %s %s\n", r.Target, colorize(useColor, ansiRed, "[error]"), r.Error)
			continue
		}
		for _, finding := range r.Findings {
			prefix := colorize(useColor, severityColor(finding.Severity), "["+finding.Level+"]")
			url := finding.URL
			if url == "" {
				url = r.Target
			}
			fmt.Fprintf(w, "%s %s %s\n", prefix, url, finding.Message)
		}
	}
	return nil
}
