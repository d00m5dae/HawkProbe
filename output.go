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
			fmt.Fprintln(w, colorize(useColor, ansiDim, "no findings"))
		} else {
			for _, finding := range r.Findings {
				prefix := colorize(useColor, severityColor(finding.Severity), "["+finding.Level+"]")
				if finding.Category != "" {
					category := colorize(useColor, ansiDim, "["+finding.Category+"]")
					fmt.Fprintf(w, "%-15s %-20s %s", prefix, category, finding.Message)
				} else {
					fmt.Fprintf(w, "%-15s %s", prefix, finding.Message)
				}
				if finding.URL != "" && finding.URL != r.Target {
					fmt.Fprintf(w, "  %s", finding.URL)
				}
				fmt.Fprintln(w)
				if opts.Evidence && finding.Evidence != "" {
					fmt.Fprintf(w, "        %s %s\n", colorize(useColor, ansiDim, "evidence:"), finding.Evidence)
				}
				if opts.Evidence && finding.Remediation != "" {
					fmt.Fprintf(w, "        %s %s\n", colorize(useColor, ansiDim, "fix:"), finding.Remediation)
				}
			}
		}
		summary := fmt.Sprintf("%d rules · %d requests · %d findings · %d clean · %d skipped · %.2fs", r.RulesChecked, r.Requests, len(r.Findings), r.NoMatch, r.Skipped, float64(r.DurationMS)/1000)
		fmt.Fprintf(w, "\n%s\n", colorize(useColor, ansiDim, summary))
	}
	return nil
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
