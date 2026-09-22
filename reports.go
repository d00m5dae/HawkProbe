package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type severityCounts map[severity]int

func countFindings(results []scanResult) (severityCounts, int, int) {
	counts := severityCounts{}
	findings := 0
	errors := 0
	for _, r := range results {
		if r.Error != "" {
			errors++
		}
		for _, f := range r.Findings {
			counts[f.Severity]++
			findings++
		}
	}
	return counts, findings, errors
}

func severityBadgeHTML(counts severityCounts) string {
	var parts []string
	for _, sev := range []severity{critical, high, medium, low, info} {
		if n := counts[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf(`<span class="badge b-%s">%d %s</span>`, sev.String(), n, sev.String()))
		}
	}
	if len(parts) == 0 {
		return `<span class="badge b-none">0 findings</span>`
	}
	return strings.Join(parts, " ")
}

const htmlReportCSS = `
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;margin:2rem auto;max-width:1100px;padding:0 1rem;color:#1c2128;line-height:1.5}
h1{border-bottom:2px solid #d0d7de;padding-bottom:.4rem}
h2{margin-top:2rem;border-bottom:1px solid #d0d7de;padding-bottom:.3rem}
.meta{color:#57606a}
.badge{display:inline-block;padding:.15rem .5rem;border-radius:999px;font-size:.8rem;font-weight:600;margin-right:.4rem}
.b-crit{background:#8250df22;color:#8250df;border:1px solid #8250df}
.b-high{background:#cf222e1a;color:#cf222e;border:1px solid #cf222e}
.b-med{background:#bf87001a;color:#9a6700;border:1px solid #bf8700}
.b-low{background:#0969da1a;color:#0969da;border:1px solid #0969da}
.b-info{background:#57606a1a;color:#57606a;border:1px solid #57606a}
.b-none{background:#1a7f371a;color:#1a7f37;border:1px solid #1a7f37}
table{border-collapse:collapse;width:100%;margin:.6rem 0 1rem;font-size:.9rem}
th,td{border:1px solid #d0d7de;padding:.4rem .6rem;text-align:left;vertical-align:top}
th{background:#f6f8fa}
.sev-crit{color:#8250df;font-weight:600}
.sev-high{color:#cf222e;font-weight:600}
.sev-med{color:#9a6700;font-weight:600}
.sev-low{color:#0969da}
.sev-info{color:#57606a}
.stats{color:#57606a;font-size:.85rem}
.error{color:#cf222e}
details{margin:.3rem 0}
code{background:#f6f8fa;padding:.1rem .3rem;border-radius:4px}
`

func outputHTML(w io.Writer, results []scanResult) error {
	counts, findings, errors := countFindings(results)
	var b strings.Builder
	b.WriteString("<!doctype html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n")
	b.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
	b.WriteString("<title>HawkProbe scan report</title>\n")
	b.WriteString("<style>" + htmlReportCSS + "</style>\n</head>\n<body>\n")
	b.WriteString("<h1>HawkProbe scan report</h1>\n")
	b.WriteString(fmt.Sprintf("<p class=\"meta\">generated %s · %d targets · %d findings · %d errors · HawkProbe %s</p>\n",
		time.Now().UTC().Format(time.RFC3339), len(results), findings, errors, version))
	b.WriteString("<p>" + severityBadgeHTML(counts) + "</p>\n")
	for _, r := range results {
		b.WriteString("<section>\n")
		b.WriteString("<h2>" + html.EscapeString(r.Target))
		if r.Status != "" {
			b.WriteString(" <small>(" + html.EscapeString(r.Status) + ")</small>")
		}
		b.WriteString("</h2>\n")
		stats := fmt.Sprintf("%d requests · %d rules checked · %d findings · %d clean · %d skipped · %.2fs",
			r.Requests, r.RulesChecked, len(r.Findings), r.NoMatch, r.Skipped, float64(r.DurationMS)/1000)
		if r.Suppressed > 0 {
			stats += fmt.Sprintf(" · %d suppressed", r.Suppressed)
		}
		b.WriteString("<p class=\"stats\">" + html.EscapeString(stats) + "</p>\n")
		if r.Error != "" {
			b.WriteString("<p class=\"error\">" + html.EscapeString(r.Error) + "</p>\n")
		}
		if r.AISummary != "" {
			b.WriteString("<p><strong>AI summary:</strong> " + html.EscapeString(r.AISummary) + "</p>\n")
		}
		if len(r.Findings) > 0 {
			b.WriteString("<table>\n<tr><th>severity</th><th>category</th><th>finding</th><th>url</th><th>details</th></tr>\n")
			for _, f := range r.Findings {
				details := ""
				if f.Evidence != "" {
					details = html.EscapeString(f.Evidence)
				}
				if f.Remediation != "" {
					if details != "" {
						details += "<br>"
					}
					details += "fix: " + html.EscapeString(f.Remediation)
				}
				if f.Confidence != "" {
					if details != "" {
						details += "<br>"
					}
					details += "confidence: " + html.EscapeString(f.Confidence)
				}
				b.WriteString(fmt.Sprintf("<tr><td class=\"sev-%s\">%s</td><td>%s</td><td>%s</td><td><code>%s</code></td><td>%s</td></tr>\n",
					f.Severity.String(), f.Severity.String(),
					html.EscapeString(f.Category), html.EscapeString(f.Message),
					html.EscapeString(f.URL), details))
			}
			b.WriteString("</table>\n")
		}
		b.WriteString("</section>\n")
	}
	b.WriteString("</body>\n</html>\n")
	_, err := io.WriteString(w, b.String())
	return err
}

func outputMarkdown(w io.Writer, results []scanResult) error {
	counts, findings, errors := countFindings(results)
	var b strings.Builder
	b.WriteString("# HawkProbe scan report\n\n")
	b.WriteString(fmt.Sprintf("- Generated: %s\n", time.Now().UTC().Format(time.RFC3339)))
	b.WriteString(fmt.Sprintf("- Targets: %d\n", len(results)))
	b.WriteString(fmt.Sprintf("- Findings: %d\n", findings))
	b.WriteString(fmt.Sprintf("- Errors: %d\n", errors))
	b.WriteString(fmt.Sprintf("- HawkProbe: %s\n\n", version))
	b.WriteString("## Summary\n\n")
	b.WriteString("| severity | count |\n| --- | --- |\n")
	for _, sev := range []severity{critical, high, medium, low, info} {
		if n := counts[sev]; n > 0 {
			b.WriteString(fmt.Sprintf("| %s | %d |\n", sev.String(), n))
		}
	}
	if findings == 0 {
		b.WriteString("| none | 0 |\n")
	}
	b.WriteString("\n")
	for _, r := range results {
		b.WriteString("## " + r.Target)
		if r.Status != "" {
			b.WriteString(" (" + r.Status + ")")
		}
		b.WriteString("\n\n")
		stats := fmt.Sprintf("%d requests · %d rules checked · %d findings · %d clean · %d skipped · %.2fs",
			r.Requests, r.RulesChecked, len(r.Findings), r.NoMatch, r.Skipped, float64(r.DurationMS)/1000)
		if r.Suppressed > 0 {
			stats += fmt.Sprintf(" · %d suppressed", r.Suppressed)
		}
		b.WriteString(fmt.Sprintf("Stats: %s\n\n", stats))
		if r.Error != "" {
			b.WriteString(fmt.Sprintf("**Error:** %s\n\n", r.Error))
		}
		if r.AISummary != "" {
			b.WriteString("**AI summary:** " + r.AISummary + "\n\n")
		}
		if len(r.Findings) == 0 {
			b.WriteString("No findings.\n\n")
			continue
		}
		byCategory := map[string][]finding{}
		var order []string
		for _, f := range r.Findings {
			cat := f.Category
			if cat == "" {
				cat = "general"
			}
			if _, ok := byCategory[cat]; !ok {
				order = append(order, cat)
			}
			byCategory[cat] = append(byCategory[cat], f)
		}
		for _, cat := range order {
			b.WriteString("### " + cat + "\n\n")
			b.WriteString("| severity | message | url | confidence |\n| --- | --- | --- | --- |\n")
			for _, f := range byCategory[cat] {
				b.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n",
					f.Severity.String(), mdEscape(f.Message), mdEscape(f.URL), mdEscape(f.Confidence)))
			}
			b.WriteString("\n")
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func mdEscape(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}

func writeBundle(dir string, results []scanResult) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("bundle: %w", err)
	}
	writers := []struct {
		name  string
		write func(io.Writer, []scanResult) error
	}{
		{"report.html", outputHTML},
		{"report.md", outputMarkdown},
		{"findings.csv", outputCSV},
		{"hawkprobe.sarif", outputSARIF},
	}
	for _, item := range writers {
		path := filepath.Join(dir, item.name)
		f, err := os.Create(path)
		if err != nil {
			return fmt.Errorf("bundle %s: %w", item.name, err)
		}
		err = item.write(f, results)
		f.Close()
		if err != nil {
			return fmt.Errorf("bundle %s: %w", item.name, err)
		}
	}
	// JSON results (pretty).
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if len(results) == 1 {
		if err := enc.Encode(results[0]); err != nil {
			return fmt.Errorf("bundle results.json: %w", err)
		}
	} else {
		if err := enc.Encode(results); err != nil {
			return fmt.Errorf("bundle results.json: %w", err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "results.json"), buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("bundle results.json: %w", err)
	}
	// JSONL for tooling.
	var jl bytes.Buffer
	jlEnc := json.NewEncoder(&jl)
	for _, r := range results {
		if err := jlEnc.Encode(r); err != nil {
			return fmt.Errorf("bundle results.jsonl: %w", err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "results.jsonl"), jl.Bytes(), 0o644); err != nil {
		return fmt.Errorf("bundle results.jsonl: %w", err)
	}
	return nil
}
