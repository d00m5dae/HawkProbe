package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func renderToTempFile(t *testing.T, results []scanResult, mutate func(*options)) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "out.txt")
	opts := options{NoColor: true, NoProgress: true, Output: path}
	if mutate != nil {
		mutate(&opts)
	}
	if err := outputResults(results, opts); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func groupedSampleResults() []scanResult {
	return []scanResult{{
		Target:       "https://example.test",
		Status:       "200 OK",
		Requests:     40,
		DurationMS:   1200,
		RulesChecked: 40,
		Findings: []finding{
			{Severity: high, Level: "high", Rule: "env", Category: "config", Message: "exposed environment file", URL: "https://example.test/.env", Evidence: "HTTP 200", Remediation: "remove it"},
			{Severity: medium, Level: "med", Rule: "phpinfo", Category: "debug", Message: "phpinfo page exposed", URL: "https://example.test/info.php"},
			{Severity: high, Level: "high", Rule: "backup-zip", Category: "backup", Message: "public backup archive", URL: "https://example.test/backup.zip"},
			{Severity: info, Level: "info", Rule: "server", Message: "server banner discloses version", URL: "https://example.test"},
		},
	}, {
		Target:     "https://other.test",
		Status:     "200 OK",
		Requests:   10,
		DurationMS: 300,
		Findings:   []finding{},
	}}
}

func TestGroupedTerminalOutput(t *testing.T) {
	out := renderToTempFile(t, groupedSampleResults(), nil)
	for _, want := range []string{"config (1)", "debug (1)", "backup (1)", "exposed environment file", "https://example.test/.env"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
	// Evidence only shows with -evidence.
	if strings.Contains(out, "evidence:") {
		t.Fatalf("evidence should be hidden without -evidence:\n%s", out)
	}
	// Uncategorized finding must not be under a category header.
	if !strings.Contains(out, "server banner discloses version") {
		t.Fatalf("uncategorized finding missing:\n%s", out)
	}
	// Overall summary only with multiple targets.
	if !strings.Contains(out, "2 targets") || !strings.Contains(out, "4 findings") {
		t.Fatalf("overall summary missing:\n%s", out)
	}
}

func TestGroupedTerminalOutputEvidence(t *testing.T) {
	out := renderToTempFile(t, groupedSampleResults(), func(o *options) { o.Evidence = true })
	for _, want := range []string{"evidence: HTTP 200", "fix: remove it"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
}

func TestQuietOutputUnchanged(t *testing.T) {
	var buf bytes.Buffer
	if err := outputQuiet(&buf, groupedSampleResults(), false); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "[high] https://example.test/.env exposed environment file") {
		t.Fatalf("quiet output wrong:\n%s", out)
	}
	if strings.Contains(out, "config (1)") {
		t.Fatalf("quiet output should not group:\n%s", out)
	}
}

func TestHTMLReport(t *testing.T) {
	var buf bytes.Buffer
	if err := outputHTML(&buf, groupedSampleResults()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"HawkProbe scan report", "https://example.test", "b-crit", "b-high", "exposed environment file", "HTTP 200"} {
		if !strings.Contains(out, want) {
			t.Fatalf("html missing %q", want)
		}
	}
}

func TestHTMLReportEscapes(t *testing.T) {
	results := []scanResult{{
		Target:   "https://example.test",
		Requests: 1,
		Findings: []finding{{
			Severity: low, Level: "low",
			Message: "bad <script>alert(1)</script> & \"quotes\"",
			URL:     "https://example.test/x",
		}},
	}}
	var buf bytes.Buffer
	if err := outputHTML(&buf, results); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "<script>alert(1)</script>") {
		t.Fatalf("html not escaped:\n%s", out)
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Fatalf("escaped message missing:\n%s", out)
	}
}

func TestMarkdownReport(t *testing.T) {
	var buf bytes.Buffer
	if err := outputMarkdown(&buf, groupedSampleResults()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"# HawkProbe scan report", "## Summary", "### config", "exposed environment file", "| high |"} {
		if !strings.Contains(out, want) {
			t.Fatalf("markdown missing %q:\n%s", want, out)
		}
	}
}

func TestWriteBundle(t *testing.T) {
	dir := t.TempDir()
	if err := writeBundle(dir, groupedSampleResults()); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"report.html", "report.md", "results.json", "results.jsonl", "findings.csv", "hawkprobe.sarif"} {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("bundle missing %s: %v", name, err)
		}
		if len(data) == 0 {
			t.Fatalf("bundle file %s is empty", name)
		}
	}
	var decoded []scanResult
	if err := json.Unmarshal(func() []byte {
		b, _ := os.ReadFile(filepath.Join(dir, "results.json"))
		return b
	}(), &decoded); err != nil {
		t.Fatalf("results.json invalid: %v", err)
	}
	if len(decoded) != 2 {
		t.Fatalf("expected 2 results, got %d", len(decoded))
	}
}
