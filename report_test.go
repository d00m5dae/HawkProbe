package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
)

func sampleReportResults() []scanResult {
	return []scanResult{{
		Target:     "https://example.test",
		Status:     "200 OK",
		Requests:   12,
		DurationMS: 125,
		Findings: []finding{{
			Severity:    high,
			Level:       "high",
			Rule:        "test-rule",
			Category:    "exposure",
			Confidence:  "high",
			Message:     "test finding",
			URL:         "https://example.test/.env",
			Evidence:    "HTTP 200",
			Remediation: "remove the exposed file",
		}},
	}}
}

func TestSARIFOutput(t *testing.T) {
	var buf bytes.Buffer
	if err := outputSARIF(&buf, sampleReportResults()); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["version"] != "2.1.0" {
		t.Fatalf("unexpected SARIF version: %#v", decoded["version"])
	}
}

func TestSARIFLevels(t *testing.T) {
	if sarifLevel(critical) != "error" || sarifLevel(high) != "error" {
		t.Fatal("high severities must map to SARIF error")
	}
	if sarifLevel(medium) != "warning" {
		t.Fatal("medium must map to SARIF warning")
	}
	if sarifLevel(low) != "note" || sarifLevel(info) != "note" {
		t.Fatal("low severities must map to SARIF note")
	}
}

func TestCSVOutput(t *testing.T) {
	var buf bytes.Buffer
	if err := outputCSV(&buf, sampleReportResults()); err != nil {
		t.Fatal(err)
	}
	records, err := csv.NewReader(strings.NewReader(buf.String())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("expected header plus one finding, got %d rows", len(records))
	}
	if records[1][2] != "high" || records[1][5] != "test-rule" {
		t.Fatalf("unexpected CSV row: %#v", records[1])
	}
}

func TestFailThreshold(t *testing.T) {
	results := sampleReportResults()
	if !resultsMeetFailThreshold(results, "high") {
		t.Fatal("high finding should meet high threshold")
	}
	if resultsMeetFailThreshold(results, "critical") {
		t.Fatal("high finding should not meet critical threshold")
	}
	if resultsMeetFailThreshold(results, "") {
		t.Fatal("empty threshold must never fail")
	}
}
