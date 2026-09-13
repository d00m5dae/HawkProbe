package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestSARIFOutput(t *testing.T) {
	results := []scanResult{{
		Target: "https://example.test",
		Findings: []finding{{
			Severity:   high,
			Level:      "high",
			Rule:       "test-rule",
			Category:   "exposure",
			Confidence: "high",
			Message:    "test finding",
			URL:        "https://example.test/.env",
		}},
	}}
	var buf bytes.Buffer
	if err := outputSARIF(&buf, results); err != nil {
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
