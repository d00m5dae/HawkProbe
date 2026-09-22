package main

import (
	"testing"
	"time"
)

func TestApplySuppressions(t *testing.T) {
	mk := func() []scanResult {
		return []scanResult{
			{Target: "https://a.test", Findings: []finding{
				{Severity: high, Level: "high", Rule: "env", Message: "env file", URL: "https://a.test/.env"},
				{Severity: low, Level: "low", Rule: "csp", Message: "no csp"},
			}},
			{Target: "https://b.test", Findings: []finding{
				{Severity: high, Level: "high", Rule: "env", Message: "env file", URL: "https://b.test/.env"},
			}},
		}
	}
	// Rule-only suppression removes on all targets.
	r := mk()
	applySuppressions(r, suppressionFile{Suppressions: []suppression{{Rule: "env"}}})
	if len(r[0].Findings) != 1 || len(r[1].Findings) != 0 {
		t.Fatalf("rule suppression wrong: %+v", r)
	}
	if r[0].Suppressed != 1 || r[1].Suppressed != 1 {
		t.Fatalf("suppressed counters wrong: %+v", r)
	}

	// Target-scoped suppression only affects that target.
	r = mk()
	applySuppressions(r, suppressionFile{Suppressions: []suppression{{Rule: "env", Target: "https://a.test"}}})
	if len(r[0].Findings) != 1 || len(r[1].Findings) != 1 {
		t.Fatalf("target suppression wrong: %+v", r)
	}

	// Path-scoped suppression matches by URL suffix.
	r = mk()
	applySuppressions(r, suppressionFile{Suppressions: []suppression{{Rule: "env", Path: "/.env"}}})
	if len(r[0].Findings) != 1 || len(r[1].Findings) != 0 {
		t.Fatalf("path suppression wrong: %+v", r)
	}

	// Expired suppressions are ignored.
	r = mk()
	applySuppressions(r, suppressionFile{Suppressions: []suppression{{Rule: "env", Expiry: time.Now().Add(-time.Hour)}}})
	if len(r[0].Findings) != 2 {
		t.Fatalf("expired suppression should not apply: %+v", r)
	}

	// Future expiry still applies.
	r = mk()
	applySuppressions(r, suppressionFile{Suppressions: []suppression{{Rule: "env", Expiry: time.Now().Add(time.Hour)}}})
	if len(r[0].Findings) != 1 {
		t.Fatalf("valid expiry should apply: %+v", r)
	}
}

func TestSuppressionsFileRoundtrip(t *testing.T) {
	t.Setenv("HAWKPROBE_SUPPRESSIONS", t.TempDir()+"/suppressions.json")
	sf, err := loadSuppressions("")
	if err != nil {
		t.Fatal(err)
	}
	if len(sf.Suppressions) != 0 {
		t.Fatalf("expected empty, got %+v", sf)
	}
	sf.Suppressions = append(sf.Suppressions, suppression{Rule: "env", Reason: "known", AddedAt: time.Now()})
	if err := saveSuppressions(sf); err != nil {
		t.Fatal(err)
	}
	got, err := loadSuppressions("")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Suppressions) != 1 || got.Suppressions[0].Rule != "env" || got.Suppressions[0].Reason != "known" {
		t.Fatalf("roundtrip failed: %+v", got)
	}
}

func TestParseDurationLoose(t *testing.T) {
	cases := map[string]time.Duration{
		"30d":   30 * 24 * time.Hour,
		"2w":    14 * 24 * time.Hour,
		"12h":   12 * time.Hour,
		"90m":   90 * time.Minute,
		"48h":   48 * time.Hour,
		"3d":    72 * time.Hour,
		"3w":    504 * time.Hour,
		"1500h": 1500 * time.Hour,
	}
	for in, want := range cases {
		got, err := parseDurationLoose(in)
		if err != nil {
			t.Fatalf("parse %q: %v", in, err)
		}
		if got != want {
			t.Fatalf("parse %q = %v, want %v", in, got, want)
		}
	}
	if _, err := parseDurationLoose("soon"); err == nil {
		t.Fatal("expected error for non-duration")
	}
}
