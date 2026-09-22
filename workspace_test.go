package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func withTempWorkspace(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HAWKPROBE_WORKSPACE", dir)
	workspaceOverride = ""
	t.Cleanup(func() { workspaceOverride = "" })
}

func wsSampleResults() []scanResult {
	return []scanResult{
		{
			Target: "https://one.test", Requests: 3, DurationMS: 12,
			Findings: []finding{
				{Severity: high, Level: "high", Rule: "env-exposure", Message: "exposed env file", Category: "config", URL: "https://one.test/.env"},
			},
		},
		{
			Target: "https://two.test", Requests: 2, DurationMS: 8,
			Findings: []finding{
				{Severity: medium, Level: "medium", Rule: "server-banner", Message: "server version disclosed"},
			},
		},
		{
			Target: "https://three.test", Requests: 1, DurationMS: 5, Error: "connection refused",
		},
	}
}

func TestRecordAndListScans(t *testing.T) {
	withTempWorkspace(t)
	opts := options{Mode: "default", Timeout: 5 * time.Second}
	started := time.Now().Add(-time.Minute)
	targets := []string{"https://one.test", "https://two.test", "https://three.test"}
	recordWorkspaceScan(targets, wsSampleResults(), opts, 42, started)

	scans, err := listScans()
	if err != nil {
		t.Fatal(err)
	}
	if len(scans) != 1 {
		t.Fatalf("expected 1 recorded scan, got %d", len(scans))
	}
	m := scans[0]
	if m.Status != "partial" {
		t.Fatalf("expected partial status (one errored target), got %q", m.Status)
	}
	if m.Summary.Findings != 2 || m.Summary.High != 1 || m.Summary.Medium != 1 || m.Summary.Errors != 1 {
		t.Fatalf("bad summary: %+v", m.Summary)
	}
	if len(m.ScannedTargets) != 2 {
		t.Fatalf("expected 2 scanned targets, got %v", m.ScannedTargets)
	}
	if m.RulesLoaded != 42 || m.Options.Mode != "default" {
		t.Fatalf("bad meta: %+v", m)
	}
	for _, f := range []string{"meta.json", "results.json", "findings.csv", "hawkprobe.sarif"} {
		if _, err := os.Stat(filepath.Join(scanDir(m.ID), f)); err != nil {
			t.Fatalf("missing artifact %s: %v", f, err)
		}
	}
}

func TestDiffComputesAddedAndRemoved(t *testing.T) {
	base := []scanResult{
		{Target: "https://one.test", Findings: []finding{
			{Severity: high, Level: "high", Rule: "env-exposure", Message: "exposed env file"},
			{Severity: low, Level: "low", Rule: "old-cookie", Message: "stale cookie"},
		}},
	}
	fresh := []scanResult{
		{Target: "https://one.test", Findings: []finding{
			{Severity: high, Level: "high", Rule: "env-exposure", Message: "exposed env file"},
			{Severity: critical, Level: "critical", Rule: "admin-panel", Message: "admin panel exposed"},
		}},
	}
	added, removed := computeDiff(base, fresh)
	if len(added) != 1 || added[0].Rule != "admin-panel" {
		t.Fatalf("added wrong: %+v", added)
	}
	if len(removed) != 1 || removed[0].Rule != "old-cookie" {
		t.Fatalf("removed wrong: %+v", removed)
	}
}

func TestDiffEmptyWhenIdentical(t *testing.T) {
	base := wsSampleResults()
	added, removed := computeDiff(base, base)
	if len(added) != 0 || len(removed) != 0 {
		t.Fatalf("expected no changes, added=%d removed=%d", len(added), len(removed))
	}
}

func TestScanIDStableForSameTargets(t *testing.T) {
	start := time.Now()
	a := newScanID(start, []string{"https://a.test"})
	b := newScanID(start.Add(time.Minute), []string{"https://a.test"})
	if a == b {
		t.Fatal("different start times should give different ids")
	}
	c := newScanID(start, []string{"https://a.test"})
	if a != c {
		t.Fatalf("same start+targets should give same id: %s vs %s", a, c)
	}
	if len(a) != 27 {
		t.Fatalf("unexpected id format: %s", a)
	}
}
