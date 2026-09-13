package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestNormalizeTarget(t *testing.T) {
	got, err := normalizeTarget("example.com/")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestProfiles(t *testing.T) {
	if !profileAllows("full", "quick") {
		t.Fatal("full should include quick")
	}
	if profileAllows("quick", "full") {
		t.Fatal("quick should not include full")
	}
}

func TestRuleMatchContent(t *testing.T) {
	r := normalizeRule(rule{Path: "/.git/HEAD", Name: "git", Severity: "high", Contains: []string{"ref:"}})
	resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
	if !ruleMatches(r, resp, []byte("ref: refs/heads/main"), baseline{}) {
		t.Fatal("expected match")
	}
	if ruleMatches(r, resp, []byte("not git"), baseline{}) {
		t.Fatal("unexpected match")
	}
}

func TestCustomRules(t *testing.T) {
	f, err := os.CreateTemp("", "hawkprobe-rules-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	_, _ = f.WriteString(`[{"id":"x","path":"/x","name":"custom","severity":"medium"}]`)
	_ = f.Close()
	rules, err := loadRules(f.Name(), "quick")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range rules {
		if r.ID == "x" {
			found = true
		}
	}
	if !found {
		t.Fatal("custom rule missing")
	}
}

func TestScanTarget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.git/HEAD":
			_, _ = w.Write([]byte("ref: refs/heads/main"))
		case "/.env":
			_, _ = w.Write([]byte("SECRET=test"))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("missing"))
		}
	}))
	defer srv.Close()
	opts := options{Concurrency: 8, Timeout: 2 * time.Second, MaxRedirects: 5}
	rules, err := loadRules("", "quick")
	if err != nil {
		t.Fatal(err)
	}
	result := scanTarget(opts, srv.URL, rules)
	if result.Error != "" {
		t.Fatal(result.Error)
	}
	joined := ""
	for _, f := range result.Findings {
		joined += f.Message + "\n"
	}
	if !strings.Contains(joined, "exposed Git repository") {
		t.Fatal("git finding missing")
	}
	if !strings.Contains(joined, "exposed environment file") {
		t.Fatal("env finding missing")
	}
}
