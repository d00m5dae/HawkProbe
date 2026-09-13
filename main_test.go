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

func TestModeFilters(t *testing.T) {
	r := rule{Category: "api", Profile: "full", Tags: []string{"htb"}}
	if !modeAllows("api", r) || !modeAllows("htb", r) {
		t.Fatal("mode filter failed")
	}
	if modeAllows("admin", r) {
		t.Fatal("admin mode should exclude API rule")
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

func TestRuleRegex(t *testing.T) {
	r, err := normalizeRuleChecked(rule{Path: "/x", Name: "x", Regex: `(?i)secret=[a-z]+`})
	if err != nil {
		t.Fatal(err)
	}
	resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
	if !ruleMatches(r, resp, []byte("SECRET=test"), baseline{}) {
		t.Fatal("regex should match")
	}
}

func TestCustomRules(t *testing.T) {
	f, err := os.CreateTemp("", "hawkprobe-rules-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	_, _ = f.WriteString(`[{"id":"x","path":"/x","name":"custom","severity":"medium","category":"test","regex":"hello"}]`)
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

func TestSoft404Baseline(t *testing.T) {
	base := baseline{stable: true, samples: []baselineSample{{status: 200, length: 13, sketch: bodySketch([]byte("not found lol"), "")}, {status: 200, length: 13, sketch: bodySketch([]byte("not found lol"), "")}}}
	if !looksLikeBaseline(200, []byte("not found lol"), base) {
		t.Fatal("expected soft-404 match")
	}
	if looksLikeBaseline(404, []byte("not found lol"), base) {
		t.Fatal("different status should not match")
	}
}

func TestReorderArgs(t *testing.T) {
	got := reorderArgs([]string{"https://example.com", "-mode", "full", "-v"})
	joined := strings.Join(got, " ")
	if joined != "-mode full -v https://example.com" {
		t.Fatalf("unexpected %q", joined)
	}
}

func TestScanTarget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.Header().Set("Allow", "GET, OPTIONS")
			return
		}
		switch r.URL.Path {
		case "/":
			w.Header().Set("Server", "test")
			_, _ = w.Write([]byte("<html><title>Lab</title></html>"))
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
	opts := options{Mode: "quick", Concurrency: 8, TargetConcurrency: 1, Timeout: 2 * time.Second, MaxRedirects: 5}
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
	if !strings.Contains(joined, "page title: Lab") {
		t.Fatal("title finding missing")
	}
}

func TestBuiltinRulesValidAndUnique(t *testing.T) {
	seen := make(map[string]bool)
	for _, r := range builtinRules {
		n, err := normalizeRuleChecked(r)
		if err != nil {
			t.Fatalf("%s: %v", r.ID, err)
		}
		if seen[n.ID] {
			t.Fatalf("duplicate rule id %q", n.ID)
		}
		seen[n.ID] = true
	}
	if len(seen) < 150 {
		t.Fatalf("expected broad built-in coverage, got %d rules", len(seen))
	}
}

func TestWordlistRules(t *testing.T) {
	f, err := os.CreateTemp("", "hawkprobe-wordlist-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	_, _ = f.WriteString("admin\napi\n")
	_ = f.Close()
	rules, err := loadWordlistRules(f.Name(), "php,bak")
	if err != nil {
		t.Fatal(err)
	}
	paths := make(map[string]bool)
	for _, r := range rules {
		paths[r.Path] = true
	}
	for _, want := range []string{"/admin", "/admin.php", "/admin.bak", "/api"} {
		if !paths[want] {
			t.Fatalf("missing %s", want)
		}
	}
}
