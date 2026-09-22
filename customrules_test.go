package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestCustomRuleValidation(t *testing.T) {
	if err := (customRule{Path: "/x", Expect: customExpect{Status: 200}}).validate(); err == nil {
		t.Fatal("expected error for missing name")
	}
	if err := (customRule{Name: "x", Expect: customExpect{Status: 200}}).validate(); err == nil {
		t.Fatal("expected error for missing path")
	}
	if err := (customRule{Name: "x", Path: "/x"}).validate(); err == nil {
		t.Fatal("expected error for empty expect")
	}
	if err := (customRule{Name: "x", Path: "/x", Severity: "urgent", Expect: customExpect{Status: 200}}).validate(); err == nil {
		t.Fatal("expected error for invalid severity")
	}
	if err := (customRule{Name: "x", Path: "/x", Method: "FETCH", Expect: customExpect{Status: 200}}).validate(); err == nil {
		t.Fatal("expected error for invalid method")
	}
	if err := (customRule{Name: "x", Path: "/x", Severity: "low", Expect: customExpect{Status: 200}}).validate(); err != nil {
		t.Fatalf("valid rule rejected: %v", err)
	}
}

func TestLoadCustomRulesFlexStrings(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/rules.json"
	body := `{"rules":[{"name":"a","path":"/a","expect":{"contains":"one"}},{"name":"b","path":"/b","expect":{"contains_any":["x","y"],"not_contains":"z"}}]}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cf, err := loadCustomRules(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cf.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(cf.Rules))
	}
	if len(cf.Rules[0].Expect.Contains) != 1 || cf.Rules[0].Expect.Contains[0] != "one" {
		t.Fatalf("string form not accepted: %+v", cf.Rules[0].Expect.Contains)
	}
	if len(cf.Rules[1].Expect.ContainsAny) != 2 || len(cf.Rules[1].Expect.NotContains) != 1 {
		t.Fatalf("array form not accepted: %+v", cf.Rules[1].Expect)
	}
	// Invalid JSON error.
	if err := os.WriteFile(path, []byte(`{"rules":`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCustomRules(path); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestExpandRuleURL(t *testing.T) {
	base := "https://a.test"
	got := expandRuleURL(base, "/admin")
	if len(got) != 1 || got[0] != "https://a.test/admin" {
		t.Fatalf("exact path wrong: %v", got)
	}
	got = expandRuleURL(base, "https://b.test/panel")
	if len(got) != 1 || got[0] != "https://b.test/panel" {
		t.Fatalf("absolute url wrong: %v", got)
	}
	got = expandRuleURL(base, "/admin*")
	if len(got) != 2 || got[0] != "https://a.test/admin" || got[1] != "https://a.test/admin/" {
		t.Fatalf("glob expansion wrong: %v", got)
	}
	// A base with a path component joins onto it (consistent with joinURL).
	got = expandRuleURL("https://a.test/base", "/admin")
	if len(got) != 1 || got[0] != "https://a.test/base/admin" {
		t.Fatalf("path-based join wrong: %v", got)
	}
}

func TestCustomExpectMatches(t *testing.T) {
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"X-Panel": []string{"AdminConsole v2"}},
	}
	body := []byte("a login page with a secret token")

	if !(customExpect{Status: 200}).matches(resp, body) {
		t.Fatal("status match")
	}
	if (customExpect{Status: 404}).matches(resp, body) {
		t.Fatal("status mismatch should fail")
	}
	if !(customExpect{StatusAny: []int{404, 200}}).matches(resp, body) {
		t.Fatal("status_any match")
	}
	if (customExpect{StatusAny: []int{404}}).matches(resp, body) {
		t.Fatal("status_any mismatch should fail")
	}
	if !(customExpect{Contains: []string{"login", "secret"}}).matches(resp, body) {
		t.Fatal("contains all")
	}
	if (customExpect{Contains: []string{"login", "missing"}}).matches(resp, body) {
		t.Fatal("contains should fail on missing needle")
	}
	if !(customExpect{ContainsAny: []string{"missing", "token"}}).matches(resp, body) {
		t.Fatal("contains_any")
	}
	if (customExpect{ContainsAny: []string{"missing"}}).matches(resp, body) {
		t.Fatal("contains_any should fail")
	}
	if (customExpect{NotContains: []string{"token"}}).matches(resp, body) {
		t.Fatal("not_contains should fail")
	}
	if !(customExpect{Header: map[string]string{"X-Panel": "console"}}).matches(resp, body) {
		t.Fatal("header contains")
	}
	if (customExpect{Header: map[string]string{"X-Panel": "nope"}}).matches(resp, body) {
		t.Fatal("header contains should fail")
	}
	if (customExpect{Header: map[string]string{"X-Missing": ""}}).matches(resp, body) {
		t.Fatal("missing header should fail")
	}
}

func TestRunCustomRules(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Panel", "admin-console")
		io.WriteString(w, "login form here")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	var requests int64
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	custom := []customRule{{
		Name:     "admin-panel",
		Path:     "/admin*",
		Severity: "medium",
		Expect:   customExpect{Status: 200, Contains: []string{"login"}},
	}}
	out := runCustomRules(ctx, client, options{Timeout: time.Second}, srv.URL, custom, &requests)
	if len(out) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(out), out)
	}
	if out[0].Rule != "custom:admin-panel" || out[0].Category != "custom" || out[0].Severity != medium {
		t.Fatalf("bad finding metadata: %+v", out[0])
	}

	// No expanded URL returns this status, so the rule must not fire.
	custom[0].Expect = customExpect{Status: 302}
	out = runCustomRules(ctx, client, options{Timeout: time.Second}, srv.URL, custom, &requests)
	if len(out) != 0 {
		t.Fatalf("expected no findings, got %+v", out)
	}

	// Header condition.
	custom[0].Expect = customExpect{Status: 200, Header: map[string]string{"X-Panel": "console"}}
	out = runCustomRules(ctx, client, options{Timeout: time.Second}, srv.URL, custom, &requests)
	if len(out) != 1 {
		t.Fatalf("header rule expected 1 finding, got %d", len(out))
	}
}

func TestCustomRuleJSONRoundtrip(t *testing.T) {
	data := []byte(`{"rules":[{"name":"r1","path":"/x","severity":"high","expect":{"status":200,"contains":["a"]}}]}`)
	var cf customRuleFile
	if err := json.Unmarshal(data, &cf); err != nil {
		t.Fatal(err)
	}
	if cf.Rules[0].Expect.Status != 200 || cf.Rules[0].Severity != "high" {
		t.Fatalf("bad parse: %+v", cf.Rules[0])
	}
}
