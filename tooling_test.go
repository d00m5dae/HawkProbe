package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNmapXMLImport(t *testing.T) {
	data := []byte(`<?xml version="1.0"?>
<nmaprun><host><status state="up"/><address addr="10.10.10.10" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
<port protocol="tcp" portid="8443"><state state="open"/><service name="https" tunnel="ssl"/></port>
</ports></host></nmaprun>`)
	targets, err := parseNmapXML(data)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(targets, "\n")
	if !strings.Contains(joined, "http://10.10.10.10") {
		t.Fatal("missing HTTP target")
	}
	if !strings.Contains(joined, "https://10.10.10.10:8443") {
		t.Fatal("missing HTTPS target")
	}
	if strings.Contains(joined, ":22") {
		t.Fatal("SSH service should not be imported")
	}
}

func TestNmapGrepableImport(t *testing.T) {
	data := []byte("Host: 10.10.10.20 ()\tPorts: 80/open/tcp//http///, 443/open/tcp//https///, 22/open/tcp//ssh///\n")
	targets, err := parseNmapGrepable(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 {
		t.Fatalf("expected 2 web targets, got %d", len(targets))
	}
}

func TestSecListsPresetResolution(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "Discovery", "Web-Content", "common.txt")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("admin\nlogin\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := resolveSecListsWordlist("common", root)
	if err != nil {
		t.Fatal(err)
	}
	if got != path {
		t.Fatalf("got %q want %q", got, path)
	}
}

func TestRuleFilters(t *testing.T) {
	rules := []rule{
		{ID: "a", Severity: "high", Category: "secrets", Tags: []string{"htb"}},
		{ID: "b", Severity: "low", Category: "api", Tags: []string{"api"}},
		{ID: "c", Severity: "critical", Category: "secrets", Tags: []string{"exposure"}},
	}
	got := filterRulesForOptions(rules, options{MinSeverity: "high", Category: "secrets"})
	if len(got) != 2 {
		t.Fatalf("expected 2 filtered rules, got %d", len(got))
	}
	got = filterRulesForOptions(rules, options{IncludeTag: "htb"})
	if len(got) != 1 || got[0].ID != "a" {
		t.Fatalf("unexpected tag filter result: %#v", got)
	}
}

func TestExtendedRulePackSize(t *testing.T) {
	if len(builtinRules) < 350 {
		t.Fatalf("expected at least 350 built-in rules, got %d", len(builtinRules))
	}
}
