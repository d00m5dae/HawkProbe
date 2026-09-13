package main

import (
	"os"
	"strings"
	"testing"
)

func writeTempInput(t *testing.T, body string) string {
	t.Helper()
	f, err := os.CreateTemp("", "hawkprobe-input-*")
	if err != nil { t.Fatal(err) }
	if _, err := f.WriteString(body); err != nil { t.Fatal(err) }
	if err := f.Close(); err != nil { t.Fatal(err) }
	t.Cleanup(func() { _ = os.Remove(f.Name()) })
	return f.Name()
}

func TestNmapXMLImport(t *testing.T) {
	path := writeTempInput(t, `<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="10.10.10.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port><port protocol="tcp" portid="443"><state state="open"/><service name="https" tunnel="ssl"/></port></ports></host></nmaprun>`)
	targets, err := loadInputTargets(path, "nmap-xml")
	if err != nil { t.Fatal(err) }
	joined := strings.Join(targets, "\n")
	if !strings.Contains(joined, "http://10.10.10.10") { t.Fatalf("missing HTTP target: %v", targets) }
	if !strings.Contains(joined, "https://10.10.10.10") { t.Fatalf("missing HTTPS target: %v", targets) }
	if strings.Contains(joined, ":22") { t.Fatalf("SSH port should not be imported: %v", targets) }
}

func TestNmapGrepableImport(t *testing.T) {
	path := writeTempInput(t, "Host: 10.10.10.11 ()\tPorts: 22/open/tcp//ssh///, 8080/open/tcp//http-proxy///, 8443/open/tcp//https-alt///\n")
	targets, err := loadInputTargets(path, "nmap-gnmap")
	if err != nil { t.Fatal(err) }
	joined := strings.Join(targets, "\n")
	if !strings.Contains(joined, "http://10.10.10.11:8080") { t.Fatalf("missing 8080 target: %v", targets) }
	if !strings.Contains(joined, "https://10.10.10.11:8443") { t.Fatalf("missing 8443 target: %v", targets) }
}

func TestFFUFImport(t *testing.T) {
	path := writeTempInput(t, `{"results":[{"url":"http://box.htb/admin"},{"url":"http://box.htb/api"}]}`)
	targets, err := loadInputTargets(path, "ffuf-json")
	if err != nil { t.Fatal(err) }
	if len(targets) != 2 { t.Fatalf("expected 2 targets, got %d", len(targets)) }
}

func TestGenericJSONLImport(t *testing.T) {
	path := writeTempInput(t, "{\"url\":\"https://one.example\"}\n{\"matched-at\":\"http://two.example/debug\"}\n")
	targets, err := loadInputTargets(path, "httpx-jsonl")
	if err != nil { t.Fatal(err) }
	if len(targets) != 2 { t.Fatalf("expected 2 targets, got %d", len(targets)) }
}

func TestExpandedRuleCatalog(t *testing.T) {
	if len(builtinRules) < 500 {
		t.Fatalf("expected at least 500 built-in rules, got %d", len(builtinRules))
	}
	seen := map[string]bool{}
	for _, r := range builtinRules {
		key := r.Method + " " + r.Path
		if seen[key] {
			t.Fatalf("duplicate rule request: %s", key)
		}
		seen[key] = true
	}
}

func TestRuleFiltering(t *testing.T) {
	rules := []rule{
		{Severity: "low", Category: "api"},
		{Severity: "high", Category: "backup"},
		{Severity: "critical", Category: "secrets"},
	}
	got := filterRules(rules, options{MinSeverity: "high", ExcludeCategory: "secrets"})
	if len(got) != 1 || got[0].Category != "backup" {
		t.Fatalf("unexpected filtered rules: %#v", got)
	}
}
