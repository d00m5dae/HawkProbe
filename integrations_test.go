package main

import (
	"strings"
	"testing"
)

func TestParseNmapXML(t *testing.T) {
	data := []byte(`<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up" />
    <address addr="10.10.10.10" addrtype="ipv4" />
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
      <port protocol="tcp" portid="8443"><state state="open"/><service name="http" tunnel="ssl"/></port>
    </ports>
  </host>
</nmaprun>`)
	got, err := parseNmapXML(data)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(got, "\n")
	if !strings.Contains(joined, "http://10.10.10.10") {
		t.Fatalf("missing HTTP target: %v", got)
	}
	if !strings.Contains(joined, "https://10.10.10.10:8443") {
		t.Fatalf("missing HTTPS target: %v", got)
	}
	if strings.Contains(joined, ":22") {
		t.Fatalf("non-web port imported: %v", got)
	}
}

func TestParseNmapGrepable(t *testing.T) {
	input := "Host: 10.10.10.20 ()\tPorts: 22/open/tcp//ssh///, 80/open/tcp//http///, 443/open/tcp//ssl|http///\n"
	got := parseNmapGrepable(input)
	joined := strings.Join(got, "\n")
	if !strings.Contains(joined, "http://10.10.10.20") || !strings.Contains(joined, "https://10.10.10.20") {
		t.Fatalf("unexpected targets: %v", got)
	}
	if strings.Contains(joined, ":22") {
		t.Fatalf("ssh port should not be imported: %v", got)
	}
}

func TestParseHTTPXJSONL(t *testing.T) {
	input := []byte("{\"url\":\"https://app.example\",\"status_code\":200}\n{\"input\":\"api.example\",\"scheme\":\"http\",\"port\":8080}\n")
	got := parseHTTPXJSONL(input)
	joined := strings.Join(got, "\n")
	if !strings.Contains(joined, "https://app.example") {
		t.Fatalf("url record missing: %v", got)
	}
	if !strings.Contains(joined, "http://api.example:8080") {
		t.Fatalf("host record missing: %v", got)
	}
}

func TestBarePortSchemeInference(t *testing.T) {
	httpTarget, err := normalizeTarget("10.10.10.10:80")
	if err != nil {
		t.Fatal(err)
	}
	if httpTarget != "http://10.10.10.10:80" {
		t.Fatalf("unexpected HTTP target %q", httpTarget)
	}
	httpsTarget, err := normalizeTarget("10.10.10.10:443")
	if err != nil {
		t.Fatal(err)
	}
	if httpsTarget != "https://10.10.10.10:443" {
		t.Fatalf("unexpected HTTPS target %q", httpsTarget)
	}
}

func TestExpandedBuiltinCatalog(t *testing.T) {
	if len(builtinRules) < 450 {
		t.Fatalf("expected expanded rule catalog, got only %d rules", len(builtinRules))
	}
	categories := map[string]bool{}
	for _, r := range builtinRules {
		categories[r.Category] = true
	}
	for _, want := range []string{"cloud", "devops", "cms", "source", "metadata"} {
		if !categories[want] {
			t.Fatalf("missing category %q", want)
		}
	}
}
