# HawkProbe

[![test](https://github.com/d00m5dae/HawkProbe/actions/workflows/test.yml/badge.svg)](https://github.com/d00m5dae/HawkProbe/actions/workflows/test.yml)
[![Go](https://img.shields.io/badge/Go-1.20%2B-00ADD8?logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

HawkProbe is a fast web exposure and misconfiguration scanner written in Go. It is built for authorized pentesting, HTB/CTF labs, homelabs, and defensive web auditing.

The goal is simple: make the common web-enumeration loop fast and pleasant without requiring a pile of glue scripts. HawkProbe combines a concurrent path engine, HTTP/TLS checks, technology fingerprinting, soft-404 filtering, content discovery, tool imports, SecLists support, and structured reporting in one small binary.

## Why HawkProbe

- Hundreds of built-in checks, including 500+ additional catalog paths in the v1.3 development branch
- Fast concurrent scanning with connection reuse and HTTP/2 support
- HTB-focused mode without making the default scan noisy
- Nmap, httpx, nuclei, feroxbuster, ffuf, Katana/plain-list, and stdin workflows
- First-class SecLists aliases plus normal text-wordlist support
- Two-sample soft-404/wildcard filtering to reduce fake hits
- Progress bar, quiet mode, evidence/remediation output, and clean summaries
- Text, JSON, JSONL, CSV, Markdown, and URL-only output
- Custom rules without rebuilding the binary
- Go 1.20+ and no runtime dependency beyond the compiled executable

## Install

### Prebuilt release

Linux/macOS:

```bash
curl -fsSL https://raw.githubusercontent.com/d00m5dae/HawkProbe/main/install-release.sh | sh
```

Windows PowerShell:

```powershell
irm https://raw.githubusercontent.com/d00m5dae/HawkProbe/main/install.ps1 | iex
```

### From source

```bash
git clone https://github.com/d00m5dae/HawkProbe.git
cd HawkProbe
sh install.sh
```

Or:

```bash
go install github.com/d00m5dae/HawkProbe@latest
```

## Quick start

Balanced scan:

```bash
hawkprobe https://example.com
```

HTB box:

```bash
hawkprobe http://box.htb -mode htb
```

Full scan with more concurrency:

```bash
hawkprobe https://example.com -mode full -c 64
```

Show evidence and remediation:

```bash
hawkprobe https://example.com -mode exposure -evidence
```

Flags can go before or after the positional target.

## HTB workflow

A common lab workflow can stay almost entirely inside HawkProbe.

Run Nmap normally:

```bash
nmap -sV -p- -oX scan.xml 10.10.10.10
```

Feed the HTTP services directly into HawkProbe:

```bash
hawkprobe -nmap scan.xml -mode htb -target-c 8
```

Then add SecLists discovery to a specific web service:

```bash
hawkprobe http://box.htb -mode htb -seclist raft-small -ext php,bak,txt
```

Need a vhost against an IP:

```bash
hawkprobe http://10.10.10.10 -host internal.htb -mode htb
```

## Scan modes

| Mode | Purpose |
| --- | --- |
| `quick` | Small high-value scan |
| `default` | Balanced everyday scan |
| `full` / `deep` | Broad built-in coverage and discovery |
| `htb` | HTB/CTF-oriented exposure, admin, API, debug, and discovery checks |
| `exposure` | Secrets, backups, VCS metadata, configs, logs |
| `admin` | Admin, login, and management surfaces |
| `api` | Swagger/OpenAPI, GraphQL, API docs, common API roots |
| `debug` | pprof, Actuator, traces, diagnostics, monitoring |
| `headers` | Security headers, cookies, CORS, HTTP methods |
| `tls` | TLS/certificate checks only |
| `tech` | Technology fingerprinting only |

`-profile` is kept as a compatibility alias for `-mode`.

## Tool imports

### Nmap

HawkProbe understands Nmap XML and grepable output and imports open HTTP-like TCP services:

```bash
hawkprobe -nmap scan.xml -mode htb
hawkprobe -nmap scan.gnmap -mode default
```

### httpx

```bash
httpx -l hosts.txt -json | hawkprobe -input - -input-format httpx-jsonl -mode exposure
```

### nuclei

```bash
hawkprobe -input nuclei.jsonl -input-format nuclei-jsonl -mode full
```

### ffuf

```bash
ffuf -w words.txt -u http://box.htb/FUZZ -of json -o ffuf.json
hawkprobe -input ffuf.json -input-format ffuf-json -mode exposure
```

### feroxbuster

```bash
hawkprobe -input ferox.jsonl -input-format ferox-jsonl -mode default
```

### Plain URLs / Katana output

```bash
hawkprobe -input urls.txt -input-format plain -mode default
```

Use `-input-format auto` when you want HawkProbe to detect the common formats itself.

More examples are in [`docs/integrations.md`](docs/integrations.md).

## SecLists

Any normal SecLists wordlist already works with `-wordlist`. HawkProbe also knows common aliases:

```bash
hawkprobe wordlists
```

Example:

```bash
hawkprobe box.htb -mode htb -seclist common
hawkprobe box.htb -mode htb -seclist raft-medium -ext php,aspx,bak
```

Common aliases include:

- `common`
- `quickhits`
- `raft-small`, `raft-medium`, `raft-large`
- `raft-small-dirs`, `raft-medium-dirs`, `raft-large-dirs`
- `dirs-small`, `dirs-medium`

HawkProbe checks common Linux/Kali locations automatically. For a custom install:

```bash
export SECLISTS_PATH="$HOME/tools/SecLists"
```

Large wordlists are bounded with `-wordlist-limit` so an accidental extension explosion does not create an endless scan.

## Progress and output

Normal single-target scans show a compact progress bar. Disable it with:

```bash
hawkprobe example.com -no-progress
```

Verbose mode shows every check instead:

```bash
hawkprobe box.htb -mode htb -v
```

Findings-only output:

```bash
hawkprobe example.com -q
```

Supported formats:

```bash
hawkprobe example.com -format text
hawkprobe example.com -format json
hawkprobe example.com -format jsonl
hawkprobe example.com -format csv -o results.csv
hawkprobe example.com -format md -o report.md
hawkprobe example.com -format urls > interesting.txt
```

The text output includes useful response metadata such as page title, server header, content type, response size, and final redirect URL when available.

## Filtering

Only medium and above:

```bash
hawkprobe example.com -mode full -severity medium
```

Only selected categories:

```bash
hawkprobe example.com -mode full -include-category backup,secrets,config
```

Skip categories:

```bash
hawkprobe example.com -mode full -exclude-category admin,discovery
```

## Built-in coverage

HawkProbe checks or identifies areas including:

- Git, SVN, Mercurial, and Bazaar metadata
- environment files, credentials, key material, and application configs
- source archives, database dumps, editor backups, and old deployment files
- Docker, Kubernetes, Terraform, Helm, Ansible, CI/CD, and build artifacts
- Apache status/info, PHP info, Go pprof, Spring Boot Actuator, ELMAH, metrics, and debug consoles
- admin/login/management panels and common CMS surfaces
- WordPress, Drupal, Joomla, TYPO3, Ghost, Umbraco, Sitecore, and related paths
- Swagger/OpenAPI, GraphQL, GraphiQL, ReDoc, OData, REST and RPC surfaces
- cloud/service-account/configuration artifacts
- security headers, cookie flags, CORS, HTTP methods, directory listing, and information disclosure
- TLS certificate validity, expiry, hostname, issuer, and negotiated protocol
- technology markers for common servers, frameworks, CDNs, and applications
- response-body indicators for private keys, access keys, generic secrets, stack traces, debug errors, source maps, and useful HTML comments

The large catalog is grouped in source instead of being a flat wall of one-off rules. Existing higher-confidence checks win when catalog paths overlap, preventing duplicate requests.

## Dynamic discovery

Enable robots/sitemap discovery explicitly:

```bash
hawkprobe https://example.com -discover
```

`full`, `deep`, and `htb` enable it automatically. Same-host paths are bounded and passed through HawkProbe's soft-404 filtering.

Use your own wordlist:

```bash
hawkprobe box.htb -wordlist paths.txt -ext php,txt,bak
```

## Custom rules

Example:

```json
[
  {
    "id": "internal-health",
    "path": "/internal/health",
    "name": "internal health endpoint exposed",
    "severity": "low",
    "category": "debug",
    "confidence": "high",
    "method": "GET",
    "statuses": [200],
    "contains": ["healthy"],
    "regex": "(?i)status\\s*[:=]\\s*ok",
    "content_type": "json",
    "remediation": "Restrict the health endpoint to trusted networks."
  }
]
```

Validate it:

```bash
hawkprobe rules validate custom-rules.json
```

Explore the built-in catalog:

```bash
hawkprobe rules stats
hawkprobe rules list
hawkprobe rules
```

## Authentication and proxying

```bash
hawkprobe example.com -H "X-Test: 1"
hawkprobe example.com -user username -pass password
hawkprobe example.com -token TOKEN
hawkprobe example.com -proxy http://127.0.0.1:8080
```

Authentication values are not added to normal findings or verbose output.

## Main options

```text
-mode string             scan mode
-c int                   concurrent requests per target
-target-c int            targets scanned concurrently
-timeout duration        request timeout
-nmap file               Nmap XML/grepable input
-input file              tool output or URL list; '-' reads stdin
-input-format string     auto/plain/nmap/httpx/nuclei/ferox/ffuf format
-discover                robots/sitemap path discovery
-wordlist file           arbitrary text wordlist
-seclist alias           installed SecLists alias
-ext php,txt,bak         expand extensionless wordlist entries
-wordlist-limit int      generated wordlist-check limit
-severity string         minimum rule severity
-include-category list   only selected categories
-exclude-category list   skip selected categories
-v                       verbose per-check output
-progress                progress bar
-no-progress             disable progress bar
-q                       findings-only output
-evidence                evidence and remediation details
-host string             override Host header
-format string           text/json/jsonl/csv/md/urls
-o file                  output file
```

Run `hawkprobe help` for the complete list.

## Development

```bash
gofmt -w *.go
go test ./...
go vet ./...
go test -race ./...
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) before submitting a larger feature or rule-set change.

## Scope

HawkProbe is intended for systems you own or are authorized to test. Normal checks are non-destructive HTTP/TLS probes. It does not deploy payloads, modify remote systems, or attempt persistence.

## License

MIT
