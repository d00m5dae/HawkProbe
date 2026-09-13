# HawkProbe

[![test](https://github.com/d00m5dae/HawkProbe/actions/workflows/test.yml/badge.svg)](https://github.com/d00m5dae/HawkProbe/actions/workflows/test.yml)
[![Go](https://img.shields.io/badge/Go-1.20%2B-00ADD8?logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Fast web exposure and misconfiguration scanning in one Go binary.**

HawkProbe is built for authorized pentesting, HTB/CTF labs, homelabs, and defensive web auditing. It combines concurrent content checks, HTTP/TLS inspection, soft-404 filtering, technology fingerprinting, discovery, SecLists support, Nmap import, and automation-friendly output without requiring a separate runtime.

## Why HawkProbe

- **350+ built-in web checks** with automatic request deduplication
- **HTB-focused mode** for useful exposure, admin, API, debug, and discovery checks
- **Nmap compatibility**: import XML, grepable (`-oG`), or normal Nmap output
- **SecLists compatibility** with presets and automatic install discovery
- **stdin pipelines** for tools such as `httpx`
- **fast concurrent scanning** per target and across target lists
- **soft-404 / wildcard filtering** to reduce noisy false positives
- **progress bar, verbose mode, rate limiting, filtering, and evidence output**
- **JSON, JSONL, CSV, and SARIF** output
- **CI-friendly exit thresholds** with `-fail-on`
- **custom JSON rules** without recompiling
- **Go 1.20+**, standard-library focused, single compiled binary

HawkProbe is not trying to replace Nmap, httpx, or every content discovery tool. It is designed to fit between them and make web-enumeration workflows faster and easier to automate.

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

Basic scan:

```bash
hawkprobe https://example.com
```

HTB/CTF scan with progress:

```bash
hawkprobe http://box.htb -mode htb -progress
```

Broad scan with evidence:

```bash
hawkprobe https://example.com -mode full -evidence
```

Flags can go before or after the target:

```bash
hawkprobe -mode full -c 64 https://example.com
hawkprobe https://example.com -mode full -c 64
```

## Nmap -> HawkProbe

Export Nmap XML:

```bash
nmap -sV -p- -oX scan.xml 10.10.10.10
hawkprobe -nmap scan.xml -mode htb -progress
```

HawkProbe also understands grepable output:

```bash
nmap -sV -oG scan.gnmap 10.10.10.10
hawkprobe -nmap scan.gnmap -mode htb
```

Normal saved Nmap text is supported too. HawkProbe extracts open HTTP/HTTPS-like TCP services and turns them into scan targets automatically.

You can combine imported Nmap services with normal input sources; duplicate targets are removed.

## httpx -> HawkProbe

Read URLs from stdin:

```bash
httpx -silent < hosts.txt | hawkprobe -stdin -mode exposure -severity high
```

Or combine stdin with another target source:

```bash
cat extra-urls.txt | hawkprobe -stdin -nmap scan.xml -mode htb
```

## SecLists integration

Use an installed SecLists preset without typing the full path:

```bash
hawkprobe http://box.htb -mode htb -seclists common
```

Use RAFT:

```bash
hawkprobe http://box.htb -mode htb -seclists raft-small -ext php,bak,txt -c 64
```

Show built-in preset names:

```bash
hawkprobe seclists
```

HawkProbe looks for SecLists in common locations including `/usr/share/seclists`, `~/SecLists`, `/opt/SecLists`, and `SECLISTS_DIR`.

Custom install:

```bash
hawkprobe box.htb -seclists raft-medium -seclists-root ~/tools/SecLists
```

You can also pass a SecLists-relative path or a normal wordlist path.

## Scan modes

| Mode | Purpose |
| --- | --- |
| `quick` | Small high-value scan |
| `default` | Balanced everyday scan |
| `full` / `deep` | Broad path coverage plus discovery |
| `htb` | CTF-oriented exposure, admin, API, debug, and discovery checks |
| `exposure` | Secrets, backups, VCS, configs, logs |
| `admin` | Admin/login/management surfaces |
| `api` | Swagger/OpenAPI, GraphQL, developer endpoints |
| `debug` | pprof, Actuator, traces, metrics, health/diagnostics |
| `headers` | Headers, cookies, CORS, HTTP methods |
| `tls` | TLS/certificate inspection |
| `tech` | Technology fingerprinting |

The old `-profile` option remains as an alias for `-mode`.

## Coverage

HawkProbe checks categories including:

- Git, SVN, Mercurial, and Bazaar metadata
- environment files and application configuration
- AWS, Docker, Kubernetes, Terraform, Ansible, Helm, and cloud configuration
- private-key and credential-like files
- ZIP/TAR backups, source archives, editor copies, and temporary files
- SQL dumps, SQLite databases, logs, and debug artifacts
- Apache diagnostics, PHP info, Go pprof, Spring Boot Actuator, ELMAH, metrics and health endpoints
- admin/login panels and common management consoles
- Swagger/OpenAPI, GraphQL, GraphiQL, ReDoc, REST roots, and developer docs
- CI/CD files for GitHub Actions, GitLab, CircleCI, Travis, Azure Pipelines, and others
- package manifests, build files, source maps, IDE metadata, and useful development artifacts
- security headers, cookie flags, CORS, and HTTP methods
- TLS certificate validity, expiry, hostname, and negotiated protocol
- technology markers for common servers, frameworks, CDNs, and applications
- response-body indicators for secrets, private keys, stack traces, debug errors, source maps, and interesting comments

The extended rule pack is deduplicated before use so overlapping categories do not intentionally repeat the same request.

## Progress and performance controls

Progress bar:

```bash
hawkprobe box.htb -mode htb -progress
```

Per-check output:

```bash
hawkprobe box.htb -mode htb -v
```

Concurrency:

```bash
hawkprobe box.htb -mode full -c 64
```

Multiple targets concurrently:

```bash
hawkprobe -list targets.txt -target-c 8
```

Rate limit requests per second per target:

```bash
hawkprobe box.htb -mode full -rate 25
```

The progress bar is written to stderr so structured output stays clean.

## Filtering

Only high/critical checks and findings:

```bash
hawkprobe example.com -mode full -severity high
```

Only one category:

```bash
hawkprobe example.com -mode full -category secrets
```

Only tagged rules:

```bash
hawkprobe box.htb -mode full -include-tag htb
```

Exclude a tag:

```bash
hawkprobe example.com -mode full -exclude-tag cloud
```

## Virtual hosts and authenticated scans

Virtual host against an IP:

```bash
hawkprobe http://10.10.10.10 -host internal.htb -mode htb
```

Custom header:

```bash
hawkprobe -H "X-Test: 1" https://example.com
```

Basic auth:

```bash
hawkprobe -user username -pass password https://example.com
```

Bearer token:

```bash
hawkprobe -token TOKEN https://example.com
```

Proxy through Burp or another HTTP proxy:

```bash
hawkprobe -proxy http://127.0.0.1:8080 https://example.com
```

Secrets supplied through auth flags are not intentionally added to normal findings or verbose output.

## Dynamic discovery

Enable robots/sitemap discovery:

```bash
hawkprobe https://example.com -discover
```

`full`, `deep`, and `htb` enable discovery automatically. HawkProbe parses same-host paths from `robots.txt` and `sitemap.xml`, probes a bounded set, and applies the same custom-404 filtering used by the normal scanner.

Use any wordlist:

```bash
hawkprobe box.htb -wordlist paths.txt -ext php,txt,bak
```

Wordlist expansion is bounded to avoid accidentally creating an unlimited scan.

## Output and automation

Human-readable output is the default.

JSON:

```bash
hawkprobe example.com -json
```

JSON Lines:

```bash
hawkprobe -list targets.txt -jsonl -o results.jsonl
```

CSV:

```bash
hawkprobe -list targets.txt -csv -o findings.csv
```

SARIF 2.1.0:

```bash
hawkprobe -list targets.txt -sarif -o hawkprobe.sarif
```

CI failure threshold:

```bash
hawkprobe staging.example.com -mode exposure -fail-on high
```

`-fail-on high` exits with code `3` when a high or critical finding is present. This makes HawkProbe easy to use in CI without treating normal scan completion as a process failure.

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

Validate before scanning:

```bash
hawkprobe rules validate custom-rules.json
```

List built-ins:

```bash
hawkprobe rules list
```

Dump them as JSON:

```bash
hawkprobe rules
```

Useful rule fields include `severity`, `category`, `confidence`, `method`, `statuses`, `exclude_statuses`, `contains`, `not_contains`, `regex`, `headers`, `content_type`, `evidence`, `remediation`, and `tags`.

## Main options

```text
-mode string          scan mode
-c int                concurrent requests per target
-target-c int         targets scanned concurrently
-rate int             max requests/sec per target
-timeout duration     request timeout
-progress             progress bar on stderr
-discover             robots/sitemap discovery
-wordlist file        arbitrary discovery wordlist
-seclists value       SecLists preset/path
-seclists-root path   custom SecLists root
-ext php,txt,bak      wordlist extension expansion
-nmap file            import Nmap services
-stdin                read target URLs from stdin
-severity level       minimum severity
-category name        filter category
-include-tag tag      require a rule tag
-exclude-tag tag      exclude a rule tag
-fail-on level        CI failure threshold
-v                    verbose per-check output
-evidence             show evidence/remediation
-rules file.json      custom rules
-H "Name: value"      repeatable request header
-host string          override Host header
-user / -pass         Basic auth
-token string         Bearer auth
-proxy URL            HTTP proxy
-ua string            custom User-Agent
-no-redirect          do not follow redirects
-max-redirects int    redirect limit
-k                    allow invalid TLS certificates
-json / -jsonl        JSON output
-csv                  CSV output
-sarif                SARIF 2.1.0 output
-o file               output file
```

## Development

```bash
gofmt -w *.go
go test ./...
go vet ./...
go test -race ./...
```

HawkProbe targets Go 1.20 and newer. See [CONTRIBUTING.md](CONTRIBUTING.md) for adding checks or features.

## Scope

HawkProbe is intended for systems you own or are authorized to test. Normal checks are non-destructive HTTP/TLS probes. It does not deploy payloads, modify remote systems, or attempt persistence.

## License

MIT
