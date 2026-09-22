# Changelog

## 1.4.0 (2026-09-22)

- Added HTML and Markdown report output with `-html` / `-md`, plus `-bundle dir` which writes report.html, report.md, findings.csv, hawkprobe.sarif, results.json, and results.jsonl in one call
- Added named scan profiles with `-profile` and `hawkprobe config show|set|rm`; profiles live in `~/.config/hawkprobe/config.json` and can pin mode, categories, rate, concurrency, severity, fail-on, wordlists, suppressions, custom rules, and AI settings
- Added retry support for transient failures with `-retries` (HTTP 502/503/504, connection resets, timeouts) and a per-target request budget with `-max-requests`
- Added scan workspaces: `-workspace dir` records every scan with full results for later review, `hawkprobe resume <id>` picks up incomplete scans where they left off, and `hawkprobe diff <id-a> <id-b>` reports new/resolved/regressed findings between any two recorded scans
- Added finding suppressions with `hawkprobe suppress list|add|remove`; suppressions can be scoped by rule, target, and/or URL path and can expire after a duration such as `30d` or `12h`; suppressed findings are excluded from output, summaries, fail-on, and workspace records
- Added optional Ollama AI summaries with `-ai` (model selection via `-ai-model`, host via `OLLAMA_HOST` or the `ai` config block); summaries appear in terminal, JSON, HTML, and Markdown output and never fail the scan if Ollama is unavailable
- Added a custom rule DSL with `-custom-rules file.json` (also `HAWKPROBE_CUSTOM_RULES` or a profile `custom-rules` key): per-rule name/path/method/severity/category/message and expect conditions (status, status_any, contains, contains_any, not_contains, header) with trailing-glob path support; validate files with `hawkprobe rules check <file>`
- Raised the built-in catalog to 899 rules
- Expanded the README with workflow documentation for profiles, reports, workspaces, suppressions, AI summaries, and the custom rule DSL
- Added custom-rules.dsl.example.json alongside the existing legacy-format example

## 1.3.0 (development)

- Added automatic Nmap XML, grepable (`-oG`), and normal saved-text target import through `-list`
- Added friendly `-nmap` and `-stdin` compatibility aliases over the same input pipeline
- Added stdin target ingestion with `-list -`
- Added httpx JSONL input support
- Added SecLists auto-discovery and presets such as `@common`, `@dirs-medium`, `@graphql`, and `@mcp`
- Added `-seclists` as a friendly alias for SecLists presets
- Raised wordlist generation limits for large RAFT/SecLists scans
- Added adaptive terminal progress bars with automatic suppression for scripts and structured output
- Added colored terminal findings with `NO_COLOR` and `-no-color` support
- Added quiet output with `-q`
- Added per-target request pacing with `-rate`
- Added category, tag, and minimum-severity filtering
- Added `-urls-out` for chaining discovered URLs into Nuclei, httpx, ffuf, and similar tools
- Added `hawkprobe doctor` and `hawkprobe wordlists`
- Added CSV findings output
- Added SARIF 2.1.0 output for security/CI tooling
- Added `-fail-on` severity thresholds with exit code 3 for CI pipelines
- Added bash, zsh, and fish completion generation
- Expanded the built-in catalog by hundreds of checks across VCS, configuration, backups, cloud, DevOps, admin, API, CMS/framework, debug, source/build, and metadata exposure classes
- Added automatic generated-rule ID and request de-duplication
- Added Nmap, httpx, SecLists, report-format, filtering, and minimum-catalog-size tests
- Added CONTRIBUTING.md, SECURITY.md, issue templates, and a pull-request template
- Reworked the README around practical pentest/HTB and automation workflows

## 1.2.0 (development)

- Added scan modes: `quick`, `default`, `full`, `deep`, `htb`, `exposure`, `admin`, `api`, `debug`, `headers`, `tls`, and `tech`
- Expanded built-in path rules from 74 to 159 and organized them by category
- Added parallel multi-target scanning with `-target-c`
- Raised the per-target concurrency ceiling and improved HTTP connection reuse/HTTP2 behavior
- Added two-sample soft-404/wildcard-response detection
- Added verbose per-rule output and richer scan summaries
- Added finding categories, confidence, evidence, and remediation fields
- Added critical severity
- Added active non-destructive CORS origin-reflection checks
- Added HTTP OPTIONS/method inspection
- Added robots.txt and sitemap.xml path discovery
- Added optional wordlist discovery with extension expansion
- Added custom Host header support for virtual-host testing
- Added response checks for private keys, AWS-key patterns, generic secrets, stack traces, source maps, and interesting HTML comments
- Expanded technology fingerprinting
- Expanded TLS details, including negotiated version, issuer, and certificate expiry metadata
- Expanded the custom rule format with methods, excluded statuses, regex, content-type, category, confidence, evidence, remediation, and tags
- Added `hawkprobe rules list` and `hawkprobe rules validate`
- Allowed flags before or after a positional target
- Preserved the old `-profile` flag as an alias for `-mode`
- Added more automated tests and race-test coverage

## 1.1.0

- Added quick, default, and full scan profiles
- Expanded built-in rules from 12 to 74
- Added external JSON rule files
- Added target list scanning
- Added JSON Lines output and output files
- Added custom request headers
- Added Basic and Bearer authentication
- Added HTTP proxy support
- Added redirect controls and custom User-Agent support
- Added more security-header and cookie checks
- Added basic CORS checks
- Added technology fingerprinting
- Added TLS legacy-version detection
- Added prebuilt release installers for Linux, macOS, and Windows
- Kept Go 1.20+ compatibility

## 1.0.0

- Initial release
- Concurrent path scanning
- Basic exposed-file checks
- Security-header checks
- Cookie checks
- TLS certificate checks
- JSON output
- Missing-path baseline filtering
