# Contributing to HawkProbe

Thanks for helping improve HawkProbe.

The project tries to stay fast, readable, easy to build, and useful in real authorized web assessments. Changes that add coverage are welcome, but maintainability and false-positive control matter as much as raw rule count.

## Before you start

For larger features, open an issue first so the design can be discussed before a big patch is written.

Good contributions include:

- new exposure or misconfiguration checks
- better false-positive handling
- performance improvements with benchmarks
- input/output integrations
- tests for unusual HTTP behavior
- documentation and examples
- clearer error messages and terminal UX

## Development setup

HawkProbe targets Go 1.20+.

```bash
git clone https://github.com/d00m5dae/HawkProbe.git
cd HawkProbe
go test ./...
go vet ./...
```

Before opening a PR:

```bash
gofmt -w *.go
go test ./...
go vet ./...
go test -race ./...
```

## Code style

Keep the code direct and idiomatic.

- Prefer small focused files and functions over giant framework-like abstractions.
- Avoid dependencies for features the standard library handles well.
- Do not add comments that only restate obvious Go syntax.
- Preserve context cancellation and bounded concurrency.
- Do not create unbounded goroutines.
- Keep structured output stable unless a breaking change is intentional and documented.
- Keep credentials, tokens, cookies, and authorization headers out of errors and normal logs.

## Adding built-in rules

Rules should represent a useful, explainable signal.

A rule should have:

- a stable ID
- path
- clear finding name
- severity
- category
- confidence when useful
- expected statuses and/or content evidence
- remediation when the fix is not obvious

Prefer strong content/header evidence for sensitive findings. Generic path-only checks should normally rely on HawkProbe's soft-404 baseline and use conservative severity.

Do not copy another scanner's proprietary/copyrighted rule database into HawkProbe. Original rules based on public protocol/application behavior are fine. External databases such as SecLists should be integrated as user-supplied inputs rather than vendored wholesale.

## Safety and scope

Default functionality should remain non-destructive.

Do not add features whose normal behavior intentionally:

- modifies target data
- uploads or deploys payloads
- creates accounts or persistence
- performs denial of service
- executes destructive commands

Safe detection probes are preferred over exploitation.

## Tests

Use `httptest` for HTTP behavior whenever possible. Tests should not depend on public websites.

Useful cases include:

- soft 404/wildcard routing
- redirects
- unusual status codes
- auth headers
- Nmap/httpx parsing
- custom rule validation
- large wordlist behavior
- cancellation and race safety

## Pull requests

Keep PRs reviewable. Explain:

1. what changed,
2. why it helps,
3. how it was tested,
4. any compatibility or performance tradeoffs.

If a feature changes CLI behavior, update the README/help text and add tests.
