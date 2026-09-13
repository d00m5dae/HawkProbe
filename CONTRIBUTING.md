# Contributing to HawkProbe

HawkProbe is intentionally kept small, readable, and Go-first. Contributions should improve coverage or usability without turning the scanner into a pile of special cases.

## Before you start

- Use Go 1.20 or newer.
- Keep default checks non-destructive.
- Prefer the standard library unless a dependency clearly earns its maintenance cost.
- Do not copy rule databases or templates from other scanners. New checks should be independently described and implemented.

## Development

```bash
git clone https://github.com/d00m5dae/HawkProbe.git
cd HawkProbe
gofmt -w *.go
go test ./...
go vet ./...
go test -race ./...
```

## Adding a built-in check

Use the existing grouped rule builders where possible. A useful rule should have:

- a stable ID
- a specific path or response condition
- a realistic severity
- a category
- a confidence level
- status codes that make sense for the resource
- content/header matching when the path alone would be noisy

Avoid adding hundreds of spelling variants when a wordlist is a better fit.

## Adding an integration

Input integrations should convert external tool output into normal HawkProbe HTTP/HTTPS targets. Keep parsers tolerant of unknown fields and strict about malformed data that could produce bad targets.

Where possible, add fixture-style tests using temporary files rather than depending on installed third-party tools.

## Pull requests

Keep PRs focused enough to review. Include:

- what changed
- why it belongs in HawkProbe
- examples of new CLI behavior
- test coverage
- any compatibility impact

A PR should pass `go test ./...`, `go vet ./...`, and the race test before merge.
