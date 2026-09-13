## What changed

<!-- Describe the behavior/code change. -->

## Why

<!-- What problem or workflow does this improve? -->

## Validation

- [ ] `gofmt -w *.go`
- [ ] `go test ./...`
- [ ] `go vet ./...`
- [ ] `go test -race ./...`
- [ ] CLI/docs updated when behavior changed

## Scanner/rule changes

- [ ] Default behavior remains non-destructive
- [ ] New rules have a clear category/severity
- [ ] False-positive behavior was considered/tested
- [ ] No third-party rule database was copied into the repository

## Notes for reviewers

<!-- Compatibility, performance, output-format changes, screenshots, benchmarks, etc. -->
