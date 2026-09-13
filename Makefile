BINARY := hawkprobe
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
PREFIX ?= /usr/local
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build install uninstall test clean

build:
	GOTOOLCHAIN=local CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BINARY) .

install: build
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 $(BINARY) $(DESTDIR)$(PREFIX)/bin/$(BINARY)

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(BINARY)

test:
	GOTOOLCHAIN=local go test ./...
	GOTOOLCHAIN=local go vet ./...
	GOTOOLCHAIN=local go test -race ./...

clean:
	rm -f $(BINARY)
