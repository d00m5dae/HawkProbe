#!/bin/sh
set -eu

if ! command -v go >/dev/null 2>&1; then
    echo "Go 1.20 or newer is required for source installation."
    echo "Or use install-release.sh to install a prebuilt release."
    exit 1
fi

version=$(GOTOOLCHAIN=local go env GOVERSION 2>/dev/null || true)
version=${version#go}
major=${version%%.*}
rest=${version#*.}
minor=${rest%%.*}

case "$major.$minor" in
    ''|*[!0-9.]*) echo "Could not determine Go version."; exit 1 ;;
esac

if [ "$major" -lt 1 ] || { [ "$major" -eq 1 ] && [ "$minor" -lt 20 ]; }; then
    echo "HawkProbe requires Go 1.20 or newer. Found go$version."
    exit 1
fi

build_version=${HAWKPROBE_VERSION:-}
if [ -z "$build_version" ]; then
    build_version=$(git describe --tags --always --dirty 2>/dev/null || printf '%s' source)
fi

GOTOOLCHAIN=local CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$build_version" -o hawkprobe .

if [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
    install -m 755 hawkprobe /usr/local/bin/hawkprobe
    dest=/usr/local/bin
elif command -v sudo >/dev/null 2>&1; then
    sudo install -d /usr/local/bin
    sudo install -m 755 hawkprobe /usr/local/bin/hawkprobe
    dest=/usr/local/bin
else
    dest="$HOME/.local/bin"
    mkdir -p "$dest"
    install -m 755 hawkprobe "$dest/hawkprobe"
fi

echo "installed: $dest/hawkprobe"
case ":$PATH:" in *":$dest:"*) ;; *) echo "add $dest to PATH" ;; esac
