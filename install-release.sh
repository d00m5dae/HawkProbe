#!/bin/sh
set -eu

os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)

case "$os" in
    linux) os=linux ;;
    darwin) os=darwin ;;
    *) echo "unsupported OS: $os"; exit 1 ;;
esac

case "$arch" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) echo "unsupported architecture: $arch"; exit 1 ;;
esac

name="hawkprobe-$os-$arch"
base="https://github.com/d00m5dae/HawkProbe/releases/latest/download"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

fetch() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$1" -o "$2"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$2" "$1"
    else
        echo "curl or wget is required"
        exit 1
    fi
}

fetch "$base/$name" "$tmp/$name"
fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS"

expected=$(awk -v n="$name" '$2 == "dist/" n || $2 == n {print $1}' "$tmp/SHA256SUMS" | head -n1)
if [ -n "$expected" ]; then
    if command -v sha256sum >/dev/null 2>&1; then
        actual=$(sha256sum "$tmp/$name" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        actual=$(shasum -a 256 "$tmp/$name" | awk '{print $1}')
    else
        echo "sha256sum or shasum is required to verify the download"
        exit 1
    fi
    if [ "$actual" != "$expected" ]; then
        echo "checksum verification failed"
        exit 1
    fi
fi

chmod 755 "$tmp/$name"
if [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
    install -m 755 "$tmp/$name" /usr/local/bin/hawkprobe
    dest=/usr/local/bin
elif command -v sudo >/dev/null 2>&1; then
    sudo install -d /usr/local/bin
    sudo install -m 755 "$tmp/$name" /usr/local/bin/hawkprobe
    dest=/usr/local/bin
else
    dest="$HOME/.local/bin"
    mkdir -p "$dest"
    install -m 755 "$tmp/$name" "$dest/hawkprobe"
fi

echo "installed: $dest/hawkprobe"
