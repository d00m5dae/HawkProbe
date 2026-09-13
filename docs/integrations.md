# Tool integrations

HawkProbe can consume output from common reconnaissance and content-discovery tools instead of forcing you to rebuild target lists by hand.

## Nmap

XML output:

```bash
nmap -sV -p- -oX scan.xml 10.10.10.10
hawkprobe -nmap scan.xml -mode htb -target-c 8
```

Grepable output is also accepted:

```bash
nmap -sV -oG scan.gnmap 10.10.10.10
hawkprobe -nmap scan.gnmap -mode htb
```

Only open TCP services that look HTTP-related are imported.

## httpx

```bash
httpx -l hosts.txt -json > httpx.jsonl
hawkprobe -input httpx.jsonl -input-format httpx-jsonl -mode exposure
```

Or stream directly:

```bash
httpx -l hosts.txt -json | hawkprobe -input - -input-format httpx-jsonl -mode default
```

## nuclei

HawkProbe can reuse URLs from nuclei JSONL output:

```bash
hawkprobe -input nuclei.jsonl -input-format nuclei-jsonl -mode full
```

This imports targets only; HawkProbe does not execute nuclei templates.

## ffuf

```bash
ffuf -w words.txt -u http://box.htb/FUZZ -of json -o ffuf.json
hawkprobe -input ffuf.json -input-format ffuf-json -mode exposure
```

## feroxbuster

JSONL results can be used as target input:

```bash
hawkprobe -input ferox.jsonl -input-format ferox-jsonl -mode default
```

## Katana and plain URL lists

Plain one-URL-per-line files work directly. This also fits Katana-style URL output:

```bash
hawkprobe -input urls.txt -input-format plain -mode default
```

## SecLists

Any SecLists file can be passed to `-wordlist`, or you can use a built-in alias:

```bash
hawkprobe wordlists
hawkprobe box.htb -mode htb -seclist raft-small -ext php,bak
```

HawkProbe searches common SecLists installation locations. Set `SECLISTS_PATH` if yours lives somewhere else:

```bash
export SECLISTS_PATH="$HOME/tools/SecLists"
```

## Pipeline output

`-format urls` prints unique finding URLs for another tool:

```bash
hawkprobe -nmap scan.xml -mode exposure -format urls > interesting.txt
```

Structured output is also available as JSON, JSONL, CSV, and Markdown.
