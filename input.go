package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
)

type nmapRun struct {
	Hosts []nmapHost `xml:"host"`
}

type nmapHost struct {
	Status struct { State string `xml:"state,attr"` } `xml:"status"`
	Addresses []struct {
		Addr string `xml:"addr,attr"`
		Type string `xml:"addrtype,attr"`
	} `xml:"address"`
	Ports []struct {
		Protocol string `xml:"protocol,attr"`
		PortID int `xml:"portid,attr"`
		State struct { State string `xml:"state,attr"` } `xml:"state"`
		Service struct {
			Name string `xml:"name,attr"`
			Tunnel string `xml:"tunnel,attr"`
		} `xml:"service"`
	} `xml:"ports>port"`
}

func loadInputTargets(path, format string) ([]string, error) {
	data, err := readInput(path)
	if err != nil {
		return nil, err
	}
	format = lower(format)
	if format == "" || format == "auto" {
		format = detectInputFormat(data)
	}
	var raw []string
	switch format {
	case "plain", "urls", "katana":
		raw = parsePlainInput(data)
	case "nmap", "nmap-xml":
		if bytes.Contains(data, []byte("<nmaprun")) {
			raw, err = parseNmapXML(data)
		} else {
			raw, err = parseNmapGrepable(data)
		}
	case "nmap-gnmap", "gnmap":
		raw, err = parseNmapGrepable(data)
	case "httpx", "httpx-jsonl", "nuclei", "nuclei-jsonl", "ferox", "ferox-jsonl":
		raw, err = parseJSONLTargets(data)
	case "ffuf", "ffuf-json":
		raw, err = parseFFUFJSON(data)
	default:
		return nil, fmt.Errorf("unsupported input format %q", format)
	}
	if err != nil {
		return nil, err
	}
	return normalizeImportedTargets(raw)
}

func readInput(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func detectInputFormat(data []byte) string {
	trimmed := bytes.TrimSpace(data)
	if bytes.HasPrefix(trimmed, []byte("<?xml")) || bytes.Contains(trimmed, []byte("<nmaprun")) {
		return "nmap-xml"
	}
	if bytes.Contains(trimmed, []byte("Host:")) && bytes.Contains(trimmed, []byte("Ports:")) {
		return "nmap-gnmap"
	}
	if bytes.HasPrefix(trimmed, []byte("{")) {
		var top map[string]json.RawMessage
		if json.Unmarshal(trimmed, &top) == nil {
			if _, ok := top["results"]; ok {
				return "ffuf-json"
			}
		}
		return "httpx-jsonl"
	}
	return "plain"
}

func parsePlainInput(data []byte) []string {
	var out []string
	s := bufio.NewScanner(bytes.NewReader(data))
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

func parseNmapXML(data []byte) ([]string, error) {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, fmt.Errorf("parse nmap XML: %w", err)
	}
	var out []string
	for _, host := range run.Hosts {
		if host.Status.State != "" && host.Status.State != "up" {
			continue
		}
		addr := ""
		for _, a := range host.Addresses {
			if a.Type == "ipv4" || a.Type == "ipv6" {
				addr = a.Addr
				break
			}
		}
		if addr == "" {
			continue
		}
		for _, p := range host.Ports {
			if p.Protocol != "tcp" || p.State.State != "open" || !looksHTTPService(p.Service.Name, p.PortID) {
				continue
			}
			scheme := schemeForService(p.Service.Name, p.Service.Tunnel, p.PortID)
			out = append(out, targetForHostPort(scheme, addr, p.PortID))
		}
	}
	return out, nil
}

func parseNmapGrepable(data []byte) ([]string, error) {
	var out []string
	s := bufio.NewScanner(bytes.NewReader(data))
	for s.Scan() {
		line := s.Text()
		if !strings.Contains(line, "Ports:") || !strings.HasPrefix(line, "Host:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		host := fields[1]
		idx := strings.Index(line, "Ports:")
		if idx < 0 {
			continue
		}
		portsPart := line[idx+len("Ports:"):]
		if tab := strings.IndexByte(portsPart, '\t'); tab >= 0 {
			portsPart = portsPart[:tab]
		}
		for _, entry := range strings.Split(portsPart, ",") {
			parts := strings.Split(strings.TrimSpace(entry), "/")
			if len(parts) < 5 || parts[1] != "open" || parts[2] != "tcp" {
				continue
			}
			port, err := strconv.Atoi(parts[0])
			if err != nil || !looksHTTPService(parts[4], port) {
				continue
			}
			out = append(out, targetForHostPort(schemeForService(parts[4], "", port), host, port))
		}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func parseJSONLTargets(data []byte) ([]string, error) {
	var out []string
	s := bufio.NewScanner(bytes.NewReader(data))
	buf := make([]byte, 64*1024)
	s.Buffer(buf, 4*1024*1024)
	for s.Scan() {
		line := bytes.TrimSpace(s.Bytes())
		if len(line) == 0 {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal(line, &record); err != nil {
			continue
		}
		if target := targetFromRecord(record); target != "" {
			out = append(out, target)
		}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func parseFFUFJSON(data []byte) ([]string, error) {
	var doc struct {
		Results []struct { URL string `json:"url"` } `json:"results"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse ffuf JSON: %w", err)
	}
	out := make([]string, 0, len(doc.Results))
	for _, result := range doc.Results {
		if result.URL != "" {
			out = append(out, result.URL)
		}
	}
	return out, nil
}

func targetFromRecord(record map[string]any) string {
	for _, key := range []string{"url", "matched-at", "matched_at"} {
		if value, ok := record[key].(string); ok && strings.TrimSpace(value) != "" {
			return value
		}
	}
	host, _ := record["host"].(string)
	if host == "" {
		host, _ = record["input"].(string)
	}
	if host == "" {
		return ""
	}
	if strings.Contains(host, "://") {
		return host
	}
	scheme, _ := record["scheme"].(string)
	if scheme == "" {
		scheme = "https"
	}
	port := 0
	switch v := record["port"].(type) {
	case float64:
		port = int(v)
	case string:
		port, _ = strconv.Atoi(v)
	}
	if port > 0 {
		return targetForHostPort(scheme, host, port)
	}
	return scheme + "://" + host
}

func normalizeImportedTargets(raw []string) ([]string, error) {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		target, err := normalizeTarget(item)
		if err != nil {
			continue
		}
		if _, ok := seen[target]; ok {
			continue
		}
		seen[target] = struct{}{}
		out = append(out, target)
	}
	if len(out) == 0 {
		return nil, errors.New("input contained no usable HTTP/HTTPS targets")
	}
	return out, nil
}

func looksHTTPService(service string, port int) bool {
	service = strings.ToLower(service)
	if strings.Contains(service, "http") || strings.Contains(service, "web") {
		return true
	}
	switch port {
	case 80, 81, 443, 3000, 5000, 7001, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090, 9443, 10000:
		return true
	default:
		return false
	}
}

func schemeForService(service, tunnel string, port int) string {
	value := strings.ToLower(service + " " + tunnel)
	if strings.Contains(value, "https") || strings.Contains(value, "ssl") || port == 443 || port == 8443 || port == 9443 {
		return "https"
	}
	return "http"
}

func targetForHostPort(scheme, host string, port int) string {
	if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
		if strings.Contains(host, ":") {
			return scheme + "://[" + strings.Trim(host, "[]") + "]"
		}
		return scheme + "://" + host
	}
	return scheme + "://" + net.JoinHostPort(strings.Trim(host, "[]"), strconv.Itoa(port))
}
