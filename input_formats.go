package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/xml"
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
	Status struct {
		State string `xml:"state,attr"`
	} `xml:"status"`
	Addresses []struct {
		Addr     string `xml:"addr,attr"`
		AddrType string `xml:"addrtype,attr"`
	} `xml:"address"`
	Hostnames []struct {
		Name string `xml:"name,attr"`
	} `xml:"hostnames>hostname"`
	Ports []nmapPort `xml:"ports>port"`
}

type nmapPort struct {
	Protocol string `xml:"protocol,attr"`
	PortID   int    `xml:"portid,attr"`
	State    struct {
		State string `xml:"state,attr"`
	} `xml:"state"`
	Service struct {
		Name   string `xml:"name,attr"`
		Tunnel string `xml:"tunnel,attr"`
	} `xml:"service"`
}

type httpxRecord struct {
	URL    string      `json:"url"`
	Input  string      `json:"input"`
	Host   string      `json:"host"`
	Scheme string      `json:"scheme"`
	Port   interface{} `json:"port"`
}

func readTargetSource(path string) ([]string, error) {
	var r io.Reader
	var f *os.File
	if path == "-" {
		r = os.Stdin
	} else {
		var err error
		f, err = os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}

	data, err := io.ReadAll(io.LimitReader(r, 64<<20))
	if err != nil {
		return nil, err
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("target input is empty")
	}

	if bytes.HasPrefix(trimmed, []byte("<")) && bytes.Contains(trimmed, []byte("<nmaprun")) {
		return parseNmapXML(trimmed)
	}
	if bytes.Contains(trimmed, []byte("Ports:")) && bytes.Contains(trimmed, []byte("Host:")) {
		if out := parseNmapGrepable(string(trimmed)); len(out) > 0 {
			return out, nil
		}
	}
	if bytes.HasPrefix(trimmed, []byte("{")) {
		if out := parseHTTPXJSONL(trimmed); len(out) > 0 {
			return out, nil
		}
	}
	return parsePlainTargets(string(trimmed)), nil
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
		name := nmapHostName(host)
		if name == "" {
			continue
		}
		for _, port := range host.Ports {
			if port.Protocol != "tcp" || port.State.State != "open" || !looksLikeWebService(port) {
				continue
			}
			scheme := nmapScheme(port)
			hostport := net.JoinHostPort(name, strconv.Itoa(port.PortID))
			if (scheme == "http" && port.PortID == 80) || (scheme == "https" && port.PortID == 443) {
				hostport = name
			}
			out = append(out, scheme+"://"+hostport)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("nmap input contained no open HTTP/HTTPS services")
	}
	return dedupeStrings(out), nil
}

func nmapHostName(host nmapHost) string {
	for _, h := range host.Hostnames {
		if h.Name != "" {
			return strings.TrimSpace(h.Name)
		}
	}
	for _, a := range host.Addresses {
		if a.AddrType == "ipv4" || a.AddrType == "ipv6" || a.AddrType == "" {
			return strings.TrimSpace(a.Addr)
		}
	}
	return ""
}

func looksLikeWebService(p nmapPort) bool {
	name := strings.ToLower(p.Service.Name)
	if strings.Contains(name, "http") || name == "ssl" {
		return true
	}
	switch p.PortID {
	case 80, 81, 443, 3000, 4000, 5000, 5601, 7001, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090, 9443:
		return true
	default:
		return false
	}
}

func nmapScheme(p nmapPort) string {
	name := strings.ToLower(p.Service.Name)
	if strings.EqualFold(p.Service.Tunnel, "ssl") || strings.Contains(name, "https") || strings.Contains(name, "ssl") {
		return "https"
	}
	switch p.PortID {
	case 443, 8443, 9443:
		return "https"
	default:
		return "http"
	}
}

func parseNmapGrepable(text string) []string {
	var out []string
	s := bufio.NewScanner(strings.NewReader(text))
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if !strings.HasPrefix(line, "Host:") || !strings.Contains(line, "Ports:") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		host := parts[1]
		portsIndex := strings.Index(line, "Ports:")
		if portsIndex < 0 {
			continue
		}
		portsText := line[portsIndex+len("Ports:"):]
		if i := strings.Index(portsText, "\t"); i >= 0 {
			portsText = portsText[:i]
		}
		for _, entry := range strings.Split(portsText, ",") {
			fields := strings.Split(strings.TrimSpace(entry), "/")
			if len(fields) < 5 || fields[1] != "open" || fields[2] != "tcp" {
				continue
			}
			port, err := strconv.Atoi(fields[0])
			if err != nil {
				continue
			}
			service := strings.ToLower(strings.Join(fields[4:], "/"))
			if !strings.Contains(service, "http") && !isCommonWebPort(port) {
				continue
			}
			scheme := "http"
			if strings.Contains(service, "ssl") || strings.Contains(service, "https") || port == 443 || port == 8443 || port == 9443 {
				scheme = "https"
			}
			hostport := net.JoinHostPort(host, strconv.Itoa(port))
			if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
				hostport = host
			}
			out = append(out, scheme+"://"+hostport)
		}
	}
	return dedupeStrings(out)
}

func parseHTTPXJSONL(data []byte) []string {
	var out []string
	s := bufio.NewScanner(bytes.NewReader(data))
	buf := make([]byte, 64*1024)
	s.Buffer(buf, 2*1024*1024)
	for s.Scan() {
		var rec httpxRecord
		if json.Unmarshal(s.Bytes(), &rec) != nil {
			continue
		}
		if rec.URL != "" {
			out = append(out, rec.URL)
			continue
		}
		host := rec.Host
		if host == "" {
			host = rec.Input
		}
		if host == "" {
			continue
		}
		scheme := rec.Scheme
		if scheme == "" {
			scheme = "https"
		}
		port := interfacePort(rec.Port)
		if port != "" && !strings.Contains(host, ":") {
			host = net.JoinHostPort(host, port)
		}
		out = append(out, scheme+"://"+host)
	}
	return dedupeStrings(out)
}

func interfacePort(v interface{}) string {
	switch x := v.(type) {
	case float64:
		return strconv.Itoa(int(x))
	case string:
		return strings.TrimSpace(x)
	default:
		return ""
	}
}

func parsePlainTargets(text string) []string {
	var out []string
	s := bufio.NewScanner(strings.NewReader(text))
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

func isCommonWebPort(port int) bool {
	switch port {
	case 80, 81, 443, 3000, 4000, 5000, 5601, 7001, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090, 9443:
		return true
	default:
		return false
	}
}

func dedupeStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, value := range in {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
