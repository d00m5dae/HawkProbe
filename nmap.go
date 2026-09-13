package main

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"fmt"
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
	Hostnames struct {
		Names []struct {
			Name string `xml:"name,attr"`
		} `xml:"hostname"`
	} `xml:"hostnames"`
	Ports struct {
		Ports []struct {
			PortID int    `xml:"portid,attr"`
			Proto  string `xml:"protocol,attr"`
			State  struct {
				State string `xml:"state,attr"`
			} `xml:"state"`
			Service struct {
				Name   string `xml:"name,attr"`
				Tunnel string `xml:"tunnel,attr"`
			} `xml:"service"`
		} `xml:"port"`
	} `xml:"ports"`
}

func loadNmapTargets(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("nmap input is empty")
	}
	var targets []string
	if trimmed[0] == '<' {
		targets, err = parseNmapXML(trimmed)
	} else if bytes.Contains(trimmed, []byte("Ports:")) && bytes.Contains(trimmed, []byte("Host:")) {
		targets, err = parseNmapGrepable(trimmed)
	} else {
		targets, err = parseNmapNormal(trimmed)
	}
	if err != nil {
		return nil, err
	}
	targets = uniqueStrings(targets)
	if len(targets) == 0 {
		return nil, fmt.Errorf("no open HTTP/HTTPS services found in nmap input")
	}
	return targets, nil
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
		hostname := ""
		for _, addr := range host.Addresses {
			if addr.AddrType == "ipv4" || addr.AddrType == "ipv6" {
				hostname = addr.Addr
				break
			}
		}
		if hostname == "" && len(host.Hostnames.Names) > 0 {
			hostname = host.Hostnames.Names[0].Name
		}
		if hostname == "" {
			continue
		}
		for _, p := range host.Ports.Ports {
			if p.State.State != "open" || p.Proto != "tcp" {
				continue
			}
			if u, ok := nmapHTTPURL(hostname, p.PortID, p.Service.Name, p.Service.Tunnel); ok {
				out = append(out, u)
			}
		}
	}
	return out, nil
}

func parseNmapGrepable(data []byte) ([]string, error) {
	var out []string
	s := bufio.NewScanner(bytes.NewReader(data))
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if !strings.HasPrefix(line, "Host:") || !strings.Contains(line, "Ports:") {
			continue
		}
		parts := strings.SplitN(line, "Ports:", 2)
		hostFields := strings.Fields(strings.TrimSpace(strings.TrimPrefix(parts[0], "Host:")))
		if len(hostFields) == 0 {
			continue
		}
		host := hostFields[0]
		for _, entry := range strings.Split(parts[1], ",") {
			fields := strings.Split(strings.TrimSpace(entry), "/")
			if len(fields) < 5 || fields[1] != "open" || fields[2] != "tcp" {
				continue
			}
			port, err := strconv.Atoi(fields[0])
			if err != nil {
				continue
			}
			if u, ok := nmapHTTPURL(host, port, fields[4], ""); ok {
				out = append(out, u)
			}
		}
	}
	return out, s.Err()
}

func parseNmapNormal(data []byte) ([]string, error) {
	var out []string
	var host string
	s := bufio.NewScanner(bytes.NewReader(data))
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if strings.HasPrefix(line, "Nmap scan report for ") {
			rest := strings.TrimSpace(strings.TrimPrefix(line, "Nmap scan report for "))
			if open := strings.LastIndex(rest, "("); open >= 0 && strings.HasSuffix(rest, ")") {
				host = strings.TrimSuffix(rest[open+1:], ")")
			} else if fields := strings.Fields(rest); len(fields) > 0 {
				host = fields[0]
			}
			continue
		}
		if host == "" || !strings.Contains(line, "/tcp") || !strings.Contains(line, " open ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		port, err := strconv.Atoi(strings.TrimSuffix(fields[0], "/tcp"))
		if err != nil {
			continue
		}
		if u, ok := nmapHTTPURL(host, port, fields[2], ""); ok {
			out = append(out, u)
		}
	}
	return out, s.Err()
}

func nmapHTTPURL(host string, port int, service, tunnel string) (string, bool) {
	service = strings.ToLower(service)
	tunnel = strings.ToLower(tunnel)
	knownHTTPPort := map[int]bool{80: true, 443: true, 3000: true, 5000: true, 7001: true, 8000: true, 8008: true, 8080: true, 8081: true, 8443: true, 8888: true, 9000: true, 9090: true, 9443: true}
	if !strings.Contains(service, "http") && !knownHTTPPort[port] {
		return "", false
	}
	scheme := "http"
	if tunnel == "ssl" || strings.Contains(service, "https") || strings.Contains(service, "ssl") || port == 443 || port == 8443 || port == 9443 {
		scheme = "https"
	}
	return scheme + "://" + hostPort(host, port, scheme), true
}

func hostPort(host string, port int, scheme string) string {
	if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
		if strings.Contains(host, ":") && net.ParseIP(host) != nil {
			return "[" + host + "]"
		}
		return host
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}
