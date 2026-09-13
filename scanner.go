package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type baseline struct {
	status int
	length int64
}

func scanTarget(opts options, target string, rules []rule) scanResult {
	start := time.Now()
	var requests int64
	client, err := newClient(opts)
	if err != nil {
		return scanResult{Target: target, DurationMS: time.Since(start).Milliseconds(), Error: err.Error()}
	}
	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout*time.Duration(len(rules)+6))
	defer cancel()

	base, body, err := fetchBody(ctx, client, opts, target, 256*1024, &requests)
	if err != nil {
		return scanResult{Target: target, DurationMS: time.Since(start).Milliseconds(), Requests: int(requests), Error: cleanError(err)}
	}

	findings := inspectBase(target, base, body)
	findings = append(findings, fingerprint(target, base, body)...)
	bl := getBaseline(ctx, client, opts, target, &requests)
	findings = append(findings, scanRules(ctx, client, opts, target, rules, bl, &requests)...)
	findings = append(findings, inspectTLS(target, opts.Insecure, opts.Timeout)...)
	sortFindings(findings)

	return scanResult{
		Target:     target,
		Status:     base.Status,
		DurationMS: time.Since(start).Milliseconds(),
		Requests:   int(requests),
		Findings:   findings,
	}
}

func newClient(opts options) (*http.Client, error) {
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          opts.Concurrency * 2,
		MaxIdleConnsPerHost:   opts.Concurrency,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   opts.Timeout,
		ResponseHeaderTimeout: opts.Timeout,
		DialContext: (&net.Dialer{
			Timeout:   opts.Timeout,
			KeepAlive: 20 * time.Second,
		}).DialContext,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: opts.Insecure},
	}
	if opts.Proxy != "" {
		u, err := url.Parse(opts.Proxy)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return nil, errors.New("invalid proxy URL")
		}
		transport.Proxy = http.ProxyURL(u)
	}
	return &http.Client{
		Transport: transport,
		Timeout:   opts.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if opts.NoRedirect {
				return http.ErrUseLastResponse
			}
			if len(via) >= opts.MaxRedirects {
				return errors.New("too many redirects")
			}
			return nil
		},
	}, nil
}

func makeRequest(ctx context.Context, client *http.Client, opts options, target string, requests *int64) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	ua := opts.UserAgent
	if ua == "" {
		ua = "hawkprobe/" + version
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "*/*")
	for _, raw := range opts.Headers {
		parts := strings.SplitN(raw, ":", 2)
		req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
	}
	if opts.Token != "" {
		req.Header.Set("Authorization", "Bearer "+opts.Token)
	} else if opts.User != "" || opts.Pass != "" {
		req.SetBasicAuth(opts.User, opts.Pass)
	}
	atomic.AddInt64(requests, 1)
	return client.Do(req)
}

func fetchBody(ctx context.Context, client *http.Client, opts options, target string, limit int64, requests *int64) (*http.Response, []byte, error) {
	resp, err := makeRequest(ctx, client, opts, target, requests)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, nil, err
	}
	return resp, body, nil
}

func getBaseline(ctx context.Context, client *http.Client, opts options, target string, requests *int64) baseline {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return baseline{}
	}
	path := "/.hawkprobe-" + hex.EncodeToString(buf)
	resp, body, err := fetchBody(ctx, client, opts, target+path, 64*1024, requests)
	if err != nil {
		return baseline{}
	}
	return baseline{status: resp.StatusCode, length: int64(len(body))}
}

func scanRules(ctx context.Context, client *http.Client, opts options, target string, rules []rule, base baseline, requests *int64) []finding {
	workers := opts.Concurrency
	if workers > len(rules) {
		workers = len(rules)
	}
	if workers < 1 {
		return nil
	}
	jobs := make(chan rule)
	results := make(chan finding, len(rules))
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for r := range jobs {
				u := target + r.Path
				resp, body, err := fetchBody(ctx, client, opts, u, 256*1024, requests)
				if err != nil || !statusAllowed(resp.StatusCode, r.Statuses) {
					continue
				}
				if !ruleMatches(r, resp, body, base) {
					continue
				}
				msg := r.Name
				if resp.StatusCode != http.StatusOK {
					msg += fmt.Sprintf(" (%d)", resp.StatusCode)
				}
				results <- finding{Severity: parseSeverity(r.Severity), Level: parseSeverity(r.Severity).String(), Rule: r.ID, Message: msg, URL: u}
			}
		}()
	}

	go func() {
		for _, r := range rules {
			select {
			case jobs <- r:
			case <-ctx.Done():
				close(jobs)
				wg.Wait()
				close(results)
				return
			}
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	var out []finding
	for f := range results {
		out = append(out, f)
	}
	return out
}

func ruleMatches(r rule, resp *http.Response, body []byte, base baseline) bool {
	text := string(body)
	if len(r.Contains) > 0 && !containsAny(text, r.Contains) {
		return false
	}
	if len(r.NotContains) > 0 && !containsNone(text, r.NotContains) {
		return false
	}
	for name, expected := range r.Headers {
		value := resp.Header.Get(name)
		if value == "" {
			return false
		}
		if expected != "" && !strings.Contains(strings.ToLower(value), strings.ToLower(expected)) {
			return false
		}
	}
	if len(r.Contains) == 0 && len(r.Headers) == 0 && looksLikeBaseline(resp.StatusCode, int64(len(body)), base) {
		return false
	}
	return true
}

func looksLikeBaseline(status int, length int64, base baseline) bool {
	if base.status == 0 || status != base.status {
		return false
	}
	if base.length == 0 {
		return length == 0
	}
	delta := length - base.length
	if delta < 0 {
		delta = -delta
	}
	return delta <= 48
}

func inspectBase(target string, resp *http.Response, body []byte) []finding {
	var out []finding
	h := resp.Header
	u, _ := url.Parse(target)

	if u != nil && u.Scheme == "https" && h.Get("Strict-Transport-Security") == "" {
		out = append(out, newFinding(low, "missing-hsts", "HSTS header is missing", target))
	}
	if h.Get("Content-Security-Policy") == "" {
		out = append(out, newFinding(low, "missing-csp", "Content-Security-Policy header is missing", target))
	}
	if h.Get("X-Content-Type-Options") == "" {
		out = append(out, newFinding(low, "missing-nosniff", "X-Content-Type-Options header is missing", target))
	}
	if h.Get("Referrer-Policy") == "" {
		out = append(out, newFinding(low, "missing-referrer-policy", "Referrer-Policy header is missing", target))
	}
	if h.Get("X-Frame-Options") == "" && !strings.Contains(strings.ToLower(h.Get("Content-Security-Policy")), "frame-ancestors") {
		out = append(out, newFinding(low, "missing-frame-protection", "frame protection is missing", target))
	}
	if h.Get("Permissions-Policy") == "" {
		out = append(out, newFinding(info, "missing-permissions-policy", "Permissions-Policy header is missing", target))
	}
	if server := h.Get("Server"); server != "" {
		out = append(out, newFinding(info, "server-header", "server header: "+server, target))
	}
	if powered := h.Get("X-Powered-By"); powered != "" {
		out = append(out, newFinding(info, "powered-by", "X-Powered-By header: "+powered, target))
	}
	if strings.EqualFold(h.Get("Access-Control-Allow-Origin"), "*") && strings.EqualFold(h.Get("Access-Control-Allow-Credentials"), "true") {
		out = append(out, newFinding(medium, "cors-wildcard-credentials", "CORS allows wildcard origin with credentials", target))
	}
	for _, raw := range h.Values("Set-Cookie") {
		cookie := strings.ToLower(raw)
		name := strings.SplitN(raw, "=", 2)[0]
		if !strings.Contains(cookie, "httponly") {
			out = append(out, newFinding(low, "cookie-httponly", "cookie "+name+" is missing HttpOnly", target))
		}
		if u != nil && u.Scheme == "https" && !strings.Contains(cookie, "secure") {
			out = append(out, newFinding(low, "cookie-secure", "cookie "+name+" is missing Secure", target))
		}
		if !strings.Contains(cookie, "samesite") {
			out = append(out, newFinding(info, "cookie-samesite", "cookie "+name+" is missing SameSite", target))
		}
	}
	text := strings.ToLower(string(body))
	if strings.Contains(text, "index of /") && strings.Contains(text, "parent directory") {
		out = append(out, newFinding(medium, "directory-listing", "directory listing appears enabled", target))
	}
	return out
}

func fingerprint(target string, resp *http.Response, body []byte) []finding {
	var out []finding
	server := strings.ToLower(resp.Header.Get("Server"))
	powered := strings.ToLower(resp.Header.Get("X-Powered-By"))
	text := strings.ToLower(string(body))
	seen := make(map[string]bool)
	add := func(id, name string) {
		if !seen[id] {
			seen[id] = true
			out = append(out, newFinding(info, id, "technology: "+name, target))
		}
	}
	if strings.Contains(server, "nginx") {
		add("tech-nginx", "nginx")
	}
	if strings.Contains(server, "apache") {
		add("tech-apache", "Apache")
	}
	if strings.Contains(server, "microsoft-iis") {
		add("tech-iis", "Microsoft IIS")
	}
	if strings.Contains(server, "cloudflare") || resp.Header.Get("CF-Ray") != "" {
		add("tech-cloudflare", "Cloudflare")
	}
	if strings.Contains(powered, "php") {
		add("tech-php", "PHP")
	}
	if strings.Contains(powered, "asp.net") {
		add("tech-aspnet", "ASP.NET")
	}
	if strings.Contains(text, "wp-content/") || strings.Contains(text, "wp-includes/") {
		add("tech-wordpress", "WordPress")
	}
	if strings.Contains(text, "grafana") && strings.Contains(text, "public/build") {
		add("tech-grafana", "Grafana")
	}
	if strings.Contains(text, "jenkins") && strings.Contains(text, "adjuncts") {
		add("tech-jenkins", "Jenkins")
	}
	return out
}

func inspectTLS(target string, insecure bool, timeout time.Duration) []finding {
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "https" {
		return nil
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, port), &tls.Config{ServerName: host, InsecureSkipVerify: insecure})
	if err != nil {
		if insecure {
			return []finding{newFinding(medium, "tls-handshake", "TLS handshake failed: "+cleanError(err), target)}
		}
		return []finding{newFinding(high, "tls-validation", "TLS certificate validation failed: "+cleanError(err), target)}
	}
	defer conn.Close()
	state := conn.ConnectionState()
	var out []finding
	if state.Version == tls.VersionTLS10 || state.Version == tls.VersionTLS11 {
		out = append(out, newFinding(high, "legacy-tls", "legacy TLS version negotiated", target))
	}
	if len(state.PeerCertificates) == 0 {
		return out
	}
	cert := state.PeerCertificates[0]
	remaining := time.Until(cert.NotAfter)
	if remaining < 0 {
		out = append(out, newFinding(high, "tls-expired", "TLS certificate is expired", target))
	} else if remaining < 30*24*time.Hour {
		out = append(out, newFinding(medium, "tls-expiring", fmt.Sprintf("TLS certificate expires in %d days", int(remaining.Hours()/24)), target))
	}
	if insecure {
		if err := cert.VerifyHostname(host); err != nil {
			out = append(out, newFinding(medium, "tls-hostname", "TLS certificate hostname mismatch", target))
		}
	}
	return out
}

func newFinding(s severity, id, message, target string) finding {
	return finding{Severity: s, Level: s.String(), Rule: id, Message: message, URL: target}
}

func cleanError(err error) string {
	msg := err.Error()
	if i := strings.Index(msg, ": "); i >= 0 {
		msg = msg[i+2:]
	}
	return msg
}
