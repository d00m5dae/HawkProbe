package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var verboseMu sync.Mutex

func scanTarget(opts options, target string, rules []rule) scanResult {
	start := time.Now()
	var requests int64
	if opts.Mode == "tls" {
		findings := inspectTLS(target, opts.Insecure, opts.Timeout)
		sortFindings(findings)
		return scanResult{Target: target, DurationMS: time.Since(start).Milliseconds(), Findings: findings}
	}

	client, err := newClient(opts)
	if err != nil {
		return scanResult{Target: target, DurationMS: time.Since(start).Milliseconds(), Error: err.Error()}
	}

	budget := opts.Timeout * time.Duration(maxInt(8, (len(rules)/maxInt(1, opts.Concurrency))+8))
	if budget < 30*time.Second {
		budget = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	baseResp, body, err := fetchBody(ctx, client, opts, http.MethodGet, target, nil, 512*1024, &requests)
	if err != nil {
		return scanResult{Target: target, DurationMS: time.Since(start).Milliseconds(), Requests: int(requests), Error: cleanError(err)}
	}
	meta := inspectResponseMeta(baseResp, body)

	var findings []finding
	if opts.Mode != "tech" {
		findings = inspectBase(target, baseResp, body)
	}
	if opts.Mode == "htb" || opts.Mode == "full" || opts.Mode == "deep" || opts.Mode == "exposure" {
		findings = append(findings, inspectContent(target, body)...)
	}
	if opts.Mode != "headers" {
		findings = append(findings, fingerprint(target, baseResp, body)...)
	}

	needBaseline := len(rules) > 0 || opts.Discover || opts.Mode == "htb" || opts.Mode == "full" || opts.Mode == "deep"
	bl := baseline{}
	if needBaseline {
		bl = getBaseline(ctx, client, opts, target, &requests)
	}
	ruleFindings, stats := scanRules(ctx, client, opts, target, rules, bl, &requests)
	findings = append(findings, ruleFindings...)

	if modeRunsHTTPProbes(opts.Mode) {
		findings = append(findings, inspectMethods(ctx, client, opts, target, &requests)...)
		findings = append(findings, inspectCORS(ctx, client, opts, target, &requests)...)
	}
	if opts.Discover || opts.Mode == "htb" || opts.Mode == "full" || opts.Mode == "deep" {
		findings = append(findings, discoverInterestingPaths(ctx, client, opts, target, bl, &requests)...)
	}
	if opts.Mode != "tech" {
		findings = append(findings, inspectTLS(target, opts.Insecure, opts.Timeout)...)
	}

	findings = dedupeFindings(findings)
	sortFindings(findings)
	return scanResult{
		Target:        target,
		Status:        baseResp.Status,
		Title:         meta.Title,
		FinalURL:      meta.FinalURL,
		ContentType:   meta.ContentType,
		ContentLength: meta.ContentLength,
		Server:        meta.Server,
		DurationMS:    time.Since(start).Milliseconds(),
		Requests:      int(requests),
		RulesChecked:  stats.Checked,
		NoMatch:       stats.NoMatch,
		Skipped:       stats.Skipped,
		Findings:      findings,
	}
}

func newClient(opts options) (*http.Client, error) {
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          maxInt(64, opts.Concurrency*4),
		MaxIdleConnsPerHost:   maxInt(32, opts.Concurrency*2),
		MaxConnsPerHost:       maxInt(32, opts.Concurrency*2),
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   opts.Timeout,
		ResponseHeaderTimeout: opts.Timeout,
		ExpectContinueTimeout: time.Second,
		ForceAttemptHTTP2:     true,
		DialContext:           (&net.Dialer{Timeout: opts.Timeout, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: opts.Insecure, MinVersion: tls.VersionTLS10},
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

func makeRequest(ctx context.Context, client *http.Client, opts options, method, target string, extra http.Header, requests *int64) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, nil)
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
	for k, values := range extra {
		for _, v := range values {
			req.Header.Add(k, v)
		}
	}
	if opts.HostHeader != "" {
		req.Host = opts.HostHeader
	}
	if opts.Token != "" {
		req.Header.Set("Authorization", "Bearer "+opts.Token)
	} else if opts.User != "" || opts.Pass != "" {
		req.SetBasicAuth(opts.User, opts.Pass)
	}
	atomic.AddInt64(requests, 1)
	return client.Do(req)
}

func fetchBody(ctx context.Context, client *http.Client, opts options, method, target string, extra http.Header, limit int64, requests *int64) (*http.Response, []byte, error) {
	resp, err := makeRequest(ctx, client, opts, method, target, extra, requests)
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

func scanRules(ctx context.Context, client *http.Client, opts options, target string, rules []rule, base baseline, requests *int64) ([]finding, ruleStats) {
	workers := minInt(opts.Concurrency, len(rules))
	if workers < 1 {
		return nil, ruleStats{}
	}
	type result struct {
		finding *finding
		matched bool
		skipped bool
	}
	jobs := make(chan rule)
	results := make(chan result, workers*2)
	var wg sync.WaitGroup
	progress := newProgressBar(opts, target, len(rules))

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for r := range jobs {
				u := joinURL(target, r.Path)
				resp, body, err := fetchBody(ctx, client, opts, r.Method, u, nil, 384*1024, requests)
				if err != nil {
					verboseCheck(opts, r.Path, 0, "error")
					results <- result{skipped: true}
					continue
				}
				if statusAllowed(resp.StatusCode, r.ExcludeStatuses) || !statusAllowed(resp.StatusCode, r.Statuses) {
					verboseCheck(opts, r.Path, resp.StatusCode, "no-match")
					results <- result{}
					continue
				}
				if !ruleMatches(r, resp, body, base) {
					verboseCheck(opts, r.Path, resp.StatusCode, "no-match")
					results <- result{}
					continue
				}
				sev := parseSeverity(r.Severity)
				message := r.Name
				if resp.StatusCode != http.StatusOK {
					message += fmt.Sprintf(" (%d)", resp.StatusCode)
				}
				evidence := r.Evidence
				if evidence == "" {
					evidence = evidenceForResponse(resp, body)
				}
				f := finding{Severity: sev, Level: sev.String(), Rule: r.ID, Category: r.Category, Confidence: r.Confidence, Message: message, URL: u, Evidence: evidence, Remediation: r.Remediation}
				verboseCheck(opts, r.Path, resp.StatusCode, "FOUND")
				results <- result{finding: &f, matched: true}
			}
		}()
	}

	go func() {
		defer close(results)
		for _, r := range rules {
			select {
			case jobs <- r:
			case <-ctx.Done():
				close(jobs)
				wg.Wait()
				return
			}
		}
		close(jobs)
		wg.Wait()
	}()

	var out []finding
	stats := ruleStats{}
	for r := range results {
		stats.Checked++
		progress.Advance()
		if r.skipped {
			stats.Skipped++
			continue
		}
		if !r.matched {
			stats.NoMatch++
			continue
		}
		out = append(out, *r.finding)
	}
	progress.Stop()
	return out, stats
}

func ruleMatches(r rule, resp *http.Response, body []byte, base baseline) bool {
	text := string(body)
	if len(r.Contains) > 0 && !containsAny(text, r.Contains) {
		return false
	}
	if len(r.NotContains) > 0 && !containsNone(text, r.NotContains) {
		return false
	}
	if r.compiledRegex != nil && !r.compiledRegex.Match(body) {
		return false
	}
	if r.ContentType != "" && !strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), strings.ToLower(r.ContentType)) {
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
	if len(r.Contains) == 0 && len(r.Headers) == 0 && r.compiledRegex == nil && looksLikeBaseline(resp.StatusCode, body, base) {
		return false
	}
	return true
}

func verboseCheck(opts options, path string, status int, state string) {
	if !opts.Verbose || opts.Quiet {
		return
	}
	verboseMu.Lock()
	defer verboseMu.Unlock()
	if status > 0 {
		fmt.Fprintf(os.Stderr, "[check] %-40s %3d %s\n", path, status, state)
	} else {
		fmt.Fprintf(os.Stderr, "[check] %-40s --- %s\n", path, state)
	}
}

func cleanError(err error) string {
	msg := err.Error()
	if i := strings.Index(msg, ": "); i >= 0 {
		msg = msg[i+2:]
	}
	return msg
}

func maxInt(a, b int) int {
	if a > b { return a }
	return b
}

func minInt(a, b int) int {
	if a < b { return a }
	return b
}

func modeRunsHTTPProbes(mode string) bool { return mode != "tls" && mode != "tech" }
