package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// flexStrings accepts either a single JSON string or an array of strings.
type flexStrings []string

func (f *flexStrings) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*f = []string{s}
		return nil
	}
	var arr []string
	if err := json.Unmarshal(data, &arr); err != nil {
		return err
	}
	*f = arr
	return nil
}

// customExpect holds the conditions a response must satisfy for the rule
// to fire. All specified conditions must match (AND semantics).
type customExpect struct {
	Status      int               `json:"status"`       // exact status code
	StatusAny   []int             `json:"status_any"`   // any of these status codes
	Contains    flexStrings       `json:"contains"`     // all must appear in the body
	ContainsAny flexStrings       `json:"contains_any"` // at least one must appear
	NotContains flexStrings       `json:"not_contains"` // none may appear
	Header      map[string]string `json:"header"`       // header must contain value (case-insensitive)
}

func (e customExpect) empty() bool {
	return e.Status == 0 && len(e.StatusAny) == 0 && len(e.Contains) == 0 &&
		len(e.ContainsAny) == 0 && len(e.NotContains) == 0 && len(e.Header) == 0
}

func (e customExpect) matches(resp *http.Response, body []byte) bool {
	if e.Status != 0 && resp.StatusCode != e.Status {
		return false
	}
	if len(e.StatusAny) > 0 && !statusAllowed(resp.StatusCode, e.StatusAny) {
		return false
	}
	text := string(body)
	for _, s := range e.Contains {
		if !strings.Contains(text, s) {
			return false
		}
	}
	if len(e.ContainsAny) > 0 && !containsAny(text, e.ContainsAny) {
		return false
	}
	for _, s := range e.NotContains {
		if strings.Contains(text, s) {
			return false
		}
	}
	for name, sub := range e.Header {
		value := resp.Header.Get(name)
		if value == "" || (sub != "" && !strings.Contains(strings.ToLower(value), strings.ToLower(sub))) {
			return false
		}
	}
	return true
}

type customRule struct {
	Name        string       `json:"name"`
	Path        string       `json:"path"`
	Method      string       `json:"method"`
	Severity    string       `json:"severity"`
	Category    string       `json:"category"`
	Message     string       `json:"message"`
	Remediation string       `json:"remediation"`
	Expect      customExpect `json:"expect"`
}

func (r customRule) validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("missing name")
	}
	if strings.TrimSpace(r.Path) == "" {
		return fmt.Errorf("missing path")
	}
	if r.Severity != "" && !validSeverityName(r.Severity) {
		return fmt.Errorf("invalid severity %q", r.Severity)
	}
	if r.Method != "" {
		switch upper := strings.ToUpper(r.Method); upper {
		case "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH":
		default:
			return fmt.Errorf("invalid method %q", r.Method)
		}
	}
	if r.Expect.empty() {
		return fmt.Errorf("expect must specify at least one condition (status, status_any, contains, contains_any, not_contains, header)")
	}
	return nil
}

type customRuleFile struct {
	Rules []customRule `json:"rules"`
}

func loadCustomRules(path string) (customRuleFile, error) {
	var cf customRuleFile
	data, err := os.ReadFile(path)
	if err != nil {
		return cf, fmt.Errorf("read rules: %w", err)
	}
	if err := json.Unmarshal(data, &cf); err != nil {
		return cf, fmt.Errorf("parse rules %s: %w", path, err)
	}
	for i, r := range cf.Rules {
		if err := r.validate(); err != nil {
			return cf, fmt.Errorf("rule %d (%q): %w", i+1, r.Name, err)
		}
	}
	return cf, nil
}

// loadCustomRuleList resolves the custom rule file (-custom-rules flag or
// HAWKPROBE_CUSTOM_RULES) and returns its validated rules.
func loadCustomRuleList(opts options) []customRule {
	path := opts.CustomRules
	if path == "" {
		path = os.Getenv("HAWKPROBE_CUSTOM_RULES")
	}
	if path == "" {
		return nil
	}
	cf, err := loadCustomRules(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "custom rules:", err)
		os.Exit(2)
	}
	return cf.Rules
}

// expandRuleURL resolves a rule path against the target. A trailing glob
// (e.g. /admin*) is treated as a prefix: both the trimmed prefix and the
// prefix with a trailing slash are fetched, and the expect conditions
// decide whether either response fires the rule.
func expandRuleURL(target, pattern string) []string {
	if !strings.ContainsAny(pattern, "*?") {
		return []string{joinURL(target, pattern)}
	}
	trimmed := strings.TrimRight(pattern, "*?")
	if strings.ContainsAny(trimmed, "*?") {
		trimmed = strings.TrimRight(trimmed, "/")
	}
	urls := []string{joinURL(target, trimmed)}
	if !strings.HasSuffix(trimmed, "/") {
		urls = append(urls, joinURL(target, trimmed+"/"))
	}
	return urls
}

func runCustomRules(ctx context.Context, client *http.Client, opts options, target string, custom []customRule, requests *int64) []finding {
	var out []finding
	for _, cr := range custom {
		method := cr.Method
		if method == "" {
			method = http.MethodGet
		}
		sev := parseSeverity(cr.Severity)
		category := cr.Category
		if category == "" {
			category = "custom"
		}
		message := cr.Message
		if message == "" {
			message = cr.Name
		}
		for _, u := range expandRuleURL(target, cr.Path) {
			if ctx.Err() != nil {
				return out
			}
			resp, body, err := fetchBody(ctx, client, opts, method, u, nil, 384*1024, requests)
			if err != nil {
				verboseCheck(opts, u, 0, "error")
				continue
			}
			if !cr.Expect.matches(resp, body) {
				verboseCheck(opts, u, resp.StatusCode, "no-match")
				continue
			}
			verboseCheck(opts, u, resp.StatusCode, "FOUND")
			out = append(out, finding{
				Severity:    sev,
				Level:       sev.String(),
				Rule:        "custom:" + cr.Name,
				Category:    category,
				Confidence:  "custom",
				Message:     message,
				URL:         u,
				Evidence:    evidenceForResponse(resp, body),
				Remediation: cr.Remediation,
			})
		}
	}
	return out
}
