package main

import (
	"regexp"
	"time"
)

type severity int

const (
	info severity = iota
	low
	medium
	high
	critical
)

type finding struct {
	Severity    severity `json:"-"`
	Level       string   `json:"level"`
	Rule        string   `json:"rule,omitempty"`
	Category    string   `json:"category,omitempty"`
	Confidence  string   `json:"confidence,omitempty"`
	Message     string   `json:"message"`
	URL         string   `json:"url,omitempty"`
	Evidence    string   `json:"evidence,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
}

type rule struct {
	ID              string            `json:"id"`
	Path            string            `json:"path"`
	Name            string            `json:"name"`
	Severity        string            `json:"severity"`
	Category        string            `json:"category,omitempty"`
	Confidence      string            `json:"confidence,omitempty"`
	Method          string            `json:"method,omitempty"`
	Statuses        []int             `json:"statuses,omitempty"`
	ExcludeStatuses []int             `json:"exclude_statuses,omitempty"`
	Contains        []string          `json:"contains,omitempty"`
	NotContains     []string          `json:"not_contains,omitempty"`
	Regex           string            `json:"regex,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	ContentType     string            `json:"content_type,omitempty"`
	Evidence        string            `json:"evidence,omitempty"`
	Remediation     string            `json:"remediation,omitempty"`
	Profile         string            `json:"profile,omitempty"`
	Tags            []string          `json:"tags,omitempty"`

	compiledRegex *regexp.Regexp
}

type options struct {
	Target            string
	ListFile          string
	RuleFile          string
	Mode              string
	Concurrency       int
	TargetConcurrency int
	Rate              int
	Timeout           time.Duration
	Insecure          bool
	JSON              bool
	JSONL             bool
	Output            string
	URLsOut           string
	Headers           headerList
	User              string
	Pass              string
	Token             string
	Proxy             string
	MaxRedirects      int
	NoRedirect        bool
	UserAgent         string
	HostHeader        string
	Verbose           bool
	Evidence          bool
	Discover          bool
	Wordlist          string
	Extensions        string
	NoProgress        bool
	NoColor           bool
	Quiet             bool
}

type scanResult struct {
	Target       string    `json:"target"`
	Status       string    `json:"status,omitempty"`
	DurationMS   int64     `json:"duration_ms"`
	Requests     int       `json:"requests"`
	RulesChecked int       `json:"rules_checked,omitempty"`
	NoMatch      int       `json:"no_match,omitempty"`
	Skipped      int       `json:"skipped,omitempty"`
	Findings     []finding `json:"findings"`
	Error        string    `json:"error,omitempty"`
}

type ruleStats struct {
	Checked int
	NoMatch int
	Skipped int
}

func (s severity) String() string {
	switch s {
	case critical:
		return "crit"
	case high:
		return "high"
	case medium:
		return "med"
	case low:
		return "low"
	default:
		return "info"
	}
}

func parseSeverity(v string) severity {
	switch lower(v) {
	case "critical", "crit":
		return critical
	case "high":
		return high
	case "medium", "med":
		return medium
	case "low":
		return low
	default:
		return info
	}
}
