package main

import "time"

type severity int

const (
	info severity = iota
	low
	medium
	high
)

type finding struct {
	Severity severity `json:"-"`
	Level    string   `json:"level"`
	Rule     string   `json:"rule,omitempty"`
	Message  string   `json:"message"`
	URL      string   `json:"url,omitempty"`
}

type rule struct {
	ID          string            `json:"id"`
	Path        string            `json:"path"`
	Name        string            `json:"name"`
	Severity    string            `json:"severity"`
	Statuses    []int             `json:"statuses,omitempty"`
	Contains    []string          `json:"contains,omitempty"`
	NotContains []string          `json:"not_contains,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Profile     string            `json:"profile,omitempty"`
}

type options struct {
	Target       string
	ListFile     string
	RuleFile     string
	Profile      string
	Concurrency  int
	Timeout      time.Duration
	Insecure     bool
	JSON         bool
	JSONL        bool
	Output       string
	Headers      headerList
	User         string
	Pass         string
	Token        string
	Proxy        string
	MaxRedirects int
	NoRedirect   bool
	UserAgent    string
}

type scanResult struct {
	Target     string    `json:"target"`
	Status     string    `json:"status,omitempty"`
	DurationMS int64     `json:"duration_ms"`
	Requests   int       `json:"requests"`
	Findings   []finding `json:"findings"`
	Error      string    `json:"error,omitempty"`
}

func (s severity) String() string {
	switch s {
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
	case "high", "critical":
		return high
	case "medium", "med":
		return medium
	case "low":
		return low
	default:
		return info
	}
}
