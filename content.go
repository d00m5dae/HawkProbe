package main

import (
	"regexp"
	"strings"
)

type contentCheck struct {
	id, message, severity, category, pattern string
	rx                                       *regexp.Regexp
}

var contentChecks = []contentCheck{
	{"content-private-key", "possible private key material in response", "critical", "secrets", `-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`, nil},
	{"content-aws-key", "possible AWS access key in response", "high", "secrets", `\bAKIA[0-9A-Z]{16}\b`, nil},
	{"content-generic-secret", "possible hard-coded secret in response", "high", "secrets", `(?i)\b(?:password|passwd|api[_-]?key|secret[_-]?key)\s*[:=]\s*["']?[^\s"'<]{6,}`, nil},
	{"content-python-trace", "Python traceback disclosed", "medium", "debug", `Traceback \(most recent call last\):`, nil},
	{"content-java-trace", "Java exception/stack trace disclosed", "medium", "debug", `(?m)^(?:[a-zA-Z_$][\w$]*\.){2,}[A-Za-z_$][\w$]*(?:Exception|Error)(?::|$)`, nil},
	{"content-dotnet-error", ".NET exception details disclosed", "medium", "debug", `(?:System\.[A-Za-z.]+Exception|Server Error in '/' Application)`, nil},
	{"content-php-error", "PHP error details disclosed", "medium", "debug", `(?i)(?:Fatal error|Parse error|Warning):.+? in .+? on line \d+`, nil},
	{"content-sourcemap", "JavaScript source map reference found", "info", "discovery", `(?i)sourceMappingURL=.+?\.map`, nil},
}

var commentRX = regexp.MustCompile(`(?is)<!--\s*(.{1,300}?)\s*-->`)

func init() {
	for i := range contentChecks {
		contentChecks[i].rx = regexp.MustCompile(contentChecks[i].pattern)
	}
}

func inspectContent(target string, body []byte) []finding {
	if len(body) == 0 {
		return nil
	}
	text := string(body)
	var out []finding
	for _, c := range contentChecks {
		if !c.rx.MatchString(text) {
			continue
		}
		sev := parseSeverity(c.severity)
		evidence := "pattern matched in response; matched value redacted"
		if c.category == "debug" || c.id == "content-sourcemap" {
			evidence = clippedMatch(c.rx, text)
		}
		out = append(out, newDetailedFinding(sev, c.id, c.category, "medium", c.message, target, evidence, contentRemediation(c.category)))
	}

	for _, match := range commentRX.FindAllStringSubmatch(text, 8) {
		comment := strings.Join(strings.Fields(match[1]), " ")
		l := strings.ToLower(comment)
		if !containsAny(l, []string{"todo", "fixme", "password", "secret", "internal", "admin", "debug", "dev"}) {
			continue
		}
		if len(comment) > 160 {
			comment = comment[:160] + "…"
		}
		out = append(out, newDetailedFinding(info, "interesting-html-comment", "discovery", "medium", "interesting HTML comment", target, comment, "Remove sensitive implementation notes from production responses."))
	}
	return out
}

func clippedMatch(rx *regexp.Regexp, text string) string {
	m := rx.FindString(text)
	m = strings.Join(strings.Fields(m), " ")
	if len(m) > 180 {
		m = m[:180] + "…"
	}
	return m
}

func contentRemediation(category string) string {
	switch category {
	case "secrets":
		return "Remove secrets from web responses, rotate exposed credentials, and store secrets outside the web root."
	case "debug":
		return "Disable verbose/debug error output in production and log details server-side instead."
	default:
		return "Review the exposed content and remove unnecessary sensitive information."
	}
}
