package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func inspectBase(target string, resp *http.Response, body []byte) []finding {
	var out []finding
	h := resp.Header
	u, _ := url.Parse(target)
	add := func(s severity, id, category, confidence, message, evidence, remediation string) {
		out = append(out, finding{Severity: s, Level: s.String(), Rule: id, Category: category, Confidence: confidence, Message: message, URL: target, Evidence: evidence, Remediation: remediation})
	}
	if u != nil && u.Scheme == "https" && h.Get("Strict-Transport-Security") == "" {
		add(low, "missing-hsts", "headers", "high", "HSTS header is missing", "Strict-Transport-Security not present", "Enable HSTS after confirming HTTPS is enforced for the site.")
	}
	if h.Get("Content-Security-Policy") == "" {
		add(low, "missing-csp", "headers", "high", "Content-Security-Policy header is missing", "Content-Security-Policy not present", "Deploy a restrictive Content-Security-Policy appropriate for the application.")
	}
	if h.Get("X-Content-Type-Options") == "" {
		add(low, "missing-nosniff", "headers", "high", "X-Content-Type-Options header is missing", "X-Content-Type-Options not present", "Set X-Content-Type-Options: nosniff.")
	}
	if h.Get("Referrer-Policy") == "" {
		add(low, "missing-referrer-policy", "headers", "high", "Referrer-Policy header is missing", "Referrer-Policy not present", "Set an appropriate Referrer-Policy.")
	}
	if h.Get("X-Frame-Options") == "" && !strings.Contains(strings.ToLower(h.Get("Content-Security-Policy")), "frame-ancestors") {
		add(low, "missing-frame-protection", "headers", "high", "frame protection is missing", "No X-Frame-Options or CSP frame-ancestors", "Set CSP frame-ancestors or X-Frame-Options.")
	}
	if h.Get("Permissions-Policy") == "" {
		add(info, "missing-permissions-policy", "headers", "high", "Permissions-Policy header is missing", "Permissions-Policy not present", "Restrict browser features that the application does not require.")
	}
	if server := h.Get("Server"); server != "" {
		add(info, "server-header", "disclosure", "high", "server header: "+server, "Server: "+server, "Remove unnecessary product/version disclosure where practical.")
	}
	if powered := h.Get("X-Powered-By"); powered != "" {
		add(info, "powered-by", "disclosure", "high", "X-Powered-By header: "+powered, "X-Powered-By: "+powered, "Remove unnecessary framework/version disclosure.")
	}
	if strings.EqualFold(h.Get("Access-Control-Allow-Origin"), "*") && strings.EqualFold(h.Get("Access-Control-Allow-Credentials"), "true") {
		add(medium, "cors-wildcard-credentials", "cors", "high", "CORS allows wildcard origin with credentials", "ACAO=* and ACAC=true", "Use an explicit allow-list of trusted origins and avoid wildcard credentials.")
	}
	for _, raw := range h.Values("Set-Cookie") {
		cookie := strings.ToLower(raw)
		name := strings.SplitN(raw, "=", 2)[0]
		if !strings.Contains(cookie, "httponly") {
			add(low, "cookie-httponly-"+name, "cookies", "high", "cookie "+name+" is missing HttpOnly", "Set-Cookie lacks HttpOnly", "Add HttpOnly to session or sensitive cookies.")
		}
		if u != nil && u.Scheme == "https" && !strings.Contains(cookie, "secure") {
			add(low, "cookie-secure-"+name, "cookies", "high", "cookie "+name+" is missing Secure", "Set-Cookie lacks Secure", "Add Secure to cookies sent by HTTPS applications.")
		}
		if !strings.Contains(cookie, "samesite") {
			add(info, "cookie-samesite-"+name, "cookies", "high", "cookie "+name+" is missing SameSite", "Set-Cookie lacks SameSite", "Set SameSite to an appropriate value for the application's flows.")
		}
	}
	text := strings.ToLower(string(body))
	if strings.Contains(text, "index of /") && (strings.Contains(text, "parent directory") || strings.Contains(text, "directory listing")) {
		add(medium, "directory-listing", "exposure", "medium", "directory listing appears enabled", "directory index markers found in response", "Disable directory indexing unless it is intentionally public.")
	}
	if title := htmlTitle(body); title != "" {
		add(info, "page-title", "discovery", "high", "page title: "+title, "<title>"+title+"</title>", "")
	}
	return out
}

func fingerprint(target string, resp *http.Response, body []byte) []finding {
	var out []finding
	server := strings.ToLower(resp.Header.Get("Server"))
	powered := strings.ToLower(resp.Header.Get("X-Powered-By"))
	text := strings.ToLower(string(body))
	cookies := strings.ToLower(strings.Join(resp.Header.Values("Set-Cookie"), " "))
	seen := make(map[string]bool)
	add := func(id, name, evidence string) {
		if seen[id] {
			return
		}
		seen[id] = true
		out = append(out, finding{Severity: info, Level: info.String(), Rule: id, Category: "technology", Confidence: "medium", Message: "technology: " + name, URL: target, Evidence: evidence})
	}
	if strings.Contains(server, "nginx") { add("tech-nginx", "nginx", resp.Header.Get("Server")) }
	if strings.Contains(server, "apache") { add("tech-apache", "Apache", resp.Header.Get("Server")) }
	if strings.Contains(server, "microsoft-iis") { add("tech-iis", "Microsoft IIS", resp.Header.Get("Server")) }
	if strings.Contains(server, "caddy") { add("tech-caddy", "Caddy", resp.Header.Get("Server")) }
	if strings.Contains(server, "cloudflare") || resp.Header.Get("CF-Ray") != "" { add("tech-cloudflare", "Cloudflare", "Cloudflare response headers") }
	if strings.Contains(powered, "php") { add("tech-php", "PHP", resp.Header.Get("X-Powered-By")) }
	if strings.Contains(powered, "asp.net") || strings.Contains(cookies, "asp.net_sessionid") { add("tech-aspnet", "ASP.NET", "ASP.NET header/cookie marker") }
	if strings.Contains(powered, "express") || strings.Contains(text, "connect.sid") { add("tech-express", "Express", "Express header/cookie marker") }
	if strings.Contains(text, "wp-content/") || strings.Contains(text, "wp-includes/") { add("tech-wordpress", "WordPress", "WordPress asset paths") }
	if strings.Contains(text, "__next_data__") || strings.Contains(text, "/_next/static/") { add("tech-nextjs", "Next.js", "Next.js asset markers") }
	if strings.Contains(text, "laravel_session") || strings.Contains(cookies, "laravel_session") { add("tech-laravel", "Laravel", "Laravel session marker") }
	if strings.Contains(cookies, "csrftoken") && strings.Contains(cookies, "sessionid") { add("tech-django", "Django", "Django cookie markers") }
	if strings.Contains(text, "grafana") && strings.Contains(text, "public/build") { add("tech-grafana", "Grafana", "Grafana frontend markers") }
	if strings.Contains(text, "jenkins") && strings.Contains(text, "adjuncts") { add("tech-jenkins", "Jenkins", "Jenkins frontend markers") }
	if strings.Contains(text, "spring") && strings.Contains(text, "whitelabel error page") { add("tech-spring", "Spring Boot", "Spring Boot error-page marker") }
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
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, port), &tls.Config{ServerName: host, InsecureSkipVerify: insecure, MinVersion: tls.VersionTLS10})
	if err != nil {
		sev := high
		id := "tls-validation"
		if insecure {
			sev = medium
			id = "tls-handshake"
		}
		return []finding{newDetailedFinding(sev, id, "tls", "high", "TLS connection failed: "+cleanError(err), target, cleanError(err), "Check the certificate chain and TLS configuration.")}
	}
	defer conn.Close()
	state := conn.ConnectionState()
	var out []finding
	version := tlsVersionName(state.Version)
	out = append(out, newDetailedFinding(info, "tls-version", "tls", "high", "TLS negotiated: "+version, target, version, ""))
	if state.Version == tls.VersionTLS10 || state.Version == tls.VersionTLS11 {
		out = append(out, newDetailedFinding(high, "legacy-tls", "tls", "high", "legacy TLS version negotiated", target, version, "Disable TLS 1.0 and TLS 1.1."))
	}
	if len(state.PeerCertificates) == 0 {
		return out
	}
	cert := state.PeerCertificates[0]
	remaining := time.Until(cert.NotAfter)
	if remaining < 0 {
		out = append(out, newDetailedFinding(high, "tls-expired", "tls", "high", "TLS certificate is expired", target, cert.NotAfter.Format(time.RFC3339), "Renew and deploy a valid certificate."))
	} else if remaining < 30*24*time.Hour {
		out = append(out, newDetailedFinding(medium, "tls-expiring", "tls", "high", fmt.Sprintf("TLS certificate expires in %d days", int(remaining.Hours()/24)), target, cert.NotAfter.Format(time.RFC3339), "Renew the certificate before expiry."))
	}
	if insecure {
		if err := cert.VerifyHostname(host); err != nil {
			out = append(out, newDetailedFinding(medium, "tls-hostname", "tls", "high", "TLS certificate hostname mismatch", target, err.Error(), "Use a certificate valid for this hostname."))
		}
	}
	issuer := cert.Issuer.CommonName
	if issuer == "" {
		issuer = cert.Issuer.String()
	}
	out = append(out, newDetailedFinding(info, "tls-certificate", "tls", "high", "TLS certificate: "+cert.Subject.CommonName, target, "issuer="+issuer+"; expires="+cert.NotAfter.Format("2006-01-02"), ""))
	return out
}

func evidenceForResponse(resp *http.Response, body []byte) string {
	parts := []string{fmt.Sprintf("HTTP %d", resp.StatusCode)}
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		parts = append(parts, "content-type="+ct)
	}
	if len(body) > 0 {
		parts = append(parts, fmt.Sprintf("body=%d bytes", len(body)))
	}
	return strings.Join(parts, "; ")
}

func htmlTitle(body []byte) string {
	text := string(body)
	lowerText := strings.ToLower(text)
	start := strings.Index(lowerText, "<title")
	if start < 0 {
		return ""
	}
	start = strings.Index(lowerText[start:], ">") + start
	if start < 0 {
		return ""
	}
	end := strings.Index(lowerText[start+1:], "</title>")
	if end < 0 {
		return ""
	}
	title := strings.TrimSpace(text[start+1 : start+1+end])
	title = strings.Join(strings.Fields(title), " ")
	if len(title) > 120 {
		title = title[:120] + "…"
	}
	return title
}

func dedupeFindings(in []finding) []finding {
	seen := make(map[string]bool)
	out := make([]finding, 0, len(in))
	for _, f := range in {
		key := f.Rule + "\x00" + f.URL + "\x00" + f.Message
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}

func newDetailedFinding(s severity, id, category, confidence, message, target, evidence, remediation string) finding {
	return finding{Severity: s, Level: s.String(), Rule: id, Category: category, Confidence: confidence, Message: message, URL: target, Evidence: evidence, Remediation: remediation}
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%x", v)
	}
}
