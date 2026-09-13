package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

func inspectMethods(ctx context.Context, client *http.Client, opts options, target string, requests *int64) []finding {
	resp, _, err := fetchBody(ctx, client, opts, http.MethodOptions, target, nil, 32*1024, requests)
	if err != nil {
		return nil
	}
	allow := resp.Header.Get("Allow")
	if allow == "" {
		return nil
	}
	methods := strings.ToUpper(allow)
	var out []finding
	out = append(out, newDetailedFinding(info, "http-methods", "methods", "high", "allowed methods: "+allow, target, "Allow: "+allow, ""))
	for _, method := range []string{"PUT", "DELETE", "TRACE", "CONNECT"} {
		if tokenContains(methods, method) {
			sev := medium
			if method == "TRACE" {
				sev = low
			}
			out = append(out, newDetailedFinding(sev, "method-"+strings.ToLower(method), "methods", "medium", method+" method appears enabled", target, "Allow: "+allow, "Disable unnecessary HTTP methods or require strong authorization."))
		}
	}
	return out
}

func inspectCORS(ctx context.Context, client *http.Client, opts options, target string, requests *int64) []finding {
	extra := make(http.Header)
	origin := "https://hawkprobe.invalid"
	extra.Set("Origin", origin)
	resp, _, err := fetchBody(ctx, client, opts, http.MethodGet, target, extra, 64*1024, requests)
	if err != nil {
		return nil
	}
	acao := resp.Header.Get("Access-Control-Allow-Origin")
	if acao == "" {
		return nil
	}
	cred := strings.EqualFold(resp.Header.Get("Access-Control-Allow-Credentials"), "true")
	if acao == origin {
		sev := medium
		message := "CORS reflects an arbitrary Origin"
		if cred {
			sev = high
			message += " with credentials"
		}
		return []finding{newDetailedFinding(sev, "cors-origin-reflection", "cors", "high", message, target, fmt.Sprintf("Origin: %s -> Access-Control-Allow-Origin: %s; credentials=%t", origin, acao, cred), "Use a strict allow-list and never reflect arbitrary origins for credentialed requests.")}
	}
	return nil
}

func tokenContains(list, method string) bool {
	for _, part := range strings.FieldsFunc(list, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		if strings.EqualFold(strings.TrimSpace(part), method) {
			return true
		}
	}
	return false
}
