package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	defaultOllamaHost  = "http://127.0.0.1:11434"
	defaultOllamaModel = "llama3.2"
)

type aiSettings struct {
	Host  string
	Model string
}

// resolveAISettings precedence: CLI flag > environment > config file > default.
func resolveAISettings(opts options, cfg configData) aiSettings {
	host := os.Getenv("OLLAMA_HOST")
	if host == "" {
		host = cfg.AI.Host
	}
	if host == "" {
		host = defaultOllamaHost
	}
	if !strings.HasPrefix(host, "http://") && !strings.HasPrefix(host, "https://") {
		host = "http://" + host
	}
	model := opts.AIModel
	if model == "" {
		model = os.Getenv("HAWKPROBE_AI_MODEL")
	}
	if model == "" {
		model = cfg.AI.Model
	}
	if model == "" {
		model = defaultOllamaModel
	}
	return aiSettings{Host: host, Model: model}
}

func aiAvailable(host string) bool {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(host + "/api/version")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func aiSummarize(host, model string, r scanResult) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "Target: %s\n", r.Target)
	if r.Error != "" {
		fmt.Fprintf(&b, "Error: %s\n", r.Error)
	}
	if len(r.Findings) == 0 {
		b.WriteString("Findings: none\n")
	} else {
		b.WriteString("Findings:\n")
		for _, f := range r.Findings {
			fmt.Fprintf(&b, "- [%s] %s: %s", f.Level, f.Rule, f.Message)
			if f.URL != "" && f.URL != r.Target {
				fmt.Fprintf(&b, " (%s)", f.URL)
			}
			if f.Evidence != "" {
				fmt.Fprintf(&b, " evidence: %s", f.Evidence)
			}
			b.WriteString("\n")
		}
	}
	prompt := "You are a web application security assistant writing a penetration test report. " +
		"Summarize the scan result below in 2-4 short bullet points. Highlight the most important " +
		"risks and give concrete next actions. If there are no findings, say the target appears " +
		"clean in one line. Respond in plain text with no preamble.\n\n" + b.String()

	payload, err := json.Marshal(map[string]any{"model": model, "prompt": prompt, "stream": false, "think": false})
	if err != nil {
		return "", err
	}
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Post(host+"/api/generate", "application/json", bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ollama returned %d", resp.StatusCode)
	}
	var out struct {
		Response string `json:"response"`
		Thinking string `json:"thinking"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	// Some thinking models put the answer in "thinking" when the response
	// field is empty; fall back to it rather than returning nothing.
	if strings.TrimSpace(out.Response) == "" {
		return strings.TrimSpace(out.Thinking), nil
	}
	return strings.TrimSpace(out.Response), nil
}

// attachAISummaries fills AISummary for every target. AI failures are
// reported on stderr and never fail the scan itself.
func attachAISummaries(results []scanResult, opts options, cfg configData) {
	if !opts.AI {
		return
	}
	s := resolveAISettings(opts, cfg)
	if !aiAvailable(s.Host) {
		if !opts.Quiet {
			fmt.Fprintf(os.Stderr, "note: Ollama not reachable at %s, skipping AI summaries\n", s.Host)
		}
		return
	}
	for i := range results {
		sum, err := aiSummarize(s.Host, s.Model, results[i])
		if err != nil {
			if !opts.Quiet {
				fmt.Fprintf(os.Stderr, "note: AI summary for %s: %v\n", results[i].Target, err)
			}
			continue
		}
		results[i].AISummary = sum
	}
}
