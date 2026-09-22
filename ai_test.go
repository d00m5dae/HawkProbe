package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func startFakeOllama(t *testing.T, failGenerate bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/version":
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, `{"version":"0.5.0"}`)
		case "/api/generate":
			var req struct {
				Model  string `json:"model"`
				Prompt string `json:"prompt"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if failGenerate {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			resp := map[string]string{"model": req.Model, "response": "- main risk noted\n- action: rotate secrets\n"}
			json.NewEncoder(w).Encode(resp)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestAISettingsPrecedence(t *testing.T) {
	t.Setenv("OLLAMA_HOST", "")
	t.Setenv("HAWKPROBE_AI_MODEL", "")
	// Defaults.
	s := resolveAISettings(options{}, configData{})
	if s.Host != defaultOllamaHost || s.Model != defaultOllamaModel {
		t.Fatalf("defaults wrong: %+v", s)
	}
	// Config file.
	s = resolveAISettings(options{}, configData{AI: configAI{Host: "ollama.example:11434", Model: "mistral"}})
	if s.Host != "http://ollama.example:11434" || s.Model != "mistral" {
		t.Fatalf("config values wrong: %+v", s)
	}
	// Env beats config.
	t.Setenv("OLLAMA_HOST", "10.0.0.5:11434")
	t.Setenv("HAWKPROBE_AI_MODEL", "qwen2.5")
	s = resolveAISettings(options{}, configData{AI: configAI{Host: "ollama.example", Model: "mistral"}})
	if s.Host != "http://10.0.0.5:11434" || s.Model != "qwen2.5" {
		t.Fatalf("env values should win: %+v", s)
	}
	// Flag beats env.
	s = resolveAISettings(options{AIModel: "llama3.1"}, configData{AI: configAI{Host: "ollama.example", Model: "mistral"}})
	if s.Model != "llama3.1" {
		t.Fatalf("flag model should win: %+v", s)
	}
}

func TestAttachAISummaries(t *testing.T) {
	srv := startFakeOllama(t, false)
	results := []scanResult{
		{Target: "https://a.test", Findings: []finding{{Severity: high, Level: "high", Rule: "env", Message: "exposed env file", URL: "https://a.test/.env"}}},
		{Target: "https://b.test"},
	}
	opts := options{AI: true}
	cfg := configData{AI: configAI{Host: strings.TrimPrefix(srv.URL, "http://")}}
	attachAISummaries(results, opts, cfg)
	for i, r := range results {
		if r.AISummary == "" {
			t.Fatalf("target %d has no AI summary", i)
		}
		if !strings.Contains(r.AISummary, "rotate secrets") {
			t.Fatalf("unexpected summary: %q", r.AISummary)
		}
	}
}

func TestAttachAISummariesSkipsWhenUnreachable(t *testing.T) {
	results := []scanResult{{Target: "https://a.test"}}
	// Point at a closed port.
	cfg := configData{AI: configAI{Host: "127.0.0.1:1"}}
	opts := options{AI: true, Quiet: true}
	attachAISummaries(results, opts, cfg)
	if results[0].AISummary != "" {
		t.Fatalf("expected no summary when Ollama is down, got %q", results[0].AISummary)
	}
}

func TestAttachAISummariesGenerateError(t *testing.T) {
	srv := startFakeOllama(t, true)
	results := []scanResult{{Target: "https://a.test"}}
	cfg := configData{AI: configAI{Host: strings.TrimPrefix(srv.URL, "http://")}}
	opts := options{AI: true, Quiet: true}
	attachAISummaries(results, opts, cfg)
	if results[0].AISummary != "" {
		t.Fatalf("expected no summary on generate error, got %q", results[0].AISummary)
	}
}

func TestAIDisabledByDefault(t *testing.T) {
	results := []scanResult{{Target: "https://a.test"}}
	attachAISummaries(results, options{}, configData{})
	if results[0].AISummary != "" {
		t.Fatal("AI should be a no-op unless enabled")
	}
}
