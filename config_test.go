package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func withTempConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("HAWKPROBE_CONFIG", path)
	return path
}

func TestConfigRoundtrip(t *testing.T) {
	withTempConfig(t)
	cfg := configData{
		Profiles: map[string]configProfile{
			"ctf": {Mode: "htb", Rate: 100, Concurrency: 64},
			"ci":  {Mode: "exposure", FailOn: "high", Severity: "low"},
		},
		AI: configAI{Model: "llama3.2"},
	}
	if err := saveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	got, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if got.Profiles["ctf"].Mode != "htb" || got.Profiles["ctf"].Rate != 100 {
		t.Fatalf("roundtrip lost ctf: %+v", got.Profiles["ctf"])
	}
	if got.Profiles["ci"].FailOn != "high" {
		t.Fatalf("roundtrip lost ci: %+v", got.Profiles["ci"])
	}
	if got.AI.Model != "llama3.2" {
		t.Fatalf("roundtrip lost ai: %+v", got.AI)
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	withTempConfig(t)
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Profiles) != 0 {
		t.Fatalf("expected empty config, got %+v", cfg)
	}
}

func TestApplyProfileFromConfig(t *testing.T) {
	cfg := configData{Profiles: map[string]configProfile{
		"ctf": {Mode: "htb", Rate: 100, Concurrency: 64, Severity: "medium", Discover: true, Timeout: "8s"},
	}}
	opts := options{Mode: "default", Timeout: 6 * time.Second, Profile: "ctf"}
	set := map[string]bool{"profile": true}
	if err := applyProfile(&opts, cfg, set); err != nil {
		t.Fatal(err)
	}
	if opts.Mode != "htb" || opts.Rate != 100 || opts.Concurrency != 64 || opts.MinSeverity != "medium" || !opts.Discover || opts.Timeout != 8*time.Second {
		t.Fatalf("profile not applied: %+v", opts)
	}
}

func TestApplyProfileExplicitFlagWins(t *testing.T) {
	cfg := configData{Profiles: map[string]configProfile{
		"ctf": {Mode: "htb", Rate: 100, Category: "cloud"},
	}}
	opts := options{Mode: "default", Rate: 50, CategoryFilter: "backup", Profile: "ctf"}
	set := map[string]bool{"profile": true, "rate": true, "category": true}
	if err := applyProfile(&opts, cfg, set); err != nil {
		t.Fatal(err)
	}
	if opts.Mode != "htb" {
		t.Fatalf("mode should come from profile: %s", opts.Mode)
	}
	if opts.Rate != 50 || opts.CategoryFilter != "backup" {
		t.Fatalf("explicit flags should win: rate=%d category=%q", opts.Rate, opts.CategoryFilter)
	}
}

func TestApplyProfileModeNameFallback(t *testing.T) {
	opts := options{Mode: "default", Profile: "htb"}
	set := map[string]bool{"profile": true}
	if err := applyProfile(&opts, configData{}, set); err != nil {
		t.Fatal(err)
	}
	if opts.Mode != "htb" {
		t.Fatalf("mode name fallback failed: %s", opts.Mode)
	}
}

func TestApplyProfileUnknown(t *testing.T) {
	opts := options{Mode: "default", Profile: "nope"}
	set := map[string]bool{"profile": true}
	if err := applyProfile(&opts, configData{}, set); err == nil {
		t.Fatal("expected unknown profile error")
	} else if !strings.Contains(err.Error(), "unknown profile") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateProfile(t *testing.T) {
	cases := []struct {
		name string
		p    configProfile
		ok   bool
	}{
		{"valid", configProfile{Mode: "htb", Rate: 100, Timeout: "5s"}, true},
		{"bad-mode", configProfile{Mode: "wibble"}, false},
		{"bad-severity", configProfile{Severity: "mega"}, false},
		{"bad-timeout", configProfile{Timeout: "soon"}, false},
		{"bad-rate", configProfile{Rate: 99999}, false},
		{"empty", configProfile{}, true},
	}
	for _, c := range cases {
		err := validateProfile(c.p)
		if (err == nil) != c.ok {
			t.Fatalf("%s: expected ok=%v, got err=%v", c.name, c.ok, err)
		}
	}
}

func TestConfigPathEnv(t *testing.T) {
	path := withTempConfig(t)
	if got := configPath(); got != path {
		t.Fatalf("configPath() = %q, want %q", got, path)
	}
}
