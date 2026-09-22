package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type suppression struct {
	Rule    string    `json:"rule"`
	Target  string    `json:"target,omitempty"`
	Path    string    `json:"path,omitempty"`
	Reason  string    `json:"reason,omitempty"`
	AddedAt time.Time `json:"added_at"`
	Expiry  time.Time `json:"expiry,omitempty"`
}

type suppressionFile struct {
	Suppressions []suppression `json:"suppressions"`
}

func suppressionsPath() string {
	if p := os.Getenv("HAWKPROBE_SUPPRESSIONS"); p != "" {
		return p
	}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "hawkprobe", "suppressions.json")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".hawkprobe-suppressions.json"
	}
	return filepath.Join(home, ".config", "hawkprobe", "suppressions.json")
}

func loadSuppressions(explicitPath string) (suppressionFile, error) {
	var sf suppressionFile
	path := explicitPath
	if path == "" {
		if _, err := os.Stat(suppressionsPath()); err != nil {
			return sf, nil
		}
		path = suppressionsPath()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return sf, nil
		}
		return sf, fmt.Errorf("read suppressions: %w", err)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return sf, nil
	}
	if err := json.Unmarshal(data, &sf); err != nil {
		return sf, fmt.Errorf("parse %s: %w", path, err)
	}
	return sf, nil
}

func saveSuppressions(sf suppressionFile) error {
	path := suppressionsPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(sf, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func (s suppression) expired(now time.Time) bool {
	return !s.Expiry.IsZero() && now.After(s.Expiry)
}

// matches reports whether a finding on result.Target is covered by this
// suppression: rule must match; target must be empty or equal; path must
// be empty or a suffix of the finding URL.
func (s suppression) matches(target string, f finding) bool {
	if !strings.EqualFold(s.Rule, f.Rule) {
		return false
	}
	if s.Target != "" && !strings.EqualFold(s.Target, target) {
		return false
	}
	if s.Path != "" {
		u := f.URL
		if u == "" {
			u = target
		}
		if !strings.HasSuffix(u, s.Path) {
			return false
		}
	}
	return true
}

// applySuppressions removes matching findings in place, counting them in
// result.Suppressed. Expired suppressions are ignored.
func applySuppressions(results []scanResult, sf suppressionFile) {
	now := time.Now()
	for i := range results {
		kept := results[i].Findings[:0]
		for _, f := range results[i].Findings {
			sup := false
			for _, s := range sf.Suppressions {
				if !s.expired(now) && s.matches(results[i].Target, f) {
					sup = true
					break
				}
			}
			if sup {
				results[i].Suppressed++
			} else {
				kept = append(kept, f)
			}
		}
		results[i].Findings = kept
	}
}

func handleSuppressCommand(args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: hawkprobe suppress list|add|remove")
		os.Exit(2)
	}
	switch args[1] {
	case "list":
		sf, err := loadSuppressions("")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if len(sf.Suppressions) == 0 {
			fmt.Printf("no suppressions in %s\n", suppressionsPath())
			return
		}
		for i, s := range sf.Suppressions {
			fmt.Printf("%d  rule=%-24s target=%-28s path=%-16s reason=%s\n", i, s.Rule, orDash(s.Target), orDash(s.Path), orDash(s.Reason))
			if !s.Expiry.IsZero() {
				fmt.Printf("   expires %s\n", s.Expiry.Format("2006-01-02 15:04"))
			}
		}
	case "add":
		fs := flag.NewFlagSet("suppress add", flag.ExitOnError)
		rule := fs.String("rule", "", "rule id (required)")
		target := fs.String("target", "", "only suppress on this target")
		path := fs.String("path", "", "only suppress findings at URLs ending with this path")
		reason := fs.String("reason", "", "why it is suppressed")
		expires := fs.String("expires", "", "relative duration, e.g. 30d, 12h (empty = forever)")
		fs.Parse(args[2:])
		if *rule == "" {
			fmt.Fprintln(os.Stderr, "suppress add requires --rule")
			os.Exit(2)
		}
		s := suppression{Rule: *rule, Target: *target, Path: *path, Reason: *reason, AddedAt: time.Now()}
		if *expires != "" {
			d, err := parseDurationLoose(*expires)
			if err != nil {
				fmt.Fprintln(os.Stderr, "invalid --expires:", err)
				os.Exit(2)
			}
			s.Expiry = time.Now().Add(d)
		}
		sf, _ := loadSuppressions("")
		sf.Suppressions = append(sf.Suppressions, s)
		if err := saveSuppressions(sf); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		fmt.Printf("added suppression for rule %q\n", *rule)
	case "remove":
		fs := flag.NewFlagSet("suppress remove", flag.ExitOnError)
		rule := fs.String("rule", "", "rule id")
		target := fs.String("target", "", "target of the suppression")
		path := fs.String("path", "", "path of the suppression")
		index := fs.Int("index", -1, "remove by list index instead of match")
		fs.Parse(args[2:])
		sf, _ := loadSuppressions("")
		removed := -1
		if *index >= 0 && *index < len(sf.Suppressions) {
			removed = *index
		} else {
			for i, s := range sf.Suppressions {
				if *rule != "" && !strings.EqualFold(s.Rule, *rule) {
					continue
				}
				if *target != "" && !strings.EqualFold(s.Target, *target) {
					continue
				}
				if *path != "" && s.Path != *path {
					continue
				}
				removed = i
				break
			}
		}
		if removed < 0 {
			fmt.Fprintln(os.Stderr, "no matching suppression")
			os.Exit(2)
		}
		sf.Suppressions = append(sf.Suppressions[:removed], sf.Suppressions[removed+1:]...)
		if err := saveSuppressions(sf); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		fmt.Printf("removed suppression %d\n", removed)
	default:
		fmt.Fprintln(os.Stderr, "usage: hawkprobe suppress list|add|remove")
		os.Exit(2)
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// parseDurationLoose accepts Go durations plus bare d/w suffixes.
func parseDurationLoose(v string) (time.Duration, error) {
	if d, err := time.ParseDuration(v); err == nil {
		return d, nil
	}
	switch {
	case strings.HasSuffix(v, "d"):
		if n, err := fmtSscanfInt(strings.TrimSuffix(v, "d")); err == nil {
			return time.Duration(n) * 24 * time.Hour, nil
		}
	case strings.HasSuffix(v, "w"):
		if n, err := fmtSscanfInt(strings.TrimSuffix(v, "w")); err == nil {
			return time.Duration(n) * 7 * 24 * time.Hour, nil
		}
	}
	return 0, fmt.Errorf("cannot parse %q (use e.g. 30d, 12h, 720h)", v)
}

func fmtSscanfInt(s string) (int, error) {
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}
