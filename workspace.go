package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type summaryCounts struct {
	Findings    int `json:"findings"`
	Critical    int `json:"critical"`
	High        int `json:"high"`
	Medium      int `json:"medium"`
	Low         int `json:"low"`
	Info        int `json:"info"`
	Errors      int `json:"errors"`
	ErrorsTotal int `json:"errors_total"`
}

func (s summaryCounts) BySeverity(name string) int {
	switch name {
	case "critical":
		return s.Critical
	case "high":
		return s.High
	case "medium":
		return s.Medium
	case "low":
		return s.Low
	case "info":
		return s.Info
	}
	return 0
}

type savedOptions struct {
	Mode              string   `json:"mode"`
	Category          string   `json:"category,omitempty"`
	Tag               string   `json:"tag,omitempty"`
	Severity          string   `json:"severity,omitempty"`
	FailOn            string   `json:"fail-on,omitempty"`
	Concurrency       int      `json:"concurrency,omitempty"`
	TargetConcurrency int      `json:"target-concurrency,omitempty"`
	Rate              int      `json:"rate,omitempty"`
	Retries           int      `json:"retries,omitempty"`
	MaxRequests       int      `json:"max-requests,omitempty"`
	TimeoutMS         int      `json:"timeout-ms,omitempty"`
	MaxRedirects      int      `json:"max-redirects,omitempty"`
	Wordlist          string   `json:"wordlist,omitempty"`
	Rules             string   `json:"rules,omitempty"`
	Extensions        string   `json:"extensions,omitempty"`
	Discover          bool     `json:"discover,omitempty"`
	Insecure          bool     `json:"insecure,omitempty"`
	NoRedirect        bool     `json:"no-redirect,omitempty"`
	Headers           []string `json:"headers,omitempty"`
	User              string   `json:"user,omitempty"`
	Pass              string   `json:"pass,omitempty"`
	Token             string   `json:"token,omitempty"`
	Proxy             string   `json:"proxy,omitempty"`
	UserAgent         string   `json:"user-agent,omitempty"`
	HostHeader        string   `json:"host-header,omitempty"`
	Suppressions      string   `json:"suppressions,omitempty"`
	CustomRules       string   `json:"custom-rules,omitempty"`
	AI                bool     `json:"ai,omitempty"`
	AIModel           string   `json:"ai-model,omitempty"`
}

type scanMeta struct {
	ID             string        `json:"id"`
	StartedAt      time.Time     `json:"started_at"`
	FinishedAt     time.Time     `json:"finished_at,omitempty"`
	Status         string        `json:"status"`
	Targets        []string      `json:"targets"`
	ScannedTargets []string      `json:"scanned_targets"`
	Mode           string        `json:"mode"`
	RulesLoaded    int           `json:"rules_loaded"`
	Summary        summaryCounts `json:"summary"`
	Options        savedOptions  `json:"options"`
}

func workspaceDir() string {
	if workspaceOverride != "" {
		return workspaceOverride
	}
	if p := os.Getenv("HAWKPROBE_WORKSPACE"); p != "" {
		return p
	}
	if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
		return filepath.Join(xdg, "hawkprobe")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".hawkprobe-workspace"
	}
	return filepath.Join(home, ".local", "share", "hawkprobe")
}

// workspaceOverride comes from the -workspace flag.
var workspaceOverride string

// recordWorkspaceScan stores the scan for history, diff and resume.
// Failures are reported on stderr but never fail the scan itself.
func recordWorkspaceScan(targets []string, results []scanResult, opts options, rulesLoaded int, started time.Time) {
	status := "completed"
	for _, r := range results {
		if r.Error != "" {
			status = "partial"
			break
		}
	}
	meta := scanMeta{
		ID:             uniqueScanID(started, targets),
		StartedAt:      started,
		FinishedAt:     time.Now(),
		Status:         status,
		Targets:        targets,
		ScannedTargets: sortedKeys(scannedTargetSet(results)),
		Mode:           opts.Mode,
		RulesLoaded:    rulesLoaded,
		Summary:        summaryOf(results, 0),
		Options:        savedOptionsFromOptions(opts),
	}
	meta.Summary.ErrorsTotal = meta.Summary.Errors
	if err := writeScanArtifacts(meta, results); err != nil {
		if !opts.Quiet {
			fmt.Fprintf(os.Stderr, "note: workspace record: %v\n", err)
		}
	}
}

func scanDir(id string) string {
	return filepath.Join(workspaceDir(), id)
}

func newScanID(start time.Time, targets []string) string {
	h := sha256.Sum256([]byte(strings.Join(targets, "\n")))
	return start.UTC().Format("20060102T150405.000Z") + "-" + hex.EncodeToString(h[:])[:6]
}

// uniqueScanID appends a counter suffix if the id already exists in the
// workspace (e.g. two scans of the same targets within one millisecond).
func uniqueScanID(start time.Time, targets []string) string {
	id := newScanID(start, targets)
	for i := 2; ; i++ {
		if _, err := os.Stat(scanDir(id)); os.IsNotExist(err) {
			return id
		}
		if i > 1000 {
			return id + "-x"
		}
		id = newScanID(start, targets) + "-" + fmt.Sprint(i)
	}
}

func summaryOf(results []scanResult, errorsTotal int) summaryCounts {
	counts, findings, errors := countFindings(results)
	s := summaryCounts{Findings: findings, Errors: errors, ErrorsTotal: errorsTotal}
	for sev, n := range counts {
		switch sev {
		case critical:
			s.Critical = n
		case high:
			s.High = n
		case medium:
			s.Medium = n
		case low:
			s.Low = n
		case info:
			s.Info = n
		}
	}
	return s
}

func writeScanArtifacts(meta scanMeta, results []scanResult) error {
	dir := scanDir(meta.ID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	writeJSON := func(name string, v any) error {
		data, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dir, name), append(data, '\n'), 0o644)
	}
	if err := writeJSON("meta.json", meta); err != nil {
		return err
	}
	if err := writeJSON("results.json", results); err != nil {
		return err
	}
	// CSV
	var csvBuf bytes.Buffer
	if err := outputCSV(&csvBuf, results); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "findings.csv"), csvBuf.Bytes(), 0o644); err != nil {
		return err
	}
	// SARIF
	var sarifBuf bytes.Buffer
	if err := outputSARIF(&sarifBuf, results); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "hawkprobe.sarif"), sarifBuf.Bytes(), 0o644); err != nil {
		return err
	}
	return nil
}

func loadScan(id string) (scanMeta, []scanResult, error) {
	var meta scanMeta
	var results []scanResult
	metaData, err := os.ReadFile(filepath.Join(scanDir(id), "meta.json"))
	if err != nil {
		return meta, results, err
	}
	if err := json.Unmarshal(metaData, &meta); err != nil {
		return meta, results, err
	}
	resData, err := os.ReadFile(filepath.Join(scanDir(id), "results.json"))
	if err != nil {
		return meta, results, err
	}
	if err := json.Unmarshal(resData, &results); err != nil {
		return meta, results, err
	}
	return meta, results, nil
}

func listScans() ([]scanMeta, error) {
	entries, err := os.ReadDir(workspaceDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []scanMeta
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		meta, _, err := loadScan(e.Name())
		if err != nil {
			continue
		}
		out = append(out, meta)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt.After(out[j].StartedAt) })
	return out, nil
}

func scannedTargetSet(results []scanResult) map[string]bool {
	set := map[string]bool{}
	for _, r := range results {
		if r.Error == "" {
			set[r.Target] = true
		}
	}
	return set
}

func optionsFromMeta(meta scanMeta) options {
	o := meta.Options
	return options{
		Mode:              o.Mode,
		CategoryFilter:    o.Category,
		TagFilter:         o.Tag,
		MinSeverity:       o.Severity,
		FailOn:            o.FailOn,
		Concurrency:       o.Concurrency,
		TargetConcurrency: o.TargetConcurrency,
		Rate:              o.Rate,
		Retries:           o.Retries,
		MaxRequests:       o.MaxRequests,
		Timeout:           time.Duration(o.TimeoutMS) * time.Millisecond,
		MaxRedirects:      o.MaxRedirects,
		Wordlist:          o.Wordlist,
		RuleFile:          o.Rules,
		Extensions:        o.Extensions,
		Discover:          o.Discover,
		Insecure:          o.Insecure,
		NoRedirect:        o.NoRedirect,
		Headers:           o.Headers,
		User:              o.User,
		Pass:              o.Pass,
		Token:             o.Token,
		Proxy:             o.Proxy,
		UserAgent:         o.UserAgent,
		HostHeader:        o.HostHeader,
		Suppressions:      o.Suppressions,
		CustomRules:       o.CustomRules,
		AI:                o.AI,
		AIModel:           o.AIModel,
	}
}

func savedOptionsFromOptions(opts options) savedOptions {
	return savedOptions{
		Mode:              opts.Mode,
		Category:          opts.CategoryFilter,
		Tag:               opts.TagFilter,
		Severity:          opts.MinSeverity,
		FailOn:            opts.FailOn,
		Concurrency:       opts.Concurrency,
		TargetConcurrency: opts.TargetConcurrency,
		Rate:              opts.Rate,
		Retries:           opts.Retries,
		MaxRequests:       opts.MaxRequests,
		TimeoutMS:         int(opts.Timeout / time.Millisecond),
		MaxRedirects:      opts.MaxRedirects,
		Wordlist:          opts.Wordlist,
		Rules:             opts.RuleFile,
		Extensions:        opts.Extensions,
		Discover:          opts.Discover,
		Insecure:          opts.Insecure,
		NoRedirect:        opts.NoRedirect,
		Headers:           opts.Headers,
		User:              opts.User,
		Pass:              opts.Pass,
		Token:             opts.Token,
		Proxy:             opts.Proxy,
		UserAgent:         opts.UserAgent,
		HostHeader:        opts.HostHeader,
		Suppressions:      opts.Suppressions,
		CustomRules:       opts.CustomRules,
		AI:                opts.AI,
		AIModel:           opts.AIModel,
	}
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func validateListFile(path string) error {
	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	f.Close()
	return nil
}

func handleWorkspaceCommand(args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: hawkprobe workspace init|scans|show|prune")
		os.Exit(2)
	}
	switch args[1] {
	case "init":
		dir := workspaceDir()
		if err := os.MkdirAll(dir, 0o755); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		_ = os.WriteFile(filepath.Join(dir, ".hawkprobe.json"), []byte("{\"version\":\"1.4.0\"}\n"), 0o644)
		fmt.Printf("workspace ready: %s\n", dir)
	case "scans":
		scans, err := listScans()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if len(scans) == 0 {
			fmt.Printf("no scans recorded in %s\n", workspaceDir())
			return
		}
		fmt.Printf("%-24s %-16s %-9s %-6s %-6s %-6s %-6s %s\n", "ID", "STARTED", "STATUS", "CRIT", "HIGH", "MED", "LOW", "MODE")
		for _, m := range scans {
			fmt.Printf("%-24s %-16s %-9s %-6d %-6d %-6d %-6d %s\n",
				m.ID, m.StartedAt.Local().Format("2006-01-02 15:04"), m.Status,
				m.Summary.Critical, m.Summary.High, m.Summary.Medium, m.Summary.Low, m.Mode)
		}
	case "show":
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: hawkprobe workspace show <scan-id>")
			os.Exit(2)
		}
		meta, results, err := loadScan(args[2])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		data, _ := json.MarshalIndent(meta, "", "  ")
		fmt.Println(string(data))
		fmt.Println()
		for _, r := range results {
			for _, f := range r.Findings {
				fmt.Printf("  [%s] %s %s\n", f.Level, f.Rule, r.Target)
			}
		}
	case "prune":
		maxKeep := 50
		days := 30
		for i := 2; i < len(args)-1; i++ {
			switch args[i] {
			case "--max":
				fmt.Sscanf(args[i+1], "%d", &maxKeep)
			case "--days":
				fmt.Sscanf(args[i+1], "%d", &days)
			}
		}
		scans, err := listScans()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		cutoff := time.Now().AddDate(0, 0, -days)
		removed := 0
		for _, m := range scans { // newest first
			if m.StartedAt.Before(cutoff) {
				_ = os.RemoveAll(scanDir(m.ID))
				removed++
				break // everything older is also before the cutoff
			}
			if len(scans)-removed > maxKeep {
				_ = os.RemoveAll(scanDir(m.ID))
				removed++
			} else {
				break
			}
		}
		fmt.Printf("pruned %d scan(s), %d remaining\n", removed, len(scans)-removed)
	default:
		fmt.Fprintln(os.Stderr, "usage: hawkprobe workspace init|scans|show|prune")
		os.Exit(2)
	}
}

func findingsOf(results []scanResult) int {
	_, n, _ := countFindings(results)
	return n
}

type keyedFinding struct {
	finding
	Target string
}

type diffFinding struct {
	RuleID   string   `json:"rule_id"`
	Title    string   `json:"title"`
	Severity string   `json:"severity"`
	Targets  []string `json:"targets"`
}

func flattenKeyed(results []scanResult) []keyedFinding {
	var out []keyedFinding
	for _, r := range results {
		for _, f := range r.Findings {
			out = append(out, keyedFinding{finding: f, Target: r.Target})
		}
	}
	return out
}

func diffKey(f keyedFinding) string {
	return f.Rule + "\x00" + f.Target
}

func computeDiff(baseResults, freshResults []scanResult) (added, removed []keyedFinding) {
	baseSet := map[string]bool{}
	for _, f := range flattenKeyed(baseResults) {
		baseSet[diffKey(f)] = true
	}
	newSet := map[string]bool{}
	for _, f := range flattenKeyed(freshResults) {
		newSet[diffKey(f)] = true
	}
	for _, f := range flattenKeyed(freshResults) {
		if !baseSet[diffKey(f)] {
			added = append(added, f)
		}
	}
	for _, f := range flattenKeyed(baseResults) {
		if !newSet[diffKey(f)] {
			removed = append(removed, f)
		}
	}
	return added, removed
}

func handleDiffCommand(args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: hawkprobe diff <base-scan-id> <new-scan-id>")
		os.Exit(2)
	}
	base, baseResults, err := loadScan(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "load base scan: "+err.Error())
		os.Exit(2)
	}
	fresh, freshResults, err := loadScan(args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "load new scan: "+err.Error())
		os.Exit(2)
	}
	added, removed := computeDiff(baseResults, freshResults)
	newTargetSet := map[string]bool{}
	for _, t := range base.Targets {
		newTargetSet[t] = true
	}
	newTargets := 0
	for _, t := range fresh.Targets {
		if !newTargetSet[t] {
			newTargets++
		}
	}
	fmt.Printf("diff: %s (base, %s) -> %s (new, %s)\n",
		base.ID, base.StartedAt.Local().Format("2006-01-02 15:04"),
		fresh.ID, fresh.StartedAt.Local().Format("2006-01-02 15:04"))
	fmt.Printf("targets: base=%d new=%d (new targets: %d)\n", len(base.Targets), len(fresh.Targets), newTargets)
	fmt.Printf("findings: base=%d new=%d\n", findingsOf(baseResults), findingsOf(freshResults))
	printDiffGroup("added", added)
	printDiffGroup("removed", removed)
	if len(added) == 0 && len(removed) == 0 {
		fmt.Println("no finding changes between scans")
	}
}

func groupByKeyed(fs []keyedFinding) map[string]*diffFinding {
	out := map[string]*diffFinding{}
	for _, f := range fs {
		d, ok := out[f.Rule]
		if !ok {
			d = &diffFinding{RuleID: f.Rule, Title: f.Message, Severity: f.Level}
			out[f.Rule] = d
		}
		d.Targets = append(d.Targets, f.Target)
	}
	return out
}

func printDiffGroup(label string, fs []keyedFinding) {
	if len(fs) == 0 {
		fmt.Printf("%-8snone\n", label+": ")
		return
	}
	g := groupByKeyed(fs)
	fmt.Printf("%-8s%d finding(s) across %d rule(s)\n", label+": ", len(fs), len(g))
	var ids []string
	for id := range g {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		d := g[id]
		targets := d.Targets
		if len(targets) > 3 {
			targets = targets[:3]
		}
		fmt.Printf("  [%s] %s (%s) on %s\n", d.Severity, id, d.Title, strings.Join(targets, ", "))
	}
}

func handleResumeCommand(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: hawkprobe resume <scan-id>")
		os.Exit(2)
	}
	meta, existing, err := loadScan(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "load scan: "+err.Error())
		os.Exit(2)
	}
	done := scannedTargetSet(existing)
	var pending []string
	for _, t := range meta.Targets {
		if !done[t] {
			pending = append(pending, t)
		}
	}
	if len(pending) == 0 {
		fmt.Printf("scan %s already covers all %d target(s)\n", meta.ID, len(meta.Targets))
		return
	}
	fmt.Printf("resuming %s: %d of %d targets pending\n", meta.ID, len(pending), len(meta.Targets))
	opts := optionsFromMeta(meta)
	opts.NoProgress = !isTerminal(os.Stdout)
	opts.NoColor = os.Getenv("NO_COLOR") != "" || !isTerminal(os.Stdout)
	if err := validateResumeOptions(&opts); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	rules, err := loadRules(opts.RuleFile, opts.Mode)
	if err != nil {
		fmt.Fprintln(os.Stderr, "rules:", err)
		os.Exit(2)
	}
	rules = filterRules(rules, opts.CategoryFilter, opts.TagFilter)
	if opts.Wordlist != "" {
		wordRules, err := loadWordlistRules(opts.Wordlist, opts.Extensions)
		if err != nil {
			fmt.Fprintln(os.Stderr, "wordlist:", err)
			os.Exit(2)
		}
		rules = append(rules, wordRules...)
	}
	custom := loadCustomRuleList(opts)
	started := time.Now()
	results := scanTargets(opts, pending, rules, custom)
	merged := append(append([]scanResult{}, existing...), results...)
	meta.ScannedTargets = sortedKeys(scannedTargetSet(merged))
	if len(meta.ScannedTargets) == len(meta.Targets) {
		meta.Status = "completed"
	}
	meta.FinishedAt = time.Now()
	meta.Summary = summaryOf(merged, meta.Summary.ErrorsTotal)
	if err := writeScanArtifacts(meta, merged); err != nil {
		fmt.Fprintln(os.Stderr, "record scan: "+err.Error())
		os.Exit(2)
	}
	fmt.Printf("resumed scan %s in %s (%d of %d targets complete)\n",
		meta.ID, time.Since(started).Round(time.Millisecond), len(meta.ScannedTargets), len(meta.Targets))
	if meta.Options.FailOn != "" && meta.Summary.BySeverity(meta.Options.FailOn) > 0 {
		os.Exit(1)
	}
}

// validateResumeOptions fills defaults for options rebuilt from a stored
// workspace record and re-checks the list file.
func validateResumeOptions(opts *options) error {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 4
	}
	if opts.TargetConcurrency <= 0 {
		opts.TargetConcurrency = 1
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 6 * time.Second
	}
	if opts.MaxRedirects <= 0 {
		opts.MaxRedirects = 5
	}
	return nil
}
