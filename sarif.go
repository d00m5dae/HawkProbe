package main

import (
	"encoding/json"
	"io"
)

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name,omitempty"`
	ShortDescription sarifMessage      `json:"shortDescription,omitempty"`
	Help             sarifMessage      `json:"help,omitempty"`
	Properties       map[string]string `json:"properties,omitempty"`
}

type sarifResult struct {
	RuleID     string            `json:"ruleId,omitempty"`
	Level      string            `json:"level,omitempty"`
	Message    sarifMessage      `json:"message"`
	Locations  []sarifLocation   `json:"locations,omitempty"`
	Properties map[string]string `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

func outputSARIF(w io.Writer, results []scanResult) error {
	ruleMap := make(map[string]sarifRule)
	var sarifResults []sarifResult
	for _, result := range results {
		for _, finding := range result.Findings {
			ruleID := finding.Rule
			if ruleID == "" {
				ruleID = "hawkprobe-finding"
			}
			if _, ok := ruleMap[ruleID]; !ok {
				ruleMap[ruleID] = sarifRule{
					ID:               ruleID,
					Name:             finding.Message,
					ShortDescription: sarifMessage{Text: finding.Message},
					Help:             sarifMessage{Text: finding.Remediation},
					Properties:       map[string]string{"category": finding.Category, "confidence": finding.Confidence, "severity": finding.Level},
				}
			}
			uri := finding.URL
			if uri == "" {
				uri = result.Target
			}
			props := map[string]string{"target": result.Target, "category": finding.Category, "confidence": finding.Confidence}
			if finding.Evidence != "" {
				props["evidence"] = finding.Evidence
			}
			sarifResults = append(sarifResults, sarifResult{
				RuleID:  ruleID,
				Level:   sarifLevel(finding.Severity),
				Message: sarifMessage{Text: finding.Message},
				Locations: []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{ArtifactLocation: sarifArtifactLocation{URI: uri}}}},
				Properties: props,
			})
		}
	}
	rules := make([]sarifRule, 0, len(ruleMap))
	for _, r := range ruleMap {
		rules = append(rules, r)
	}
	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{Name: "HawkProbe", Version: version, InformationURI: "https://github.com/d00m5dae/HawkProbe", Rules: rules}},
			Results: sarifResults,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func sarifLevel(s severity) string {
	switch s {
	case critical, high:
		return "error"
	case medium:
		return "warning"
	default:
		return "note"
	}
}
