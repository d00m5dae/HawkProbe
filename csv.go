package main

import (
	"encoding/csv"
	"io"
	"strconv"
)

func outputCSV(w io.Writer, results []scanResult) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{
		"target", "status", "severity", "category", "confidence", "rule",
		"message", "url", "evidence", "remediation", "requests", "duration_ms",
	}); err != nil {
		return err
	}

	for _, result := range results {
		if len(result.Findings) == 0 {
			if result.Error != "" {
				if err := cw.Write([]string{
					result.Target, result.Status, "error", "", "", "", result.Error, "", "", "",
					strconv.Itoa(result.Requests), strconv.FormatInt(result.DurationMS, 10),
				}); err != nil {
					return err
				}
			}
			continue
		}

		for _, f := range result.Findings {
			if err := cw.Write([]string{
				result.Target, result.Status, f.Level, f.Category, f.Confidence, f.Rule,
				f.Message, f.URL, f.Evidence, f.Remediation,
				strconv.Itoa(result.Requests), strconv.FormatInt(result.DurationMS, 10),
			}); err != nil {
				return err
			}
		}
	}

	cw.Flush()
	return cw.Error()
}
