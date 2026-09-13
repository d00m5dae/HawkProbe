package main

func resultsMeetFailThreshold(results []scanResult, threshold string) bool {
	if threshold == "" {
		return false
	}
	minimum := parseSeverity(threshold)
	for _, result := range results {
		for _, finding := range result.Findings {
			if finding.Severity >= minimum {
				return true
			}
		}
	}
	return false
}
