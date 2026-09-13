package main

import (
	"bufio"
	"context"
	"encoding/xml"
	"net/http"
	"net/url"
	"strings"
)

type sitemapURLSet struct {
	URLs []struct {
		Loc string `xml:"loc"`
	} `xml:"url"`
}

func discoverInterestingPaths(ctx context.Context, client *http.Client, opts options, target string, base baseline, requests *int64) []finding {
	paths := make(map[string]string)
	robotsURL := joinURL(target, "/robots.txt")
	if resp, body, err := fetchBody(ctx, client, opts, http.MethodGet, robotsURL, nil, 128*1024, requests); err == nil && resp.StatusCode == 200 {
		s := bufio.NewScanner(strings.NewReader(string(body)))
		for s.Scan() {
			line := strings.TrimSpace(s.Text())
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.ToLower(strings.TrimSpace(parts[0]))
			value := strings.TrimSpace(parts[1])
			if (key == "disallow" || key == "allow") && strings.HasPrefix(value, "/") && value != "/" {
				paths[value] = "robots.txt"
			}
			if key == "sitemap" && (strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://")) {
				paths[value] = "robots sitemap"
			}
		}
	}

	sitemapURL := joinURL(target, "/sitemap.xml")
	if resp, body, err := fetchBody(ctx, client, opts, http.MethodGet, sitemapURL, nil, 256*1024, requests); err == nil && resp.StatusCode == 200 {
		var set sitemapURLSet
		if xml.Unmarshal(body, &set) == nil {
			for _, item := range set.URLs {
				if item.Loc != "" {
					paths[item.Loc] = "sitemap.xml"
				}
				if len(paths) >= 60 {
					break
				}
			}
		}
	}

	interesting := make([]finding, 0)
	count := 0
	for raw, source := range paths {
		if count >= 40 {
			break
		}
		u := raw
		if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
			u = joinURL(target, raw)
		}
		parsed, err := url.Parse(u)
		baseParsed, _ := url.Parse(target)
		if err != nil || parsed.Host != baseParsed.Host {
			continue
		}
		resp, body, err := fetchBody(ctx, client, opts, http.MethodGet, u, nil, 192*1024, requests)
		if err != nil {
			continue
		}
		if resp.StatusCode != 200 && resp.StatusCode != 401 && resp.StatusCode != 403 && resp.StatusCode != 301 && resp.StatusCode != 302 {
			continue
		}
		if looksLikeBaseline(resp.StatusCode, body, base) {
			continue
		}
		sev := info
		pathLower := strings.ToLower(parsed.Path)
		if strings.Contains(pathLower, "admin") || strings.Contains(pathLower, "internal") || strings.Contains(pathLower, "private") || strings.Contains(pathLower, "backup") {
			sev = low
		}
		interesting = append(interesting, newDetailedFinding(sev, "discovered-path", "discovery", "medium", "discovered endpoint from "+source, u, "HTTP "+resp.Status+"; path="+parsed.Path, "Review whether this endpoint should be publicly reachable."))
		count++
	}
	return interesting
}
