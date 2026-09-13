package main

import (
	"html"
	"net/http"
	"regexp"
	"strings"
)

var titlePattern = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
var tagPattern = regexp.MustCompile(`(?s)<[^>]+>`)

type responseMeta struct {
	Title string
	ContentType string
	ContentLength int64
	Server string
	FinalURL string
}

func inspectResponseMeta(resp *http.Response, body []byte) responseMeta {
	meta := responseMeta{
		ContentType: resp.Header.Get("Content-Type"),
		ContentLength: int64(len(body)),
		Server: resp.Header.Get("Server"),
	}
	if resp.Request != nil && resp.Request.URL != nil {
		meta.FinalURL = resp.Request.URL.String()
	}
	if match := titlePattern.FindSubmatch(body); len(match) == 2 {
		title := tagPattern.ReplaceAllString(string(match[1]), " ")
		title = html.UnescapeString(title)
		meta.Title = strings.Join(strings.Fields(title), " ")
		if len(meta.Title) > 160 {
			meta.Title = meta.Title[:157] + "..."
		}
	}
	return meta
}
