package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"hash/fnv"
	"net/http"
	"regexp"
	"strings"
)

type baselineSample struct {
	status int
	length int64
	sketch uint64
}

type baseline struct {
	samples []baselineSample
	stable  bool
}

var spaceRX = regexp.MustCompile(`\s+`)

func getBaseline(ctx context.Context, client *http.Client, opts options, target string, requests *int64) baseline {
	bl := baseline{samples: make([]baselineSample, 0, 2)}
	for i := 0; i < 2; i++ {
		buf := make([]byte, 12)
		if _, err := rand.Read(buf); err != nil {
			continue
		}
		token := ".hawkprobe-" + hex.EncodeToString(buf)
		resp, body, err := fetchBody(ctx, client, opts, http.MethodGet, joinURL(target, "/"+token), nil, 96*1024, requests)
		if err != nil {
			continue
		}
		bl.samples = append(bl.samples, baselineSample{status: resp.StatusCode, length: int64(len(body)), sketch: bodySketch(body, token)})
	}
	if len(bl.samples) == 2 {
		a, b := bl.samples[0], bl.samples[1]
		bl.stable = a.status == b.status && closeLength(a.length, b.length) && a.sketch == b.sketch
	}
	return bl
}

func bodySketch(body []byte, strip string) uint64 {
	text := strings.ToLower(string(body))
	if strip != "" {
		text = strings.ReplaceAll(text, strings.ToLower(strip), "")
	}
	text = spaceRX.ReplaceAllString(text, " ")
	if len(text) > 4096 {
		text = text[:4096]
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(text))
	return h.Sum64()
}

func closeLength(a, b int64) bool {
	if a == 0 || b == 0 {
		return a == b
	}
	delta := a - b
	if delta < 0 {
		delta = -delta
	}
	tolerance := int64(64)
	larger := a
	if b > larger {
		larger = b
	}
	if pct := larger / 25; pct > tolerance {
		tolerance = pct
	}
	return delta <= tolerance
}

func looksLikeBaseline(status int, body []byte, base baseline) bool {
	if len(base.samples) == 0 {
		return false
	}
	length := int64(len(body))
	sketch := bodySketch(body, "")
	for _, sample := range base.samples {
		if status != sample.status {
			continue
		}
		if base.stable && closeLength(length, sample.length) {
			return true
		}
		if closeLength(length, sample.length) && sketch == sample.sketch {
			return true
		}
	}
	return false
}
