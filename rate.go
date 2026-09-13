package main

import (
	"net/http"
	"sync"
	"time"
)

type pacedTransport struct {
	base     http.RoundTripper
	interval time.Duration
	mu       sync.Mutex
	next     time.Time
}

func wrapRateLimit(base http.RoundTripper, rate int) http.RoundTripper {
	if rate <= 0 {
		return base
	}
	interval := time.Second / time.Duration(rate)
	if interval <= 0 {
		return base
	}
	return &pacedTransport{base: base, interval: interval}
}

func (p *pacedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	p.mu.Lock()
	now := time.Now()
	if p.next.After(now) {
		delay := p.next.Sub(now)
		p.mu.Unlock()
		select {
		case <-time.After(delay):
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
		p.mu.Lock()
		now = time.Now()
	}
	p.next = now.Add(p.interval)
	p.mu.Unlock()
	return p.base.RoundTrip(req)
}
