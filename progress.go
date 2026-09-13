package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

type progressTracker struct {
	mu      sync.Mutex
	total   int
	done    int
	width   int
	started time.Time
	last    time.Time
	closed  bool
}

func newProgressTracker(total, width int) *progressTracker {
	if width < 10 {
		width = 28
	}
	return &progressTracker{total: total, width: width, started: time.Now()}
}

func (p *progressTracker) Add(n int) {
	if p == nil || n <= 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.done += n
	if p.done > p.total {
		p.done = p.total
	}
	now := time.Now()
	if p.done != p.total && !p.last.IsZero() && now.Sub(p.last) < 80*time.Millisecond {
		return
	}
	p.last = now
	p.render(false)
}

func (p *progressTracker) Finish() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	p.render(true)
	fmt.Fprintln(os.Stderr)
}

func (p *progressTracker) render(final bool) {
	if p.total <= 0 {
		return
	}
	done := p.done
	if final && done > p.total {
		done = p.total
	}
	percent := float64(done) / float64(p.total)
	filled := int(percent * float64(p.width))
	if filled > p.width {
		filled = p.width
	}
	bar := strings.Repeat("#", filled) + strings.Repeat("-", p.width-filled)
	elapsed := time.Since(p.started).Round(100 * time.Millisecond)
	fmt.Fprintf(os.Stderr, "\r[%s] %3.0f%%  %d/%d checks  %s", bar, percent*100, done, p.total, elapsed)
}
