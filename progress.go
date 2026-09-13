package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

type progressBar struct {
	mu       sync.Mutex
	enabled  bool
	target   string
	total    int
	done     int
	started  time.Time
	lastDraw time.Time
}

func newProgressBar(opts options, target string, total int) *progressBar {
	p := &progressBar{target: target, total: total, started: time.Now()}
	if total < 1 || opts.NoProgress || opts.Verbose || opts.Quiet || opts.JSON || opts.JSONL || opts.CSV || opts.SARIF {
		return p
	}
	if !isTerminal(os.Stderr) || os.Getenv("TERM") == "dumb" {
		return p
	}
	p.enabled = true
	p.draw(true)
	return p
}

func (p *progressBar) Advance() {
	if p == nil || !p.enabled {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.done++
	now := time.Now()
	if p.done < p.total && now.Sub(p.lastDraw) < 75*time.Millisecond {
		return
	}
	p.drawLocked(now)
}

func (p *progressBar) Finish() {
	if p == nil || !p.enabled {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.done < p.total {
		p.done = p.total
	}
	p.drawLocked(time.Now())
	fmt.Fprint(os.Stderr, "\n")
}

func (p *progressBar) draw(force bool) {
	if !p.enabled {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	if !force && now.Sub(p.lastDraw) < 75*time.Millisecond {
		return
	}
	p.drawLocked(now)
}

func (p *progressBar) drawLocked(now time.Time) {
	p.lastDraw = now
	width := 28
	fraction := float64(p.done) / float64(p.total)
	if fraction < 0 {
		fraction = 0
	}
	if fraction > 1 {
		fraction = 1
	}
	filled := int(fraction * float64(width))
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	elapsed := now.Sub(p.started)
	rate := 0.0
	if elapsed > 0 {
		rate = float64(p.done) / elapsed.Seconds()
	}
	label := compactTarget(p.target, 28)
	fmt.Fprintf(os.Stderr, "\r\x1b[2K%s [%s] %6d/%-6d %5.1f%% %6.0f/s", label, bar, p.done, p.total, fraction*100, rate)
}

func compactTarget(target string, max int) string {
	if len(target) <= max {
		return target
	}
	if max < 4 {
		return target[:max]
	}
	return target[:max-3] + "..."
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
