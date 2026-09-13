package main

import (
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

type progressBar struct {
	total int64
	done atomic.Int64
	label string
	stop chan struct{}
	finished chan struct{}
}

func newProgressBar(opts options, label string, total int) *progressBar {
	if !opts.Progress || opts.Verbose || opts.Quiet || opts.TargetConcurrency > 1 || total < 1 {
		return nil
	}
	p := &progressBar{total: int64(total), label: label, stop: make(chan struct{}), finished: make(chan struct{})}
	go func() {
		defer close(p.finished)
		ticker := time.NewTicker(120 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				p.render(false)
			case <-p.stop:
				p.render(true)
				return
			}
		}
	}()
	return p
}

func (p *progressBar) Advance() {
	if p != nil {
		p.done.Add(1)
	}
}

func (p *progressBar) Stop() {
	if p == nil {
		return
	}
	close(p.stop)
	<-p.finished
}

func (p *progressBar) render(final bool) {
	done := p.done.Load()
	if done > p.total {
		done = p.total
	}
	percent := int(float64(done) / float64(p.total) * 100)
	const width = 28
	filled := int(float64(width) * float64(done) / float64(p.total))
	if filled > width {
		filled = width
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	label := p.label
	if len(label) > 34 {
		label = label[:31] + "..."
	}
	verboseMu.Lock()
	defer verboseMu.Unlock()
	fmt.Fprintf(os.Stderr, "\r[%s] %3d%% %d/%d  %-34s", bar, percent, done, p.total, label)
	if final {
		fmt.Fprintln(os.Stderr)
	}
}
