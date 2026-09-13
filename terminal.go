package main

import (
	"io"
	"os"
)

const (
	ansiReset   = "\x1b[0m"
	ansiBold    = "\x1b[1m"
	ansiDim     = "\x1b[2m"
	ansiRed     = "\x1b[31m"
	ansiYellow  = "\x1b[33m"
	ansiBlue    = "\x1b[34m"
	ansiMagenta = "\x1b[35m"
	ansiCyan    = "\x1b[36m"
)

func colorEnabled(opts options, w io.Writer) bool {
	if opts.NoColor || os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	f, ok := w.(*os.File)
	return ok && isTerminal(f)
}

func colorize(enabled bool, code, text string) string {
	if !enabled {
		return text
	}
	return code + text + ansiReset
}

func severityColor(s severity) string {
	switch s {
	case critical:
		return ansiMagenta
	case high:
		return ansiRed
	case medium:
		return ansiYellow
	case low:
		return ansiBlue
	default:
		return ansiCyan
	}
}
