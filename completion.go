package main

import (
	"fmt"
	"strings"
)

var completionWords = []string{
	"help", "version", "doctor", "wordlists", "rules", "completion",
	"quick", "default", "full", "deep", "htb", "exposure", "admin", "api", "debug", "headers", "tls", "tech",
	"-mode", "-profile", "-c", "-target-c", "-rate", "-timeout", "-discover", "-wordlist", "-seclists", "-ext",
	"-list", "-nmap", "-stdin", "-category", "-tag", "-severity", "-fail-on", "-v", "-evidence", "-rules",
	"-H", "-host", "-user", "-pass", "-token", "-proxy", "-ua", "-no-redirect", "-max-redirects", "-k",
	"-json", "-jsonl", "-csv", "-sarif", "-o", "-urls-out", "-no-progress", "-no-color", "-q",
}

func printCompletion(shell string) error {
	words := strings.Join(completionWords, " ")
	switch lower(shell) {
	case "bash":
		fmt.Printf("_hawkprobe() { COMPREPLY=( $(compgen -W %q -- \"${COMP_WORDS[COMP_CWORD]}\") ); }\ncomplete -F _hawkprobe hawkprobe\n", words)
	case "zsh":
		fmt.Printf("#compdef hawkprobe\n_arguments '*: :((%s))'\n", words)
	case "fish":
		for _, word := range completionWords {
			if strings.HasPrefix(word, "-") {
				fmt.Printf("complete -c hawkprobe -l %s\n", strings.TrimLeft(word, "-"))
			} else {
				fmt.Printf("complete -c hawkprobe -f -a %q\n", word)
			}
		}
	default:
		return fmt.Errorf("unsupported shell %q; use bash, zsh, or fish", shell)
	}
	return nil
}
