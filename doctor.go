package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

func printDoctor() {
	fmt.Printf("HawkProbe %s\n", version)
	fmt.Printf("Go runtime: %s\n", runtime.Version())
	fmt.Printf("OS/arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Println()

	root := findSecListsRoot()
	if root == "" {
		fmt.Println("[warn] SecLists      not found")
		fmt.Println("       install SecLists or set SECLISTS_PATH")
	} else {
		fmt.Printf("[ ok ] SecLists      %s\n", root)
	}

	tools := []string{"nmap", "httpx", "nuclei", "ffuf", "gobuster", "feroxbuster"}
	for _, name := range tools {
		path, err := exec.LookPath(name)
		if err != nil {
			fmt.Printf("[ -- ] %-13s not installed (optional)\n", name)
			continue
		}
		fmt.Printf("[ ok ] %-13s %s\n", name, path)
	}

	if os.Getenv("NO_COLOR") != "" {
		fmt.Println("[info] NO_COLOR is set; colored output is disabled")
	}
	fmt.Println()
	fmt.Println("HawkProbe does not require the optional tools above; doctor lists them because they fit common pentest pipelines.")
}
