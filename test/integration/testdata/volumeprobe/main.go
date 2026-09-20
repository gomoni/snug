// Command volumeprobe is a from-scratch container's own entrypoint for the
// named-volume lifecycle claim (issue #464): a volume survives
// the container that wrote it, so a SECOND, unrelated container reading the
// same named volume back sees what the first one left there.
//
// It has no shell and no libc — the image is `FROM scratch` with nothing but
// this static binary, for the same from-scratch-needs-no-registry reason
// every other probe in this directory is shaped this way.
//
// Usage: volumeprobe write PATH CONTENT | volumeprobe read PATH
//
// `write` creates PATH with CONTENT and exits 0. `read` prints
// "VOLUME-CONTENT-BEGIN", the bytes at PATH (or "VOLUME-READ-ERROR <err>" if
// it does not exist), then "VOLUME-CONTENT-END" — delimited so a Go test can
// extract the content without guessing at a shell quoting convention.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("VOLUME-USAGE-ERROR")
		os.Exit(1)
	}
	switch os.Args[1] {
	case "write":
		content := ""
		if len(os.Args) > 3 {
			content = os.Args[3]
		}
		if err := os.WriteFile(os.Args[2], []byte(content), 0o644); err != nil {
			fmt.Printf("VOLUME-WRITE-ERROR %v\n", err)
			os.Exit(1)
		}
		fmt.Println("VOLUME-WRITE-OK")
	case "read":
		fmt.Println("VOLUME-CONTENT-BEGIN")
		b, err := os.ReadFile(os.Args[2])
		if err != nil {
			fmt.Printf("VOLUME-READ-ERROR %v\n", err)
		} else {
			fmt.Print(string(b))
		}
		fmt.Println("VOLUME-CONTENT-END")
	default:
		fmt.Println("VOLUME-USAGE-ERROR")
		os.Exit(1)
	}
}
