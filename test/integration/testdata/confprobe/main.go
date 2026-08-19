// Command confprobe is a from-scratch container's own entrypoint (issue
// #132): it reports everything a HOST containers.conf could have authored for
// this container without any client ever asking for it.
//
// It has no shell and no libc — the image is `FROM scratch` with nothing but
// this static binary, because the whole point is that the image needs no base
// layer and therefore no registry pull, and so can be built with the
// sandbox's egress CLOSED. Same reason testdata/resolvprobe is shaped this
// way; see TestHostContainersConfAuthorsNothingInAContainer for why it
// matters here.
//
// Four sections, each delimited so the Go test can extract one without
// guessing at a shell quoting convention:
//
//	ROOT — every name at /, which is where a `mounts`/`volumes` destination
//	       lands. A leaked bind shows up as a directory nobody asked for.
//	LEAK — the content of the marker files this test's plant points at, if
//	       they are reachable at all.
//	ENV  — the whole environment, which is what `env` and `env_host` author.
//	DEV  — every name at /dev, which is what `devices` authors.
//	LIMITS — /proc/self/limits, which is what `default_ulimits` authors.
//
// LIMITS is the one that earns its place. The other three keys are ENUMERATED
// in snug's own generated containers.conf, so they stay closed even if that
// file were merely loaded last instead of replacing the host's — which means
// they cannot tell the two mechanisms apart. `default_ulimits` is deliberately
// NOT enumerated (issue #136: closing it means choosing a value on podman's
// behalf for every container), so it is visible exactly when the host's file
// is read at all. It is the probe's discriminator for CONTAINERS_CONF's
// suppression.
package main

import (
	"fmt"
	"os"
)

func main() {
	dumpDir("ROOT", "/")
	dumpFiles("LEAK", "/leak/token", "/leak2/token")
	dumpEnv("ENV")
	dumpDir("DEV", "/dev")
	dumpFiles("LIMITS", "/proc/self/limits")
	fmt.Println("PROBE-COMPLETE")
}

func dumpDir(label, path string) {
	fmt.Printf("%s-BEGIN\n", label)
	entries, err := os.ReadDir(path)
	if err != nil {
		fmt.Printf("%s-READ-ERROR %v\n", label, err)
	}
	for _, e := range entries {
		fmt.Println(e.Name())
	}
	fmt.Printf("%s-END\n", label)
}

func dumpFiles(label string, paths ...string) {
	fmt.Printf("%s-BEGIN\n", label)
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			fmt.Printf("%s: unreadable (%v)\n", p, err)
			continue
		}
		fmt.Printf("%s: %s\n", p, string(b))
	}
	fmt.Printf("%s-END\n", label)
}

func dumpEnv(label string) {
	fmt.Printf("%s-BEGIN\n", label)
	for _, kv := range os.Environ() {
		fmt.Println(kv)
	}
	fmt.Printf("%s-END\n", label)
}
