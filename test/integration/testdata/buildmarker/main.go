// Command buildmarker is the RUN step of the build probe's Dockerfile: it
// prints one marker and exits.
//
// It exists to take the LAST registry dependency out of this suite (issue
// #235). The probe used to build `FROM docker.io/library/alpine:3.20` with
// `RUN echo BUILT-INSIDE-SNUG`, because a shell was the obvious way to make a
// build prove it had really executed a step. That made two tests — and
// requireRealEngine, which gates sixteen more — depend on an anonymous Docker
// Hub pull. When Docker Hub refuses one (measured: `toomanyrequests: You have
// reached your unauthenticated pull rate limit`), the build cannot start, the
// probe never finishes, and the test reports a 30-second timeout naming no
// registry at all. That failure has been misdiagnosed four times.
//
// `FROM scratch` has no shell, so `RUN echo …` is not available — but the EXEC
// form needs none: `RUN ["/marker"]` runs this binary directly, and its stdout
// lands in the build output exactly where the shell's did. Measured with
// podman 5.x before it was written down.
//
// The same reasoning holder next door already carries for a container that has
// to keep RUNNING; this is its build-time counterpart.
package main

import "fmt"

// Marker is what the probe greps for. It is deliberately the same string the
// alpine-based probe printed, so no assertion in the suite had to change.
const Marker = "BUILT-INSIDE-SNUG"

func main() { fmt.Println(Marker) }
