package draft

// Abuse holds, per built-in, one sentence copied from the ABUSE comment above
// that profile in internal/profile/profiles/base.toml. The rendered profile
// carries it next to the include so the human reading the file sees the cost
// of each grant. TestAbuseSentencesAreStillInBaseToml fails when base.toml
// changes a sentence, so these cannot drift.
var Abuse = map[string]string{
	"@sys":           "the sandbox can read every world-readable file in /usr and the few /etc entries below.",
	"@home":          "a hostile process inside the sandbox can write anything it likes into any of these directories.",
	"@target-rw":     "the sandbox can rewrite anything in the target directory.",
	"@parent-ro":     "a hostile process inside the sandbox can read every file under the target's parent — every sibling project, their .git/config, their .env files, any credential anyone left in one, and any SOCKET sitting in the tree.",
	"@net":           "the sandbox can reach the whole internet — exfiltrate anything it can read, fetch and run anything it likes.",
	"@claude":        "the sandbox can spend your Anthropic credits and read your Claude settings and personal skills.",
	"@podman-socket": "the sandbox can run arbitrary code in a container that shares the sandbox's OWN network namespace — so it reaches exactly what the sandbox reaches and no more: with @net, the whole internet, as the sandbox already could; WITHOUT @net, nothing.",
	"@podman-build":  "the sandbox can build an image from a Dockerfile it wrote, which means running arbitrary commands in a container — but that is already true of `@podman-socket`, so this adds no new execution.",
	"identity":       "the sandbox gets a SIGNING ORACLE for the pinned ssh key(s). It can push to any repository the authentication key reaches, authenticate to any host that trusts it",
	"listen_names":   "a hostile process inside the sandbox can use this to serve a page of its own writing into YOUR browser, on an origin your browser treats as local.",
}
