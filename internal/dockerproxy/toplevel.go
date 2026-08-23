package dockerproxy

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// The create body's TOP level, inverted — issues #375 and #397.
//
// #338 inverted HostConfig: a non-empty field nobody modelled is refused rather
// than forwarded. THE OBJECT THAT CONTAINS HostConfig WAS NOT INVERTED, and the
// asymmetry was the whole defect: handleCreate judged HostConfig field by field
// and forwarded its siblings whole. Measured — 18 top-level keys in
// testdata/docker-run-create-body.json, 6 non-empty, and exactly two judged
// (Volumes and HostConfig). handleCreate's own strategy comment conceded it in
// words: "a NEW dangerous field added to podman's top-level create body would
// pass."
//
// One of them already did. See topLevelRefusalReason["Healthcheck"].
//
// ── why this is closable where the original design was not ──────────────────
//
// The design this package was built from specified strict decoding of the WHOLE
// create request into pinned types, and that was abandoned as unshippable
// because "clients send a large and moving set of benign fields". The reason the
// same inversion works now is not that the fields got fewer — it is that TWO
// bounds arrived that the original design did not have:
//
//  1. THE SCHEMA IS BOUNDED — but NOT closed, and the difference matters.
//     ServeHTTP refuses every state-changing libpod-native request outright
//     (normaliseFull + libpodExamined), so handleCreate only ever sees the
//     DOCKER-COMPAT schema rather than podman's open-ended SpecGenerator. That
//     is docker's container.Config (25 fields) plus HostConfig plus
//     NetworkingConfig — 27 names, read from docker's own
//     api/types/container/config.go rather than remembered, with the 9 a stock
//     `docker run` omits pinned in dockerOnlyTopLevelFields.
//
//     THIS COMMENT SAID "27 top-level names, closed and versioned" AND THAT WAS
//     WRONG — corrected in place, because the error is the instructive part. A
//     redteam pass measured three MORE top-level keys podman's compat handler
//     accepts and docker's Config does not define: EnvMerge, UnsetEnv,
//     UnsetEnvAll. So the docker schema bounds what a DOCKER client can send,
//     not what the compat ENDPOINT accepts, and "closed" was a claim about the
//     wrong one of the two.
//
//     The inversion is unharmed and that is the point of building it this way:
//     all three fail closed today (driven — 403 each), because they are
//     modelled nowhere and the catch-all does not need to have heard of a field
//     to refuse it. An enumeration would have needed to know they existed.
//     They are in podmanOnlyTopLevelFields in the test, which is also what
//     keeps the completeness sweep's negative branch alive.
//
//     KNOWN COST, since it is a refusal and not a no-op: a podman-native
//     compat client using `--env-merge` or `--unsetenv` gets a 403. A stock
//     `docker run` never sends them.
//
//  2. THE EMPTY DROP. isEmptyJSON is what made #338 shippable and it does the
//     same work here: an unmodelled EMPTY field is dropped and named in the
//     audit, not refused. Without it an allowlist evaluated on raw PRESENCE
//     would 403 every `docker run` on 18 keys — the LogConfig trap at schema
//     scale.
//
// ── the residual, stated rather than hidden ─────────────────────────────────
//
// Same as #338's, one level up: for a POINTER field an explicit zero and an
// absent key do differ on the far side, and at this level StopTimeout *int is
// the live example (MemorySwappiness *int64 is HostConfig's). The direction of
// the miss is always "the engine's own default applies" — a tightening, never
// attacker-chosen — and it reaches only fields nobody has modelled, which
// StopTimeout is not.

// checkTopLevel judges every key of the create body's top level, and returns the
// empty unmodelled fields it dropped so the caller can name them in the audit.
//
// It MUTATES req: an unmodelled empty key is deleted. Nothing else is rewritten
// here — Labels is stamped and HostConfig is re-encoded by the caller, which is
// where those two already lived.
func (p *Proxy) checkTopLevel(req map[string]json.RawMessage) ([]string, error) {
	// Refuse outright. Same shape as refusedHostConfig's loop, and the sole
	// member today (Volumes) used to be an inline check here — it is on a list
	// now so that every sweep which iterates the refused set covers it, which is
	// the lesson containeridfile_test.go was written for one level down.
	for _, k := range refusedTopLevel {
		v, ok := req[k]
		if !ok || isEmptyJSON(v) {
			continue
		}
		return nil, fmt.Errorf("%s is not permitted: %s", k, topLevelRefusalReason[k])
	}

	// Judged by a function of its own, because admitting "the value that asks
	// for nothing" and refusing "the value that asks for something" cannot be
	// expressed as membership in a list. These are the LogConfig/RestartPolicy
	// pattern at the top level.
	for _, k := range topLevelChecked {
		raw, ok := req[k]
		if !ok || isEmptyJSON(raw) {
			continue
		}
		if err := topLevelChecks[k](raw); err != nil {
			return nil, err
		}
	}

	// THE INVERSION. Everything left must be a name snug has been taught about.
	var dropped []string
	for k, v := range req {
		lower := strings.ToLower(k)
		if judgedTopLevelField[lower] || unexaminedTopLevelField[lower] {
			continue
		}
		if isEmptyJSON(v) {
			dropped = append(dropped, k)
			delete(req, k)
			continue
		}
		return nil, fmt.Errorf("%s is not permitted. snug allows a named set of top-level "+
			"create fields and refuses the rest, so a field it has not been taught about "+
			"fails closed rather than reaching the engine unexamined. HostConfig has been "+
			"filtered this way since issue #338 and its SIBLINGS were not, which is what "+
			"issue #375 closed — Healthcheck was the sibling that turned out to reach the "+
			"host's own session manager. If this one is harmless it belongs in "+
			"unexaminedTopLevelFields with the abuse sentence for why", k)
	}
	sort.Strings(dropped)
	return dropped, nil
}

// refusedTopLevel is every top-level create key refused outright.
//
// Volumes was an inline check in handleCreate until issue #375. Moving it onto a
// list is not tidying: containeridfile_test.go records what an inline check
// costs one level down — ContainerIDFile was refused by a check of its own, so
// every sweep that iterates refusedHostConfig silently skipped it, and the
// case-folding sweep among them.
var refusedTopLevel = []string{"Volumes", "Healthcheck", "MacAddress"}

var topLevelRefusalReason = map[string]string{
	// Unchanged in substance from the inline check this replaces ("snug decides
	// what a container may mount"), with the mechanism named: an anonymous
	// volume is a host path by another name, and the engine — not the client —
	// picks where it lands.
	"Volumes": "an anonymous volume is a host path by another name, allocated in the " +
		"engine's own store rather than named by the client. snug decides what a container " +
		"may mount, and it can only approve a source it was shown (see checkedMounts, " +
		"which resolves and REWRITES every bind rather than validating a string the engine " +
		"will re-resolve)",

	// ISSUE #397, and the field that proves #375 was not a papercut.
	//
	// A healthcheck asks the ENGINE to run, on the HOST user's session manager,
	// as the host uid (libpod/healthcheck_linux.go's createTimer):
	//
	//	systemd-run --user --unit <cid> --on-unit-inactive=<interval> <podman> healthcheck run <cid>
	//
	// A transient unit AND TIMER outside the sandbox — invariant 4, which is not
	// "no daemon" in the sense of process count but "no process the user did not
	// start and no state that survives them". Nothing unschedules it: teardown
	// collapses the engine's pid namespace and the kernel SIGKILLs it, and the
	// container RECORD stays (#174), so no removal ever runs.
	//
	// ── THE INTERVAL IS NOT THE CUT, AND THE OBVIOUS CUT IS INVERTED ──────
	//
	// #397 proposed refusing a non-zero Interval. That would have ADMITTED the
	// unsafe case and REFUSED the only spelling a human would write to opt out.
	// podman's compat handler initialises its own default (30s) and overrides it
	// from the body ONLY when Interval > 0 (containers_create.go). MEASURED
	// against podman 6.0.2 over its own socket, reading back the recorded config:
	//
	//	{"Test":["CMD-SHELL","true"]}           -> Interval 30000000000
	//	{"Test":[...],"Interval":0}             -> Interval 30000000000
	//	{"Test":[...],"Interval":-1} and -999   -> Interval 30000000000
	//	{"Test":["NONE"]}                       -> Interval 30000000000
	//	{"Test":[...],"Interval":1}             -> Interval 1  (1ns, accepted)
	//	{}                                      -> 500, "must define a healthcheck command"
	//
	// Interval is the exact field disableHealthCheckSystemd tests for zero
	// (healthcheck_linux.go: `c.config.HealthCheckConfig.Interval == 0`), and
	// every row carrying a usable Test recorded 30s or 1ns — never 0. So absent,
	// zero AND NEGATIVE all schedule the timer. The switch is the presence of a
	// parseable Test, not the interval.
	//
	// Test:["NONE"] is not a safe spelling either: init()'s createTimer call is
	// gated on HealthCheckConfig != nil with no NONE test — only unpause() checks
	// for NONE — so NONE records 30s and still reaches createTimer.
	//
	// Test itself runs IN THE CONTAINER (healthCheckExec, an exec session), and
	// is deliberately NOT a command table in CLAUDE.md's sense: it never reaches
	// snug's side, the unit name is not client-chosen, and the only client-chosen
	// value in the systemd-run argv is the interval, rendered by
	// time.Duration.String(). That bounds the severity and is worth saying,
	// because "the engine runs a command the client named" would otherwise read
	// as argv injection, which this is not.
	//
	// ── THE BARRIERS TODAY ARE NOT SNUG'S POLICY, WHICH IS THE TICKET ─────
	//
	// #397 drove it against both engines and no unit appeared. There are THREE
	// barriers, not the two it named, and not one of them is a decision:
	//
	//   (a) RunsOnSystemd() stats /run/systemd/system in the ENGINE's own mount
	//       view. NOT "a default sandbox has no /run" — #397's own wording, and
	//       wrong in the direction that matters: the engine's view HAS a /run, a
	//       fresh empty tmpfs graft (internal/cli/engineview.go), and the stat
	//       fails only because nothing was created in it. That is WEAKER than "no
	//       /run at all" — anything that makes one directory in a writable tmpfs
	//       lapses it, and #399 proposes putting per-run state there.
	//   (b) Rootless ConnectToDBUS dials $XDG_RUNTIME_DIR/systemd/private, and
	//       snug repoints the engine's XDG_RUNTIME_DIR at the runroot graft
	//       (internal/engine/engine.go). createTimer calls ConnectToDBUS BEFORE
	//       systemd-run, so this gates it too. #397 did not name this one.
	//   (c) The barrier #397 rested on is already GONE: the pinned bundle's
	//       podman lacked the systemd build tag, and the distribution podman
	//       6.0.2 that #398 made snug resolve has it.
	//
	// systemd-run itself is reachable — PinnedPATH is /usr/bin:/usr/sbin:/bin:/sbin.
	//
	// ── WHAT THIS REFUSAL DOES NOT CLOSE ─────────────────────────────────
	//
	// Refusing the FIELD does not close the MECHANISM, and saying so is the
	// difference between a narrowing and a claimed closure. With no Test in the
	// body, CompleteSpec takes the IMAGE's HEALTHCHECK (specgen/generate) and
	// applyHealthCheckOverrides defaults Interval to the same 30s — so an image
	// declaring HEALTHCHECK produces an identical non-nil HealthCheckConfig and
	// an identical createTimer call with NO Healthcheck key in any create body.
	// The payload can author that image itself: /v1.41/build is allowed.
	//
	// The one barrier that would be snug's OWN policy is DISABLE_HC_SYSTEMD=true
	// in the engine's authored env — disableHealthCheckSystemd returns true on it
	// unconditionally, before RunsOnSystemd and before D-Bus, whatever the
	// healthcheck's origin. That is an engine-env change rather than a proxy one,
	// so it is filed rather than smuggled in here.
	//
	// Refused rather than normalised (standing ruling): normalising Interval
	// would hand back a container whose configured healthcheck silently never
	// runs, with `docker inspect` showing it configured.
	//
	// It costs no ergonomics, MEASURED: docker's Config.Healthcheck is a
	// *HealthConfig with omitempty, so it appears only when a human typed
	// --health-*, and it is absent from testdata/docker-run-create-body.json
	// entirely. Not the LogConfig trap — the clients that ask for nothing do not
	// send the key.
	"Healthcheck": "a healthcheck is SCHEDULED WORK, and the engine schedules it on the " +
		"HOST user's own session manager: podman runs `systemd-run --user --unit <cid> " +
		"--on-unit-inactive=<interval> podman healthcheck run <cid>` " +
		"(libpod/healthcheck_linux.go's createTimer), creating a transient unit and timer as " +
		"your uid that can outlive this sandbox — teardown collapses the engine's pid " +
		"namespace and removes no container, so nothing ever unschedules it. THE INTERVAL IS " +
		"NOT THE CUT: podman overrides its own 30s default only when the body's Interval is " +
		"> 0, so absent, 0 AND NEGATIVE all record 30s — measured on podman 6.0.2, Interval " +
		"0 and Interval -1 both produced Interval=30000000000, which is the exact field " +
		"disableHealthCheckSystemd tests for zero. Test:[\"NONE\"] records the same 30s and " +
		"reaches the same timer. No spelling asks for a healthcheck without asking for the " +
		"timer, which is why the whole field is refused rather than one subfield. THE THINGS " +
		"STOPPING IT TODAY ARE NOT SNUG'S POLICY: the engine's /run is snug's own empty " +
		"tmpfs so the stat of /run/systemd/system fails, and rootless D-Bus dials an " +
		"XDG_RUNTIME_DIR snug repointed at the runroot — both lapse the day a profile grants " +
		"/run or a session bus, and the third barrier, a podman built without the systemd " +
		"tag, is already gone. Refused so that the barrier is a decision rather than a side " +
		"effect. To check a container's health, poll it from inside the sandbox, where the " +
		"work stays",

	// ISSUE #375. The same object as the endpoint MacAddress checkNetworkingConfig
	// refuses — a static hardware address for the interface the container gets —
	// spelled at the top level instead. Refused at BOTH spellings or neither:
	// leaving one open is the "rule applied to one of its two halves" shape this
	// change exists to close.
	//
	// It costs nothing measurable. It is honoured only in bridge mode, and bridge
	// mode cannot start a container in this sandbox at all — MEASURED, netavark is
	// refused the netlink call (`Netlink error: Operation not permitted`) because
	// the engine holds no CAP_NET_ADMIN. docker 29.4 dropped it from Config as
	// deprecated, so it is absent from the recorded body too.
	"MacAddress": "it asks for a static hardware address on the interface the container " +
		"gets, which snug authors: every container runs in this sandbox's own network " +
		"namespace (issue #63, Tier B) and the engine holds no CAP_NET_ADMIN to configure " +
		"one. The same value is refused inside NetworkingConfig.EndpointsConfig, and a " +
		"refusal covering only one of the two spellings would be no refusal at all",
}

// topLevelChecked and topLevelChecks are the top-level keys judged by a function
// rather than by membership: the ones where the VALUE decides, because a real
// client sends the key populated with something that asks for nothing.
//
// This is the LogConfig lesson as a category. {"Type":"","Config":{}} is sent on
// every create and isEmptyJSON does not call it empty, so a denylist entry for
// LogConfig refused every `docker run` there had ever been, with a message about
// log drivers. NetworkingConfig is the same shape at the top level and is the
// object issue #375 was actually filed about.
//
// ── why this is TWO symbols and not one ────────────────────────────────────
//
// A GENUINE Go initialization cycle, not a style choice, and it is worth naming
// because the obvious cleanup reintroduces it:
//
//	canonicalKey -> topLevelChecks -> checkNetworkingConfig -> decodeObject -> canonicalKey
//
// canonicalKey needs these NAMES (a client may spell them in any case, and
// decodeObject canonicalises through that map before any check runs), while the
// checks themselves reach decodeObject. So the names live in a plain []string
// that refers to no function, and canonicalKey derives from THAT.
//
// The split is the kind this lane exists to be suspicious of — one rule in two
// places — so it is closed by assertion rather than by care:
// TestTopLevelChecksAgreeWithTheirKeyList compares the two as SETS in both
// directions, and a key in either alone fails.
var topLevelChecked = []string{"Env", "NetworkingConfig"}

var topLevelChecks = map[string]func(json.RawMessage) error{
	"Env":              checkEnv,
	"NetworkingConfig": checkNetworkingConfig,
}

// checkEnv requires every element to be NAME=VALUE with a non-empty name.
//
// ── Env is NOT "the container's own variables", and that was measured ────────
//
// This was very nearly allowlisted-unexamined on the reasoning that a
// container's environment is the container's business. It is not: podman's
// parseEnv reads a BARE NAME out of the ENGINE's own os.Environ(), and a
// trailing `*` copies every engine variable matching the prefix. `docker run -e
// FOO` (no value) is the documented client spelling for it.
//
// MEASURED through snug's own proxy, inside a real sandbox, against podman
// 6.0.2 — reading back .Config.Env from the created container:
//
//	Env: ["*"]              -> 10 variables copied out of the ENGINE's environment:
//	                           TMPDIR=/snug/engine/runroot/tmp
//	                           HOME=/snug/engine/conf/home
//	                           XDG_RUNTIME_DIR=/snug/engine/runroot
//	                           REGISTRY_AUTH_FILE=/snug/engine/conf/auth.json
//	                           CONTAINERS_{CONF,STORAGE_CONF,REGISTRIES_CONF,CONF_OVERRIDE}=...
//	                           PATH=/usr/bin:/usr/sbin:/bin:/sbin
//	Env: ["SSH_AUTH_SOCK","HOME","PATH"]
//	                        -> HOME and PATH returned verbatim; SSH_AUTH_SOCK
//	                           absent, because snug's authored engine env has
//	                           none — the mechanism worked, the variable was not
//	                           there to take
//	Env: ["CONTAINERS_*"]   -> 4 variables, so the prefix wildcard works too
//	Env: ["FOO=bar"]        -> FOO=bar, and nothing else
//
// ── what it is, and what it is not ──────────────────────────────────────────
//
// NOT a host-credential leak today, and the SSH_AUTH_SOCK row is what says so:
// the environment being read is the one internal/engine AUTHORS, not the host's,
// so there is no token in it to take. What it IS: the engine's process
// environment read out through a container create body — one layer over the
// /proc/1/environ leak CLAUDE.md records — and every value above names THIS
// RUN'S GRAFT LAYOUT. That is the map a -v request navigates by, and the #251
// class is exactly navigation of the grafts.
//
// So it is judged rather than refused: the direction of the leak is snug's own
// paths, not the user's secrets, and a blanket refusal of Env would break every
// `docker run -e`. NAME=VALUE is what every ordinary client sends — Env is null
// in the recorded body — which makes this the LogConfig/RestartPolicy precedent
// again: admit the shape that asks for nothing, refuse the shape that asks.
//
// The refusal names the mechanism rather than saying "malformed", because a
// user who typed `docker run -e FOO` did nothing wrong and needs to be told
// which half is missing.
func checkEnv(raw json.RawMessage) error {
	var env []string
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("Env is not a list of strings: %v", err)
	}
	for _, e := range env {
		name, _, ok := strings.Cut(e, "=")
		if !ok {
			return fmt.Errorf("Env entry %q is not permitted: an entry with no `=` asks the "+
				"ENGINE to copy its OWN environment variable of that name into the container, "+
				"and a trailing `*` copies every one matching the prefix (measured on podman "+
				"6.0.2: Env:[\"*\"] copied 10 variables out of the engine's environment, every "+
				"one of them naming this run's graft paths — the runroot, the config "+
				"directory and the registry auth file). That is snug's own layout read out "+
				"through a create body. Pass NAME=VALUE and the value is yours", e)
		}
		if name == "" {
			return fmt.Errorf("Env entry %q is not permitted: it has an empty variable name", e)
		}
	}
	return nil
}

// checkNetworkingConfig admits an EndpointsConfig that asks for nothing and
// refuses one that asks for anything at all.
//
// ── what #375 leads with, and what it turned out to be ─────────────────────
//
// #375 names NetworkingConfig.EndpointsConfig as "the largest unexamined object"
// — per-network static IPs, aliases, link-local addresses, driver options for
// the netns the container joins — and says outright it is "not measured. No
// route through it has been driven." Measured since, on both engines: inert.
//
// It is judged anyway, and NOT allowlisted with an abuse sentence, because
// "inert on the engine I tried" is a fact about an engine and this is a
// PER-NETWORK CONFIGURATION OBJECT aimed at the one namespace Tier B made the
// containment boundary. NetworkMode is filtered three keys away for reaching
// that subsystem; this reaches it by a different door.
//
// ── no field list, deliberately ────────────────────────────────────────────
//
// Every endpoint field is required to be EMPTY, whatever it is called. There is
// no enumeration of IPAMConfig/Aliases/DriverOpts/MacAddress here, and that is
// the point: this file exists because gating on an enumerated set of known keys
// let an unenumerated sibling through. A test that named the 15 fields docker
// defines today would be a third copy of the same mistake, and podman's 16th
// would arrive unjudged.
//
// ── THE SECOND DOOR, AND WHY THIS LANE DID NOT CLOSE IT ─────────────────────
//
// POST /networks/{id}/connect carries the IDENTICAL object — its body is
// {"Container":"<id>","EndpointConfig":{<EndpointSettings>}} — and allowed()
// returns true for `networks`, so it is forwarded with the body unread. On the
// face of it that is this whole change's own defect one endpoint over: a rule
// applied to one of its two halves.
//
// It is left alone anyway, because the other half is a SETTLED MAINTAINER
// DECISION and not an oversight. TIER-B.md Q5: "the `networks` endpoints are NOT
// special-cased as a hole and carry no refusal list: containment answers it
// structurally … Do not also inject NetworkMode constraints." Adding a filter
// there would be reopening that, which CLAUDE.md calls a maintainer decision
// rather than a refactor.
//
// The two are not actually inconsistent, and the line between them is WHICH
// ENDPOINT rather than which object: Q5 governs the /networks/* routes, while
// the create body has been constrained on exactly this subsystem since Tier B
// (namespaceModeKeys refuses NetworkMode there and Q5 does not ask it to stop).
// So refusing an endpoint that asks for something at CREATE is consistent with
// how create is treated, and it is defence-in-depth rather than the only
// barrier — the same footing refusalReason["Devices"] stands on.
//
// What a reader should take from this: if Q5 is ever revisited, these two doors
// want ONE predicate between them (invariant 6, one author), and this function
// is the half that already exists. Filed for the maintainer rather than decided
// here.
//
// MEASURED, which is what makes it shippable: a stock docker 29.4.0-ce sends
// NetworkingConfig NON-EMPTY on a plain `docker run --rm alpine true` —
// {"EndpointsConfig":{"default":{...15 fields...}}} — and every one of those 15
// is empty by isEmptyJSON (IPAMConfig null, GwPriority 0, NetworkID "", …). So
// "refuse any non-empty endpoint field" admits the real client exactly, and
// refusing the OBJECT for being non-empty would 403 every `docker run`.
func checkNetworkingConfig(raw json.RawMessage) error {
	top, err := decodeObject(raw)
	if err != nil {
		return fmt.Errorf("NetworkingConfig: %v", err)
	}
	for _, k := range sortedKeysOf(top) {
		if k != "EndpointsConfig" {
			if isEmptyJSON(top[k]) {
				continue
			}
			return fmt.Errorf("NetworkingConfig.%s is not permitted: snug reads only "+
				"EndpointsConfig here, and a sibling of it is a field nobody has modelled "+
				"reaching the network namespace this sandbox's containment rests on", k)
		}
		endpoints, err := decodeObject(top[k])
		if err != nil {
			return fmt.Errorf("NetworkingConfig.EndpointsConfig: %v", err)
		}
		for _, netName := range sortedKeysOf(endpoints) {
			if isEmptyJSON(endpoints[netName]) {
				continue
			}
			ep, err := decodeObject(endpoints[netName])
			if err != nil {
				return fmt.Errorf("NetworkingConfig.EndpointsConfig[%q]: %v", netName, err)
			}
			for _, f := range sortedKeysOf(ep) {
				if isEmptyJSON(ep[f]) {
					continue
				}
				return fmt.Errorf("NetworkingConfig.EndpointsConfig[%q].%s is not permitted; "+
					"it asks for %s. snug authors this sandbox's network namespace and every "+
					"container runs in it (issue #63, Tier B), so per-endpoint addressing, "+
					"aliases and driver options are not the client's to choose — a static IP "+
					"or a driver option is a request to reconfigure the one namespace the "+
					"containment rests on. An endpoint that asks for NOTHING is accepted, "+
					"which is what a stock `docker run` sends",
					netName, f, string(ep[f]))
			}
		}
	}
	return nil
}

// unexaminedTopLevelFields is every top-level create field forwarded to the
// engine without its value being looked at, each carrying the abuse sentence for
// why that is safe. It is the top level's half of the shape HostConfig has in
// unexaminedCreateFields and the build query has in unexaminedBuildParams, and
// it exists for the same reason: a field snug does not judge cannot be SILENT
// about it.
//
// Keys are canonical docker spellings; every lookup folds through
// strings.ToLower, because podman folds and snug must agree with podman about
// which field a name is.
//
// Membership is authored one entry at a time and is NOT derived from what a
// client sends. The mistake that would be is on the record twice —
// unexaminedBuildParams' own comment records it for `secrets` and
// `idmappingoptions`, and `secrets` turned out to be a host read that climbed
// out of the build context.
var unexaminedTopLevelFields = map[string]string{
	// ── what the payload chooses about its own container ──────────────────
	"Cmd":         containerProcessChoice,
	"Entrypoint":  containerProcessChoice,
	"Hostname":    containerProcessChoice,
	"Tty":         containerProcessChoice,
	"OpenStdin":   containerProcessChoice,
	"StopSignal":  containerProcessChoice,
	"StopTimeout": containerProcessChoice,

	// ── resolved by the ENGINE, inside this container's own rootfs ────────
	"Image":      resolvedInsideTheContainerRootfs,
	"WorkingDir": resolvedInsideTheContainerRootfs,
	"User":       resolvedInsideTheContainerRootfs,

	// ── metadata, and only because of what is refused beside it ───────────
	"ExposedPorts": exposedPortMetadata,

	// ── the honest class: read NOWHERE by the engine measured ─────────────
	"AttachStdin":     unreadByThisEngine,
	"AttachStdout":    unreadByThisEngine,
	"AttachStderr":    unreadByThisEngine,
	"StdinOnce":       unreadByThisEngine,
	"Domainname":      unreadByThisEngine,
	"NetworkDisabled": unreadByThisEngine,
	"ArgsEscaped":     unreadByThisEngine,
	"OnBuild":         unreadByThisEngine,
	"Shell":           unreadByThisEngine,
	"Name":            unreadByThisEngine,
}

// The abuse sentences for the create body's top level, written per CLASS so the
// claim a reader has to judge is one paragraph rather than one per field — the
// same reasoning unexaminedCreateFields' own constants carry.
//
// NOTE WHICH FIELDS ARE NOT HERE, because two of them nearly were. `Env` looked
// like the most obvious member of containerProcessChoice and is JUDGED instead:
// a bare name in it copies a variable out of the ENGINE's environment
// (checkEnv's measurement). `MacAddress` looked like harmless metadata and is
// REFUSED: it is the same object as an endpoint field checkNetworkingConfig
// already refuses. Both were caught by asking what the engine does with the
// value rather than what the field is called.
const (
	// The claim is "its own container", and Cmd/Entrypoint naming programs is
	// deliberately NOT a command table in CLAUDE.md's sense: a command table is
	// a file a TOOL interprets, whose danger is that snug supplies commands to
	// something the payload did not choose. This is the payload naming its own
	// argv, and it already has a shell in the sandbox.
	containerProcessChoice = "A hostile process inside the sandbox can use these to choose " +
		"what runs inside its own container, what that container calls itself, how its " +
		"terminal and stdin behave, and which signal a stop request delivers. None names a " +
		"host path, selects a namespace, or reaches a resource on snug's side of the proxy: " +
		"Entrypoint and Cmd become the container's argv, StopSignal is delivered to the " +
		"container's own pid 1, and StopTimeout bounds the client's own stop request. The " +
		"payload already has a shell in the sandbox, so naming its own container's command " +
		"grants it nothing it did not have — and which MOUNTS that command can see is " +
		"decided by checkedMounts, not here. The network the hostname resolves ON is the " +
		"sandbox's own namespace N, which snug authors and no value here can change."

	// This class exists because the honest sentence for these three is NOT
	// "in-container only" — the engine touches the host filesystem for each of
	// them, and a sentence claiming otherwise would be the kind of comment
	// CLAUDE.md warns is wrong when written. What bounds them is WHERE: inside
	// this container's rootfs, inside this run's store.
	resolvedInsideTheContainerRootfs = "A hostile process inside the sandbox can use these to " +
		"name an image, a working directory and a user for its own container. Each is " +
		"resolved by the ENGINE rather than in the container, which is why they are named " +
		"together and not called in-container: Image is a store lookup (LookupImage) and can " +
		"never be read as a host directory from a docker-compat body, because the compat " +
		"handler never sets rootfs mode; WorkingDir causes a host-side MkdirAll that " +
		"SecureJoin confines to this container's own rootfs inside this run's store, or, when " +
		"the path falls on a mount, is bounded by the bind checkOne already approved at the " +
		"access it approved; User causes a host-side read of /etc/passwd inside that same " +
		"rootfs. So each one reaches the filesystem, and each is confined to material this " +
		"run already owns."

	// The one sentence in this file whose truth DEPENDS on another refusal, so
	// it names it. If PublishAllPorts or PortBindings ever stops being refused,
	// this stops being metadata and nothing here would notice.
	exposedPortMetadata = "A hostile process inside the sandbox can use this to declare which " +
		"ports its own container exposes. It is metadata and reaches nothing — but only " +
		"because of what is refused beside it: Expose becomes publish requests ONLY when " +
		"PublishExposedPorts is set, which comes from HostConfig.PublishAllPorts, and that " +
		"field and PortBindings are both on refusedHostConfig. THIS SENTENCE IS CONDITIONAL " +
		"ON THAT. If either is ever allowed, ExposedPorts is a third spelling of publishing " +
		"and belongs out of this map."

	// build.go's notYetAnalysed says "nobody has established what". This says
	// something stronger and more perishable: somebody DID look, and the engine
	// measured does not read the field at all. That is a claim about a VERSION,
	// so it dates — which is exactly why these are allowlisted with a named
	// measurement rather than folded into a behavioural class whose sentence
	// would outlive its evidence.
	//
	// Name is stronger than unread and worth its own line: the compat handler
	// does `body.Name = query.Name`, OVERWRITING it, so a rule judging the body's
	// Name would be judging a string podman discards. A name rule belongs on the
	// query string.
	unreadByThisEngine = "A hostile process inside the sandbox can use these to ___ — and the " +
		"answer measured against podman 6.0.2's docker-compat create handler is that it does " +
		"not read them at all (grepped per name; of this group only OpenStdin and Tty are " +
		"read, and they are classed elsewhere). Name is stronger still: the handler " +
		"overwrites it from the query string, so the body's value is discarded. UNREAD BY " +
		"THIS VERSION IS NOT HARMLESS, and that is why these carry a named claim about a " +
		"measured engine rather than a behavioural sentence that would outlive its evidence: " +
		"the day podman starts reading one, it needs judging, and this sentence is what a " +
		"reader has to come back to."
)

// judgedTopLevelField reports whether checkTopLevel or handleCreate itself
// decides on a top-level key.
//
// DERIVED rather than written out, so a key added to refusedTopLevel or
// topLevelChecks does not also have to be remembered here — the same reason
// judgedCreateField is derived one level down. The two written names are the
// ones no list already holds: HostConfig is decided by the whole of
// handleCreate's steps 2-7, and Labels is read and rewritten by stampRunLabel.
var judgedTopLevelField = func() map[string]bool {
	m := map[string]bool{}
	add := func(names ...string) {
		for _, n := range names {
			m[strings.ToLower(n)] = true
		}
	}
	add(refusedTopLevel...)
	add(topLevelChecked...)
	add("HostConfig", "Labels")
	return m
}()

// unexaminedTopLevelField is the folded index of unexaminedTopLevelFields, built
// once — decodeObject canonicalises a client's spelling through canonicalKey,
// but this is what the sweep consults, so the two agree on a name whatever case
// it arrived in.
var unexaminedTopLevelField = func() map[string]bool {
	m := make(map[string]bool, len(unexaminedTopLevelFields))
	for k := range unexaminedTopLevelFields {
		m[strings.ToLower(k)] = true
	}
	return m
}()

// sortedKeysOf iterates a map in a stable order.
//
// Not a convenience: every loop above can produce a REFUSAL, and map order is
// random, so without this a body with two offending fields would be refused for
// a different one run to run. An error message that changes between identical
// requests is one nobody can act on — the same reasoning decodeObject's own
// sort carries.
func sortedKeysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
