package dockerproxy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/gomoni/snug/internal/policy"
)

// libpodcreate_test.go pins issue #459 phase 2: podman's own
// POST /libpod/containers/create body, read against libpodcreate.go's
// catalogue. Every body below is either the MEASURED plain-run baseline
// (captured against a real podman 6.0.2 CLI posting to a logging unix
// socket, VERIFY.md §22's method) or that baseline with one field changed to
// the value the SAME CLI was measured sending for the named flag.

// libpodPlainRunBody is `podman run --rm docker.io/library/alpine:3.20 true`
// on the wire, byte for byte — MEASURED, minus containerCreateCommand (an
// echo of the client's own argv, irrelevant to every case below) and with
// remove/volatile normalised to what --rm sends, since the variants this
// file diffs against were captured WITHOUT --rm.
const libpodPlainRunBody = `{
 "Networks": null,
 "cgroupns": {},
 "command": ["true"],
 "env_host": false,
 "healthLogDestination": "local",
 "healthMaxLogCount": 5,
 "healthMaxLogSize": 500,
 "healthconfig": {},
 "httpproxy": true,
 "idmappings": {"AutoUserNs": false, "AutoUserNsOpts": {}, "GIDMap": null, "HostGIDMapping": true, "HostUIDMapping": true, "UIDMap": null},
 "image": "docker.io/library/alpine:3.20",
 "image_volume_mode": "anonymous",
 "init": false,
 "init_container_type": "",
 "ipcns": {},
 "log_configuration": {},
 "manage_password": true,
 "netns": {},
 "pidns": {},
 "privileged": false,
 "publish_image_ports": false,
 "raw_image_name": "docker.io/library/alpine:3.20",
 "read_only_filesystem": false,
 "read_write_tmpfs": false,
 "remove": true,
 "sdnotifyMode": "container",
 "seccomp_policy": "default",
 "stdin": false,
 "stop_timeout": 10,
 "systemd": "true",
 "terminal": false,
 "umask": "0022",
 "unsetenvall": false,
 "use_image_hostname": false,
 "use_image_hosts": false,
 "use_image_resolve_conf": false,
 "userns": {},
 "utsns": {},
 "volatile": true
}`

func TestPlainLibpodRunReachesTheEngine(t *testing.T) {
	sock, eng, _ := startProxy(t)
	before := eng.reached.Load()
	code, resp := post(t, sock, "/v6.0.2/libpod/containers/create", libpodPlainRunBody)
	if code != 200 && code != 201 {
		t.Fatalf("status %d, want 2xx: %s", code, resp)
	}
	if eng.reached.Load() == before {
		t.Fatal("the plain-run body never reached the engine")
	}
}

// withLibpodField returns libpodPlainRunBody with one top-level field
// replaced (as raw JSON) or removed (rawJSON == "").
func withLibpodField(t *testing.T, field, rawJSON string) string {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(libpodPlainRunBody), &m); err != nil {
		t.Fatal(err)
	}
	if rawJSON == "" {
		delete(m, field)
	} else {
		m[field] = json.RawMessage(rawJSON)
	}
	enc, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(enc)
}

func TestLibpodRefusedFieldsFailClosed(t *testing.T) {
	sock, eng, _ := startProxy(t)

	cases := []struct {
		name, field, value, wantMsg string
	}{
		{"privileged", "privileged", "true", "privileged is not permitted"},
		{"cap_add", "cap_add", `["ALL"]`, "cap_add is not permitted"},
		{"devices", "devices", `[{"path":"/dev/null","major":0,"minor":0,"type":""}]`, "devices is not permitted"},
		{"device_cgroup_rule", "device_cgroup_rule",
			`[{"allow":true,"type":"c","major":1,"minor":1,"access":"rwm"}]`,
			"device_cgroup_rule is not permitted"},
		{"cgroup_parent", "cgroup_parent", `"/foo"`, "cgroup_parent is not permitted"},
		{"sysctl", "sysctl", `{"net.ipv4.ip_forward":"1"}`, "sysctl is not permitted"},
		{"hostadd", "hostadd", `["foo:1.2.3.4"]`, "hostadd is not permitted"},
		{"portmappings", "portmappings",
			`[{"host_ip":"","container_port":80,"host_port":8080,"range":1,"protocol":""}]`,
			"portmappings is not permitted"},
		{"publish_image_ports", "publish_image_ports", "true", "publish_image_ports"},
		{"weightDevice", "weightDevice",
			`{"/dev/null":{"major":0,"minor":0,"weight":100}}`, "weightDevice is not permitted"},
		{"volumes", "volumes",
			`[{"Name":"myvol","Dest":"/data","IsAnonymous":false}]`, "volumes is not permitted"},
		{"healthconfig", "healthconfig",
			`{"Test":["CMD-SHELL","true"],"Interval":30000000000,"Timeout":30000000000,"Retries":3}`,
			"healthconfig is not permitted"},
		{"seccomp_profile_path", "seccomp_profile_path", `"unconfined"`, "seccomp_profile_path is not permitted"},
		{"apparmor_profile", "apparmor_profile", `"unconfined"`, "apparmor_profile is not permitted"},
		{"no_new_privileges false", "no_new_privileges", "false", "no_new_privileges = false is not permitted"},
		{"env_host", "env_host", "true", "env_host = true is not permitted"},
		{"envmerge", "envmerge", `["FOO=bar"]`, "envmerge is not permitted"},
		{"unsetenv", "unsetenv", `["FOO"]`, "unsetenv is not permitted"},
		{"unsetenvall", "unsetenvall", "true", "unsetenvall = true is not permitted"},
		{"timezone local", "timezone", `"local"`, `"local" is not permitted`},
		{"seccomp_policy", "seccomp_policy", `"empty"`, "seccomp_policy = \"empty\" is not permitted"},
		{"restart_policy", "restart_policy", `"always"`, "restart_policy = \"always\" is not permitted"},
		{"restart_tries", "restart_tries", "3", "restart_tries = 3 is not permitted"},
		{"healthLogDestination", "healthLogDestination", `"/etc"`, "healthLogDestination"},
		{"healthMaxLogCount", "healthMaxLogCount", "9", "healthMaxLogCount = 9"},
		{"healthMaxLogSize", "healthMaxLogSize", "9", "healthMaxLogSize = 9"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := withLibpodField(t, tc.field, tc.value)
			refuse(t, sock, eng, "/v6.0.2/libpod/containers/create", body, tc.wantMsg)
		})
	}
}

// TestLibpodTimezoneAcceptsAnyZoneButLocal is the positive half of the
// timezone case above: an IANA zone is container-internal and must not be
// refused just because "local" (the ONE value that bind-mounts a host file)
// is.
func TestLibpodTimezoneAcceptsAnyZoneButLocal(t *testing.T) {
	sock, eng, _ := startProxy(t)
	before := eng.reached.Load()
	body := withLibpodField(t, "timezone", `"America/New_York"`)
	code, resp := post(t, sock, "/v6.0.2/libpod/containers/create", body)
	if code != 200 && code != 201 {
		t.Fatalf("status %d, want 2xx: %s", code, resp)
	}
	if eng.reached.Load() == before {
		t.Fatal("a plain IANA zone name was refused; it should have reached the engine")
	}
}

func TestLibpodNamespaceModesShareTheDockerCompatJudge(t *testing.T) {
	sock, eng, _ := startProxy(t)

	t.Run("network host is this sandbox's own netns", func(t *testing.T) {
		before := eng.reached.Load()
		body := withLibpodField(t, "netns", `{"nsmode":"host"}`)
		code, resp := post(t, sock, "/v6.0.2/libpod/containers/create", body)
		if code != 200 && code != 201 {
			t.Fatalf("status %d, want 2xx: %s", code, resp)
		}
		if eng.reached.Load() == before {
			t.Fatal("network host should reach the engine, same as docker-compat's NetworkMode=host")
		}
	})

	refusals := []struct{ field, value, wantMsg string }{
		{"netns", `{"nsmode":"bridge"}`, "netns.nsmode"},
		{"netns", `{"nsmode":"none"}`, "netns.nsmode"},
		{"netns", `{"nsmode":"private"}`, "netns.nsmode"},
		{"netns", `{"nsmode":"container","value":"deadbeef"}`, "netns.nsmode"},
		{"pidns", `{"nsmode":"host"}`, "pidns.nsmode"},
		{"pidns", `{"nsmode":"container","value":"deadbeef"}`, "pidns.nsmode"},
		{"ipcns", `{"nsmode":"host"}`, "ipcns.nsmode"},
		{"utsns", `{"nsmode":"host"}`, "utsns.nsmode"},
		{"userns", `{"nsmode":"host"}`, "userns.nsmode"},
		{"cgroupns", `{"nsmode":"host"}`, "cgroupns.nsmode"},
	}
	for _, tc := range refusals {
		t.Run(tc.field+"="+tc.value, func(t *testing.T) {
			body := withLibpodField(t, tc.field, tc.value)
			refuse(t, sock, eng, "/v6.0.2/libpod/containers/create", body, tc.wantMsg)
		})
	}

	// The DENYLIST five must still forward an ordinary value that is none of
	// "host"/"container"/"path" — the same convergence
	// TestJudgeNamespaceModeOtherFiveAreADenylist pins at the unit level, run
	// here through a full request.
	t.Run("ipc shareable is forwarded, not refused", func(t *testing.T) {
		before := eng.reached.Load()
		body := withLibpodField(t, "ipcns", `{"nsmode":"shareable"}`)
		code, resp := post(t, sock, "/v6.0.2/libpod/containers/create", body)
		if code != 200 && code != 201 {
			t.Fatalf("status %d, want 2xx: %s", code, resp)
		}
		if eng.reached.Load() == before {
			t.Fatal("ipcns shareable should reach the engine")
		}
	})
}

// TestLibpodNetworksIsJudgedIndependentlyOfNetns is the MEASURED gap that
// makes Networks its own check rather than folded into the namespace-mode
// judge: `--ip 10.0.0.5` sets a static IP on the default network while netns
// stays absent, so a namespace-mode-only check would miss it entirely.
func TestLibpodNetworksIsJudgedIndependentlyOfNetns(t *testing.T) {
	sock, eng, _ := startProxy(t)
	body := withLibpodField(t, "Networks",
		`{"default":{"static_ips":["10.0.0.5"],"interface_name":""}}`)
	refuse(t, sock, eng, "/v6.0.2/libpod/containers/create", body, "Networks")
}

func TestLibpodIdMappingsReusesTheBuildQueryJudge(t *testing.T) {
	sock, eng, _ := startProxy(t)
	body := withLibpodField(t, "idmappings", `{"AutoUserNs":true}`)
	refuse(t, sock, eng, "/v6.0.2/libpod/containers/create", body, "idmappings")
}

func TestLibpodImageTransportIsRefusedLikeImagesPull(t *testing.T) {
	sock, eng, _ := startProxy(t)
	body := withLibpodField(t, "image", `"dir:/etc"`)
	refuse(t, sock, eng, "/v6.0.2/libpod/containers/create", body, "IMPORT wearing a pull")
}

func TestLibpodAnnotationsRefusesTheUnmeasuredAndCrossChecksTheKnown(t *testing.T) {
	sock, eng, _ := startProxy(t)

	t.Run("unrecognised annotation refuses", func(t *testing.T) {
		body := withLibpodField(t, "annotations", `{"run.oci.keep_original_groups":"1"}`)
		refuse(t, sock, eng, "/v6.0.2/libpod/containers/create", body, "annotations")
	})

	t.Run("seccomp annotation always refuses", func(t *testing.T) {
		body := withLibpodField(t, "annotations", `{"io.podman.annotations.seccomp":"unconfined"}`)
		refuse(t, sock, eng, "/v6.0.2/libpod/containers/create", body, "annotations")
	})

	t.Run("userns annotation must match the judged mode", func(t *testing.T) {
		var m map[string]json.RawMessage
		if err := json.Unmarshal([]byte(libpodPlainRunBody), &m); err != nil {
			t.Fatal(err)
		}
		m["userns"] = json.RawMessage(`{"nsmode":"keep-id"}`)
		m["annotations"] = json.RawMessage(`{"io.podman.annotations.userns":"auto"}`)
		enc, _ := json.Marshal(m)
		refuse(t, sock, eng, "/v6.0.2/libpod/containers/create", string(enc), "does not match the judged")
	})

	t.Run("userns annotation matching the judged mode is accepted", func(t *testing.T) {
		var m map[string]json.RawMessage
		if err := json.Unmarshal([]byte(libpodPlainRunBody), &m); err != nil {
			t.Fatal(err)
		}
		m["userns"] = json.RawMessage(`{"nsmode":"keep-id"}`)
		m["annotations"] = json.RawMessage(`{"io.podman.annotations.userns":"keep-id"}`)
		enc, _ := json.Marshal(m)
		before := eng.reached.Load()
		code, resp := post(t, sock, "/v6.0.2/libpod/containers/create", string(enc))
		if code != 200 && code != 201 {
			t.Fatalf("status %d, want 2xx: %s", code, resp)
		}
		if eng.reached.Load() == before {
			t.Fatal("a userns annotation matching the judged mode should reach the engine")
		}
	})
}

// TestLibpodMountsShareCheckOneWithDockerCompat is invariant 6's whole
// point, run at the request level: the SAME visibility rule refuses an
// invisible bind and the SAME rewrite forwards a resolved path, regardless
// of which wire asked.
func TestLibpodMountsShareCheckOneWithDockerCompat(t *testing.T) {
	sock, eng, target := startProxy(t)

	t.Run("a path the sandbox cannot see is refused", func(t *testing.T) {
		body := withLibpodField(t, "mounts",
			`[{"type":"bind","source":"/etc","destination":"/host-etc"}]`)
		refuse(t, sock, eng, "/v6.0.2/libpod/containers/create", body, "cannot see /etc")
	})

	t.Run("a granted path is forwarded, resolved", func(t *testing.T) {
		before := eng.reached.Load()
		body := withLibpodField(t, "mounts",
			`[{"type":"bind","source":"`+target+`","destination":"/proj"}]`)
		code, resp := post(t, sock, "/v6.0.2/libpod/containers/create", body)
		if code != 200 && code != 201 {
			t.Fatalf("status %d, want 2xx: %s", code, resp)
		}
		if eng.reached.Load() == before {
			t.Fatal("a granted bind should reach the engine")
		}
		if !strings.Contains(eng.lastBody.Load().(string), target) {
			t.Errorf("forwarded body does not carry the resolved source: %s", eng.lastBody.Load())
		}
	})

	t.Run("a volume-typed mount refuses; only bind and tmpfs are permitted", func(t *testing.T) {
		body := withLibpodField(t, "mounts",
			`[{"type":"volume","source":"myvol","destination":"/data"}]`)
		refuse(t, sock, eng, "/v6.0.2/libpod/containers/create", body, "only bind and tmpfs are")
	})

	t.Run("a tmpfs mount is forwarded unexamined", func(t *testing.T) {
		before := eng.reached.Load()
		body := withLibpodField(t, "mounts",
			`[{"type":"tmpfs","source":"tmpfs","destination":"/scratch"}]`)
		code, resp := post(t, sock, "/v6.0.2/libpod/containers/create", body)
		if code != 200 && code != 201 {
			t.Fatalf("status %d, want 2xx: %s", code, resp)
		}
		if eng.reached.Load() == before {
			t.Fatal("a tmpfs mount should reach the engine")
		}
	})
}

// TestLibpodBindOptionsAreForwardedCanonicalRatherThanCopied is issue #459's
// fix, pinned on the accepting path rather than only the refusing one: a
// legitimate options array reaches the engine REBUILT from judgeBindOptions'
// return, not copied through unchanged. "rw" and "" are the default and
// judgeBindOptions never spells them back, so the forwarded body must not
// carry the literal string "rw" the client sent — a future refactor that
// validates m.Options but then forwards the ORIGINAL array on success (rather
// than the rebuilt one judgeLibpodMounts assigns back into m.Options today)
// would still refuse every case TestBindOptionSmugglingRefusedOnBothWires
// covers, since judgeBindOptions itself still errors on those, and would only
// show up here, in what actually reaches the engine on a request that is
// accepted.
func TestLibpodBindOptionsAreForwardedCanonicalRatherThanCopied(t *testing.T) {
	sock, eng, target := startProxy(t)
	body := withLibpodField(t, "mounts",
		`[{"type":"bind","source":"`+target+`","destination":"/src","options":["rw","ro","z"]}]`)
	code, resp := post(t, sock, "/v6.0.2/libpod/containers/create", body)
	if code != 200 && code != 201 {
		t.Fatalf("status %d, want 2xx: %s", code, resp)
	}
	sent, _ := eng.lastBody.Load().(string)
	if !strings.Contains(sent, `"options":["ro","z"]`) {
		t.Errorf("forwarded mount options are not the canonical [\"ro\",\"z\"]: %s", sent)
	}
	if strings.Contains(sent, `"rw"`) {
		t.Errorf("the client's \"rw\" was forwarded verbatim instead of being rebuilt away: %s", sent)
	}
}

// TestLibpodUnmodelledFieldFailsClosed is the whole point of this file's own
// design comment: a field this catalogue has never heard of refuses rather
// than forwarding unread, whether or not it happens to be dangerous.
func TestLibpodUnmodelledFieldFailsClosed(t *testing.T) {
	sock, eng, _ := startProxy(t)
	body := withLibpodField(t, "a_field_podman_added_tomorrow", `"anything"`)
	refuse(t, sock, eng, "/v6.0.2/libpod/containers/create", body,
		"is not permitted. snug reads a named set")
}

// TestLibpodEmptyUnmodelledFieldIsDroppedNotForwarded is #338's own lesson
// applied to the libpod catalogue: an unmodelled field that asks for
// NOTHING is dropped and audited, not refused — otherwise a podman client
// that pads its body with a zero-valued field snug has never heard of would
// 403 a request that asked for nothing new.
func TestLibpodEmptyUnmodelledFieldIsDroppedNotForwarded(t *testing.T) {
	var audited string
	sock, eng, _ := startProxyAudited(t, policy.PodmanSocket, func(msg string) { audited += msg + "\n" })
	before := eng.reached.Load()
	body := withLibpodField(t, "a_field_podman_added_tomorrow", `""`)
	code, resp := post(t, sock, "/v6.0.2/libpod/containers/create", body)
	if code != 200 && code != 201 {
		t.Fatalf("status %d, want 2xx: %s", code, resp)
	}
	if eng.reached.Load() == before {
		t.Fatal("an empty unmodelled field should not refuse the whole request")
	}
	if strings.Contains(eng.lastBody.Load().(string), "a_field_podman_added_tomorrow") {
		t.Errorf("the dropped field was forwarded anyway: %s", eng.lastBody.Load())
	}
	if !strings.Contains(audited, "a_field_podman_added_tomorrow") {
		t.Errorf("the drop was silent; invariant 5 forbids that. audit log: %q", audited)
	}
}

func TestLibpodLabelsAreStampedWithTheRunLabel(t *testing.T) {
	sock, eng, _ := startProxy(t)
	code, resp := post(t, sock, "/v6.0.2/libpod/containers/create", libpodPlainRunBody)
	if code != 200 && code != 201 {
		t.Fatalf("status %d, want 2xx: %s", code, resp)
	}
	if !strings.Contains(eng.lastBody.Load().(string), `"snug.run":"test"`) {
		t.Errorf("run label not stamped into libpod labels: %s", eng.lastBody.Load())
	}
}

func TestLibpodNoNewPrivilegesIsForcedRegardlessOfClient(t *testing.T) {
	sock, eng, _ := startProxy(t)
	code, resp := post(t, sock, "/v6.0.2/libpod/containers/create", libpodPlainRunBody)
	if code != 200 && code != 201 {
		t.Fatalf("status %d, want 2xx: %s", code, resp)
	}
	if !strings.Contains(eng.lastBody.Load().(string), `"no_new_privileges":true`) {
		t.Errorf("no_new_privileges:true was not injected: %s", eng.lastBody.Load())
	}
}
