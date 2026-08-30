package dockerproxy

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// ── named volumes (issue #464) ──────────────────────────────────────────────

// volumeInspectAnswer builds the engine's answer to GET /volumes/{name}. The
// shape is the measured one, podman 6.0.2:
//
//	{"CreatedAt":"...","Driver":"local","Labels":{},
//	 "Mountpoint":"/tmp/s459/root/volumes/NAMEDVOL/_data","Name":"NAMEDVOL",
//	 "Options":{},"Scope":"local"}
func volumeInspectAnswer(driver string, options, labels map[string]string) func(string) (int, string) {
	return func(ref string) (int, string) {
		b, _ := json.Marshal(map[string]any{
			"Name":    ref,
			"Driver":  driver,
			"Options": options,
			"Labels":  labels,
		})
		return 200, string(b)
	}
}

func plainVolume() func(string) (int, string) {
	return volumeInspectAnswer("local", map[string]string{}, map[string]string{})
}

// TestAHostBindVolumeIsRefusedByName is the finding this whole file exists for,
// and the measurement is what makes the check load-bearing rather than tidy.
//
// MEASURED, podman 6.0.2, isolated store:
//
//	podman volume create --opt type=none --opt o=bind --opt device=/home/<u>/.ssh EVIL
//	GET /v1.41/volumes/EVIL
//	  {"Driver":"local", ...,
//	   "Options":{"device":"/home/<u>/.ssh","o":"bind","type":"none"}}
//	podman run --rm -v EVIL:/x alpine ls /x
//	  -> the host's private keys, listed
//
// READ THE DRIVER. It is still "local", so a driver check alone clears that
// volume; the OPTIONS are what separate it from an ordinary one. handleVolumeCreate
// refuses those options — but it governs only volumes created through this proxy,
// and the engine store is shared with every later run and with any host process
// using the same --root, so the check has to happen at USE time.
func TestAHostBindVolumeIsRefusedByName(t *testing.T) {
	evil := volumeInspectAnswer("local", map[string]string{
		"type": "none", "o": "bind", "device": "/home/u/.ssh",
	}, map[string]string{})

	for _, tc := range []struct{ name, body string }{
		{"the compat Binds spelling",
			`{"HostConfig":{"Binds":["EVIL:/x"]}}`},
		{"the compat structured spelling",
			`{"HostConfig":{"Mounts":[{"Type":"volume","Source":"EVIL","Target":"/x"}]}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sock, rec := startRecordedWith(t, "snug.run=1234", &recorder{volumeInspect: evil})
			before := rec.requests.Load() - rec.inspects.Load()
			code, resp := do(t, sock, http.MethodPost, "/v1.41/containers/create", tc.body)
			if code != http.StatusForbidden {
				t.Fatalf("status %d, want 403: %s", code, resp)
			}
			if msg := denyMessage(resp); !strings.Contains(msg, "local-driver options") {
				t.Errorf("refused, but not for the options: %s", msg)
			}
			if rec.requests.Load()-rec.inspects.Load() != before {
				t.Errorf("the create reached the engine: %v", rec.seen())
			}
		})
	}

	t.Run("the libpod volumes[] spelling", func(t *testing.T) {
		sock, rec := startRecordedWith(t, "snug.run=1234", &recorder{volumeInspect: evil})
		before := rec.requests.Load() - rec.inspects.Load()
		code, resp := do(t, sock, http.MethodPost, "/v6.0.2/libpod/containers/create",
			`{"image":"alpine","volumes":[{"Name":"EVIL","Dest":"/x"}]}`)
		if code != http.StatusForbidden {
			t.Fatalf("status %d, want 403: %s", code, resp)
		}
		if rec.requests.Load()-rec.inspects.Load() != before {
			t.Errorf("the create reached the engine: %v", rec.seen())
		}
	})
}

// TestTheVolumeGateFailsClosed. Every direction: a name the engine does not
// know, a non-local driver, and an answer that does not name the volume snug
// asked about. The last one matters most — an engine answer snug did not
// understand is not a pass, and reading it as one is how a check that looks
// present forwards everything.
func TestTheVolumeGateFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name    string
		inspect func(string) (int, string)
		wantMsg string
	}{
		{"the engine does not know the name",
			func(string) (int, string) { return 404, `{"message":"no such volume"}` },
			"could not confirm what volume"},
		{"a driver that resolves the name somewhere snug cannot see",
			volumeInspectAnswer("nfs", map[string]string{}, map[string]string{}),
			`reports the driver "nfs"`},
		{"an EMPTY driver, which is an answer snug did not understand",
			volumeInspectAnswer("", map[string]string{}, map[string]string{}),
			`reports the driver ""`},
		{"an answer naming a different volume",
			func(string) (int, string) { return 200, `{"Name":"other","Driver":"local"}` },
			"which is not the volume snug asked about"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sock, rec := startRecordedWith(t, "snug.run=1234", &recorder{volumeInspect: tc.inspect})
			before := rec.requests.Load() - rec.inspects.Load()
			code, resp := do(t, sock, http.MethodPost, "/v1.41/containers/create",
				`{"HostConfig":{"Binds":["myvol:/x"]}}`)
			if code != http.StatusForbidden {
				t.Fatalf("status %d, want 403: %s", code, resp)
			}
			if msg := denyMessage(resp); !strings.Contains(msg, tc.wantMsg) {
				t.Errorf("refused, but not for the reason this case exists to test.\n"+
					"  want the message to contain: %q\n  got: %s", tc.wantMsg, msg)
			}
			if rec.requests.Load()-rec.inspects.Load() != before {
				t.Errorf("the create reached the engine: %v", rec.seen())
			}
		})
	}
}

// TestAnOrdinaryNamedVolumeWorks is the ergonomics half — the whole point of
// issue #464 — and without it every assertion above is satisfied by a proxy
// that refuses named volumes exactly as it did before.
func TestAnOrdinaryNamedVolumeWorks(t *testing.T) {
	for _, tc := range []struct{ name, path, body string }{
		{"`docker run -v myvol:/data`", "/v1.41/containers/create",
			`{"HostConfig":{"Binds":["myvol:/data"]}}`},
		{"`docker run -v myvol:/data:ro`", "/v1.41/containers/create",
			`{"HostConfig":{"Binds":["myvol:/data:ro"]}}`},
		{"`docker run --mount type=volume,...`", "/v1.41/containers/create",
			`{"HostConfig":{"Mounts":[{"Type":"volume","Source":"myvol","Target":"/data"}]}}`},
		{"`podman run -v NAMEDVOL:/data`, the measured libpod shape",
			"/v6.0.2/libpod/containers/create",
			`{"image":"alpine","volumes":[{"Name":"NAMEDVOL","Dest":"/data","Options":null,"IsAnonymous":false,"SubPath":""}]}`},
		{"`podman run -v NAMEDVOL:/ro:ro`", "/v6.0.2/libpod/containers/create",
			`{"image":"alpine","volumes":[{"Name":"NAMEDVOL","Dest":"/ro","Options":["ro"]}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sock, rec := startRecordedWith(t, "snug.run=1234", &recorder{volumeInspect: plainVolume()})
			before := rec.requests.Load() - rec.inspects.Load()
			code, resp := do(t, sock, http.MethodPost, tc.path, tc.body)
			if code != http.StatusOK {
				t.Fatalf("status %d, want 200: %s", code, resp)
			}
			if rec.requests.Load()-rec.inspects.Load() == before {
				t.Error("the create did not reach the engine, so this proves nothing about " +
					"a named volume being usable")
			}
		})
	}
}

// TestAnAnonymousVolumeIsStillRefused. The payload is the MEASURED one and the
// comment is the reason this is a separate test: `-v /anon` sends an empty Name
// with `IsAnonymous: FALSE` beside it, so a check written on IsAnonymous would
// forward every anonymous volume while looking like it refused them.
func TestAnAnonymousVolumeIsStillRefused(t *testing.T) {
	sock, rec := startRecordedWith(t, "snug.run=1234", &recorder{volumeInspect: plainVolume()})
	before := rec.requests.Load() - rec.inspects.Load()
	code, resp := do(t, sock, http.MethodPost, "/v6.0.2/libpod/containers/create",
		`{"image":"alpine","volumes":[{"Name":"","Dest":"/anon","Options":null,"IsAnonymous":false,"SubPath":""}]}`)
	if code != http.StatusForbidden {
		t.Fatalf("status %d, want 403: %s", code, resp)
	}
	if rec.requests.Load()-rec.inspects.Load() != before {
		t.Errorf("the create reached the engine: %v", rec.seen())
	}
}

// TestAVolumeNameIsNotAPath. A source that is neither an absolute path nor a
// name refuses, and `..` must land there rather than in the volume gate: a `..`
// reaching the engine as a NAME would be resolved relative to its store.
func TestAVolumeNameIsNotAPath(t *testing.T) {
	for _, s := range []string{"..", "../..", "a/b", ".hidden", "-flag", "vol name", "vol$", ""} {
		if isVolumeName(s) {
			t.Errorf("isVolumeName(%q) = true; podman's own rule is [a-zA-Z0-9][a-zA-Z0-9_.-]*", s)
		}
	}
	for _, s := range []string{"myvol", "NAMEDVOL", "my-vol_1.2", "0"} {
		if !isVolumeName(s) {
			t.Errorf("isVolumeName(%q) = false; this is a name podman accepts", s)
		}
	}
}

// TestVolumeCreateStampsThisRun is step 2 of three, and the two wires spell the
// field DIFFERENTLY — MEASURED, `podman volume create --label a=b` sends
// {"Name":...,"Driver":"local","Label":{"a":"b"},"Labels":null,...} on the
// libpod wire. A stamp written into the field the engine does not read leaves
// every volume unowned while looking stamped, which is silent.
func TestVolumeCreateStampsThisRun(t *testing.T) {
	for _, tc := range []struct{ name, path, body, wantKey string }{
		{"compat spells it Labels", "/v1.41/volumes/create",
			`{"Name":"myvol","Driver":"local"}`, "Labels"},
		{"libpod spells it Label", "/v6.0.2/libpod/volumes/create",
			`{"Name":"myvol","Driver":"local","Label":{"a":"b"},"Labels":null,"Options":{}}`, "Label"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sock, rec := startRecorded(t, "snug.run=1234", nil)
			code, resp := do(t, sock, http.MethodPost, tc.path, tc.body)
			if code != http.StatusOK {
				t.Fatalf("status %d, want 200: %s", code, resp)
			}
			var got map[string]json.RawMessage
			if err := json.Unmarshal([]byte(rec.lastBody()), &got); err != nil {
				t.Fatalf("forwarded body is not JSON: %v (%s)", err, rec.lastBody())
			}
			var labels map[string]string
			if err := json.Unmarshal(got[tc.wantKey], &labels); err != nil {
				t.Fatalf("forwarded %s is not a map of strings: %s", tc.wantKey, rec.lastBody())
			}
			if labels["snug.run"] != "1234" {
				t.Errorf("the forwarded %s carries no run stamp: %s", tc.wantKey, rec.lastBody())
			}
			_ = resp
		})
	}

	t.Run("libpod carrying BOTH Label and Labels is refused rather than guessed at", func(t *testing.T) {
		sock, rec := startRecorded(t, "snug.run=1234", nil)
		before := rec.requests.Load() - rec.inspects.Load()
		code, resp := do(t, sock, http.MethodPost, "/v6.0.2/libpod/volumes/create",
			`{"Name":"myvol","Label":{"a":"b"},"Labels":{"c":"d"}}`)
		if code != http.StatusForbidden {
			t.Fatalf("status %d, want 403: %s", code, resp)
		}
		if rec.requests.Load()-rec.inspects.Load() != before {
			t.Errorf("the create reached the engine: %v", rec.seen())
		}
	})
}

// TestVolumeRemovalIsScopedToThisRun is step 3, and the negatives are what make
// step 3 safe to take at all: symmetry with a label is create/rm for THIS run's
// volumes; symmetry without one is cross-run destruction.
func TestVolumeRemovalIsScopedToThisRun(t *testing.T) {
	t.Run("this run's own volume is removable", func(t *testing.T) {
		sock, rec := startRecordedWith(t, "snug.run=1234", &recorder{
			volumeInspect: volumeInspectAnswer("local", map[string]string{},
				map[string]string{"snug.run": "1234"}),
		})
		before := rec.requests.Load() - rec.inspects.Load()
		code, resp := do(t, sock, http.MethodDelete, "/v1.41/volumes/myvol", "")
		if code != http.StatusOK {
			t.Fatalf("status %d, want 200: %s", code, resp)
		}
		if rec.requests.Load()-rec.inspects.Load() == before {
			t.Error("the removal did not reach the engine")
		}
	})

	for _, tc := range []struct {
		name    string
		labels  map[string]string
		wantMsg string
	}{
		{"another run's volume", map[string]string{"snug.run": "OTHER"}, "created by another sandbox run"},
		{"a volume nothing stamped", map[string]string{}, "carries no snug.run label at all"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, path := range []string{"/v1.41/volumes/theirs", "/v6.0.2/libpod/volumes/theirs"} {
				sock, rec := startRecordedWith(t, "snug.run=1234", &recorder{
					volumeInspect: volumeInspectAnswer("local", map[string]string{}, tc.labels),
				})
				before := rec.requests.Load() - rec.inspects.Load()
				code, resp := do(t, sock, http.MethodDelete, path, "")
				if code != http.StatusForbidden {
					t.Errorf("%s: status %d, want 403: %s", path, code, resp)
					continue
				}
				if msg := denyMessage(resp); !strings.Contains(msg, tc.wantMsg) {
					t.Errorf("%s: refused, but not for the reason this case tests.\n"+
						"  want: %q\n  got: %s", path, tc.wantMsg, msg)
				}
				if rec.requests.Load()-rec.inspects.Load() != before {
					t.Errorf("%s: the removal reached the engine: %v", path, rec.seen())
				}
			}
		})
	}
}

// TestAnotherRunsVolumeCanBeMountedButNotRemoved pins the ASYMMETRY, and it is
// here because the asymmetry is deliberate and reads like an oversight.
//
// Sharing the engine store across runs on one target is what makes a warm start
// warm, so a later run may MOUNT what an earlier one wrote — the volume is an
// option-free local directory with no host path in it, which is what the use-time
// gate proves. It may not DESTROY it: that is another run's data.
//
// If either half of this test flips, someone has changed a boundary. A failing
// mount is an ergonomics regression; a passing removal is a data-loss one.
func TestAnotherRunsVolumeCanBeMountedButNotRemoved(t *testing.T) {
	theirs := volumeInspectAnswer("local", map[string]string{}, map[string]string{"snug.run": "OTHER"})

	t.Run("mount: permitted", func(t *testing.T) {
		sock, rec := startRecordedWith(t, "snug.run=1234", &recorder{volumeInspect: theirs})
		before := rec.requests.Load() - rec.inspects.Load()
		code, resp := do(t, sock, http.MethodPost, "/v1.41/containers/create",
			`{"HostConfig":{"Binds":["foreignvol:/data"]}}`)
		if code != http.StatusOK {
			t.Fatalf("status %d, want 200 — a later run must still be able to READ what an "+
				"earlier one left in the shared store: %s", code, resp)
		}
		if rec.requests.Load()-rec.inspects.Load() == before {
			t.Error("the create did not reach the engine")
		}
	})

	t.Run("removal: refused", func(t *testing.T) {
		sock, rec := startRecordedWith(t, "snug.run=1234", &recorder{volumeInspect: theirs})
		before := rec.requests.Load() - rec.inspects.Load()
		code, resp := do(t, sock, http.MethodDelete, "/v1.41/volumes/foreignvol", "")
		if code != http.StatusForbidden {
			t.Fatalf("status %d, want 403: %s", code, resp)
		}
		if rec.requests.Load()-rec.inspects.Load() != before {
			t.Errorf("the removal reached the engine: %v", rec.seen())
		}
	})
}
