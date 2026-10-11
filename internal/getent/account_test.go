package getent

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type fakeNode struct {
	mode fs.FileMode // includes fs.ModeDir or fs.ModeSymlink
	uid  uint32
	text string // symlink target
}

type fakeLinks map[string]fakeNode

type fakeInfo struct {
	name string
	n    fakeNode
}

func (i fakeInfo) Name() string       { return i.name }
func (i fakeInfo) Size() int64        { return 0 }
func (i fakeInfo) Mode() fs.FileMode  { return i.n.mode }
func (i fakeInfo) ModTime() time.Time { return time.Time{} }
func (i fakeInfo) IsDir() bool        { return i.n.mode.IsDir() }
func (i fakeInfo) Sys() any           { return &syscall.Stat_t{Uid: i.n.uid} }

func (f fakeLinks) Lstat(p string) (fs.FileInfo, error) {
	n, ok := f[path.Clean(p)]
	if !ok {
		return nil, &fs.PathError{Op: "lstat", Path: p, Err: fs.ErrNotExist}
	}
	return fakeInfo{path.Base(p), n}, nil
}

func (f fakeLinks) Readlink(p string) (string, error) {
	n, ok := f[path.Clean(p)]
	if !ok || n.mode&fs.ModeSymlink == 0 {
		return "", &fs.PathError{Op: "readlink", Path: p, Err: fs.ErrInvalid}
	}
	return n.text, nil
}

func usrBin() fakeLinks {
	return fakeLinks{
		"/":               {mode: fs.ModeDir | 0o755},
		"/usr":            {mode: fs.ModeDir | 0o755},
		"/usr/bin":        {mode: fs.ModeDir | 0o755},
		"/usr/bin/getent": {mode: 0o755},
		"/bin":            {mode: fs.ModeSymlink | 0o777, text: "usr/bin"},
	}
}

func TestLocateTakesTheFirstTrustedCandidate(t *testing.T) {
	got, err := locate(usrBin(), 1000, []string{"/usr/bin/getent", "/bin/getent"})
	if err != nil || got != "/usr/bin/getent" {
		t.Fatalf("got %q, %v", got, err)
	}
	got, err = locate(usrBin(), 1000, []string{"/nonexistent", "/bin/getent"})
	if err != nil || got != "/bin/getent" {
		t.Fatalf("root-owned /bin link in a root-owned dir should pass: got %q, %v", got, err)
	}
}

func TestLocateRefusesWhatARootlessUserCouldHaveWritten(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(fakeLinks)
		want   string
	}{
		{"file owned by the user", func(f fakeLinks) { f["/usr/bin/getent"] = fakeNode{mode: 0o755, uid: 1000} }, "not owned by root"},
		{"file owned by the overflow uid", func(f fakeLinks) { f["/usr/bin/getent"] = fakeNode{mode: 0o755, uid: 65534} }, "not owned by root"},
		{"file group-writable", func(f fakeLinks) { f["/usr/bin/getent"] = fakeNode{mode: 0o775} }, "written by group or other"},
		{"file not executable", func(f fakeLinks) { f["/usr/bin/getent"] = fakeNode{mode: 0o644} }, "not executable"},
		{"directory world-writable", func(f fakeLinks) { f["/usr/bin"] = fakeNode{mode: fs.ModeDir | 0o777} }, "directory /usr/bin"},
		{"directory owned by the user", func(f fakeLinks) { f["/usr"] = fakeNode{mode: fs.ModeDir | 0o755, uid: 1000} }, "directory /usr"},
		{"directory owned by the overflow uid", func(f fakeLinks) { f["/"] = fakeNode{mode: fs.ModeDir | 0o755, uid: 65534} }, "directory /"},
		{"file is a user link", func(f fakeLinks) {
			f["/usr/bin/getent"] = fakeNode{mode: fs.ModeSymlink | 0o777, uid: 1000, text: "/home/u/getent"}
		}, "owned by uid 1000"},
		{"missing", func(f fakeLinks) { delete(f, "/usr/bin/getent") }, "does not exist"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := usrBin()
			tc.mutate(f)
			_, err := locate(f, 1000, []string{"/usr/bin/getent"})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want a refusal containing %q", err, tc.want)
			}
		})
	}
}

func TestChooseSourceByUidMap(t *testing.T) {
	for _, tc := range []struct {
		name, m string
		uid     int
		want    SourceKind
	}{
		{"snug sandbox", "      1000          0          1\n", 1000, KindAuthored},
		{"host", "         0          0 4294967295\n", 1000, KindGetent},
		{"two ranges", "1000 0 1\n1001 1 65535\n", 1000, KindGetent},
		{"one range, many ids", "1000 0 65536\n", 1000, KindGetent},
		{"inside id is not our uid", "0 0 1\n", 1000, KindGetent},
		{"empty", "", 1000, KindGetent},
		{"garbage", "a b c\n", 1000, KindGetent},
	} {
		if got := ChooseSource([]byte(tc.m), tc.uid); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

const mountinfoFixture = `42062 41192 0:184 /newroot / ro,nosuid,nodev,relatime - tmpfs tmpfs rw,seclabel
42085 42062 0:184 /bindfileGfsu75//deleted /etc/group ro,nosuid,nodev,relatime - tmpfs tmpfs rw,seclabel
42086 42062 0:184 /bindfileX//deleted /etc/rw rw,nosuid,nodev,relatime - tmpfs tmpfs rw,seclabel
42087 42062 0:300 / /etc/other ro,nosuid,nodev,relatime - tmpfs tmpfs rw,seclabel
42088 42062 0:184 / /etc/ext4 ro,nosuid,nodev,relatime shared:1 - ext4 /dev/x rw
10 1 0:5 / / ro,relatime - ext4 /dev/x rw
`

func TestAuthoredMountOK(t *testing.T) {
	mi := []byte(mountinfoFixture)
	if err := AuthoredMountOK(mi, 42085, 42062); err != nil {
		t.Fatalf("a read-only tmpfs bind on the root's device: %v", err)
	}
	for _, tc := range []struct {
		name       string
		file, root int
		want       string
	}{
		{"writable mount", 42086, 42062, "not read-only"},
		{"another device", 42087, 42062, "not the root's device"},
		{"not tmpfs", 42088, 42062, "not tmpfs"},
		{"root not tmpfs", 42085, 10, "not tmpfs"},
		{"unknown file mount", 1, 42062, "not in /proc/self/mountinfo"},
		{"unknown root mount", 42085, 2, "not in /proc/self/mountinfo"},
	} {
		err := AuthoredMountOK(mi, tc.file, tc.root)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want %q", tc.name, err, tc.want)
		}
	}
}

func TestParseAuthoredPasswdIsStrict(t *testing.T) {
	ok := "michal:x:1000:1000:michal:/home/michal:/usr/bin/bash\n"
	pw, err := ParseAuthoredPasswd([]byte(ok), 1000, 1000)
	if err != nil || pw.Name != "michal" || pw.Home != "/home/michal" {
		t.Fatalf("got %+v, %v", pw, err)
	}
	for name, b := range map[string]string{
		"two lines":  ok + ok,
		"no newline": strings.TrimSuffix(ok, "\n"),
		"six fields": "m:x:1000:1000:m:/h\n",
		"other uid":  "m:x:1001:1000:m:/h:/bin/sh\n",
		"other gid":  "m:x:1000:1001:m:/h:/bin/sh\n",
		"empty name": ":x:1000:1000:m:/h:/bin/sh\n",
		"relative":   "m:x:1000:1000:m:h:/bin/sh\n",
		"control":    "m:x:1000:1000:m:/h\x01:/bin/sh\n",
	} {
		if _, err := ParseAuthoredPasswd([]byte(b), 1000, 1000); err == nil {
			t.Errorf("passwd %s: accepted", name)
		}
	}
	if gr, err := ParseAuthoredGroup([]byte("users:x:1000:\n"), 1000); err != nil || gr.Name != "users" {
		t.Fatalf("got %+v, %v", gr, err)
	}
	for name, b := range map[string]string{
		"members":   "users:x:1000:a,b\n",
		"other gid": "users:x:1001:\n",
		"no name":   ":x:1000:\n",
		"two lines": "users:x:1000:\nusers:x:1000:\n",
		"not x":     "users:*:1000:\n",
	} {
		if _, err := ParseAuthoredGroup([]byte(b), 1000); err == nil {
			t.Errorf("group %s: accepted", name)
		}
	}
}

// measuredSnugMountinfo is the relevant part of /proc/self/mountinfo read
// inside a snug sandbox on the development host: the root is a read-only
// tmpfs, and /etc/group and /etc/passwd are bwrap data binds whose root string
// is bwrap's own bindfile name on the root's device. Only the ids, the options
// and the device matter to the rule.
const measuredSnugMountinfo = `61206 60336 0:232 /newroot / ro,nosuid,nodev,relatime - tmpfs tmpfs rw,seclabel,uid=1000,gid=1000,inode64
61208 61206 0:233 / /dev ro,nosuid,nodev,relatime - tmpfs tmpfs rw,seclabel,mode=755,uid=1000,gid=1000,inode64
61218 61206 0:236 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
61229 61206 0:232 /bindfileg7hboa//deleted /etc/group ro,nosuid,nodev,relatime - tmpfs tmpfs rw,seclabel,uid=1000,gid=1000,inode64
61236 61206 0:232 /bindfileNHLy2S//deleted /etc/passwd ro,nosuid,nodev,relatime - tmpfs tmpfs rw,seclabel,uid=1000,gid=1000,inode64
`

// TestAuthoredMountRule fails if the decision to believe a passwd file stops
// resting on the mount that serves the open descriptor. It is judged on the
// shape a snug sandbox really has (measured), and on each way a payload with
// a user namespace of its own could put its own file there: a bind from
// another device, a writable mount, a root that is not tmpfs, and, the case
// that makes the mount id and not the path the key, a later bind onto
// /etc/passwd while snug's original entry is still listed.
func TestAuthoredMountRule(t *testing.T) {
	const root, passwd, group = 61206, 61236, 61229
	for _, id := range []int{passwd, group} {
		if err := AuthoredMountOK([]byte(measuredSnugMountinfo), id, root); err != nil {
			t.Fatalf("the measured snug shape, mount %d: %v", id, err)
		}
	}

	later := func(line string) []byte { return []byte(measuredSnugMountinfo + line + "\n") }
	for _, tc := range []struct {
		name       string
		mi         []byte
		file, root int
		want       string
	}{
		{"bind from another device",
			later("61300 61206 0:300 /x /etc/passwd ro,nosuid,nodev,relatime - tmpfs tmpfs rw"),
			61300, root, "not the root's device"},
		{"writable mount on the root's device",
			later("61300 61206 0:232 /bindfileZZZZZZ//deleted /etc/passwd rw,nosuid,nodev,relatime - tmpfs tmpfs rw"),
			61300, root, "not read-only"},
		{"host file on a disk filesystem",
			later("61300 61206 0:50 /etc/passwd /etc/passwd ro,relatime - ext4 /dev/sda1 rw"),
			61300, root, "not tmpfs"},
		{"root that is not tmpfs",
			[]byte("10 1 0:5 / / ro,relatime - ext4 /dev/sda1 rw\n" +
				"11 10 0:5 /etc/passwd /etc/passwd ro,relatime - ext4 /dev/sda1 rw\n"),
			11, 10, "not tmpfs"},
		{"file mount id absent from the table", []byte(measuredSnugMountinfo), 1, root, "not in /proc/self/mountinfo"},
		// snug's own entry is still listed and still fine (checked above); the
		// descriptor opened AFTER a payload mounted over the path reports the new
		// mount's id, and that id is what is judged.
		{"a later bind over /etc/passwd while the original is listed",
			later("61301 61206 0:400 / /etc/passwd rw,nosuid,nodev,relatime - tmpfs tmpfs rw"),
			61301, root, "not read-only"},
	} {
		err := AuthoredMountOK(tc.mi, tc.file, tc.root)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want a refusal containing %q", tc.name, err, tc.want)
		}
	}
	// Control for the last case: the original entry is judged OK in the very
	// table that refuses the later one, so the refusal is the id's doing.
	mi := later("61301 61206 0:400 / /etc/passwd rw,nosuid,nodev,relatime - tmpfs tmpfs rw")
	if err := AuthoredMountOK(mi, passwd, root); err != nil {
		t.Errorf("control: the original entry is refused in the table with the later bind: %v", err)
	}
}

// readAuthoredFileHere runs readAuthoredFile with a mount table that lacks
// every mount, so a file that gets past the open and the ownership checks is
// refused at the mount rule with a message that says so. That is the
// positive control for the two tests below: it shows a refusal EARLIER than
// the mount rule is the early check's.
func readAuthoredFileHere(path string) error {
	_, err := readAuthoredFile(path, nil, 0)
	return err
}

// TestAuthoredSourceRefusesAFileNotOwnedByTheUser fails if a passwd file that
// someone other than the invoking user owns (root's /etc/passwd on a plain
// host, or a file a subuid wrote) is ever read as snug's own. Ownership is
// read from the descriptor, before the mount is consulted. It does not cover
// a file owned by a subuid, which needs root to create here.
func TestAuthoredSourceRefusesAFileNotOwnedByTheUser(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root: no file is owned by someone else")
	}
	var st syscall.Stat_t
	if err := syscall.Stat("/etc/passwd", &st); err != nil || int(st.Uid) == os.Getuid() {
		t.Skipf("control unavailable: /etc/passwd stat %v, owner %d", err, st.Uid)
	}
	err := readAuthoredFileHere("/etc/passwd")
	if err == nil || !strings.Contains(err.Error(), "is not a regular file owned by uid") {
		t.Errorf("a file owned by uid %d: got %v", st.Uid, err)
	}
	// Control: a file the user does own passes the ownership check and meets
	// the mount rule, so the refusal above is the ownership check's.
	own := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(own, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := readAuthoredFileHere(own); err == nil || !strings.Contains(err.Error(), "not in /proc/self/mountinfo") {
		t.Errorf("control: a file the user owns should reach the mount rule: got %v", err)
	}
}

// TestAuthoredSourceRefusesASymlink fails if /etc/passwd being a symbolic link
// is ever followed: the open is O_NOFOLLOW, so a link planted at the path
// cannot redirect the read to a file that passes the other checks. A FIFO is
// held to the same file: it must be refused at once and not waited on.
func TestAuthoredSourceRefusesASymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.WriteFile(real, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := readAuthoredFileHere(real); err == nil || !strings.Contains(err.Error(), "not in /proc/self/mountinfo") {
		t.Fatalf("control: the link's target on its own should reach the mount rule: got %v", err)
	}
	err := readAuthoredFileHere(link)
	if err == nil || !errors.Is(err, syscall.ELOOP) {
		t.Errorf("a symbolic link: got %v, want ELOOP", err)
	}

	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- readAuthoredFileHere(fifo) }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "is not a regular file owned by uid") {
			t.Errorf("a FIFO: got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a FIFO at the passwd path blocked the read")
	}
}

// TestPinnedNeverSearchesPATH fails if getent is ever found through $PATH: a
// getent there is a program the invoking environment chose, run before any
// sandbox exists with the user's full authority. The candidates are absolute
// and fixed, no source file calls exec.LookPath, and a getent planted first on
// $PATH is not what Locate returns.
func TestPinnedNeverSearchesPATH(t *testing.T) {
	if len(Candidates) == 0 {
		t.Fatal("no candidates")
	}
	for _, c := range Candidates {
		if !path.IsAbs(c) {
			t.Errorf("candidate %q is not absolute", c)
		}
	}
	for _, f := range []string{"getent.go", "pinned.go", "account.go"} {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(src), "exec.LookPath") {
			t.Errorf("%s calls exec.LookPath; getent is found only at its pinned, root-owned paths", f)
		}
	}

	planted := t.TempDir()
	if err := os.WriteFile(filepath.Join(planted, "getent"), []byte("#!/bin/sh\necho planted\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", planted+":"+os.Getenv("PATH"))
	// Control: the planted getent really is what a PATH search would find.
	if _, err := os.Stat(filepath.Join(planted, "getent")); err != nil {
		t.Fatal(err)
	}
	if got, err := locate(fakeLinks{}, 1000, Candidates); err == nil {
		t.Errorf("an empty host with a getent on $PATH: Locate answered %q", got)
	}
	if got, err := Locate(); err == nil && strings.HasPrefix(got, planted) {
		t.Errorf("Locate returned the getent planted on $PATH: %q", got)
	}
}

// TestRunPassesAnEmptyEnvironment fails if getent is started with the
// invoking environment: LD_PRELOAD, LD_LIBRARY_PATH, NSS and locale variables
// are all read by a program that is about to be run before any sandbox exists.
// The script reports two variables set in this process; the control is that
// the script ran and printed its marker, and that this process really had them.
func TestRunPassesAnEmptyEnvironment(t *testing.T) {
	t.Setenv("SNUG_TEST_LEAK", "leaked")
	t.Setenv("LD_PRELOAD", "/nonexistent.so")
	if os.Getenv("SNUG_TEST_LEAK") != "leaked" {
		t.Fatal("control: the variable is not set in this process")
	}
	script := filepath.Join(t.TempDir(), "getent")
	body := "#!/bin/sh\necho \"MARK leak=${SNUG_TEST_LEAK-unset} preload=${LD_PRELOAD-unset} home=${HOME-unset}\"\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	line, err := runAt(script, "passwd", "1000")
	if err != nil {
		t.Fatal(err)
	}
	if want := "MARK leak=unset preload=unset home=unset"; line != want {
		t.Errorf("getent saw %q, want %q", line, want)
	}
}
