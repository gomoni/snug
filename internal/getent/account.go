package getent

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/gomoni/snug/internal/policy"
)

// Source is where this process's account comes from.
type Source struct {
	// FromPasswd is true inside a snug sandbox, where the account is the one
	// line snug itself generated into /etc/passwd and /etc/group. Otherwise
	// Getent is the path of the root-owned getent that answered.
	FromPasswd bool
	Getent     string
}

// String names the source the way the -v account note does.
func (s Source) String() string {
	if s.FromPasswd {
		return "snug's generated /etc/passwd"
	}
	return s.Getent
}

// SourceKind is ChooseSource's answer.
type SourceKind int

const (
	// KindGetent: the host's NSS, through a pinned getent.
	KindGetent SourceKind = iota
	// KindAuthored: snug's own generated /etc/passwd and /etc/group.
	KindAuthored
)

// ChooseSource decides, from the bytes of /proc/self/uid_map and the process's
// uid, whether the account is read from getent or from a generated passwd.
// Exactly one line mapping exactly one id, with the inside id equal to uid, is
// the shape of a snug sandbox's user namespace (and of any other namespace
// made with a single mapping, which readAuthored then refuses). Everything
// else, the host's `0 0 4294967295` and any multi-range map included, is a
// namespace whose /etc/passwd is not snug's to trust, and gets getent.
func ChooseSource(uidMap []byte, uid int) SourceKind {
	lines := strings.Split(strings.TrimSuffix(string(uidMap), "\n"), "\n")
	if len(lines) != 1 {
		return KindGetent
	}
	f := strings.Fields(lines[0])
	if len(f) != 3 || f[2] != "1" || f[0] != strconv.Itoa(uid) {
		return KindGetent
	}
	return KindAuthored
}

// currentSource is a variable so a test can pick a source without a user
// namespace.
var currentSource = hereSource

func hereSource() (Source, error) {
	b, err := os.ReadFile("/proc/self/uid_map")
	if err != nil {
		return Source{}, fmt.Errorf("snug could not read /proc/self/uid_map to decide where this "+
			"account's name and home directory come from: %v. Mount /proc", err)
	}
	if ChooseSource(b, os.Getuid()) == KindAuthored {
		return Source{FromPasswd: true}, nil
	}
	path, err := Locate()
	if err != nil {
		return Source{}, err
	}
	return Source{Getent: path}, nil
}

// Account returns this process's passwd entry and primary group entry and
// where they came from. Outside a snug sandbox they are `getent passwd <uid>`
// and `getent group <gid>` run from a root-owned getent (Locate); inside one
// they are the single lines snug generated, read from descriptors it checked.
// A failure is a refusal that names the fix; there is no fallback from one
// source to the other.
func Account() (Passwd, Group, Source, error) {
	src, err := currentSource()
	if err != nil {
		return Passwd{}, Group{}, Source{}, err
	}
	if src.FromPasswd {
		pw, gr, err := readAuthored()
		return pw, gr, src, err
	}
	pw, err := PasswdByUID(os.Getuid())
	if err != nil {
		return Passwd{}, Group{}, src, err
	}
	gr, err := GroupByGID(os.Getgid())
	if err != nil {
		return Passwd{}, Group{}, src, err
	}
	return pw, gr, src, nil
}

const maxAuthoredFile = 4096

func notThisAccount(what string) error {
	return fmt.Errorf("%s: not this sandbox's account", what)
}

func authoredByUID(uid int) (Passwd, error) {
	pw, _, err := readAuthored()
	if err != nil {
		return Passwd{}, err
	}
	if pw.UID != uid {
		return Passwd{}, fmt.Errorf("uid %d: %w (%v)", uid, ErrNoEntry, notThisAccount("passwd"))
	}
	return pw, nil
}

func authoredByName(name string) (Passwd, error) {
	pw, _, err := readAuthored()
	if err != nil {
		return Passwd{}, err
	}
	if pw.Name != name {
		return Passwd{}, notThisAccount(fmt.Sprintf("account %q", policy.VisibleText(name)))
	}
	return pw, nil
}

func authoredByGID(gid int) (Group, error) {
	_, gr, err := readAuthored()
	if err != nil {
		return Group{}, err
	}
	if gr.GID != gid {
		return Group{}, fmt.Errorf("gid %d: %w (%v)", gid, ErrNoEntry, notThisAccount("group"))
	}
	return gr, nil
}

// readAuthored reads /etc/passwd and /etc/group as snug generated them. Each
// is opened without following a final symlink and every check is made on the
// descriptor that is then read, so no path is resolved twice. The files must
// be owned by this uid and sit on a read-only tmpfs mount on the same device as
// the root mount, which itself must be tmpfs: that is what a bwrap data bind
// into a snug root looks like, and a file a payload could write is not on it.
func readAuthored() (Passwd, Group, error) {
	mi, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return Passwd{}, Group{}, fmt.Errorf("snug could not read /proc/self/mountinfo: %v", err)
	}
	// HOSTREAD-EXEMPT: "/" is a directory, which open(2) never blocks on.
	root, err := os.Open("/")
	if err != nil {
		return Passwd{}, Group{}, err
	}
	rootID, err := mountID(root)
	root.Close()
	if err != nil {
		return Passwd{}, Group{}, err
	}
	pwb, err := readAuthoredFile("/etc/passwd", mi, rootID)
	if err != nil {
		return Passwd{}, Group{}, notSnug(mi, rootID, err)
	}
	grb, err := readAuthoredFile("/etc/group", mi, rootID)
	if err != nil {
		return Passwd{}, Group{}, notSnug(mi, rootID, err)
	}
	pw, err := ParseAuthoredPasswd(pwb, os.Getuid(), os.Getgid())
	if err != nil {
		return Passwd{}, Group{}, notSnug(mi, rootID, err)
	}
	gr, err := ParseAuthoredGroup(grb, os.Getgid())
	if err != nil {
		return Passwd{}, Group{}, notSnug(mi, rootID, err)
	}
	return pw, gr, nil
}

// notSnug picks the wording only; it grants nothing. A read-only tmpfs root
// is what a snug sandbox has and an ordinary host does not.
func notSnug(mountinfo []byte, rootID int, why error) error {
	if rootIsReadOnlyTmpfs(mountinfo, rootID) {
		if errors.Is(why, fs.ErrNotExist) {
			return fmt.Errorf("inside snug, the account comes from the generated /etc/passwd, and this "+
				"run's profiles generate none; select a profile with nss = true (for example @sys) in "+
				"the outer run (%v)", why)
		}
		// A file is there and it is not snug's: something mounted over it
		// or replaced it, so "select nss" would name the wrong fix.
		return fmt.Errorf("inside snug, the account comes from snug's generated /etc/passwd, and the "+
			"file there now is not it (%v); snug will not read an account from it", why)
	}
	return fmt.Errorf("this is a user namespace but not a snug sandbox: snug reads the account from a "+
		"root-owned getent on the host, or from snug's own generated /etc/passwd inside snug, and "+
		"neither is available here (%v)", why)
}

func mountID(f *os.File) (int, error) {
	b, err := os.ReadFile("/proc/self/fdinfo/" + strconv.Itoa(int(f.Fd())))
	if err != nil {
		return 0, fmt.Errorf("reading the mount id of %s: %w", f.Name(), err)
	}
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "mnt_id:"); ok {
			return strconv.Atoi(strings.TrimSpace(v))
		}
	}
	return 0, fmt.Errorf("/proc/self/fdinfo has no mnt_id for %s", f.Name())
}

func readAuthoredFile(path string, mountinfo []byte, rootID int) ([]byte, error) {
	// HOSTREAD-EXEMPT: O_NONBLOCK makes open(2) on a FIFO return at once, and the
	// fstat below then refuses it as not a regular file.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	defer f.Close()
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG || int(st.Uid) != os.Getuid() {
		return nil, fmt.Errorf("%s is not a regular file owned by uid %d", path, os.Getuid())
	}
	id, err := mountID(f)
	if err != nil {
		return nil, err
	}
	if err := AuthoredMountOK(mountinfo, id, rootID); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxAuthoredFile+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(b) > maxAuthoredFile {
		return nil, fmt.Errorf("%s is longer than %d bytes", path, maxAuthoredFile)
	}
	return b, nil
}

type mountEntry struct {
	id           int
	dev, options string
	fstype       string
}

func findMount(mountinfo []byte, id int) (mountEntry, bool) {
	for _, l := range strings.Split(string(mountinfo), "\n") {
		f := strings.Fields(l)
		if len(f) < 10 {
			continue
		}
		got, err := strconv.Atoi(f[0])
		if err != nil || got != id {
			continue
		}
		sep := -1
		for i := 6; i < len(f); i++ {
			if f[i] == "-" {
				sep = i
				break
			}
		}
		if sep < 0 || sep+1 >= len(f) {
			return mountEntry{}, false
		}
		return mountEntry{id: got, dev: f[2], options: f[5], fstype: f[sep+1]}, true
	}
	return mountEntry{}, false
}

func hasOption(options, want string) bool {
	for _, o := range strings.Split(options, ",") {
		if o == want {
			return true
		}
	}
	return false
}

func rootIsReadOnlyTmpfs(mountinfo []byte, rootID int) bool {
	r, ok := findMount(mountinfo, rootID)
	return ok && r.fstype == "tmpfs" && hasOption(r.options, "ro")
}

// AuthoredMountOK returns nil when the mount that serves a file (fileMntID) is
// a read-only tmpfs on the same device as the mount serving "/" (rootMntID),
// and "/" is a tmpfs. The mount's root string is not examined: bwrap's data
// binds show a name of its own making there, which is not a contract.
// "ro" is the per-mount option (field 6 of mountinfo), the one a payload
// cannot lift without a mount namespace of its own.
func AuthoredMountOK(mountinfo []byte, fileMntID, rootMntID int) error {
	file, ok := findMount(mountinfo, fileMntID)
	if !ok {
		return fmt.Errorf("mount %d is not in /proc/self/mountinfo", fileMntID)
	}
	root, ok := findMount(mountinfo, rootMntID)
	if !ok {
		return fmt.Errorf("the root mount %d is not in /proc/self/mountinfo", rootMntID)
	}
	switch {
	case root.fstype != "tmpfs":
		return fmt.Errorf("the root filesystem is %s, not tmpfs", root.fstype)
	case file.fstype != "tmpfs":
		return fmt.Errorf("it is on a %s mount, not tmpfs", file.fstype)
	case !hasOption(file.options, "ro"):
		return errors.New("its mount is not read-only")
	case file.dev != root.dev:
		return fmt.Errorf("it is on device %s, not the root's device %s", file.dev, root.dev)
	}
	return nil
}

func oneLine(b []byte) (string, error) {
	s := string(b)
	if strings.Count(s, "\n") != 1 || !strings.HasSuffix(s, "\n") {
		return "", errors.New("is not exactly one line")
	}
	line := strings.TrimSuffix(s, "\n")
	if i := strings.IndexFunc(line, isForbiddenControlByte); i >= 0 {
		return "", fmt.Errorf("carries a control byte (0x%02x)", line[i])
	}
	return line, nil
}

// ParseAuthoredPasswd parses snug's generated /etc/passwd: exactly one line of
// exactly 7 fields whose uid and gid are the ones given, with a non-empty name
// and an absolute home. Anything else is not a file snug wrote for this run.
func ParseAuthoredPasswd(b []byte, uid, gid int) (Passwd, error) {
	line, err := oneLine(b)
	if err != nil {
		return Passwd{}, fmt.Errorf("passwd %v", err)
	}
	f := strings.Split(line, ":")
	if len(f) != 7 {
		return Passwd{}, fmt.Errorf("passwd has %d fields, want exactly 7", len(f))
	}
	gotUID, uerr := strconv.Atoi(f[2])
	gotGID, gerr := strconv.Atoi(f[3])
	if uerr != nil || gerr != nil || gotUID != uid || gotGID != gid {
		return Passwd{}, fmt.Errorf("passwd is not for uid %d gid %d", uid, gid)
	}
	if f[0] == "" {
		return Passwd{}, errors.New("passwd has an empty account name")
	}
	if !strings.HasPrefix(f[5], "/") {
		return Passwd{}, errors.New("passwd home directory is not an absolute path")
	}
	return Passwd{Name: f[0], UID: uid, GID: gid, Gecos: f[4], Home: f[5], Shell: f[6]}, nil
}

// ParseAuthoredGroup parses snug's generated /etc/group: one line,
// `<name>:x:<gid>:`, with a non-empty name and the gid given.
func ParseAuthoredGroup(b []byte, gid int) (Group, error) {
	line, err := oneLine(b)
	if err != nil {
		return Group{}, fmt.Errorf("group %v", err)
	}
	f := strings.Split(line, ":")
	if len(f) != 4 || f[1] != "x" || f[3] != "" || f[0] == "" || f[2] != strconv.Itoa(gid) {
		return Group{}, fmt.Errorf("group is not a single `<name>:x:%d:` line", gid)
	}
	return Group{Name: f[0], GID: gid}, nil
}
