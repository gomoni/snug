// Package intent is the contract between the intent model and snug-setup:
// the action vocabulary (schema.json), a strict parser for it, and the prompt
// the model is shown.
//
// Nothing here grants anything. An Action is a request that Go validates
// again, asks the human about where identities are concerned, and only then
// applies to the draft profile.
package intent

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

// Schema is schema.json, the same bytes llama-server is handed to constrain
// decoding. Parse enforces it independently, so a server that ignores the
// constraint cannot widen what is accepted.
//
//go:embed schema.json
var Schema []byte

// MaxActions is the schema's maxItems.
const MaxActions = 8

// Builtins, Refusals and Topics are the enums of schema.json. A test holds
// them equal to the embedded schema.
var (
	Builtins = []string{"@target-rw", "@parent-ro", "@git", "@net", "@claude", "@podman-socket", "@podman-build"}
	Refusals = []string{"host_network", "host_port", "desktop_socket", "deny_rule", "sensitive_home", "whole_home",
		"secret_in_env", "docker_sock", "port_publish", "repo_profile", "no_seccomp", "out_of_scope"}
	Topics = []string{"help", "profiles", "defaults", "net", "parent_ro", "podman_offline", "podman_build", "port_publish",
		"compose_subdir_volume", "secrets_file", "identity_one", "git", "claude", "layering", "readonly_target"}
	IdentityKinds = []string{"ssh", "github", "git"}
)

// Op names. They are the schema's `op` constants.
const (
	OpUseProfile     = "use_profile"
	OpDropProfile    = "drop_profile"
	OpGrantPath      = "grant_path"
	OpDropPath       = "drop_path"
	OpStageBinary    = "stage_binary"
	OpSetEnv         = "set_env"
	OpOpenDoor       = "open_door"
	OpListIdentities = "list_identities"
	OpSelectIdentity = "select_identity"
	OpReadFile       = "read_file"
	OpNameProfile    = "name_profile"
	OpShow           = "show"
	OpSave           = "save"
	OpRefuse         = "refuse"
	OpNote           = "note"
	OpAsk            = "ask"
)

// Action is one validated entry of the model's reply. Which fields are set
// depends on Op; Parse guarantees that exactly the fields the schema requires
// for that op (plus `value` for set_env when given) are present.
type Action struct {
	Op       string
	Name     string // use_profile, drop_profile, stage_binary, set_env, open_door, name_profile
	Path     string // grant_path, drop_path, read_file
	Access   string // grant_path: ro, rw or tmpfs
	Host     string // stage_binary: host path
	Verb     string // set_env: set, inherit or prepend
	Value    string // set_env
	HasValue bool   // set_env: `value` was present
	Kind     string // list_identities, select_identity
	Account  string // select_identity
	Code     string // refuse
	Topic    string // note
	Question string // ask
}

var (
	pathRE    = regexp.MustCompile(`^(/|~/|\{home\}|\{target\}|\{target_parent\})`)
	binNameRE = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,64}$`)
	envNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
	doorRE    = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	profRE    = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]{0,63}$`)
)

// ValidProfileName reports whether s is a name snug accepts for a user
// profile (no leading @, no underscore).
func ValidProfileName(s string) bool { return profRE.MatchString(s) }

// strictObject decodes one JSON object whose values must all be strings,
// refusing duplicate keys (encoding/json would keep the last silently).
func strictObject(raw json.RawMessage) (map[string]string, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errors.New("not a JSON object")
	}
	out := map[string]string{}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, _ := kt.(string)
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("duplicate field %q", key)
		}
		var v string
		if err := dec.Decode(&v); err != nil {
			return nil, fmt.Errorf("field %q is not a string", key)
		}
		out[key] = v
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data after object")
	}
	return out, nil
}

func inEnum(v string, set []string) bool { return slices.Contains(set, v) }

func maxLen(v string, n int) bool { return utf8.RuneCountInString(v) <= n }

// Parse validates a model reply against schema.json and returns its actions.
// It returns an error, and no actions, for anything the schema would refuse:
// invalid JSON, trailing data, a key other than "actions", an action count
// outside 1..MaxActions, an unknown op, an unknown or missing field, a
// non-string field value, a duplicate key, an enum value outside its set, a
// string that violates its pattern or maxLength, or a set_env with verb set or
// prepend and no value. The caller must treat an error as "did not
// understand" and change nothing.
func Parse(reply []byte) ([]Action, error) {
	dec := json.NewDecoder(bytes.NewReader(reply))
	dec.DisallowUnknownFields()
	var top struct {
		Actions []json.RawMessage `json:"actions"`
	}
	if err := dec.Decode(&top); err != nil {
		return nil, fmt.Errorf("reply is not {\"actions\":[...]}: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data after the reply object")
	}
	if len(top.Actions) < 1 || len(top.Actions) > MaxActions {
		return nil, fmt.Errorf("%d actions (want 1..%d)", len(top.Actions), MaxActions)
	}
	out := make([]Action, 0, len(top.Actions))
	for i, raw := range top.Actions {
		m, err := strictObject(raw)
		if err != nil {
			return nil, fmt.Errorf("action %d: %w", i, err)
		}
		a, err := buildAction(m)
		if err != nil {
			return nil, fmt.Errorf("action %d: %w", i, err)
		}
		out = append(out, a)
	}
	return out, nil
}

func buildAction(m map[string]string) (Action, error) {
	op, ok := m["op"]
	if !ok {
		return Action{}, errors.New("no op")
	}
	var required, optional []string
	switch op {
	case OpUseProfile, OpDropProfile, OpOpenDoor, OpNameProfile:
		required = []string{"name"}
	case OpGrantPath:
		required = []string{"path", "access"}
	case OpDropPath, OpReadFile:
		required = []string{"path"}
	case OpStageBinary:
		required = []string{"host", "name"}
	case OpSetEnv:
		required, optional = []string{"name", "verb"}, []string{"value"}
	case OpListIdentities:
		required = []string{"kind"}
	case OpSelectIdentity:
		required = []string{"kind", "account"}
	case OpShow, OpSave:
	case OpRefuse:
		required = []string{"code"}
	case OpNote:
		required = []string{"topic"}
	case OpAsk:
		required = []string{"question"}
	default:
		return Action{}, fmt.Errorf("unknown op %q", op)
	}
	for k := range m {
		if k != "op" && !slices.Contains(required, k) && !slices.Contains(optional, k) {
			return Action{}, fmt.Errorf("%s: unknown field %q", op, k)
		}
	}
	for _, k := range required {
		if _, ok := m[k]; !ok {
			return Action{}, fmt.Errorf("%s: missing field %q", op, k)
		}
	}
	a := Action{Op: op}
	bad := func(field, why string) (Action, error) {
		return Action{}, fmt.Errorf("%s: %s %q: %s", op, field, m[field], why)
	}
	checkPath := func(field string) (string, bool) {
		v := m[field]
		return v, pathRE.MatchString(v) && maxLen(v, 256)
	}
	switch op {
	case OpUseProfile, OpDropProfile:
		if !inEnum(m["name"], Builtins) {
			return bad("name", "not a built-in snug-setup can name")
		}
		a.Name = m["name"]
	case OpGrantPath:
		p, ok := checkPath("path")
		if !ok {
			return bad("path", "must start with /, ~/, {home}, {target} or {target_parent} (max 256)")
		}
		if !inEnum(m["access"], []string{"ro", "rw", "tmpfs"}) {
			return bad("access", "want ro, rw or tmpfs")
		}
		a = Action{Op: op, Path: p, Access: m["access"]}
	case OpDropPath:
		p, ok := checkPath("path")
		if !ok {
			return bad("path", "must start with /, ~/, {home}, {target} or {target_parent} (max 256)")
		}
		a.Path = p
	case OpStageBinary:
		h, ok := checkPath("host")
		if !ok {
			return bad("host", "must start with /, ~/, {home}, {target} or {target_parent} (max 256)")
		}
		if !binNameRE.MatchString(m["name"]) {
			return bad("name", "want 1-64 of A-Za-z0-9._+-")
		}
		a.Host, a.Name = h, m["name"]
	case OpSetEnv:
		if !envNameRE.MatchString(m["name"]) {
			return bad("name", "not an environment variable name")
		}
		if !inEnum(m["verb"], []string{"set", "inherit", "prepend"}) {
			return bad("verb", "want set, inherit or prepend")
		}
		v, has := m["value"]
		if has && !maxLen(v, 256) {
			return bad("value", "longer than 256 characters")
		}
		if !has && m["verb"] != "inherit" {
			return Action{}, fmt.Errorf("set_env: verb %q needs a value", m["verb"])
		}
		a.Name, a.Verb, a.Value, a.HasValue = m["name"], m["verb"], v, has
	case OpOpenDoor:
		if !doorRE.MatchString(m["name"]) || !maxLen(m["name"], 32) {
			return bad("name", "want lowercase words joined by single dashes, max 32")
		}
		a.Name = m["name"]
	case OpListIdentities:
		if !inEnum(m["kind"], IdentityKinds) {
			return bad("kind", "want ssh, github or git")
		}
		a.Kind = m["kind"]
	case OpSelectIdentity:
		if !inEnum(m["kind"], IdentityKinds) {
			return bad("kind", "want ssh, github or git")
		}
		if !maxLen(m["account"], 128) {
			return bad("account", "longer than 128 characters")
		}
		a.Kind, a.Account = m["kind"], m["account"]
	case OpReadFile:
		if !maxLen(m["path"], 256) {
			return bad("path", "longer than 256 characters")
		}
		a.Path = m["path"]
	case OpNameProfile:
		if !profRE.MatchString(m["name"]) {
			return bad("name", "want [a-zA-Z0-9][a-zA-Z0-9-]{0,63}")
		}
		a.Name = m["name"]
	case OpRefuse:
		if !inEnum(m["code"], Refusals) {
			return bad("code", "not a refusal code")
		}
		a.Code = m["code"]
	case OpNote:
		if !inEnum(m["topic"], Topics) {
			return bad("topic", "not a note topic")
		}
		a.Topic = m["topic"]
	case OpAsk:
		if !maxLen(m["question"], 200) {
			return bad("question", "longer than 200 characters")
		}
		a.Question = strings.TrimSpace(m["question"])
	}
	return a, nil
}
