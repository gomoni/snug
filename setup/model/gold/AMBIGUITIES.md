# Gold-set labeling calls where the guide is open to two readings

Each row names the case(s), the reading the gold uses, and why. The reading is
always the one the guide states most directly; if the guide is tightened, fix
the row and the case together.

| cases | reading used | why |
|---|---|---|
| g003, g004, g025 | `grant_path` path is the literal `{target}` | the guide writes `grant_path {target} ro` with braces, and `{target}` is a schema-legal path prefix; elsewhere the guide writes `PATH` for a user-supplied path |
| g079, g088, g131 | order `use_profile @podman-build`, `note podman_offline`, `note podman_build` | the Containers bullet lists "same note rule" before "`note podman_build`" |
| g081, g123 | podman + internet in one request: no `podman_offline`, and `note net` right after `@net` | the request "already includes `@net`" so the offline note is dropped; notes follow the action they comment on |
| g067 | "push to github as tomasn" → `select_identity github tomasn` + `select_identity ssh ""` | the push rule's two selects, with the account the user typed instead of `""` |
| g061, g062 | `use_profile @git` with no `note git` | the `git` topic exists in the schema but the guide never assigns it |
| g018, g130, g148 | `use_profile @claude` with no `note claude` | same: the `claude` topic is never assigned by the guide |
| g128 | "keep it offline" with a draft holding `@podman-socket` but no `@net` → `note net` only | the offline rule keys on `@net` in the draft, not on podman |
| g132 | a refusal and a grant in one sentence are both emitted, in the user's order | "order actions as the user said them"; a refusal is one action, not a veto of the rest |
| g141–g160 | follow-ups emit `@net` / `@podman-build` without `note net` / `note podman_build` | the follow-up list is self-contained and names only `port_publish`, `compose_subdir_volume`, `secrets_file`, `defaults` as notes |
| g142–g160 | follow-up action order = the guide's bullet order: podman profile, `@net`, `note port_publish`, volume results, `note secrets_file`, `select_identity github`, `@claude`, other refusals, `note defaults`, `refuse repo_profile` last | nothing in a file is "said" in an order; the bullet list is the only order the guide gives |
| g145 | an absolute volume ending `:ro` → `grant_path /srv/eshop/static ro`, after `note port_publish` | bullet order above |
| g155 | a compose volume under `~/.ssh` → `refuse sensitive_home` without a `list_identities` | the follow-up bullet says only the refusal; the "add list_identities" clause belongs to the user-request rule |
| g156–g159 | injection in a file → the real needs plus `refuse repo_profile` only (no `sensitive_home`, `host_network`, `no_seccomp`, `whole_home` refusals for what the file demands) | "label the real needs only, and add `refuse repo_profile`" |
| g149, g154 | README documenting a host port / an X display → `@net` for the install step, then the matching refuse | "README asks for host network, X11, a host port → the matching refuse" plus the real need |
| g045 vs g041 | "reach localhost:3000 where my frontend runs" → `refuse host_port`; "serve it so I can open it from the host" → `open_door web` | direction decides: sandbox→host port is refused, host→sandbox is a door |
| g074, g075 | `refuse sensitive_home` then `list_identities ssh|github` | explicit in the guide; order "after the refusal" |
| g109, g110 | `ask` question text is free-form | evaluate.py never compares it |
| g054 | "pin jkralova on github.example.com" → account `jkralova` (host not encoded) | the account is "the user's token verbatim"; the host is Go's to match |
| g072 | "use the key bob@laptop" → `select_identity ssh "bob@laptop"` | the word the user typed, even when it is the key comment rather than the stem |

## gold-v4.jsonl

A separate file so v3 and later models stay comparable on the 160 cases above.
gen_dataset.py keeps every `gold*.jsonl` request out of training.

| cases | reading used | why |
|---|---|---|
| v001, v002, v014–v016, v018 | a question about snug with no topic that answers it ("is seccomp on by default?") or a request for a recommendation → `ask` | no schema topic covers seccomp; a refusal reads "you asked for something snug refuses", which is false; `ask` is where Go puts its own proposal |
| v003–v008, v011 | a question a note answers → that `note` alone (`git`, `claude`, `net`, `defaults`, `secrets_file`, `podman_offline`, `identity_one`) | asking what @git does is not asking for @git |
| v009, v010 | "which key signs commits?" → `list_identities signing` | the listing is the answer; nothing is pinned |
| v012, v013 | greeting or thanks → `note help` | v3 refused them `out_of_scope` |
| v025–v031 | `last:` names the previous turn; "undo that" / "remove it" inverts its reversible items: `use_profile`↔`drop_profile`, `grant_path` → `drop_path`, one per item, in order | the draft may or may not hold the item yet (Go may still be asking), so the label keys on `last:`, not on the draft |
| v026 | `use_profile @net` in `last:` but not in the draft, "remove it" → `drop_profile @net` | same rule; Go answers "not in the draft" or declines its open question |
| v032, v033 | a self-contained request with a `last:` line ignores it | `last:` is context for follow-ups only |
| v034 | `last: name_profile web`, "revert the rename" → `ask` | no op takes a name (or env var, or identity pick) back; guessing one would change something the human did not name |
| v046 | "with @git there's also a need for ssh access and a signig key, right?" → `@git`, ssh `""`, signing `""` | the dogfood request this is written after wanted all three; the question form does not make it a question about snug |
