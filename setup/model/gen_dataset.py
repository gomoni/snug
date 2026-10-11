"""Generate the training set for snug-setup's intent model.

Utterances come from data/pools.json (intent id -> phrasings with {slots}),
project files from data/projects.jsonl (hand-written) and data/projects-gen.jsonl
(gen_projects.py), each a body plus feature tags. Labels are
COMPUTED here from the intent id, the filled slots and the context, following
.claude/scratchpad/setup-labeling-guide.md — never written by hand, so one
rule change relabels every example consistently.

The gold set (gold/gold.jsonl) is written independently and is read here only to
keep it out: gold_set() makes build() skip a training example whose request text
or file body appears in it verbatim.

    uv run python gen_projects.py           # data/projects-gen.jsonl
    uv run python gen_dataset.py --n 2700 --seed 303 --out data/train-v3.jsonl
"""

import argparse
import json
import random
import re
from pathlib import Path

import prompt

HERE = Path(__file__).parent

# --- context ---------------------------------------------------------------

USERS = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan", "judy", "mallory",
         "niaj", "olivia", "peggy", "rupert", "sybil", "trent", "victor", "walter", "yuki", "zdenek",
         "petra", "jakub", "lena", "tomas", "marta", "ondrej", "sven", "ines", "kofi"]
PROJECTS = ["webapp", "api", "shop", "blog", "infra", "ml-pipeline", "cli", "dotfiles", "game", "scraper",
            "backend", "frontend", "monorepo", "docs", "etl", "bot", "compiler", "kernel-mod", "site", "tools"]
COMPANIES = ["acme", "initech", "globex", "umbrella", "hooli", "corp", "work", "client", "contoso", "stark"]
SURNAMES = ["Novak", "Smith", "Doe", "Svoboda", "Muller", "Garcia", "Kim", "Okafor", "Rossi", "Larsen"]


def ssh_keys(rng, user, company, proj, k):
    """k host keys. Real hosts carry many (a developer laptop measured 12: backups,
    routers, signing keys, per-account GitHub keys), so the model must not learn
    that the key list is short."""
    stem_pool = ["id_ed25519", "id_rsa", f"id_{company}", "id_personal", "id_work", f"github_{user}",
                 f"id_ed25519_{company}", "id_ecdsa", "github_auth_id_ed25519", "github_sign_id_ed25519",
                 f"backup_{rng.choice(['nas', 'turris', 'borg'])}_id_ed25519", "root_router_id_ed25519",
                 f"{user}_{company}_auth_id_ed25519", "restore_ed25519", f"id_rsa.{company}", "deploy_key",
                 f"gitlab_{user}", "yubikey_sk", f"{user}_vps_ed25519", "id_build", "ci_deploy_ed25519",
                 f"deploy_{proj}", "id_ed25519_signing", "homelab_ed25519", f"id_{user}_old", "aur_ed25519",
                 "gitlab_work_ed25519", "pi_ed25519", "id_ed25519_sk", "hetzner_ed25519", f"{company}_bastion",
                 "codeberg_ed25519", "id_rsa_legacy", f"{proj}_ci"]
    out = []
    for s in rng.sample(stem_pool, k=k):
        out.append({"stem": s,
                    "comment": rng.choice([f"{user}@laptop", f"{user}@{company}.com", f"{user}@desktop", "",
                                           f"{user}+github@mail.org", f"backup@{rng.choice(['nas', 'turris'])}",
                                           f"{user}@10.0.0.{rng.randint(2, 254)}", f"{user}@thinkpad", "",
                                           f"ci@{company}", f"{user}@workstation", "yubikey"]),
                    "agent": rng.random() < 0.6})
    return out


KEY_STOP = {"id", "ed25519", "rsa", "ecdsa", "key", "auth", "sk"}


def typed_key(rng, keys):
    """The word a user types to name one of the host keys: the stem, a fragment
    of it, the comment or its host part. The label is that word verbatim — Go
    matches it against the keys and asks (guide: Identities)."""
    k = rng.choice(keys)
    mode = rng.choices(["stem", "frag", "comment", "chost"], weights=[4, 4, 1, 1])[0]
    if mode == "frag":
        toks = [t for t in re.split(r"[_.\-]", k["stem"]) if t and t not in KEY_STOP]
        if toks:
            return rng.choice(toks)
    if mode in ("comment", "chost") and k["comment"]:
        host = k["comment"].split("@", 1)[1] if "@" in k["comment"] else ""
        return host if mode == "chost" and host and "." not in host else k["comment"]
    return k["stem"]


def rand_context(rng: random.Random) -> dict:
    user = rng.choice(USERS)
    company = rng.choice(COMPANIES)
    proj = rng.choice(PROJECTS)
    target = rng.choice([
        f"/home/{user}/src/{proj}", f"/home/{user}/projects/{proj}", f"/home/{user}/work/{company}/{proj}",
        f"/home/{user}/code/{proj}", f"/srv/{proj}", f"/home/{user}/git/{proj}",
    ])
    k = rng.choices([0, 1, 2, 3, 4, 6, 8, 10, 12], weights=[1, 3, 3, 2, 2, 1, 1, 1, 1])[0]
    ssh = ssh_keys(rng, user, company, proj, k)
    gh = []
    accounts = rng.sample([user, f"{user}-{company}", f"{user}2", f"{user}-work", f"{user}dev"],
                          k=rng.choice([0, 1, 1, 2, 2, 3]))
    for i, a in enumerate(accounts):
        host = "github.com" if rng.random() < 0.85 else f"github.{company}.com"
        gh.append({"host": host, "user": a, "active": i == 0})
    full = f"{user.capitalize()} {rng.choice(SURNAMES)}"
    git = [] if rng.random() < 0.2 else [f"{full} <{user}@{rng.choice(['example.com', company + '.com', 'mail.org'])}>"]
    draft = {"name": None, "include": [], "rw": [], "ro": [], "tmpfs": [], "env": [], "identity": []}
    if rng.random() < 0.45:
        draft["name"] = rng.choice([proj, company, "work", "dev", f"{proj}-{company}"])
        draft["include"] = rng.sample(["@net", "@git", "@podman-socket", "@claude", "@parent-ro"], k=rng.choice([0, 1, 1, 2]))
        if rng.random() < 0.3:
            draft["rw"] = [rng.choice(["/srv/data", f"/home/{user}/datasets", "/opt/cache"])]
        if rng.random() < 0.2 and gh:
            draft["identity"] = [f"github:{gh[0]['user']}"]
    return {"target": target, "draft": draft, "ssh": ssh, "github": gh, "git": git, "file": None,
            "_user": user, "_company": company, "_proj": proj}


def public(ctx: dict) -> dict:
    return {k: v for k, v in ctx.items() if not k.startswith("_")}


# --- slots -----------------------------------------------------------------

REL_BARE = [".git", "node_modules", ".env", "secrets/", ".git/", "build/", "tests/fixtures/private", "config/credentials.yml",
            "~/work/private", "~/projects/secret-stuff", "dist", ".terraform", "logs/", ".venv", "vendor/", "private/"]
REL_PHRASE = ["the .git directory", "the secrets folder", "the vendor dir", "the .venv", "*.pem files", "the keys directory",
              "the docs folder", "the node_modules folder"]

def fill_slots(rng, ctx, text):
    user, company = ctx["_user"], ctx["_company"]
    slots = {}

    def path():
        return rng.choice([
            "/srv/data", "/opt/cache", f"/home/{user}/datasets", "~/datasets", "/mnt/storage/media", "/data/models",
            f"~/work/{company}/shared", "/var/lib/myapp", "~/notes", "/opt/sdk", "~/Downloads/fixtures",
            "/srv/www", f"/home/{user}/shared-libs", "~/.cache/pip", "/scratch", "~/models", "/opt/toolchains/arm",
        ])

    gen = {
        "path": path,
        "subpath": None,
        "secret_path": lambda: rng.choice(["~/.aws", "~/.gnupg", "~/.netrc", "~/.docker/config.json",
                                           "~/.kube/config", "~/.local/share/keyrings", "~/.aws/credentials",
                                           "~/.gnupg/private-keys-v1.d", "~/.docker", "~/.kube"]),
        "binpath": lambda: rng.choice(["~/bin/jq", "/opt/gh/bin/gh", "~/.cargo/bin/rg", "~/go/bin/golangci-lint",
                                       "/opt/node/bin/node", "~/.local/bin/uv", "~/bin/terraform", "/usr/local/bin/helm"]),
        "port": lambda: rng.choice(["5432", "6379", "8080", "3000", "27017", "9200", "11434", "3306"]),
        "door": lambda: rng.choice(["web", "api", "admin", "docs", "grafana", "app", "dev-server", "ui"]),
        "account": lambda: (rng.choice(ctx["github"])["user"] if ctx["github"] and rng.random() < 0.8
                            else rng.choice([f"{user}2", f"{company}-bot", "account2", f"{user}-oss"])),
        "key": lambda: (typed_key(rng, ctx["ssh"]) if ctx["ssh"] and rng.random() < 0.8
                        else rng.choice(["work", "personal", company, "github", "id_work", "deploy", "signing", "ci",
                                         "old", "backup"])),
        "user": lambda: user,
        # bare paths only inside a Czech/German phrasing, so the sentence stays in one language
        "relpath": lambda: rng.choice(REL_BARE + ([] if not text.isascii() else REL_PHRASE)),
        "gitid": lambda: rng.choice(ctx["git"]) if ctx["git"] and rng.random() < 0.5
        else f"{rng.choice(USERS).capitalize()} {rng.choice(SURNAMES)} <{rng.choice(USERS)}@{rng.choice(['example.org', company + '.com'])}>",
        "envname": None,
        "envval": None,
        "bindir": lambda: rng.choice(["~/go/bin", "~/.cargo/bin", "~/.local/bin", "/opt/node/bin", "~/bin", "/opt/flutter/bin"]),
        "secretname": lambda: rng.choice(["GITHUB_TOKEN", "OPENAI_API_KEY", "AWS_SECRET_ACCESS_KEY", "DB_PASSWORD",
                                          "NPM_TOKEN", "ANTHROPIC_API_KEY", "STRIPE_SECRET_KEY", "my API key"]),
        "profile": lambda: rng.choice([ctx["_company"], "work", "oss", "webdev", "agent", "build", "personal", "ci", "data"]),
        "file": lambda: rng.choice(["README.md", "docker-compose.yml", "Dockerfile", "package.json", "Makefile",
                                    "pyproject.toml", "compose.yaml", "CONTRIBUTING.md", "go.mod", "Cargo.toml"]),
    }
    for name in re.findall(r"\{(\w+)\}", text):
        if name in slots:
            continue
        if name == "subpath":
            base = slots.get("path") or path()
            slots.setdefault("path", base)
            slots["subpath"] = base.rstrip("/") + "/" + rng.choice(["out", "results", "build", "tmp", "cache", "logs"])
        elif name in ("envname", "envval"):
            n, v = rng.choice([("EDITOR", "vim"), ("EDITOR", "nano"), ("VISUAL", "code"), ("PAGER", "less"),
                               ("NO_COLOR", "1"), ("EDITOR", "hx"), ("PAGER", "bat"), ("PYTHONBREAKPOINT", "0")])
            slots.setdefault("envname", n)
            slots.setdefault("envval", v)
        elif name in gen and gen[name]:
            slots[name] = gen[name]()
    # inherit-only pool may use {envname} alone
    out = text
    for k, v in slots.items():
        out = out.replace("{" + k + "}", v)
    return out, slots


# --- labels ----------------------------------------------------------------

def A(op, **kw):
    return {"op": op, **kw}


ASK_Q = "What should the sandbox be able to do: write here, reach the internet, run containers, or use an account?"


def label(intent, s, ctx, net_requested=False):
    draft = ctx["draft"]
    has_net = net_requested or "@net" in draft["include"]
    podman_note = [] if has_net else [A("note", topic="podman_offline")]
    L = {
        "write_here": [A("use_profile", name="@target-rw"), A("note", topic="defaults")],
        "readonly_here": [A("grant_path", path="{target}", access="ro"), A("note", topic="readonly_target")],
        "parent_ro": [A("use_profile", name="@parent-ro"), A("note", topic="parent_ro")],
        "path_rw": lambda: [A("grant_path", path=s["path"], access="rw")],
        "path_ro": lambda: [A("grant_path", path=s["path"], access="ro")],
        "path_tmpfs": lambda: [A("grant_path", path=s["path"], access="tmpfs")],
        "layering": lambda: [A("grant_path", path=s["path"], access="ro"),
                             A("grant_path", path=s["subpath"], access="rw"), A("note", topic="layering")],
        "deny": [A("refuse", code="deny_rule"), A("note", topic="layering")],
        "deny_rel": [A("refuse", code="deny_rule"), A("note", topic="layering")],
        "sensitive": [A("refuse", code="sensitive_home")],
        "sensitive_ssh": [A("refuse", code="sensitive_home"), A("list_identities", kind="ssh")],
        "sensitive_gh": [A("refuse", code="sensitive_home"), A("list_identities", kind="github")],
        "claude_dir": [A("use_profile", name="@claude")],
        "whole_home": [A("refuse", code="whole_home")],
        "drop_path": lambda: [A("drop_path", path=s["path"])],
        "stage_binary": lambda: [A("stage_binary", host=s["binpath"], name=s["binpath"].rsplit("/", 1)[-1])],
        "net": [A("use_profile", name="@net"), A("note", topic="net")],
        "offline": [A("drop_profile", name="@net")] if "@net" in draft["include"] else [A("note", topic="net")],
        "host_network": [A("refuse", code="host_network")],
        "host_port": [A("refuse", code="host_port")],
        "desktop": [A("refuse", code="desktop_socket")],
        "open_door": lambda: [A("open_door", name=s["door"])],
        "open_door_default": [A("open_door", name="web")],
        "list_ssh": [A("list_identities", kind="ssh")],
        "list_github": [A("list_identities", kind="github")],
        "list_git": [A("list_identities", kind="git")],
        "select_github": lambda: [A("select_identity", kind="github", account=s["account"])],
        "select_github_any": [A("select_identity", kind="github", account="")],
        "select_ssh": lambda: [A("select_identity", kind="ssh", account=s["key"])],
        "select_ssh_any": [A("select_identity", kind="ssh", account="")],
        "select_git": lambda: [A("select_identity", kind="git", account=s["gitid"])],
        "git_default": [A("use_profile", name="@git")],
        "two_accounts": [A("note", topic="identity_one")],
        "two_accounts_named": [A("note", topic="identity_one")],
        "push_github": [A("select_identity", kind="github", account=""), A("select_identity", kind="ssh", account="")],
        # the push rule's two selects, with the account the user typed (guide: account = the token verbatim)
        "push_github_as": lambda: [A("select_identity", kind="github", account=s["account"]),
                                   A("select_identity", kind="ssh", account="")],
        "podman": [A("use_profile", name="@podman-socket")] + podman_note,
        "podman_build": [A("use_profile", name="@podman-build")] + podman_note + [A("note", topic="podman_build")],
        "docker_sock": [A("refuse", code="docker_sock")],
        "port_publish": [A("refuse", code="port_publish")],
        "env_set": lambda: [A("set_env", name=s["envname"], verb="set", value=s["envval"])],
        "env_inherit": lambda: [A("set_env", name=s["envname"], verb="inherit")],
        "path_prepend": lambda: [A("grant_path", path=s["bindir"], access="ro"),
                                 A("set_env", name="PATH", verb="prepend", value=s["bindir"])],
        "secret_env": [A("refuse", code="secret_in_env"), A("note", topic="secrets_file")],
        "claude": [A("use_profile", name="@claude")],
        "name": lambda: [A("name_profile", name=s["profile"])],
        "show": [A("show")],
        "save": [A("save")],
        "help": [A("note", topic="help")],
        "profiles": [A("note", topic="profiles")],
        "repo_profile": [A("refuse", code="repo_profile")],
        "no_seccomp": [A("refuse", code="no_seccomp")],
        "out_of_scope": [A("refuse", code="out_of_scope")],
        "ambiguous": [A("ask", question=ASK_Q)],
        "read_file": lambda: [A("read_file", path=s["file"])],
        "read_readme": [A("read_file", path="README.md")],
        "read_compose": [A("read_file", path="docker-compose.yml")],
    }[intent]
    return L() if callable(L) else L


# Intents that read naturally joined with another one in a single request.
COMBINABLE = ["write_here", "readonly_here", "parent_ro", "path_rw", "path_ro", "path_tmpfs", "layering", "net", "offline",
              "podman", "podman_build", "select_github", "select_github_any", "select_ssh", "select_ssh_any", "select_git",
              "push_github", "push_github_as", "git_default", "claude", "env_set", "env_inherit", "name", "save", "show",
              "open_door", "open_door_default", "list_ssh", "list_github", "list_git", "path_prepend", "stage_binary",
              "drop_path", "host_port", "host_network", "desktop", "docker_sock", "port_publish", "secret_env", "whole_home",
              "deny", "deny_rel", "sensitive", "sensitive_ssh", "two_accounts_named"]
# At most one intent of each group per request: they contradict or duplicate each other.
EXCLUSIVE = [{"select_github", "select_github_any", "push_github", "push_github_as", "two_accounts_named"},
             {"select_ssh", "select_ssh_any", "push_github", "push_github_as", "sensitive_ssh", "list_ssh"},
             {"net", "offline", "host_network"}, {"offline", "podman", "podman_build"}, {"write_here", "readonly_here"},
             {"podman", "podman_build"}, {"open_door", "open_door_default"}, {"deny", "deny_rel", "layering"},
             {"sensitive", "sensitive_ssh"}, {"save", "show"}, {"git_default", "select_git"},
             {"path_rw", "path_ro", "path_tmpfs", "drop_path", "layering"}, {"env_set", "env_inherit"}]
JOIN = [" and ", ", also ", ". ", " + ", ", and ", " plus ", "; ", " — and ", ". Also ", " & ", ", then ", " and then "]

# Single-intent sampling weights (default 1). Raised where v1 had ~19 examples
# per intent and the gold run showed the class confused with a neighbour.
WEIGHTS = {"deny": 2.5, "deny_rel": 3, "whole_home": 3, "host_network": 3, "out_of_scope": 7, "ambiguous": 3.5, "no_seccomp": 1.5,
           "offline": 2.5, "parent_ro": 2, "select_ssh": 3, "select_ssh_any": 2, "push_github": 1.5,
           "push_github_as": 2, "two_accounts": 1.2, "two_accounts_named": 1.5, "sensitive_ssh": 2, "open_door": 2,
           "host_port": 1.5, "read_file": 3.5, "read_readme": 1.5, "read_compose": 1.5, "git_default": 1.5,
           "desktop": 1.3, "docker_sock": 1.3, "repo_profile": 1.5, "path_prepend": 1.3}
SSH_HEAVY = {"select_ssh", "select_ssh_any", "push_github_as", "push_github", "list_ssh"}


def conflicts(chosen):
    return any(len(g & set(chosen)) > 1 for g in EXCLUSIVE)


def bias_context(rng, ctx, intents):
    """Context the intent's label depends on: offline needs @net in the draft
    half the time (drop_profile vs note net), naming a key needs long key lists."""
    if "offline" in intents and rng.random() < 0.55 and "@net" not in ctx["draft"]["include"]:
        ctx["draft"]["include"] = ctx["draft"]["include"] + ["@net"]
    if SSH_HEAVY & set(intents) and rng.random() < 0.6:
        ctx["ssh"] = ssh_keys(rng, ctx["_user"], ctx["_company"], ctx["_proj"], rng.choice([4, 6, 8, 10, 12]))


# --- project files ---------------------------------------------------------

def file_labels(features):
    """Follow-up labels for a tagged project file, in the guide's bullet order
    ("read_file and the follow-up"): podman profile, @net, volume results,
    note secrets_file, select_identity github, @claude, the other refusals,
    note defaults, refuse repo_profile last. The follow-up list names its own
    notes (port_publish, compose_subdir_volume, secrets_file, defaults); it does
    not carry the request-level podman_offline / net / podman_build notes."""
    f = set(features)
    acts = []
    if "build" in f:
        acts.append(A("use_profile", name="@podman-build"))
    elif "podman" in f:
        acts.append(A("use_profile", name="@podman-socket"))
    if "net" in f:
        acts.append(A("use_profile", name="@net"))
    if "docker_sock" in f:
        acts.append(A("refuse", code="docker_sock"))
    if "secrets" in f:
        acts.append(A("note", topic="secrets_file"))
    if "github" in f:
        acts.append(A("select_identity", kind="github", account=""))
    if "claude" in f:
        acts.append(A("use_profile", name="@claude"))
    for tag, code in [("host_network", "host_network"), ("desktop", "desktop_socket"), ("host_port", "host_port")]:
        if tag in f:
            acts.append(A("refuse", code=code))
    if not acts:
        acts.append(A("note", topic="defaults"))
    if "injection" in f:
        acts.append(A("refuse", code="repo_profile"))
    return acts


IMAGES = ["postgres:16", "redis:7-alpine", "nginx:alpine", "node:20", "python:3.12-slim", "minio/minio",
          "grafana/grafana", "mariadb:11", "rabbitmq:3-management", "mongo:7", "elasticsearch:8.13.0",
          "traefik:v3", "adminer", "mailhog/mailhog", "prom/prometheus", "ghcr.io/acme/worker:latest"]
SVC = ["web", "api", "db", "cache", "worker", "proxy", "queue", "search", "frontend", "backend", "mail", "metrics"]
SECRET_ENV = ["POSTGRES_PASSWORD", "MYSQL_ROOT_PASSWORD", "API_TOKEN", "JWT_SECRET", "AWS_SECRET_ACCESS_KEY",
              "STRIPE_KEY", "MINIO_ROOT_PASSWORD", "SMTP_PASSWORD"]
PLAIN_ENV = ["NODE_ENV", "DEBUG", "LOG_LEVEL", "TZ", "PORT", "DATABASE_HOST", "REDIS_URL", "WORKERS"]


def rand_compose(rng, ctx):
    user = ctx["_user"]
    lines, feats = [], {"net"}
    abs_vols = []
    n = rng.choice([1, 2, 2, 3, 3, 4])
    for name in rng.sample(SVC, n):
        parts = []
        if rng.random() < 0.35:
            parts.append("build=" + rng.choice([".", "./api", "./web", "./docker/worker"]))
            feats.add("build")
        else:
            parts.append("image=" + rng.choice(IMAGES))
            feats.add("podman")
        if rng.random() < 0.4:
            p = rng.choice(["8080", "3000", "5432", "80", "443", "9000", "6379"])
            parts.append(f"ports={p}:{rng.choice([p, '80', '8000'])}")
            feats.add("ports")
        vols = []
        for _ in range(rng.choice([0, 0, 1, 1, 2])):
            kind = rng.choices(["named", "dot", "sub", "sock", "abs", "abs_ro", "sensitive"],
                               weights=[4, 2, 4, 2, 2, 2, 1])[0]
            if kind == "named":
                vols.append(f"{name}-data:/var/lib/{name}")
            elif kind == "dot":
                vols.append(".:/app")
            elif kind == "sub":
                vols.append(f"./{rng.choice(['src', 'data', 'config', 'migrations', 'static'])}:/{rng.choice(['app', 'data', 'etc/app'])}")
                feats.add("subdir")
            elif kind == "sock":
                vols.append("/var/run/docker.sock:/var/run/docker.sock")
                feats.add("docker_sock")
            elif kind in ("abs", "abs_ro"):
                h = rng.choice(["/srv/media", "/opt/models", "/data/uploads", "/mnt/backup", "/srv/certs"])
                ro = kind == "abs_ro"
                vols.append(f"{h}:/{rng.choice(['media', 'models', 'data', 'certs'])}" + (":ro" if ro else ""))
                abs_vols.append((h, "ro" if ro else "rw"))
            else:
                vols.append(rng.choice([f"~/.ssh:/root/.ssh", f"/home/{user}/.aws:/root/.aws:ro", "~/.gnupg:/gnupg"]))
                feats.add("sensitive")
        if vols:
            parts.append("volumes=" + ",".join(vols))
        envs = rng.sample(PLAIN_ENV, rng.choice([0, 0, 1, 2]))
        if rng.random() < 0.35:
            envs.append(rng.choice(SECRET_ENV))
            feats.add("secrets")
        if envs:
            parts.append("env=" + ",".join(envs))
        lines.append(f"service {name}: " + " ".join(parts))
    # labels (guide: podman or build first, then @net, grants, refusals, notes)
    acts = [A("use_profile", name="@podman-build" if "build" in feats else "@podman-socket"),
            A("use_profile", name="@net")]
    if "ports" in feats:
        acts.append(A("note", topic="port_publish"))
    if "subdir" in feats:
        acts.append(A("note", topic="compose_subdir_volume"))
    if "docker_sock" in feats:
        acts.append(A("refuse", code="docker_sock"))
    seen = set()
    for h, acc in abs_vols:
        if h not in seen:
            seen.add(h)
            acts.append(A("grant_path", path=h, access=acc))
    if "sensitive" in feats:
        acts.append(A("refuse", code="sensitive_home"))
    if "secrets" in feats:
        acts.append(A("note", topic="secrets_file"))
    return "\n".join(lines), acts


# --- assembly --------------------------------------------------------------

def gold_set():
    """Gold request texts and file bodies, read only to keep them OUT of training."""
    p = HERE / "gold" / "gold.jsonl"
    g = {"requests": set(), "bodies": set()}
    if not p.exists():
        return g
    for l in p.read_text().splitlines():
        if l.strip():
            r = json.loads(l)
            g["requests"].add(r["request"].strip().lower())
            if (r.get("context") or {}).get("file"):
                g["bodies"].add(r["context"]["file"]["body"])
    return g


def lower_first(s):
    return s[:1].lower() + s[1:] if s[:1].isupper() and not s[:2].isupper() else s


def build(n, seed, pools, projects, gold, mix):
    rng = random.Random(seed)
    intents = sorted(pools)
    w = [WEIGHTS.get(i, 1.0) for i in intents]
    p_single, p_combo = mix
    out, skipped = [], 0
    proj_order = []
    while len(out) < n:
        ctx = rand_context(rng)
        r = rng.random()
        if r < p_single:
            intent = rng.choices(intents, weights=w)[0]
            bias_context(rng, ctx, [intent])
            text, slots = fill_slots(rng, ctx, rng.choice(pools[intent]))
            acts = label(intent, slots, ctx)
            tag = intent
        elif r < p_single + p_combo:
            k = rng.choices([2, 3, 4], weights=[65, 30, 5])[0]
            chosen = rng.sample([i for i in COMBINABLE if i in pools], k)
            if conflicts(chosen):
                continue
            bias_context(rng, ctx, chosen)
            texts, slots_all = [], []
            for c in chosen:
                # one language per request: Czech/German phrasings stay single-intent
                t, s = fill_slots(rng, ctx, rng.choice([u for u in pools[c] if u.isascii()] or pools[c]))
                texts.append(t.rstrip(".!? "))
                slots_all.append(s)
            text = texts[0]
            for t in texts[1:]:
                text += rng.choice(JOIN) + lower_first(t)
            net_req = "net" in chosen
            acts = []
            for c, s in zip(chosen, slots_all):
                acts += label(c, s, ctx, net_requested=net_req)
            tag = "combo:" + "+".join(chosen)
        else:
            # project files: walk a shuffled deck so every file is used before any repeats
            if rng.random() < 0.6 and projects:
                if not proj_order:
                    proj_order = list(range(len(projects)))
                    rng.shuffle(proj_order)
                proj = projects[proj_order.pop()]
                ctx["file"] = {"name": proj["name"], "body": proj["body"][:1200]}
                acts = file_labels(proj["features"])
                req_pool = "read_readme" if proj["name"].lower().startswith("readme") else "read_file"
                if proj["body"] in gold["bodies"]:
                    skipped += 1
                    continue
            else:
                body, acts = rand_compose(rng, ctx)
                ctx["file"] = {"name": rng.choice(["docker-compose.yml", "compose.yaml", "docker-compose.dev.yml", "compose.yml"]), "body": body}
                req_pool = "read_compose" if ctx["file"]["name"] == "docker-compose.yml" or rng.random() < 0.5 else "read_file"
            text, _ = fill_slots(rng, ctx, rng.choice(pools[req_pool]).replace("{file}", ctx["file"]["name"]))
            tag = "file:" + ctx["file"]["name"]
        if text.strip().lower() in gold["requests"]:
            skipped += 1
            continue
        if len(acts) > 8:
            continue
        out.append({"tag": tag, "context": public(ctx), "request": text, "actions": acts})
    return out, skipped


def token_lengths(rows, base):
    """Token count of each row exactly as train.py builds it (chat template, prompt + reply)."""
    from transformers import AutoTokenizer
    tok = AutoTokenizer.from_pretrained(base, local_files_only=True)
    lens = []
    for r in rows:
        m = prompt.messages(r["context"], r["request"], r["actions"])
        lens.append(len(tok(tok.apply_chat_template(m, tokenize=False), add_special_tokens=False)["input_ids"]))
    return lens


def stats(rows, lens):
    import collections
    import statistics
    kind = collections.Counter(r["tag"].split(":")[0] if ":" in r["tag"] else "single" for r in rows)
    print("mix", dict(kind))
    per = collections.Counter()
    for r in rows:
        if r["tag"].startswith("file:"):
            continue
        for t in (r["tag"][6:].split("+") if r["tag"].startswith("combo:") else [r["tag"]]):
            per[t] += 1
    print("per intent (single + inside combos):")
    print("  " + ", ".join(f"{k}={v}" for k, v in sorted(per.items(), key=lambda x: -x[1])))
    fu = [r for r in rows if r["tag"].startswith("file:")]
    feat = collections.Counter()
    for r in fu:
        for a in r["actions"]:
            feat[a["op"] + ":" + str(a.get("name") or a.get("code") or a.get("topic") or a.get("kind") or a.get("access"))] += 1
    compose = sum("service " in r["context"]["file"]["body"] for r in fu)
    bodies = collections.Counter(r["context"]["file"]["body"] for r in fu if "service " not in r["context"]["file"]["body"])
    print(f"follow-ups {len(fu)} (compose {compose}, project files {len(fu) - compose}, distinct files {len(bodies)}, "
          f"max uses of one file {max(bodies.values()) if bodies else 0})")
    print("follow-up labels:", ", ".join(f"{k}={v}" for k, v in sorted(feat.items(), key=lambda x: -x[1])))
    refusals = collections.Counter(a["code"] for r in rows for a in r["actions"] if a["op"] == "refuse")
    print("refusal codes:", dict(sorted(refusals.items(), key=lambda x: -x[1])))
    if lens:
        print(f"tokens: median {statistics.median(lens)}, p95 {sorted(lens)[int(len(lens) * .95)]}, max {max(lens)}, "
              f"total {sum(lens)}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=2700)
    ap.add_argument("--seed", type=int, default=30)
    ap.add_argument("--out", default=str(HERE / "data" / "train.jsonl"))
    ap.add_argument("--val", type=int, default=120, help="held-out tail written to <out>.val.jsonl")
    ap.add_argument("--single", type=float, default=0.48, help="share of single-intent rows")
    ap.add_argument("--combo", type=float, default=0.22, help="share of multi-intent rows; the rest are file follow-ups")
    ap.add_argument("--max-len", type=int, default=768, help="drop rows longer than this (train.py would truncate the reply)")
    ap.add_argument("--base", default="Qwen/Qwen2.5-1.5B-Instruct", help="tokenizer for --max-len; 0 --max-len skips it")
    a = ap.parse_args()
    # pool keys may carry their slot list ("open_door{door}"); the intent id is the part before it
    pools = {re.sub(r"\{.*", "", k): v for k, v in json.loads((HERE / "data" / "pools.json").read_text()).items()}
    projects = []
    for name in ("projects.jsonl", "projects-gen.jsonl"):
        pj = HERE / "data" / name
        if pj.exists():
            projects += [json.loads(l) for l in pj.read_text().splitlines() if l.strip()]
    want = a.n + a.val
    # over-generate, then drop what does not fit max_len
    rows, skipped = build(int(want * 1.05) + 20, a.seed, pools, projects, gold_set(), (a.single, a.combo))
    lens = token_lengths(rows, a.base) if a.max_len else []
    too_long = 0
    if lens:
        keep = [(r, l) for r, l in zip(rows, lens) if l <= a.max_len]
        too_long = len(rows) - len(keep)
        rows, lens = [r for r, _ in keep], [l for _, l in keep]
    rows, lens = rows[:want], lens[:want]
    train, val = rows[: a.n], rows[a.n:]
    Path(a.out).write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in train))
    Path(a.out.replace(".jsonl", ".val.jsonl")).write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in val))
    print(f"wrote {len(train)} train, {len(val)} val; {len(projects)} project files; skipped {skipped} colliding with gold; "
          f"dropped {too_long} over {a.max_len} tokens")
    stats(train, lens[: a.n])


if __name__ == "__main__":
    main()
