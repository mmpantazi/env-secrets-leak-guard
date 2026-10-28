"""Where to look: working tree, git history, docker image tarballs, CI logs."""
import json
import os
import re
import subprocess
import tarfile
import tempfile
from pathlib import Path

from .model import Location, env_file_finding, scan_text
from .rules import RULES, SPECIFIC
from .rules import is_env_file, is_sensitive_file

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache", ".next", "site-packages"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".tgz", ".woff", ".woff2", ".ttf", ".so", ".pyc", ".class", ".jar", ".mp4", ".mp3", ".lock", ".svg", ".map"}
SKIP_NAMES = {".gitleaksignore", ".leakguardignore", ".secrets.baseline", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Cargo.lock", "go.sum"}
MAX_FILE = 1_000_000
IMAGE_SKIP = ("usr/lib/", "usr/share/", "usr/include/", "lib/", "var/lib/dpkg/", "var/lib/apt/", "var/cache/", "etc/ssl/certs/", "usr/local/lib/", "proc/", "sys/", "usr/bin/", "bin/", "sbin/", "usr/sbin/")
DOC_EXT = {".md", ".rst", ".txt", ".adoc", ".html"}
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
LOG_TS = re.compile(r"^\s*\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z?\s?", re.M)


def git(root, *args, check=True):
    r = subprocess.run(["git", "-C", str(root), "-c", "core.quotepath=off", *args], capture_output=True)
    if check and r.returncode:
        raise RuntimeError(r.stderr.decode(errors="replace").strip())
    return r.stdout.decode(errors="replace")


def rules_for(path: str):
    return SPECIFIC if Path(path).suffix.lower() in DOC_EXT else RULES


def is_text(data: bytes) -> bool:
    return b"\0" not in data[:8192]


class GitInfo:
    def __init__(self, root: Path):
        self.root = root
        self.ok = subprocess.run(["git", "-C", str(root), "rev-parse", "--git-dir"], capture_output=True).returncode == 0
        self.tracked = set()
        self.ignored = set()
        self.pushed = set()
        self.has_remote = False
        if not self.ok:
            return
        self.tracked = set(git(root, "ls-files", "-z").split("\0"))
        self.ignored = set(git(root, "ls-files", "-z", "-o", "-i", "--exclude-standard", check=False).split("\0"))
        self.has_remote = bool(git(root, "remote", check=False).strip())
        self.pushed = set(git(root, "rev-list", "--remotes", check=False).split())
        head = git(root, "rev-parse", "HEAD", check=False).strip()
        self.head_pushed = head in self.pushed


def scan_tree(root: Path, info: GitInfo, ignored_fps, exclude=frozenset()):
    findings = []
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            full = Path(dirpath) / name
            rel = full.relative_to(root).as_posix()
            if full.suffix.lower() in SKIP_EXT or name in SKIP_NAMES or full.is_symlink() or full.resolve() in exclude:
                continue
            if not info.ok:
                channel = "file"
            elif rel in info.tracked:
                channel = "pushed" if info.head_pushed else "history-local"
            elif rel in info.ignored:
                channel = "local-ignored"
            else:
                channel = "local-untracked"
            if (is_env_file(rel) or is_sensitive_file(rel)) and channel in ("local-untracked", "pushed", "history-local"):
                kind = "env file" if is_env_file(rel) else "sensitive file"
                f = env_file_finding(rel, Location(channel, rel, detail=kind))
                findings.append(f)
            try:
                if full.stat().st_size > MAX_FILE:
                    continue
                data = full.read_bytes()
            except OSError:
                continue
            if not is_text(data):
                continue
            text = data.decode("utf-8", errors="replace")
            findings += scan_text(text, lambda ln, c=channel, r=rel: Location(c, r, ln), rules_for(rel), ignored=ignored_fps)
    return findings


def _added_blobs(diff_output: str):
    """Yield (commit_header, path, added_text) from `git log -p` or `git diff` output."""
    cur = ("", "", "")
    path = None
    buf: list = []
    for line in diff_output.split("\n") + ["diff --git end"]:
        if line.startswith("\0") or line.startswith("diff --git "):
            if path and buf:
                yield cur, path, "\n".join(buf)
            buf, path = [], None
            if line.startswith("\0"):
                cur = tuple(line[1:].split("\x01", 2))
        elif line.startswith("+++ "):
            p = line[4:].split("\t")[0]
            path = p[2:] if p.startswith("b/") else None
        elif line.startswith("+") and path:
            buf.append(line[1:])


def _scannable(path: str, text: str) -> bool:
    return Path(path).name not in SKIP_NAMES and len(text) <= 2 * MAX_FILE and Path(path).suffix.lower() not in SKIP_EXT


def scan_history(root: Path, info: GitInfo, ignored_fps):
    findings = []
    if not info.ok:
        return findings
    out = git(root, "log", "--all", "-p", "-U0", "--no-color", "--no-ext-diff", "--format=%x00%H%x01%aI%x01%an", check=False)
    for cur, path, text in _added_blobs(out):
        if _scannable(path, text):
            channel = "pushed" if cur[0] in info.pushed else "history-local"
            findings += scan_text(text, lambda ln, c=channel, p=path, k=cur: Location(
                c, p, None, "history", k[0], k[1], k[2]), rules_for(path), ignored=ignored_fps)
    added = git(root, "log", "--all", "--diff-filter=A", "--name-only", "--format=%x00%H%x01%aI%x01%an", check=False)
    k = None
    for line in added.split("\n"):
        if line.startswith("\0"):
            h, d, a = line[1:].split("\x01", 2)
            k = (h, d, a)
        elif line and k and (is_env_file(line) or is_sensitive_file(line)):
            channel = "pushed" if k[0] in info.pushed else "history-local"
            kind = "env file" if is_env_file(line) else "sensitive file"
            findings.append(env_file_finding(line, Location(channel, line, None, "committed", k[0], k[1], k[2])))
    return findings


def scan_staged(root: Path, info: GitInfo, ignored_fps):
    """Added lines of the index (what the next commit would contain)."""
    if not info.ok:
        raise RuntimeError(f"{root} is not a git repository, --staged needs one")
    out = git(root, "diff", "--cached", "-U0", "--no-color", "--no-ext-diff", check=False)
    findings = []
    for _, path, text in _added_blobs(out):
        if _scannable(path, text):
            findings += scan_text(text, lambda ln, p=path: Location("staged", p, None, "staged for commit"),
                                  rules_for(path), ignored=ignored_fps)
        if is_env_file(path) or is_sensitive_file(path):
            findings.append(env_file_finding(path, Location("staged", path, None, "staged for commit")))
    return findings


def scan_ci_log(path: Path, ignored_fps):
    text = path.read_text(errors="replace")
    text = LOG_TS.sub("", ANSI.sub("", text))
    return scan_text(text, lambda ln: Location("ci-log", str(path), ln), ignored=ignored_fps)


def _open_image(target: str):
    if os.path.isfile(target):
        return open(target, "rb"), None
    tmp = tempfile.NamedTemporaryFile(suffix=".tar")
    try:
        r = subprocess.run(["docker", "save", target, "-o", tmp.name], capture_output=True)
    except FileNotFoundError:
        raise RuntimeError(f"'{target}' is not a file and the docker CLI is not installed; pass a `docker save` tarball")
    if r.returncode:
        raise RuntimeError(f"cannot read image '{target}': {r.stderr.decode(errors='replace').strip()}")
    return open(tmp.name, "rb"), tmp


def scan_image(target: str, ignored_fps):
    """Scan a `docker save` tarball (or an image name, saved via the local docker CLI)."""
    fh, tmp = _open_image(target)
    findings = []
    with fh, tarfile.open(fileobj=fh, mode="r:*") as outer:
        manifest = json.load(outer.extractfile("manifest.json"))[0]
        config = json.load(outer.extractfile(manifest["Config"]))
        cfg = config.get("config") or {}
        meta = [("image env", e) for e in cfg.get("Env") or []]
        meta += [("image label", f"{k}={v}") for k, v in (cfg.get("Labels") or {}).items()]
        meta += [("image cmd", " ".join(cfg.get(k) or [])) for k in ("Cmd", "Entrypoint")]
        meta += [(f"build step {i + 1}", h.get("created_by", "")) for i, h in enumerate(config.get("history", []))]
        for where, text in meta:
            findings += scan_text(text, lambda ln, w=where: Location("image", f"{target}", None, w), ignored=ignored_fps)
        layers = manifest["Layers"]
        whiteouts = []
        per_layer = []
        for idx, name in enumerate(layers):
            wo = set()
            files = []
            with tarfile.open(fileobj=outer.extractfile(name), mode="r|*") as layer:
                for m in layer:
                    base = os.path.basename(m.name)
                    if base.startswith(".wh."):
                        wo.add(os.path.join(os.path.dirname(m.name), base[4:]).removeprefix("./"))
                        continue
                    if not m.isfile() or m.size > MAX_FILE or m.size == 0:
                        continue
                    rel = m.name[2:] if m.name.startswith("./") else m.name
                    if rel.startswith(IMAGE_SKIP) or "/node_modules/" in rel or "/site-packages/" in rel:
                        continue
                    body = layer.extractfile(m).read()
                    if is_text(body):
                        files.append((rel, body.decode("utf-8", errors="replace")))
            whiteouts.append(wo)
            per_layer.append(files)
        for idx, files in enumerate(per_layer):
            later = set().union(*whiteouts[idx + 1:]) if idx + 1 < len(whiteouts) else set()
            for rel, text in files:
                deleted = rel in later
                if is_env_file(rel) or is_sensitive_file(rel):
                    findings.append(env_file_finding(rel, Location("image", target, None, f"layer {idx + 1}: {rel}", deleted_later=deleted)))
                for f in scan_text(text, lambda ln, r=rel, d=deleted, i=idx: Location(
                        "image", f"{target}:{r}", ln, f"layer {i + 1}", deleted_later=d), rules_for(rel), ignored=ignored_fps):
                    findings.append(f)
    if tmp:
        tmp.close()
    return findings
