import argparse
import sys
from pathlib import Path

from . import __version__
from .model import merge
from .rank import ORDER, rank
from .report import to_json, to_rotation, to_text
from .sources import GitInfo, scan_ci_log, scan_history, scan_image, scan_staged, scan_tree


def load_ignored(root: Path, extra):
    fps = set()
    for p in [root / ".leakguardignore", *([Path(extra)] if extra else [])]:
        if p.is_file():
            for line in p.read_text().splitlines():
                line = line.split("#")[0].strip()
                if line:
                    fps.add(line)
    return frozenset(fps)


def build_parser():
    ap = argparse.ArgumentParser(prog="leakguard", description="Offline scanner for leaked secrets in repos, Docker images and CI logs; ranks by exploitability and writes rotation steps.")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan a project folder, plus optional images and CI logs")
    s.add_argument("path", nargs="?", default=".", help="project folder (default: .)")
    s.add_argument("--no-history", action="store_true", help="skip git history")
    s.add_argument("--staged", action="store_true", help="scan only what is staged for the next commit (for pre-commit hooks)")
    s.add_argument("--no-tree", action="store_true", help="skip the working tree (only images/logs/history)")
    s.add_argument("--image", action="append", default=[], metavar="TAR|NAME", help="docker save tarball or local image name (repeatable)")
    s.add_argument("--ci-log", action="append", default=[], metavar="FILE", help="saved CI log file (repeatable)")
    s.add_argument("--visibility", choices=["public", "private", "unknown"], default="unknown", help="is the repo/image/logs public? offline cannot tell (default: unknown)")
    s.add_argument("--format", choices=["text", "json"], default="text")
    s.add_argument("--rotation", metavar="FILE", help="write the rotation plan (markdown) to FILE")
    s.add_argument("--ignore-file", metavar="FILE", help="extra file of fingerprints to ignore (default also reads <path>/.leakguardignore)")
    s.add_argument("--fail-on", choices=["low", "medium", "high", "critical", "never"], default="high", help="exit 1 if a finding at or above this tier exists (default: high)")
    return ap


def run(args) -> int:
    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"error: {root} is not a folder", file=sys.stderr)
        return 2
    ignored = load_ignored(root, args.ignore_file)
    info = GitInfo(root)
    findings, parts = [], []
    try:
        if args.staged:
            findings += scan_staged(root, info, ignored)
            parts.append("staged changes")
        if not args.no_tree and not args.staged:
            findings += scan_tree(root, info, ignored, exclude={Path(args.rotation).resolve()} if args.rotation else frozenset())
            parts.append("working tree")
        if info.ok and not args.no_history and not args.staged:
            findings += scan_history(root, info, ignored)
            parts.append("git history" + ("" if info.has_remote else " (no remote configured)"))
        for img in args.image:
            findings += scan_image(img, ignored)
            parts.append(f"image {img}")
        for log in args.ci_log:
            findings += scan_ci_log(Path(log), ignored)
            parts.append(f"CI log {log}")
    except (RuntimeError, OSError, KeyError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    findings = rank(merge(findings), args.visibility)
    stats = "scanned " + ", ".join(parts) + f"; visibility {args.visibility}"
    print(to_json(findings, stats) if args.format == "json" else to_text(findings, stats), end="")
    if args.rotation:
        Path(args.rotation).write_text(to_rotation(findings, stats))
    if args.fail_on == "never":
        return 0
    return 1 if any(ORDER[f.tier] >= ORDER[args.fail_on.upper()] for f in findings) else 0


def main(argv=None):
    sys.exit(run(build_parser().parse_args(argv)))
