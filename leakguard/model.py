import base64
import hashlib
import re
from dataclasses import dataclass, field
from typing import Optional

from .rules import RULES, SPECIFIC, Rule, looks_placeholder

ALLOW_MARK = "leakguard:allow"
TEST_PATH = re.compile(r"(^|/)(tests?|__tests__|spec|fixtures?|examples?|samples?|docs?|testdata|mocks?)(/|$)|[._](test|spec)\.|(^|/)test_[^/]*\.py$|_test\.(go|py|rb|js|ts)$", re.I)
B64 = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{24,2000}={0,2})(?![A-Za-z0-9+/=])")


@dataclass
class Location:
    channel: str
    path: str
    line: Optional[int] = None
    detail: str = ""
    commit: str = ""
    date: str = ""
    author: str = ""
    deleted_later: bool = False


@dataclass
class Finding:
    rule: Rule
    fingerprint: str
    redacted: str
    validity: float
    notes: list = field(default_factory=list)
    locations: list = field(default_factory=list)
    power: float = 0.0
    exposure: float = 0.0
    score: float = 0.0
    tier: str = "LOW"
    file_level: bool = False


def fingerprint(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()[:12]


def redact(secret: str) -> str:
    if len(secret) >= 12:
        return f"{secret[:4]}…{secret[-2:]} ({len(secret)} chars)"
    return f"{secret[:2]}… ({len(secret)} chars)"


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _line_text(text: str, pos: int) -> str:
    s = text.rfind("\n", 0, pos) + 1
    e = text.find("\n", pos)
    return text[s: e if e != -1 else len(text)]


def scan_text(text: str, make_location, rules=RULES, decode=True, ignored=frozenset()):
    """Return findings for one blob. make_location(line) builds the Location."""
    found: dict = {}
    taken = set()
    for rule in rules:
        for m in rule.pattern.finditer(text):
            secret = (next(g for g in m.groups() if g) if rule.group < 0 else m.group(rule.group)).strip()
            line = _line_text(text, m.start())
            if ALLOW_MARK in line:
                continue
            fp = fingerprint(secret)
            if fp in taken or fp in ignored:
                continue
            validity, note = (1.0, "")
            if rule.check:
                validity, note = rule.check(secret, line)
            if validity <= 0:
                taken.add(fp)
                continue
            if not rule.specific and looks_placeholder(secret):
                continue
            taken.add(fp)
            f = Finding(rule, fp, redact(secret), validity, [note] if note else [])
            f.locations.append(make_location(_line_of(text, m.start())))
            found[fp] = f
    if decode:
        for m in B64.finditer(text):
            blob = m.group(1)
            try:
                raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
                dec = raw.decode("ascii")
            except (ValueError, UnicodeDecodeError):
                continue
            if not dec.isprintable() and "\n" not in dec:
                continue
            line_no = _line_of(text, m.start())
            for f in scan_text(dec, lambda _l: make_location(line_no), SPECIFIC, decode=False, ignored=ignored):
                if f.fingerprint in found or f.fingerprint in taken:
                    continue
                f.notes.append("found inside a base64-encoded value (log masking and plain greps miss this)")
                found[f.fingerprint] = f
    return list(found.values())


def merge(findings):
    merged: dict = {}
    for f in findings:
        cur = merged.get(f.fingerprint)
        if cur is None:
            merged[f.fingerprint] = f
            continue
        cur.locations.extend(f.locations)
        for n in f.notes:
            if n not in cur.notes:
                cur.notes.append(n)
        if f.rule.specific and not cur.rule.specific:
            cur.rule, cur.validity = f.rule, f.validity
    return list(merged.values())


def path_adjust(f: Finding):
    """Lower validity for findings that only exist in example/test/template paths."""
    paths = [l.path for l in f.locations]
    if paths and all(TEST_PATH.search(p) or p.endswith((".example", ".sample", ".template")) for p in paths):
        f.validity *= 0.5
        f.notes.append("only seen in test/example/template paths")


def env_file_finding(path: str, loc: Location) -> Finding:
    rule = Rule("env-file", "env-file", ".env file committed or at risk", None, 3)
    f = Finding(rule, fingerprint("envfile:" + path), path, 1.0, file_level=True)
    f.locations.append(loc)
    return f
