"""Exploitability = what the key can do x how widely it is exposed x whether it looks real."""
from .model import path_adjust

EXPOSURE = {
    "pushed": {"public": 1.0, "unknown": 0.85, "private": 0.6},
    "image": {"public": 1.0, "unknown": 0.85, "private": 0.55},
    "ci-log": {"public": 0.95, "unknown": 0.8, "private": 0.45},
}
FIXED = {"history-local": 0.3, "local-untracked": 0.5, "file": 0.5, "local-ignored": 0.15}
TIERS = [(7.0, "CRITICAL"), (4.0, "HIGH"), (2.0, "MEDIUM"), (0.0, "LOW")]
ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def exposure_of(channel: str, visibility: str) -> float:
    if channel in EXPOSURE:
        return EXPOSURE[channel][visibility]
    return FIXED[channel]


def rank(findings, visibility="unknown"):
    for f in findings:
        path_adjust(f)
        f.power = f.rule.power
        f.exposure = max(exposure_of(l.channel, visibility) for l in f.locations)
        f.score = round(f.power * f.exposure * f.validity, 1)
        f.tier = next(name for floor, name in TIERS if f.score >= floor)
        if f.file_level:
            f.score = min(f.score, 3.9)
            f.tier = next(name for floor, name in TIERS if f.score >= floor)
    findings.sort(key=lambda f: (-f.score, f.rule.id, f.fingerprint))
    return findings


def first_seen(f):
    dated = sorted(l.date for l in f.locations if l.date)
    return dated[0] if dated else ""
