"""Detection rules and the offline checks that decide how much a match is worth."""
import base64
import json
import math
import re
import time
import zlib
from dataclasses import dataclass
from typing import Callable, Optional

B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


@dataclass(frozen=True)
class Rule:
    id: str
    provider: str
    label: str
    pattern: "re.Pattern[str]"
    power: float
    group: int = 0
    specific: bool = True
    check: Optional[Callable[[str, str], "tuple[float, str]"]] = None


def entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in (s.count(ch) for ch in set(s)))


def b62(n: int) -> str:
    out = ""
    while n:
        n, r = divmod(n, 62)
        out = B62[r] + out
    return out


def github_checksum_ok(token: str) -> bool:
    body = token.split("_", 1)[1]
    if len(body) != 36:
        return True
    return b62(zlib.crc32(body[:30].encode())).rjust(6, "0") == body[30:]


PLACEHOLDER_WORDS = (
    "changeme", "change_me", "change-me", "example", "placeholder", "your_", "your-", "yourkey",
    "xxxx", "****", "dummy", "sample", "redacted", "todo", "fixme", "insert", "replace", "<", "{{",
    "${", "$(", "%(", "process.env", "os.environ", "getenv", "secrets.", "env.", "null", "none",
    "undefined", "password123", "12345678", "abcdefgh", "foobar", "notasecret", "not_a_secret",
)
LOCAL_HOSTS = ("localhost", "127.0.0.1", "0.0.0.0", "::1", "host.docker.internal")


def looks_placeholder(value: str) -> bool:
    v = value.lower()
    if any(w in v for w in PLACEHOLDER_WORDS):
        return True
    return len(set(v)) <= 2


def _github(secret: str, _line: str):
    if secret.startswith("github_pat_"):
        return 1.0, ""
    if github_checksum_ok(secret):
        if secret.startswith("ghs_"):
            return 0.3, "server-to-server token, expires after about an hour"
        return 1.0, "checksum valid"
    return 0.3, "checksum mismatch: probably not a real token"


def _aws_id(secret: str, _line: str):
    if secret.endswith("EXAMPLE"):
        return 0.0, "AWS documentation example key"
    if secret.startswith("ASIA"):
        return 0.55, "temporary STS key, expires on its own (usually within hours)"
    return 1.0, "long-lived key ID"


def _stripe(secret: str, _line: str):
    if "_test_" in secret:
        return 0.2, "test-mode key, cannot move real money"
    return 1.0, "live-mode key"


def _jwt(secret: str, _line: str):
    try:
        payload = secret.split(".")[1]
        data = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (ValueError, IndexError):
        return 1.0, ""
    exp = data.get("exp") if isinstance(data, dict) else None
    if isinstance(exp, (int, float)) and exp < time.time():
        return 0.15, "token already expired"
    return 1.0, "not expired" if exp else "no expiry claim"


def _dburl(secret: str, line: str):
    m = re.search(r"@([^/\s'\"?]+)", line)
    host = (m.group(1) if m else "").split(":")[0].lower()
    if looks_placeholder(secret):
        return 0.0, "placeholder password"
    if host in LOCAL_HOSTS:
        return 0.2, "points at localhost"
    if "." not in host:
        return 0.4, f"host '{host}' looks like a local container/service name"
    return 1.0, f"remote host {host}"


DOTTED_IDENT = re.compile(r"^[A-Za-z_][A-Za-z_]*(\.[A-Za-z_][A-Za-z_]*)+$")
BARE_ASSIGN = re.compile(r"^(export\s+)?[A-Za-z0-9_\-]+\s*[=:]\s*[^\s\"'(),;]+$")


def _generic(secret: str, line: str):
    if looks_placeholder(secret):
        return 0.0, "placeholder"
    if secret.startswith(("/", "./", "http://", "https://")) and "@" not in secret:
        return 0.0, "path or URL"
    if "(" in secret or "[" in secret:
        return 0.0, "looks like code"
    if DOTTED_IDENT.match(secret):
        return 0.0, "looks like a code reference"
    has_digit = any(c.isdigit() for c in secret)
    if " " in secret and not (has_digit and not secret.endswith(("?", ".", "!", ":"))):
        return 0.0, "sentence, not a secret"
    has_symbol = any(c in "!@#$%^&*+~|?" for c in secret)
    if not (has_digit or has_symbol) and len(secret) < 20 and not BARE_ASSIGN.match(line.strip()):
        return 0.0, "plain word in code or prose"
    if not (has_digit or has_symbol) and len(secret) < 20:
        return 0.5, "plain word, probably a weak or dev password"
    h = entropy(secret)
    if h < 2.5 and len(secret) < 14:
        return 0.35, "low-entropy value, probably a weak or dev password"
    return 1.0, ""


def _r(p: str, flags: int = 0) -> "re.Pattern[str]":
    return re.compile(p, flags)


RULES = [
    Rule("aws-access-key-id", "aws", "AWS access key ID", _r(r"\b((?:AKIA|ASIA)[A-Z0-9]{16})\b"), 9, 1, check=_aws_id),
    Rule("aws-secret-access-key", "aws", "AWS secret access key",
         _r(r"(?i)aws_?secret_?(?:access_?)?key[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})\b"), 10, 1,
         check=lambda s, l: (0.0, "AWS documentation example") if s.endswith("EXAMPLEKEY") else (1.0, "")),
    Rule("github-token", "github", "GitHub token", _r(r"\b(gh[pousr]_[A-Za-z0-9]{36})\b"), 8, 1, check=_github),
    Rule("github-fine-grained", "github", "GitHub fine-grained token", _r(r"\b(github_pat_[A-Za-z0-9_]{70,100})\b"), 8, 1, check=_github),
    Rule("gitlab-token", "gitlab", "GitLab personal access token", _r(r"\b(glpat-[A-Za-z0-9_\-]{20})\b"), 8, 1),
    Rule("stripe-secret", "stripe", "Stripe secret/restricted key", _r(r"\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,99})\b"), 9, 1, check=_stripe),
    Rule("stripe-webhook", "stripe", "Stripe webhook signing secret", _r(r"\b(whsec_[A-Za-z0-9]{32,})\b"), 6, 1),
    Rule("anthropic-key", "anthropic", "Anthropic API key", _r(r"\b(sk-ant-[A-Za-z0-9_\-]{40,})"), 7, 1),
    Rule("openai-key", "openai", "OpenAI API key", _r(r"\b(sk-(?!ant-)(?:proj-|svcacct-)?[A-Za-z0-9_\-]{32,})"), 7, 1),
    Rule("google-api-key", "google", "Google API key", _r(r"\b(AIza[0-9A-Za-z_\-]{35})\b"), 4, 1),
    Rule("slack-token", "slack", "Slack token", _r(r"\b(xox[abprs]-[A-Za-z0-9\-]{10,})"), 6, 1),
    Rule("slack-webhook", "slack-webhook", "Slack incoming webhook",
         _r(r"(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,})"), 4, 1),
    Rule("sendgrid-key", "sendgrid", "SendGrid API key", _r(r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b"), 7, 1),
    Rule("twilio-key", "twilio", "Twilio API key", _r(r"\b(SK[0-9a-f]{32})\b"), 6, 1),
    Rule("npm-token", "npm", "npm access token", _r(r"\b(npm_[A-Za-z0-9]{36})\b"), 8, 1),
    Rule("pypi-token", "pypi", "PyPI API token", _r(r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})"), 8, 1),
    Rule("digitalocean-token", "digitalocean", "DigitalOcean token", _r(r"\b(dop_v1_[a-f0-9]{64})\b"), 8, 1),
    Rule("huggingface-token", "huggingface", "Hugging Face token", _r(r"\b(hf_[A-Za-z]{34})\b"), 6, 1),
    Rule("groq-key", "groq", "Groq API key", _r(r"\b(gsk_[A-Za-z0-9]{52})\b"), 6, 1),
    Rule("shopify-token", "shopify", "Shopify access token", _r(r"\b(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})\b"), 8, 1),
    Rule("mailgun-key", "mailgun", "Mailgun API key", _r(r"\b(key-[0-9a-f]{32})\b"), 6, 1),
    Rule("telegram-bot-token", "telegram", "Telegram bot token", _r(r"\b(\d{8,10}:AA[A-Za-z0-9_\-]{33})\b"), 5, 1),
    Rule("azure-storage-key", "azure", "Azure storage account key", _r(r"AccountKey=([A-Za-z0-9+/]{86}==)"), 9, 1),
    Rule("private-key", "private-key", "Private key",
         _r(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----((?:\\n|\s)*[A-Za-z0-9+/=]{20,})"), 9, 1),
    Rule("db-url-password", "database", "Password in database/broker URL",
         _r(r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?)://[^\s:/@'\"]+:([^\s@'\"/]{4,})@[^\s/'\"?]+"), 8, 1, check=_dburl),
    Rule("jwt", "jwt", "JSON Web Token", _r(r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})"), 5, 1, check=_jwt),
    Rule("auth-header", "bearer", "Authorization header credential",
         _r(r"(?i)authorization[\"']?\s*[:=]\s*[\"']?(?:bearer|token|basic)\s+([A-Za-z0-9._~+/=\-]{16,})"), 6, 1,
         specific=False, check=_generic),
    Rule("basic-auth-url", "basic-auth", "Password in URL",
         _r(r"\bhttps?://[^\s:/@'\"]+:([^\s@'\"/]{4,})@[A-Za-z0-9.\-]+"), 6, 1, specific=False, check=_generic),
    Rule("generic-secret", "generic", "Hard-coded secret assignment",
         _r(r"(?i)\b[A-Za-z0-9_.\-]*(?:password|passwd|secret|token|api_?key|access_?key|private_?key|auth_?key|credentials?)[A-Za-z0-9_.\-]*[\"']?[ \t]*[:=][ \t]*(?:\"([^\"\n]{8,})\"|'([^'\n]{8,})'|`([^`\n]{8,})`|([^\s\"'`#,;]{8,}))"),
         5, -1, specific=False, check=_generic),
]

SPECIFIC = [r for r in RULES if r.specific]

ENV_FILE = re.compile(r"(^|/)\.env(\.[A-Za-z0-9_\-]+)*$")
ENV_TEMPLATE = re.compile(r"\.(example|sample|template|dist|defaults?)$", re.I)
SENSITIVE_FILES = re.compile(
    r"(^|/)(id_rsa|id_dsa|id_ecdsa|id_ed25519|\.pgpass|\.netrc|\.htpasswd|terraform\.tfstate(\.backup)?|"
    r"[^/]+\.(pem|p12|pfx|jks|keystore)|credentials\.json|service-?account[^/]*\.json)$"
)


def is_env_file(path: str) -> bool:
    return bool(ENV_FILE.search(path)) and not ENV_TEMPLATE.search(path)


def is_sensitive_file(path: str) -> bool:
    return bool(SENSITIVE_FILES.search(path))
