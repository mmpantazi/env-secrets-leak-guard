"""Seeded positives and look-alike traps in the formats people actually commit."""
import unittest

from helpers import gh_token
from leakguard.model import Location, scan_text

STRIPE = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
AWS = "AKIAJ3Q7ZB5MXW2KD4PA"

POSITIVES = {
    "env-quoted-spaces": 'DB_PASSWORD="correct horse 7 battery"',
    "env-single-quoted": "API_SECRET='Zk39xQpL02mVb7Ya'",
    "env-export": "export STRIPE_SECRET_KEY=" + STRIPE,
    "yaml-compose": "    environment:\n      POSTGRES_PASSWORD: Zk39xQpL02mVb7Ya\n",
    "yaml-quoted": 'password: "Zk39xQpL02mVb7Ya"',
    "json": '{"client_secret": "Zk39xQpL02mVb7Ya"}',
    "terraform": 'access_key = "' + AWS + '"',
    "python": 'client = Client(api_key="' + STRIPE + '")',
    "js-object": "const cfg = { token: '" + gh_token() + "' };",
    "dockerfile-env": "ENV NPM_TOKEN=npm_" + "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bD1fH3jL5",
    "dockerfile-arg": "ARG GITHUB_TOKEN=" + gh_token("ghp", "Q1w2E3r4T5y6U7i8O9p0A1s2D3f4G5"),
    "curl-header": "curl -H 'Authorization: Bearer Zk39xQpL02mVb7YaQ' https://x.io",
    "url-basic": "git clone https://deploy:Zk39xQpL02mV@github.com/acme/app.git",
    "mongo": "MONGO_URL=mongodb+srv://admin:Zk39xQpL02mV@cluster0.ab12c.mongodb.net/app",
    "redis-remote": "REDIS_URL=redis://default:Zk39xQpL02mV@redis.acme.io:6379",
    "pem-json": '{"private_key": "-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\\n-----END PRIVATE KEY-----\\n"}',
    "properties": "spring.datasource.password=Zk39xQpL02mVb7Ya",
    "ini": "[smtp]\npassword = Zk39xQpL02mVb7Ya",
    "slack": "SLACK=xoxb-" + "1234567890-" + "0987654321098-" + "AbCdEfGhIjKlMnOpQrStUvWx",
    "sendgrid": "SG." + "a1B2c3D4e5F6g7H8i9J0kL" + "." + "a1B2c3D4e5F6g7H8i9J0kLa1B2c3D4e5F6g7H8i9J0k",
    "gcp-key": "key=AIza" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q",
    "pypi": "password: pypi-AgEIcHlwaS5vcmc" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6",
}

TRAPS = {
    "placeholder": "API_KEY=your_api_key_here",
    "template": "DB_PASSWORD=${DB_PASSWORD}",
    "angle": "SECRET_KEY=<generate-me>",
    "env-lookup": 'password = os.environ["DB_PASSWORD"]',
    "getenv": 'const token = process.env.API_TOKEN;',
    "doc-key": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
    "stars": "PASSWORD=************",
    "uuid": "request_id = 'f47ac10b-58cc-4372-a567-0e02b2c3d479'",
    "sha": "commit = 3a7bd3e2360a3d29eea436fcfb7e44c735d117c4",
    "integrity": 'integrity "sha512-Zk39xQpL02mVb7YaZk39xQpL02mVb7YaZk39xQpL02mVb7YaZk39xQpL02mVb7Ya=="',
    "prose": "Set the token: see the docs for details",
    "func": "def get_password(user, password_hash=None):",
    "label": "<label for=password>Password</label>",
    "token-field": "if (token === undefined) return;",
    "stripe-test": "STRIPE=sk_test_" + "4eC39HqLyjWDarjtT1zdp7dc",
    "localhost-db": "DATABASE_URL=postgres://postgres:postgres@localhost:5432/dev",
    "i18n": "forgot_password: Forgot your password?",
    "i18n-quoted": 'forgot_password: "Forgot your password?"',
    "ui-text": 'password_hint = "Use at least 8 characters."',
    "empty": 'PASSWORD=""',
    "type-hint": "secret_key: str = Field(...)",
    "import": "from secrets import token_hex",
}


def hits(text):
    return [f for f in scan_text(text, lambda ln: Location("file", "config.txt", ln)) if f.validity >= 0.5]


class Corpus(unittest.TestCase):
    def test_every_seeded_secret_is_found(self):
        missed = [k for k, t in POSITIVES.items() if not hits(t)]
        self.assertEqual(missed, [])

    def test_no_trap_is_reported(self):
        false_alarms = {k: [f.rule.id for f in hits(t)] for k, t in TRAPS.items() if hits(t)}
        self.assertEqual(false_alarms, {})


if __name__ == "__main__":
    unittest.main()
