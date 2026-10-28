# leakguard

Offline scanner that finds committed secrets and `.env` leaks in **git repos, Docker images and CI logs**, ranks them by how exploitable they are, and writes a step-by-step **rotation plan**. Python standard library only, no network access, secrets are never printed in full.

RO: găsește parole și chei scăpate în repo-uri, imagini Docker și loguri CI, le ordonează după cât de periculoase sunt și scrie pașii de rotire.

## Why another scanner

Gitleaks, TruffleHog and detect-secrets answer "is there a secret-shaped string?". A solo developer with 40 findings needs to know which one to fix first and what to click. leakguard ranks findings and prints the fix. Unlike TruffleHog/Kingfisher it never sends a candidate secret to a provider to check it, so it works on an air-gapped laptop and cannot leak what it finds.

## Install and run

```bash
pip install .            # or run in place: python -m leakguard ...
leakguard scan .                                   # working tree + full git history
leakguard scan . --rotation ROTATION.md            # also write the rotation plan
leakguard scan . --image app.tar                   # a `docker save app:latest -o app.tar` tarball
leakguard scan . --image myapp:latest              # or an image name (needs the docker CLI)
leakguard scan . --ci-log run1.log --ci-log run2.log
leakguard scan . --visibility public --format json
leakguard scan . --min-tier high                    # hide medium/low findings in the output
```

Needs Python 3.9+ and `git` on PATH. Exit code is 1 when a finding at or above `--fail-on` (default `high`) exists, so it works as a pre-commit/CI gate (`--no-history` for speed, or `--staged` to look only at what the next commit would add).

### As a pre-commit hook

Plain git hook (`.git/hooks/pre-commit`, then `chmod +x`):

```sh
#!/bin/sh
exec python -m leakguard scan --staged --fail-on high
```

or with the pre-commit framework, point `repo:` at this repository and use hook id `leakguard` (`.pre-commit-hooks.yaml`).

## What it looks at

| Source | What is scanned |
|---|---|
| Working tree | text files; skips `.git`, `node_modules`, venvs, binaries, files over 1 MB |
| Git history | every line ever added on any branch, including secrets deleted later; `.env`/key files ever committed |
| Docker image | each layer's files (also files deleted in a later layer), `ENV`, labels, `CMD`, and build steps (`ARG` values) |
| CI logs | saved log files with ANSI colours and timestamps stripped; credentials in `Authorization:` headers, `env` dumps, `set -x` echoes |
| Any of them | secrets hidden in base64 (Kubernetes `Secret` YAML, unmasked derived values in logs) |

About 30 rules: AWS, Azure storage, GitHub, GitLab, Stripe, OpenAI, Anthropic, Groq, Hugging Face, Google, Slack, SendGrid, Twilio, Mailgun, Shopify, Telegram, npm, PyPI, DigitalOcean, private keys, JWTs, passwords in database/broker URLs, auth headers, plus a generic `NAME_PASSWORD=value` rule.

## How findings are ranked

`score = power x exposure x validity` (0 to 10): CRITICAL >= 7, HIGH >= 4, MEDIUM >= 2, else LOW.

- **power**: what the credential can do. AWS keys 9, live Stripe 9, npm/PyPI/GitHub/DigitalOcean 8, database passwords 8, private keys 9, Google API keys 4 (often meant to be public).
- **exposure**: how far it travelled. Pushed to a remote, baked into an image, or printed in a CI log counts most; committed but unpushed is 0.3; git-ignored local file is 0.15. `--visibility public|private` adjusts this because offline cannot tell.
- **validity** (offline checks): GitHub token CRC32 checksum, AWS documentation keys, Stripe test vs live, expired JWTs, localhost database URLs, placeholders (`changeme`, `${VAR}`, `<token>`), values that look like code, and test/example paths.

Findings for the same secret in several places are merged; the worst exposure wins.

## Rotation plan

`--rotation ROTATION.md` writes, per finding: where it is, since when, and provider-specific steps in the right order: **rotate, check provider logs for the exposure window, then scrub** (history rewrite, rebuild image without the secret, delete CI logs). Dashboard paths change, so each step states its goal.

## Ignoring false positives

- Inline: put `leakguard:allow` on the line.
- By fingerprint: the `id:` shown for each finding goes into `.leakguardignore` (one per line, `#` comments allowed) or `--ignore-file`.
- `.env.example`/`.sample`/`.template` files are never reported as leaked `.env` files.

## Limits

- No live check whether a key still works. Treat every ranked finding as live until the provider says otherwise.
- Regex rules cover the common providers, not every SaaS. The generic rule catches `*_PASSWORD=...` style assignments; unusual formats can be missed.
- "Pushed" means reachable from a remote ref known locally (run `git fetch` first). History scanning covers `git log --all`; stashes, reflog-only and dangling commits are not read.
- GitHub tokens are checked with the documented CRC32/base62 checksum; other formats are matched by shape only.
- Images: pass a `docker save` tarball or a name; OCI-only layouts without `manifest.json` are not read. System paths (`/usr/lib`, `/usr/share`, ...) are skipped.

## Accuracy

`tests/test_corpus.py` holds 21 seeded secrets (env files, YAML, JSON, Terraform, Dockerfile, curl, git URLs, PEM-in-JSON, ...) and 25 look-alike traps (placeholders, env lookups, UUIDs, hashes, test keys, UI text); all seeds are found and no trap is reported. This is a small author-written set, not an independent benchmark. On real repos (flask, express) it reports nothing but a test `.env`.

## Development

```bash
PYTHONPATH=tests:. python -m unittest discover -s tests
```
