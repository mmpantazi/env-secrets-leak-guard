"""Rotation steps per provider. Console paths drift over time, so each step names the goal first."""

PLAYBOOKS = {
    "aws": ("https://console.aws.amazon.com/iam/home#/security_credentials", [
        "Create a replacement: IAM > Users > the owning user > Security credentials > Create access key.",
        "Deploy the new key everywhere the old one was used, then set the old key to Inactive and test that nothing breaks.",
        "Delete the inactive key.",
        "Check misuse: CloudTrail > Event history > filter by Access key ID (the key ID is not secret) for the period since the first exposure; also look for new IAM users, new access keys, and EC2 instances in regions you do not use.",
        "If the key had admin rights, review IAM users/roles created recently and check Billing for unexpected spend.",
    ]),
    "github": ("https://github.com/settings/tokens", [
        "Delete the token: Settings > Developer settings > Personal access tokens (or the owning OAuth app/installation).",
        "Create a new token with the minimum scopes (fine-grained, single repo, short expiry) and update the places that used it.",
        "Check misuse: Settings > Security log for unexpected token use, and the affected repos for unknown commits, workflows or deploy keys.",
        "GitHub revokes some token types it finds in public repos on its own; do not rely on that having happened.",
    ]),
    "gitlab": ("https://gitlab.com/-/user_settings/personal_access_tokens", [
        "Revoke the token: User settings > Access tokens > Revoke.",
        "Create a replacement with the narrowest scopes and an expiry date; update CI variables and local config.",
        "Review the audit events / authentication log for the exposure window.",
    ]),
    "stripe": ("https://dashboard.stripe.com/apikeys", [
        "Roll the key: Developers > API keys > the key > Roll key. Choose to expire the old key immediately for live-mode secret keys.",
        "Put the new key into your server environment only (never client code or git).",
        "Check misuse: Developers > Logs for requests you do not recognise, and Payments/Payouts/Customers for unexpected changes.",
        "Webhook secrets: Developers > Webhooks > the endpoint > Roll secret.",
    ]),
    "anthropic": ("https://console.anthropic.com/settings/keys", [
        "Delete the key in the Console (Settings > API keys) and create a new one in the same workspace.",
        "Update your deployment's environment and any CI secrets.",
        "Check misuse: compare Console usage/cost for the exposure window against what you expect.",
    ]),
    "openai": ("https://platform.openai.com/api-keys", [
        "Revoke the key on the API keys page and create a new project-scoped key.",
        "Update deployment environment and CI secrets.",
        "Check misuse: Usage dashboard for spikes since the first exposure; consider a monthly spend limit.",
    ]),
    "google": ("https://console.cloud.google.com/apis/credentials", [
        "Decide first if this is a browser key (Maps, Firebase client): those are meant to be public and must instead be restricted by HTTP referrer/app and API.",
        "For server keys: APIs & Services > Credentials > the key > create a new key, restrict it to the needed APIs and IPs, then delete the old key.",
        "Check misuse: APIs & Services > Metrics and Billing reports for unexpected usage.",
    ]),
    "slack": ("https://api.slack.com/apps", [
        "Revoke the token: api.slack.com/apps > your app > OAuth & Permissions > revoke, or reinstall the app to issue a new token (legacy xoxp tokens: revoke from the user's account).",
        "Update the new token in your deployment.",
        "Check misuse: workspace Access logs / Audit logs for unexpected API calls.",
    ]),
    "slack-webhook": ("https://api.slack.com/apps", [
        "Remove the webhook: your app > Incoming Webhooks > delete the URL, then add a new one.",
        "Anyone with the URL could post to the channel; check the channel history for unexpected messages.",
    ]),
    "sendgrid": ("https://app.sendgrid.com/settings/api_keys", [
        "Delete the key: Settings > API Keys, then create a new key with restricted access.",
        "Check misuse: Activity feed and Email Activity for mail you did not send; watch sender reputation and abuse reports.",
    ]),
    "twilio": ("https://console.twilio.com/us1/account/keys-credentials/api-keys", [
        "Delete the API key in Console > Account > API keys & tokens and create a new one.",
        "Check misuse: Monitor > Logs > Calls/Messages and Usage for unexpected traffic or premium-number charges.",
    ]),
    "npm": ("https://www.npmjs.com/settings/~/tokens", [
        "Revoke the token: npmjs.com > profile > Access Tokens (or `npm token revoke <id>`), then create a granular token with a short expiry.",
        "Check misuse: look at the release history of every package the token could publish for versions you did not release; deprecate or unpublish any you find.",
    ]),
    "pypi": ("https://pypi.org/manage/account/#api-tokens", [
        "Remove the token: Account settings > API tokens, then create a new token scoped to a single project (or move to Trusted Publishing).",
        "Check misuse: the release history of each affected project for uploads you did not make.",
    ]),
    "digitalocean": ("https://cloud.digitalocean.com/account/api/tokens", [
        "Delete the token: API > Tokens, and generate a replacement with the least scope.",
        "Check misuse: Droplets, Spaces keys, firewalls and the account Security/activity history for things you did not create.",
    ]),
    "private-key": ("", [
        "Generate a new key pair; never reuse the exposed one.",
        "Remove the old public key from every place it was trusted: ~/.ssh/authorized_keys on servers, GitHub/GitLab SSH and deploy keys, cloud key pairs. For TLS/signing keys, revoke the certificate and reissue.",
        "Check misuse: server auth logs (`journalctl -u ssh` or /var/log/auth.log) for logins with the old key's fingerprint.",
    ]),
    "database": ("", [
        "Change the password on the database server (for PostgreSQL: `ALTER USER name PASSWORD '...'`; MySQL: `ALTER USER ... IDENTIFIED BY`), or create a new user and drop the old one.",
        "Update the connection string in your deployment secrets.",
        "Restrict network access: a managed database should accept connections only from your app's IPs/VPC, not the whole internet.",
        "Check misuse: connection logs for unfamiliar client addresses; look for new users, dumped tables or ransom notes.",
    ]),
    "jwt": ("", [
        "A JWT is a bearer session: revoke the session or user it belongs to. If it is long-lived and unrevocable, rotate the signing secret (this logs everyone out).",
        "If it contains a service credential in its claims, rotate that too.",
    ]),
    "bearer": ("", [
        "Work out which service this token authenticates to (the URL next to it usually tells you), then revoke it in that service's settings and issue a new one.",
    ]),
    "basic-auth": ("", [
        "Change the password of the account in the URL on the target service, and prefer a token with limited scope.",
        "Update the URL wherever it is configured.",
    ]),
    "generic": ("", [
        "Find what the value protects (the variable name and file usually say) and change it there; a hard-coded password is only as safe as the last person who saw it.",
        "If it is a shared or reused password, change it everywhere it is reused.",
        "If it is not a real secret (a test value), add `leakguard:allow` on that line or its fingerprint to .leakguardignore.",
    ]),
    "env-file": ("", [
        "Stop tracking it: `git rm --cached <file>` and add the filename to .gitignore.",
        "Commit a `.env.example` with fake values so others know which variables exist.",
        "Treat every real value inside the file as leaked (they appear as separate findings).",
    ]),
}

SCRUB = {
    "pushed": [
        "Only after rotating: remove the value from history, e.g. `git filter-repo --replace-text replacements.txt` (a file with `THE-SECRET==>REMOVED`) or `--invert-paths --path <file>`, then force-push all branches and tags.",
        "Forks, clones, CI caches and PR refs keep the old data, so the rewrite is hygiene, not a fix. Rotation is the fix.",
    ],
    "history-local": [
        "These commits are not on any remote yet, so you can still rewrite them before pushing: `git commit --amend` or `git rebase -i`, or `git filter-repo`. If the secret was never pushed, rotating is optional.",
    ],
    "image": [
        "Rebuild the image without the secret: use BuildKit `RUN --mount=type=secret,id=...` for build-time credentials, pass runtime values with `docker run --env-file` or your orchestrator's secrets, and add the file to .dockerignore. Deleting a file in a later layer does not remove it from earlier layers.",
        "Delete the leaked tag from every registry it was pushed to and prune cached copies; anyone who pulled it still has the secret.",
    ],
    "ci-log": [
        "Delete the affected workflow run logs (GitHub: run > ... > Delete all logs), then rotate. CI masking only matches the exact stored value, so encoded copies slip through.",
        "Stop it recurring: remove `set -x`/`env`/`printenv` from the job, never pass secrets on command lines, and register any derived value with `::add-mask::`.",
    ],
    "local-untracked": [
        "Add the file to .gitignore before your next `git add .`.",
    ],
    "local-ignored": [],
    "file": [],
}

PREVENT = [
    "Add a pre-commit hook that runs `leakguard scan --no-history --fail-on high` (or any scanner).",
    "Keep real secrets in a secrets manager or your host's environment settings, not in files inside the project.",
]


def steps_for(f):
    provider = f.rule.provider
    url, steps = PLAYBOOKS.get(provider, PLAYBOOKS["generic"])
    return url, steps
