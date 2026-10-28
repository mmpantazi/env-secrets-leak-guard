import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from leakguard.cli import build_parser, run
from leakguard.model import merge, scan_text
from leakguard.model import Location
from leakguard.rank import rank
from leakguard.report import to_json, to_rotation, to_text
from leakguard.rules import github_checksum_ok
from leakguard.sources import GitInfo, scan_ci_log, scan_history, scan_image, scan_staged, scan_tree

from helpers import gh_token, git, make_image

AWS = "AKIAJ3Q7ZB5MXW2KD4PA"
STRIPE = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"


def scan(text, rules=None):
    kw = {"rules": rules} if rules else {}
    return scan_text(text, lambda ln: Location("file", "x", ln), **kw)


class Detection(unittest.TestCase):
    def test_github_checksum(self):
        good = gh_token()
        self.assertTrue(github_checksum_ok(good))
        f = scan(f"T={good}")[0]
        self.assertEqual(f.rule.id, "github-token")
        self.assertEqual(f.validity, 1.0)
        fake = good[:-1] + ("A" if good[-1] != "A" else "B")
        self.assertLess(scan(f"T={fake}")[0].validity, 0.5)

    def test_aws_example_key_ignored_and_sts_downweighted(self):
        self.assertEqual(scan("AKIAIOSFODNN7EXAMPLE"), [])
        self.assertLess(scan("ASIAJ3Q7ZB5MXW2KD4PA")[0].validity, 1)

    def test_stripe_test_vs_live(self):
        live = scan(STRIPE)[0]
        test = scan(STRIPE.replace("live", "test"))[0]
        self.assertEqual(live.validity, 1.0)
        self.assertLess(test.validity, 0.5)

    def test_db_url_local_vs_remote(self):
        local = scan("DATABASE_URL=postgres://app:Zq81xKd2@localhost:5432/db")
        remote = scan("DATABASE_URL=postgres://app:Zq81xKd2@db.prod.example.net:5432/db")
        self.assertEqual(local[0].rule.id, "db-url-password")
        self.assertLess(local[0].validity, remote[0].validity)

    def test_placeholders_not_reported(self):
        for t in ["API_KEY=your_api_key_here", "PASSWORD=changeme", "SECRET_KEY=${SECRET_KEY}", "token: <token>",
                  'password = os.environ["PASSWORD"]', "PASSWORD=********", "api_key = get_key()", "TOKEN=process.env.TOKEN"]:
            self.assertEqual(scan(t), [], t)

    def test_code_and_prose_not_reported(self):
        for t in ["var secret = this.req.secret;", "SECRET_KEY = 'development key'", 'app.secret_key = "secret_key"',
                  "secret: 'keyboard cat'", "connect(password=secret)", 'msg = "Revoke the token: npmjs.com > profile"',
                  "Webhook secrets: Developers > Webhooks", "Secret: requiredFinding.Secret,", "baseRule.SecretGroup = currentRule.SecretGroup",
                  "x = `password: someLongWordHere`"]:
            self.assertEqual(scan(t), [], t)

    def test_bare_env_word_password_is_kept_but_weak(self):
        f = scan("DB_PASSWORD=postgres")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].validity, 0.5)

    def test_generic_env_secret(self):
        f = scan("STRIPE_WEBHOOK_TOKEN=Zk39xQpL02mVb7Ya")
        self.assertEqual(f[0].rule.id, "generic-secret")

    def test_specific_rule_wins_over_generic(self):
        f = scan(f"GITHUB_TOKEN={gh_token()}")
        self.assertEqual([x.rule.id for x in f], ["github-token"])

    def test_json_style_assignment(self):
        self.assertEqual(scan('{"db_password": "Zk39xQpL02mVb7Ya"}')[0].rule.id, "generic-secret")

    def test_private_key(self):
        pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAyV3qk2lP0aQxYbN8\n-----END RSA PRIVATE KEY-----"
        self.assertEqual(scan(pem)[0].rule.id, "private-key")
        self.assertEqual(scan("-----BEGIN CERTIFICATE-----\nMIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJJ\n"), [])

    def test_jwt_expired(self):
        import base64
        def seg(d):
            return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
        old = f"{seg({'alg': 'HS256'})}.{seg({'exp': 1000})}.c2lnbmF0dXJlLXNpZw"
        new = f"{seg({'alg': 'HS256'})}.{seg({'exp': 4102444800})}.c2lnbmF0dXJlLXNpZw"
        self.assertLess(scan(old)[0].validity, 0.2)
        self.assertEqual(scan(new)[0].validity, 1.0)

    def test_inline_allow(self):
        self.assertEqual(scan(f"k = '{AWS}'  # leakguard:allow"), [])

    def test_base64_wrapped_secret(self):
        import base64
        enc = base64.b64encode(f"token={gh_token()}".encode()).decode()
        f = scan_text(f"data:\n  value: {enc}\n", lambda ln: Location("file", "k8s.yaml", ln))
        self.assertEqual(f[0].rule.id, "github-token")
        self.assertTrue(any("base64" in n for n in f[0].notes))

    def test_full_secret_never_in_reports(self):
        f = rank(merge(scan(f"A={STRIPE}\nB={gh_token()}")))
        for out in (to_text(f, "s"), to_json(f, "s"), to_rotation(f, "s")):
            self.assertNotIn(STRIPE, out)
            self.assertNotIn(gh_token(), out)


class MoreRules(unittest.TestCase):
    def test_new_providers(self):
        cases = {
            "huggingface-token": "hf_" + "aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgH",
            "groq-key": "gsk_" + "a1B2c3D4e5" * 5 + "a1",
            "shopify-token": "shpat_" + "0123456789abcdef" * 2,
            "mailgun-key": "key-" + "0123456789abcdef" * 2,
            "telegram-bot-token": "123456789:AA" + "a1B2c3D4e5" * 3 + "a1B",
            "azure-storage-key": "AccountKey=" + "A1b2C3d4" * 10 + "A1b2C3==",
        }
        for rule, text in cases.items():
            self.assertEqual(scan(f"x = '{text}'")[0].rule.id, rule, rule)

    def test_ghs_is_short_lived(self):
        self.assertLess(scan(gh_token("ghs"))[0].validity, 0.5)


class Ranking(unittest.TestCase):
    def tier(self, text, channel="pushed", vis="unknown"):
        f = scan_text(text, lambda ln: Location(channel, "f", ln))
        return rank(merge(f), vis)[0]

    def test_live_aws_pushed_is_critical(self):
        self.assertEqual(self.tier(f"AWS={AWS}").tier, "CRITICAL")

    def test_same_key_local_ignored_is_low(self):
        self.assertEqual(self.tier(f"AWS={AWS}", "local-ignored").tier, "LOW")

    def test_unpushed_history_lower_than_pushed(self):
        self.assertLess(self.tier(STRIPE, "history-local").score, self.tier(STRIPE, "pushed").score)

    def test_visibility_changes_score(self):
        self.assertGreater(self.tier(STRIPE, vis="public").score, self.tier(STRIPE, vis="private").score)

    def test_max_exposure_across_locations(self):
        a = scan_text(STRIPE, lambda ln: Location("local-ignored", "a", ln))
        b = scan_text(STRIPE, lambda ln: Location("pushed", "b", ln))
        r = rank(merge(a + b))
        self.assertEqual(len(r), 1)
        self.assertEqual(len(r[0].locations), 2)
        self.assertEqual(r[0].exposure, 0.85)

    def test_test_path_halves(self):
        f = scan_text(STRIPE, lambda ln: Location("pushed", "tests/fixtures/a.py", ln))
        plain = scan_text(STRIPE, lambda ln: Location("pushed", "src/a.py", ln))
        self.assertLess(rank(merge(f))[0].score, rank(merge(plain))[0].score)


class Sources(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.dir = Path(self._t.name)

    def tearDown(self):
        self._t.cleanup()

    def repo(self):
        r = self.dir / "repo"
        r.mkdir()
        git(r, "init", "-q")
        return r

    def test_history_finds_removed_secret_and_env_file(self):
        r = self.repo()
        (r / ".env").write_text(f"STRIPE_KEY={STRIPE}\n")
        (r / "app.py").write_text("print(1)\n")
        git(r, "add", "."); git(r, "commit", "-qm", "one")
        (r / ".env").unlink()
        git(r, "add", "-A"); git(r, "commit", "-qm", "two")
        info = GitInfo(r)
        found = rank(merge(scan_tree(r, info, frozenset()) + scan_history(r, info, frozenset())))
        ids = {f.rule.id for f in found}
        self.assertIn("stripe-secret", ids)
        self.assertIn("env-file", ids)
        s = next(f for f in found if f.rule.id == "stripe-secret")
        self.assertEqual(s.locations[0].channel, "history-local")
        self.assertTrue(s.locations[0].commit)

    def test_staged_scan(self):
        r = self.repo()
        (r / "old.py").write_text(f'K = "{AWS}"\n')
        git(r, "add", "."); git(r, "commit", "-qm", "one")
        (r / "new.py").write_text(f'K = "{STRIPE}"\n')
        (r / ".env").write_text("A=1\n")
        git(r, "add", "new.py", ".env")
        found = rank(merge(scan_staged(r, GitInfo(r), frozenset())))
        self.assertEqual({f.rule.id for f in found}, {"stripe-secret", "env-file"})
        self.assertEqual(found[0].tier, "CRITICAL")
        self.assertIn("staged for the next commit", to_text(found, "x"))

    def test_staged_needs_git(self):
        with self.assertRaises(RuntimeError):
            scan_staged(self.dir, GitInfo(self.dir), frozenset())

    def test_removed_from_head_is_explained(self):
        remote = self.dir / "remote.git"
        remote.mkdir()
        git(remote, "init", "-q", "--bare")
        r = self.repo()
        git(r, "remote", "add", "origin", str(remote))
        (r / "a.py").write_text(f'KEY = "{STRIPE}"\n')
        git(r, "add", "."); git(r, "commit", "-qm", "one")
        (r / "a.py").write_text("KEY = None\n")
        git(r, "commit", "-qam", "two")
        git(r, "push", "-q", "origin", "HEAD")
        info = GitInfo(r)
        found = rank(merge(scan_tree(r, info, frozenset()) + scan_history(r, info, frozenset())))
        self.assertIn("still in git history", to_text(found, "x"))
        self.assertIn("Fix first", to_text(found, "x"))

    def test_scan_subfolder_of_repo(self):
        r = self.repo()
        (r / "sub").mkdir()
        (r / "sub" / "a.py").write_text(f'KEY = "{STRIPE}"\n')
        git(r, "add", "."); git(r, "commit", "-qm", "one")
        info = GitInfo(r / "sub")
        found = scan_tree(r / "sub", info, frozenset())
        self.assertEqual(found[0].locations[0].channel, "history-local")

    def test_pushed_vs_unpushed(self):
        remote = self.dir / "remote.git"
        remote.mkdir()
        git(remote, "init", "-q", "--bare")
        r = self.repo()
        git(r, "remote", "add", "origin", str(remote))
        (r / "a.py").write_text(f'KEY = "{STRIPE}"\n')
        git(r, "add", "."); git(r, "commit", "-qm", "one")
        git(r, "push", "-q", "origin", "HEAD")
        info = GitInfo(r)
        found = rank(merge(scan_history(r, info, frozenset())))
        self.assertEqual(found[0].locations[0].channel, "pushed")
        self.assertEqual(found[0].tier, "CRITICAL")

    def test_gitignored_env_is_local_only(self):
        r = self.repo()
        (r / ".gitignore").write_text(".env\n")
        (r / ".env").write_text(f"AWS_ACCESS_KEY_ID={AWS}\n")
        git(r, "add", "."); git(r, "commit", "-qm", "one")
        found = rank(merge(scan_tree(r, GitInfo(r), frozenset())))
        self.assertEqual(found[0].locations[0].channel, "local-ignored")
        self.assertEqual(found[0].tier, "LOW")
        self.assertNotIn("env-file", {f.rule.id for f in found})

    def test_untracked_env_flagged(self):
        r = self.repo()
        (r / ".env").write_text("DEBUG=1\n")
        found = merge(scan_tree(r, GitInfo(r), frozenset()))
        self.assertEqual([f.rule.id for f in found], ["env-file"])

    def test_env_example_not_flagged(self):
        r = self.repo()
        (r / ".env.example").write_text("API_KEY=your_api_key_here\n")
        self.assertEqual(scan_tree(r, GitInfo(r), frozenset()), [])

    def test_non_git_folder(self):
        d = self.dir / "plain"
        d.mkdir()
        (d / "c.py").write_text(f"k='{AWS}'\n")
        (d / "node_modules").mkdir()
        (d / "node_modules" / "x.js").write_text(f"k='{AWS}'\n")
        found = scan_tree(d, GitInfo(d), frozenset())
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].locations[0].channel, "file")

    def test_ci_log_strips_ansi_and_timestamps(self):
        log = self.dir / "run.log"
        log.write_text(f"2026-10-01T10:00:00.123Z \x1b[36mexport STRIPE=\x1b[0m\n2026-10-01T10:00:01Z curl -H 'Authorization: Bearer {gh_token('gho')}' x\n"
                       f"2026-10-01T10:00:02Z token is ***\n2026-10-01T10:00:03Z KEY={STRIPE}\n")
        found = scan_ci_log(log, frozenset())
        ids = {f.rule.id for f in found}
        self.assertIn("stripe-secret", ids)
        self.assertEqual({f.locations[0].channel for f in found}, {"ci-log"})

    def test_github_actions_style_log(self):
        log = self.dir / "gha.log"
        log.write_text(
            "2026-10-01T10:00:00.1234567Z ##[group]Run ./deploy.sh\n"
            "2026-10-01T10:00:00.2000000Z env:\n"
            "2026-10-01T10:00:00.2000001Z   API_TOKEN: ***\n"
            f"2026-10-01T10:00:00.3000000Z + curl -s -H 'Authorization: Bearer {gh_token('gho')}' https://api.example.net\n"
            f"2026-10-01T10:00:00.4000000Z + export DB_PASSWORD=Zk39xQpL02mVb7Ya\n"
            "2026-10-01T10:00:00.5000000Z ##[endgroup]\n")
        found = scan_ci_log(log, frozenset())
        self.assertEqual({f.rule.id for f in found}, {"github-token", "generic-secret"})
        self.assertTrue(all(f.locations[0].line for f in found))

    def test_image_layers_config_and_deleted_file(self):
        img = self.dir / "img.tar"
        make_image(img, [{"app/.env": f"SK={STRIPE}\n", "usr/lib/x.txt": f"SK={AWS}\n"}, {"app/.wh..env": ""}],
                   env=[f"DB=postgres://u:Zq81xKd2@db.prod.example.net/x"], history=["ARG NPM_TOKEN=npm_" + "a" * 36])
        found = rank(merge(scan_image(str(img), frozenset())))
        ids = {f.rule.id for f in found}
        self.assertTrue({"stripe-secret", "db-url-password", "npm-token", "env-file"} <= ids)
        self.assertNotIn("aws-access-key-id", ids)
        s = next(f for f in found if f.rule.id == "stripe-secret")
        self.assertTrue(s.locations[0].deleted_later)
        self.assertIn("deleted in a later layer", to_text([s], "x"))

    def test_gzip_layers(self):
        img = self.dir / "gz.tar"
        make_image(img, [{"srv/config.ini": f"password = Zk39xQpL02mVb7Ya\nkey={AWS}\n"}], gz=True)
        self.assertEqual({f.rule.id for f in scan_image(str(img), frozenset())}, {"generic-secret", "aws-access-key-id"})

    def test_missing_image_is_error(self):
        with self.assertRaises(RuntimeError):
            scan_image("no-such-image-xyz:1", frozenset())


class Cli(unittest.TestCase):
    def test_end_to_end_and_exit_codes(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            git(d, "init", "-q")
            (d / "a.py").write_text(f"KEY='{STRIPE}'\n")
            (d / "ok.py").write_text("x = 1\n")
            rot = d / "ROT.md"
            args = build_parser().parse_args(["scan", str(d), "--rotation", str(rot), "--format", "json"])
            self.assertEqual(run(args), 1)
            md = rot.read_text()
            self.assertIn("Roll the key", md)
            self.assertIn("rotate first", md)
            fp = next(l for l in md.splitlines() if "Fingerprint" in l).split("`")[1]
            (d / ".leakguardignore").write_text(f"{fp}  # test key\n")
            self.assertEqual(run(build_parser().parse_args(["scan", str(d)])), 0)

    def test_staged_flag_and_exit(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            git(d, "init", "-q")
            (d / "a.py").write_text(f"KEY='{AWS}'\n")
            git(d, "add", "a.py")
            self.assertEqual(run(build_parser().parse_args(["scan", str(d), "--staged"])), 1)
            self.assertEqual(run(build_parser().parse_args(["scan", str(d / "..") , "--staged"])), 2)

    def test_min_tier_hides_low(self):
        import contextlib
        import io
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "a.py").write_text(f"K='{AWS}'\n")
            (Path(d) / "b.cfg").write_text("password = weakword\n")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                run(build_parser().parse_args(["scan", d, "--min-tier", "high", "--fail-on", "never"]))
            self.assertIn("1 lower-tier finding hidden by --min-tier", out.getvalue())
            self.assertNotIn("b.cfg", out.getvalue())

    def test_never_and_bad_path(self):
        self.assertEqual(run(build_parser().parse_args(["scan", "/nonexistent-dir-xyz"])), 2)

    def test_module_entry(self):
        r = subprocess.run([sys.executable, "-m", "leakguard", "--version"], capture_output=True, text=True,
                           cwd=Path(__file__).parent.parent)
        self.assertEqual(r.stdout.strip(), "0.1.0")


if __name__ == "__main__":
    unittest.main()
