"""Unit tests for the pure-Python parts of devstack (no incus, no sudo, no network).

Run: python3 -m unittest discover -s tests   (Python >= 3.11; the CA test also needs openssl)
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("devstack_py", ROOT / "devstack.py")
ds = importlib.util.module_from_spec(spec)
sys.modules["devstack_py"] = ds
spec.loader.exec_module(ds)


def make_config(**overrides: object) -> "ds.Config":
    values = ds.defaults()
    values.update(overrides)
    return ds.Config(values, None)


class FakeRunner:
    """Records commands instead of running them; `fail` lists argv[0] values that exit non-zero."""

    def __init__(self, fail: tuple[str, ...] = ()):
        self.interactive = False
        self.calls: list[list[str]] = []
        self.fail = fail

    def run(self, argv, *, check=True, sudo=False, **kw):
        argv = [str(a) for a in argv]
        self.calls.append(["sudo", *argv] if sudo else argv)
        rc = 1 if argv[0] in self.fail else 0
        if check and rc:
            raise ds.CommandError(argv, rc, "")
        return subprocess.CompletedProcess(argv, rc, "", "")


def make_ctx(tmp: Path, runner=None, **overrides: object) -> "ds.Ctx":
    cfg = make_config(**{
        "host.state_dir": str(tmp / "state"),
        "project.host_path": str(tmp / "project"),
        "ssh.key_path": str(tmp / "ssh" / "key"),
        "ssh.known_hosts_file": str(tmp / "ssh" / "known_hosts.d" / "devstack-webstack"),
        **overrides,
    })
    args = argparse.Namespace(yes=False)
    ctx = ds.Ctx(cfg, args, interactive=False)
    if runner is not None:
        ctx.r = runner
    (tmp / "project").mkdir(exist_ok=True)
    return ctx


class ConfigTests(unittest.TestCase):
    def test_defaults_resolve_and_validate(self):
        cfg = make_config()
        self.assertEqual(cfg["container.name"], "webstack")
        self.assertEqual(cfg.dev_host, "app.example.com.webstack")
        self.assertEqual(cfg["postgres.db"], "webstack")

    def test_stack_name_derives_everything(self):
        cfg = make_config(**{"stack.name": "my-app"})
        self.assertEqual(cfg["container.name"], "my-app")
        self.assertEqual(cfg["dns.tld"], "my-app")
        self.assertEqual(cfg["postgres.role"], "my_app_app")
        self.assertTrue(cfg["project.host_path"].endswith("/code/my-app"))

    def test_unknown_key_suggests_fix(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "c.toml"
            f.write_text('[stack]\nnmae = "x"\n')
            with self.assertRaises(ds.ConfigError) as cm:
                ds.parse_toml(f)
            self.assertIn("did you mean stack.name", str(cm.exception))

    def test_validation_errors(self):
        with self.assertRaises(ds.ConfigError):
            make_config(**{"app.port": 70000})
        with self.assertRaises(ds.ConfigError):
            make_config(**{"firewall.allow": [22, 8080]})  # app.port must stay internal

    def test_cycle_detected(self):
        with self.assertRaises(ds.ConfigError):
            make_config(**{"container.name": "{stack.name}{container.name}"})

    def test_example_file_is_valid(self):
        cfg = ds.load_config(ROOT / "devstack.example.toml")
        self.assertEqual(cfg["stack.name"], "webstack")

    def test_toml_roundtrip(self):
        text = ds.config_to_toml(ds.defaults())
        import tomllib
        self.assertEqual(tomllib.loads(text)["stack"]["name"], "webstack")


class TldTests(unittest.TestCase):
    def test_real_tlds_rejected(self):
        for tld in ("com", "dev", "app", "internal.com", "foo.dev"):
            self.assertIsNotNone(ds.public_tld_problem(tld), tld)
            with self.assertRaises(ds.ConfigError, msg=tld):
                make_config(**{"dns.tld": tld})

    def test_safe_names_accepted(self):
        for tld in ("webstack", "internal", "home.arpa", "test", "localhost", ""):
            self.assertIsNone(ds.public_tld_problem(tld), tld)

    def test_escape_hatch(self):
        cfg = make_config(**{"dns.tld": "dev", "dns.allow_public_tld": True})
        self.assertEqual(cfg["dns.tld"], "dev")

    def test_default_stack_name_that_is_a_tld_is_rejected(self):
        with self.assertRaises(ds.ConfigError):
            make_config(**{"stack.name": "app"})  # default tld = container.name = app

    def test_bundled_list_looks_sane(self):
        tlds = ds.delegated_tlds()
        self.assertGreater(len(tlds), 1000)
        self.assertIn("com", tlds)
        self.assertNotIn("webstack", tlds)
        self.assertNotIn("internal", tlds)


class RenderAndQuoteTests(unittest.TestCase):
    def test_render_fills_and_fails_on_unknown(self):
        out = ds.render("system/sshd-devstack.conf", {"STACK": "s", "USER": "bob"})
        self.assertIn("AllowUsers bob", out)
        self.assertIn("X11Forwarding no", out)
        self.assertIn("AllowAgentForwarding no", out)
        with self.assertRaises(ds.DevstackError):
            ds.render("system/sshd-devstack.conf", {"STACK": "s"})

    def test_bash_quotes_values(self):
        out = ds.bash("echo @@A@@ @@B@@ @@C@@", A="a b; rm -rf /", B=["x y", "z"], C=True)
        self.assertIn("'a b; rm -rf /'", out)
        self.assertIn("'x y' z", out)
        self.assertIn(" true", out)
        self.assertNotIn("@@", out)

    def test_bash_missing_value(self):
        with self.assertRaises(ds.DevstackError):
            ds.bash("echo @@NOPE@@")

    def test_scaffold_templates_render(self):
        with tempfile.TemporaryDirectory() as d:
            tv = make_ctx(Path(d)).tvars()
        for tpl, _rel, _mode in ds.SCAFFOLD:
            self.assertNotIn("@@", ds.render(tpl, tv), tpl)
        self.assertNotIn("@@", ds.render("system/app.service", tv))

    def test_runner_docs_do_not_promise_state_directory(self):
        """Regression: the scaffolded README told agents a runner may write
        `$STATE_DIRECTORY/incoming/`, but a runner unit has no StateDirectory= -- the variable a job
        gets is INCOMING_DIR. Never describe a protection or a path the unit doesn't actually set."""
        self.assertNotIn("StateDirectory", (ds.TEMPLATES / "system/runner@.service").read_text())
        with tempfile.TemporaryDirectory() as d:
            tv = make_ctx(Path(d)).tvars()
        for tpl, rel, _mode in ds.SCAFFOLD:
            hit = re.search(r"STATE_DIRECTORY\W{0,2}/?incoming", ds.render(tpl, tv))
            self.assertIsNone(hit, f"{rel} points a runner at $STATE_DIRECTORY: {hit.group(0) if hit else ''}")

    def test_agents_md_states_the_runner_constraints(self):
        """AGENTS.md is the only place an agent in the container learns the runner contract, so the
        constraints that aren't guessable must actually be written down."""
        with tempfile.TemporaryDirectory() as d:
            tv = make_ctx(Path(d)).tvars()
        text = ds.render("project/AGENTS.md", tv)
        for needle in ("INCOMING_DIR", "No loopback", "stdin", "@system-service",
                       "--redo isolation", "devstack-sync restart runners"):
            self.assertIn(needle, text, needle)

    def test_key_fingerprint_scripts_have_values(self):
        for script, extra in ((ds.CADDY_INSTALL, {}), (ds.PG_INSTALL, dict(VER=18, PORT=5432, PGUID=500))):
            out = ds.bash(script, FPR=ds.CADDY_KEY_FPR, **extra)
            self.assertIn("check_key_fpr", out)
            self.assertIn(ds.CADDY_KEY_FPR, out)


class ScriptSyntaxTests(unittest.TestCase):
    def test_rendered_scripts_pass_bash_n(self):
        scripts = {
            "base": ds.bash(ds.BASE_PROVISION, USER="u", UID=1000),
            "node": ds.bash(ds.NODE_INSTALL, VER="24.20.0", PREFIX="/usr/local",
                            KEYRING_COMMIT=ds.NODE_KEYRING_COMMIT, KEYRING_SHA=ds.NODE_KEYRING_SHA256),
            "caddy": ds.bash(ds.CADDY_INSTALL, FPR=ds.CADDY_KEY_FPR),
            "pg": ds.bash(ds.PG_INSTALL, VER=18, PORT=5432, PGUID=500, FPR=ds.PGDG_KEY_FPR),
            "restore": ds.bash(ds.PG_RESTORE, ENVFILE="/etc/app-secrets/postgres.env"),
        }
        for name, script in scripts.items():
            p = subprocess.run(["bash", "-n"], input=script, text=True, capture_output=True)
            self.assertEqual(p.returncode, 0, f"{name}: {p.stderr}")

    def test_scaffolded_shell_scripts_pass_bash_n(self):
        """The bash() constants are covered above; these are shell files in templates/project that
        get rendered into the user's repo and run there."""
        with tempfile.TemporaryDirectory() as d:
            tv = make_ctx(Path(d)).tvars()
        for tpl, rel, _mode in ds.SCAFFOLD:
            if not rel.endswith(".sh"):
                continue
            out = ds.render(tpl, tv)
            p = subprocess.run(["bash", "-n"], input=out, text=True, capture_output=True)
            self.assertEqual(p.returncode, 0, f"{rel}: {p.stderr}")

    def test_fingerprint_constants_look_right(self):
        for fpr in (ds.CADDY_KEY_FPR, ds.PGDG_KEY_FPR):
            self.assertRegex(fpr, r"^[0-9A-F]{40}$")
        self.assertRegex(ds.NODE_KEYRING_COMMIT, r"^[0-9a-f]{40}$")
        self.assertRegex(ds.NODE_KEYRING_SHA256, r"^[0-9a-f]{64}$")

    def test_fingerprint_check_function(self):
        if not shutil.which("gpg"):
            self.skipTest("gpg not installed")
        with tempfile.TemporaryDirectory() as d:
            home = Path(d) / "gnupg"
            home.mkdir(mode=0o700)
            env = {**os.environ, "GNUPGHOME": str(home)}
            subprocess.run(["gpg", "--batch", "--passphrase", "", "--quick-gen-key", "t <t@example.com>", "ed25519"],
                           env=env, check=True, capture_output=True)
            pub = Path(d) / "k.asc"
            with open(pub, "wb") as fh:
                subprocess.run(["gpg", "--armor", "--export"], env=env, check=True, stdout=fh)
            fpr = subprocess.run(["gpg", "--with-colons", "--fingerprint"], env=env, capture_output=True, text=True,
                                 check=True).stdout.split("fpr:::::::::")[1].split(":")[0]
            run = lambda want: subprocess.run(  # noqa: E731
                ["bash", "-c", ds.KEY_FPR_CHECK + f'check_key_fpr {pub} {want}'], env=env, capture_output=True, text=True)
            self.assertEqual(run(fpr).returncode, 0)
            bad = run("0" * 40)
            self.assertNotEqual(bad.returncode, 0)
            self.assertIn("fingerprint mismatch", bad.stderr)


class RiskTests(unittest.TestCase):
    home = "/home/alice"

    def test_dangerous(self):
        for path in ("/", "/home/alice", "/home", "/home/alice/.ssh", "/home/alice/.ssh/keys", "/home/alice/.gnupg",
                     "/etc", "/etc/ssl", "/root", "/var", "/var/lib/foo"):
            self.assertIsNotNone(ds.risky_path_reason(path, self.home), path)

    def test_fine(self):
        for path in ("/home/alice/code/app", "/home/alice/data", "/srv/data", "/mnt/shared"):
            self.assertIsNone(ds.risky_path_reason(path, self.home), path)

    def test_confirm_risks_noninteractive(self):
        with tempfile.TemporaryDirectory() as d:
            ctx = make_ctx(Path(d))
            with self.assertRaises(ds.NeedsInput):
                ds.confirm_risks(ctx, ["bad"])
            ctx.args.yes = True
            self.assertTrue(ds.confirm_risks(ctx, ["bad"]))
            self.assertTrue(ds.confirm_risks(ctx, []))


class JournalAndUndoTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_journal_persists_and_marks(self):
        j = ds.Journal(self.tmp / "j.jsonl")
        e = j.add("base", "dir", path="/x")
        j.mark(e, "applied")
        j2 = ds.Journal(self.tmp / "j.jsonl")
        self.assertEqual(j2.entries[0]["status"], "applied")
        self.assertTrue(j2.owns("dir", path="/x"))
        self.assertFalse(j2.owns("dir", path="/y"))
        self.assertEqual((self.tmp / "j.jsonl").stat().st_mode & 0o777, 0o600)

    def test_project_file_undo_restores_and_respects_edits(self):
        ctx = make_ctx(self.tmp, FakeRunner())
        ctx.phase = "app"
        self.assertTrue(ctx.project_file("a.txt", "hello\n"))
        self.assertFalse(ctx.project_file("a.txt", "other\n"))  # unmanaged: never overwrite
        entry = ctx.journal.find("project_file", ds.ACTIVE)
        self.assertEqual(ds.UNDO["project_file"](ctx, entry["args"], ds.UndoOpts()), "undone")
        self.assertFalse((ctx.project / "a.txt").exists())
        ctx.project_file("b.txt", "mine\n")
        (ctx.project / "b.txt").write_text("edited by the user\n")
        entry = ctx.journal.find("project_file", ds.ACTIVE, path=str(ctx.project / "b.txt"))
        self.assertEqual(ds.UNDO["project_file"](ctx, entry["args"], ds.UndoOpts()), "kept")
        self.assertTrue((ctx.project / "b.txt").exists())

    def test_marked_block_roundtrip(self):
        ctx = make_ctx(self.tmp, FakeRunner())
        cfgfile = self.tmp / "ssh_config"
        cfgfile.write_text("Host other\n    User x\n")
        ctx.set_marked_block(cfgfile, "Host webstack\n    User y")
        self.assertIn("Host webstack", cfgfile.read_text())
        entry = ctx.journal.find("marked_block", ds.ACTIVE)
        ds.UNDO["marked_block"](ctx, entry["args"], ds.UndoOpts())
        self.assertEqual(cfgfile.read_text(), "Host other\n    User x\n")

    def test_host_file_undo_uses_sudo_only_for_expected_paths(self):
        runner = FakeRunner()
        ctx = make_ctx(self.tmp, runner)
        good = ctx.cfg["dns.dnsmasq_file"]
        args = {"path": good, "backup": None, "sudo": True, "mode": "0o644", "then_restart": "dnsmasq"}
        self.assertEqual(ds.UNDO["host_file"](ctx, args, ds.UndoOpts()), "undone")
        self.assertIn(["sudo", "rm", "-f", good], runner.calls)

    def test_host_file_undo_refuses_foreign_paths(self):
        runner = FakeRunner()
        ctx = make_ctx(self.tmp, runner)
        for bad in ("/etc/passwd", "/etc/dnsmasq.d/../passwd", "relative/path", str(Path.home() / "other")):
            args = {"path": bad, "backup": None, "sudo": True, "mode": "0o644", "then_restart": None}
            self.assertEqual(ds.UNDO["host_file"](ctx, args, ds.UndoOpts()), "kept", bad)
        self.assertEqual(runner.calls, [])

    def test_host_file_undo_refuses_foreign_backup(self):
        runner = FakeRunner()
        ctx = make_ctx(self.tmp, runner)
        args = {"path": ctx.cfg["dns.dnsmasq_file"], "backup": "/etc/shadow", "sudo": True, "mode": "0o644",
                "then_restart": None}
        self.assertEqual(ds.UNDO["host_file"](ctx, args, ds.UndoOpts()), "kept")
        self.assertEqual(runner.calls, [])

    def test_host_ca_undo_checks_path(self):
        runner = FakeRunner()
        ctx = make_ctx(self.tmp, runner)
        self.assertEqual(ds.UNDO["host_ca"](ctx, {"path": "/etc/ssl/certs/ca-certificates.crt"}, ds.UndoOpts()), "kept")
        self.assertEqual(runner.calls, [])
        ok = ctx.cfg["tls.host_ca_file"]
        self.assertEqual(ds.UNDO["host_ca"](ctx, {"path": ok}, ds.UndoOpts()), "undone")
        self.assertIn(["sudo", "rm", "-f", ok], runner.calls)

    def test_project_tree_undo_stays_inside_project(self):
        ctx = make_ctx(self.tmp, FakeRunner())
        inside = ctx.project / "node_modules"
        inside.mkdir()
        outside = self.tmp / "precious"
        outside.mkdir()
        sneaky = str(ctx.project / ".." / "precious")
        self.assertEqual(ds.UNDO["project_tree"](ctx, {"path": sneaky}, ds.UndoOpts()), "kept")
        self.assertEqual(ds.UNDO["project_tree"](ctx, {"path": str(ctx.project)}, ds.UndoOpts()), "kept")
        self.assertTrue(outside.exists() and ctx.project.exists())
        self.assertEqual(ds.UNDO["project_tree"](ctx, {"path": str(inside)}, ds.UndoOpts()), "undone")
        self.assertFalse(inside.exists())

    def test_ssh_key_undo_checks_path(self):
        ctx = make_ctx(self.tmp, FakeRunner())
        key = Path(ctx.cfg["ssh.key_path"])
        key.parent.mkdir(parents=True)
        key.write_text("k")
        Path(str(key) + ".pub").write_text("p")
        victim = self.tmp / "victim"
        victim.write_text("keep me")
        self.assertEqual(ds.UNDO["ssh_key"](ctx, {"path": str(victim)}, ds.UndoOpts()), "kept")
        self.assertTrue(victim.exists())
        self.assertEqual(ds.UNDO["ssh_key"](ctx, {"path": str(key)}, ds.UndoOpts()), "undone")
        self.assertFalse(key.exists())

    def _mount_ctx(self, devices: dict):
        runner = FakeRunner()
        src = self.tmp / "store"
        src.mkdir(exist_ok=True)
        ctx = make_ctx(self.tmp, runner, **{"network.acl": False, "project.readonly_paths": [], "container.mounts": [
            {"name": "store", "source": str(src), "path": "/srv/store"}]})
        git = dict(ds.readonly_devices(ctx)[0][2], type="disk")  # .git already read-only: only the mount is new
        ctx.instance = lambda name=None: {"status": "Running", "devices": {"git": git, **devices}}
        return ctx, runner

    def test_new_mount_is_added_to_existing_container(self):
        ctx, runner = self._mount_ctx({"project": {"type": "disk"}})
        self.assertEqual(ds.pending_mounts(ctx), [])  # base not done: base adds it itself
        ctx.state.set_status("base", "done")
        self.assertEqual([m["name"] for m in ds.pending_mounts(ctx)], ["store"])
        self.assertTrue(ds.add_pending_mounts(ctx))
        self.assertIn(["incus", "config", "device", "add", ctx.name, "store", "disk",
                       f"source={self.tmp / 'store'}", "path=/srv/store", "shift=true"], runner.calls)
        self.assertTrue(ctx.journal.owns("incus_device", instance=ctx.name, device="store"))
        self.assertEqual(ctx.journal.entries[-1]["phase"], "base")

    def test_present_mount_is_left_alone_and_drift_reported(self):
        same = {"type": "disk", "source": str(self.tmp / "store"), "path": "/srv/store", "shift": "true"}
        ctx, runner = self._mount_ctx({"store": same})
        ctx.state.set_status("base", "done")
        self.assertFalse(ds.add_pending_mounts(ctx))
        self.assertEqual(runner.calls, [])
        self.assertEqual(ds.mount_drift(ctx, ctx.instance()), [])
        ctx.instance = lambda name=None: {"devices": {"store": {**same, "readonly": "true"}}}
        drift = ds.mount_drift(ctx, ctx.instance())
        self.assertEqual(len(drift), 1)
        self.assertIn("readonly", drift[0])

    def test_purged_volume_waits_for_the_container(self):
        runner = FakeRunner()
        ctx = make_ctx(self.tmp, runner)
        args = {"pool": "default", "volume": "webstack-pgdata", "adopted": False}
        purge_all = ds.UndoOpts(purge_data=True, whole=True)
        used = {"used_by": ["/1.0/instances/webstack"]}
        ctx.iq = lambda path: used
        self.assertEqual(ds.UNDO["incus_volume"](ctx, args, purge_all), "kept")  # still attached: later
        self.assertEqual(runner.calls, [])
        used["used_by"] = ["/1.0/instances/other"]
        with self.assertRaises(ds.DevstackError):
            ds.UNDO["incus_volume"](ctx, args, purge_all)
        used["used_by"] = []
        self.assertEqual(ds.UNDO["incus_volume"](ctx, args, purge_all), "undone")
        self.assertEqual(runner.calls, [["incus", "storage", "volume", "delete", "default", "webstack-pgdata"]])

    def test_data_backup_skipped_when_nothing_is_attached(self):
        ctx = make_ctx(self.tmp, FakeRunner())
        ctx.state.set_status("isolation", "done")
        ctx.instance = lambda name=None: {"status": "Running", "devices": {"project": {}}}  # built without app data
        backups = []
        orig, ds.data_backup = ds.data_backup, lambda c, dest: backups.append(dest)
        try:
            ds.maybe_backup_data(ctx, required=True)  # nothing to archive, nothing of ours to lose
            self.assertEqual(backups, [])
            e = ctx.journal.add("isolation", "incus_volume", pool="default", volume="webstack-appdata", adopted=False)
            ctx.journal.mark(e, "applied")
            ctx.volume = lambda name=None: {"name": name}
            with self.assertRaises(ds.DevstackError):  # ours, exists, detached: a purge must not take it unarchived
                ds.maybe_backup_data(ctx, required=True)
            ctx.instance = lambda name=None: {"status": "Running", "devices": {"appdata": {}}}
            ds.maybe_backup_data(ctx, required=True)
            self.assertEqual(backups, [None])
        finally:
            ds.data_backup = orig

    def test_app_phase_installs_existing_projects_dependencies(self):
        runner = FakeRunner()
        ctx = make_ctx(self.tmp, runner)
        ctx.phase = "app"
        (ctx.project / "package.json").write_text('{"dependencies": {"postgres": "^3.4.9"}}\n')
        (ctx.project / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n")
        ds.PHASE_BY_ID["app"].apply(ctx)
        scripts = [" ".join(c) for c in runner.calls if "pnpm" in " ".join(c)]
        self.assertEqual(len(scripts), 1)
        self.assertIn("pnpm install --frozen-lockfile", scripts[0])
        self.assertNotIn("pnpm add", scripts[0])  # never touches an existing project's package.json
        (ctx.project / "node_modules").mkdir()
        runner.calls.clear()
        ds.PHASE_BY_ID["app"].apply(ctx)
        self.assertFalse(any("pnpm" in " ".join(c) for c in runner.calls))  # already installed: left alone
        for rel in ds.SCAFFOLD_NEW_PROJECT_ONLY:  # no lint config for packages it doesn't have
            self.assertFalse((ctx.project / rel).exists(), rel)

    def test_app_phase_scaffolds_the_toolchain_for_a_new_project(self):
        runner = FakeRunner()
        ctx = make_ctx(self.tmp, runner)
        ctx.phase = "app"
        ds.PHASE_BY_ID["app"].apply(ctx)
        for rel in ds.SCAFFOLD_NEW_PROJECT_ONLY:
            self.assertTrue((ctx.project / rel).exists(), rel)
        self.assertTrue(os.access(ctx.project / "scripts" / "lint-changed.sh", os.X_OK))
        scripts = [" ".join(c) for c in runner.calls if "pnpm add" in " ".join(c)]
        self.assertEqual(len(scripts), 1)
        for pkg in ds.dev_packages(ctx.cfg):
            self.assertIn(pkg, scripts[0])

    def test_undo_phase_marks_entries(self):
        ctx = make_ctx(self.tmp, FakeRunner())
        ctx.phase = "app"
        ctx.project_file("a.txt", "x\n")
        ds.undo_phase(ctx, ds.PHASE_BY_ID["app"], ds.UndoOpts())
        self.assertEqual(ctx.journal.entries[-1]["status"], "undone")
        self.assertEqual(ctx.state.status("app"), "pending")


class RequirementsTests(unittest.TestCase):
    def mounts(self):
        return [{"name": "data", "source": "/home/alice/data", "path": "/srv/data", "readonly": True}]

    def test_roundtrip_has_no_host_details(self):
        cfg = make_config(**{"project.host_path": "/home/alice/code/app", "container.mounts": self.mounts(),
                             "node.version": "24.1.0"})
        text = ds.requirements_to_toml(ds.requirements(cfg.v))
        self.assertNotIn("/home/alice", text)
        self.assertNotIn("state_dir", text)
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "req.toml"
            path.write_text(text)
            want = ds.load_requirements(path)
        self.assertEqual(want, ds.requirements(cfg.v))
        self.assertEqual(ds.requirements_diff(want, cfg.v), ([], []))

    def test_rejects_host_keys_sources_and_placeholders(self):
        for body in ('[ssh]\nconfig_file = "/tmp/x"\n',
                     '[[container.mounts]]\nname = "d"\npath = "/srv/d"\nsource = "/"\n',
                     '[project]\ncontainer_path = "{env.home}/x"\n'):
            with tempfile.TemporaryDirectory() as d:
                path = Path(d) / "req.toml"
                path.write_text(body)
                with self.assertRaises(ds.ConfigError, msg=body):
                    ds.load_requirements(path)

    def test_caddy_placeholders_allowed(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "req.toml"
            path.write_text('[caddy.headers]\nX-Host = "{http.request.host}"\n')
            self.assertEqual(ds.load_requirements(path), {"caddy.headers": {"X-Host": "{http.request.host}"}})
            self.assertIsNone(ds.load_requirements(Path(d) / "missing.toml"))

    def test_diff(self):
        want = {"node.version": "24.1.0", "container.mounts": [{"name": "data", "path": "/srv/data", "readonly": True}]}
        missing, diffs = ds.requirements_diff(want, make_config().v)
        self.assertEqual(len(missing), 1)
        self.assertIn('name = "data"', missing[0])
        self.assertEqual(len(diffs), 1)
        self.assertIn("node.version", diffs[0])

    def test_diff_shows_runners(self):
        cfg = make_config(**{"app.runners": ds.normalize_runners(
            [{"name": "fetch", "command": "node scripts/fetch.ts", "port": 9101}])})
        _missing, diffs = ds.requirements_diff({"app.runners": []}, cfg.v)
        self.assertEqual(len(diffs), 1)
        self.assertIn('app.runners: project [], your config [{ name = "fetch", ', diffs[0])
        self.assertIn("port = 9101", diffs[0])

    def test_preflight_foreign_vs_own_file(self):
        with tempfile.TemporaryDirectory() as d:
            ctx = make_ctx(Path(d), FakeRunner(), **{"node.version": "24.1.0"})
            path = ctx.project / ds.REQUIRES_FILE
            path.parent.mkdir(parents=True)
            path.write_text('[node]\nversion = "24.0.0"\n')  # from the repo
            rep = ds.Report()
            ds.check_requirements(ctx, rep)
            self.assertTrue(any("node.version" in r for r in rep.risks))
            ctx.phase = "base"
            ds.write_requirements(ctx)  # ours now: later config changes rewrite it without asking
            rep = ds.Report()
            ds.check_requirements(ctx, rep)
            self.assertFalse(any(ds.REQUIRES_FILE in r for r in rep.risks))
            self.assertIn('version = "24.1.0"', path.read_text())

    def test_init_adopts_requirements(self):
        with tempfile.TemporaryDirectory() as d:
            proj = Path(d) / "proj"
            (proj / "infra").mkdir(parents=True)
            (proj / ds.REQUIRES_FILE).write_text('[node]\nversion = "24.1.0"\n')
            out = Path(d) / "mine.toml"
            ds.cmd_init(argparse.Namespace(config=str(out), project=str(proj), force=False), interactive=False)
            cfg = ds.load_config(out)
            self.assertEqual(cfg["node.version"], "24.1.0")
            self.assertEqual(cfg["project.host_path"], str(proj.resolve()))


class CaddyfileTests(unittest.TestCase):
    def test_global_options_are_devstacks_and_use_host_intermediate(self):
        with tempfile.TemporaryDirectory() as d:
            ctx = make_ctx(Path(d), FakeRunner())
            for level in (ds.LEVEL_PROXY, ds.LEVEL_STANDARDS, ds.LEVEL_ISOLATION):
                glob = ds.caddy_global(ctx, level)
                self.assertTrue(ds.caddyfile_has_global_block(glob))
                self.assertIn("skip_install_trust", glob)
                self.assertIn(f"cert {ds.CADDY_PKI_DIR}/intermediate.crt", glob)
                self.assertIn(f"key {ds.CADDY_PKI_DIR}/intermediate.key", glob)
                self.assertTrue(glob.rstrip().endswith(f"import {ctx.cproject}/infra/Caddyfile"))
                self.assertEqual("admin unix//run/caddy/admin.sock" in glob, level >= ds.LEVEL_ISOLATION)
                project = ds.caddyfile(ctx, level)
                self.assertFalse(ds.caddyfile_has_global_block(project), level)
                self.assertNotIn("admin", project)
                self.assertIn("app.example.com.webstack {", project)

    def test_global_block_detection(self):
        self.assertTrue(ds.caddyfile_has_global_block("# comment\n\n  {\n\tadmin localhost:2019\n}\n"))
        self.assertTrue(ds.caddyfile_has_global_block("{ admin localhost:2019 }"))
        self.assertFalse(ds.caddyfile_has_global_block("# { not this\nexample.com {\n}\n"))
        self.assertFalse(ds.caddyfile_has_global_block("(snippet) {\n}\n"))

    def test_owned_caddyfile_with_global_block_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            runner = FakeRunner()
            ctx = make_ctx(Path(d), runner, **{"caddy.manage_caddyfile": False})
            path = ctx.project / "infra" / "Caddyfile"
            path.parent.mkdir(parents=True)
            path.write_text("{\n\tadmin localhost:2019\n}\nexample.com {\n}\n")
            with self.assertRaises(ds.DevstackError):
                ds.apply_caddyfile(ctx, ds.LEVEL_ISOLATION)
            self.assertEqual(runner.calls, [])  # nothing written to the container

    def test_same_origin_snippet_per_mode(self):
        """Defined in the root file, before the project's import (a snippet must exist before use), in
        every mode: 'off' leaves it empty so project files that import it still parse."""
        with tempfile.TemporaryDirectory() as d:
            for mode in ("strict", "allow-navigation", "off"):
                ctx = make_ctx(Path(d), FakeRunner(), **{"caddy.same_origin": mode})
                glob = ds.caddy_global(ctx, ds.LEVEL_PROXY)
                self.assertTrue(ds.caddyfile_defines(glob, ds.SAME_ORIGIN_SNIPPET), mode)
                self.assertLess(glob.index("(devstack_same_origin)"), glob.index("import /"), mode)
                self.assertEqual(ds.SAME_ORIGIN_FOREIGN in glob, mode != "off", mode)
                self.assertEqual(ds.SAME_ORIGIN_NAVIGATION in glob, mode == "allow-navigation", mode)
                self.assertEqual("respond @foreign 403" in glob, mode != "off", mode)
                self.assertNotIn("Access-Control", glob + ds.caddyfile(ctx, ds.LEVEL_ISOLATION))

    def test_generated_site_blocks_import_the_snippet(self):
        with tempfile.TemporaryDirectory() as d:
            ctx = make_ctx(Path(d), FakeRunner())
            for level in (ds.LEVEL_PROXY, ds.LEVEL_STANDARDS, ds.LEVEL_ISOLATION):
                project = ds.caddyfile(ctx, level)
                self.assertEqual(project.count("\timport devstack_same_origin\n"), 2, level)  # site + http://
                self.assertTrue(ds.caddyfile_imports(project, ds.SAME_ORIGIN_SNIPPET))
                self.assertFalse(ds.caddyfile_defines(project, ds.SAME_ORIGIN_SNIPPET))
                self.assertNotIn("request_body", project)
            ctx = make_ctx(Path(d), FakeRunner(), **{"caddy.max_request_body": "4GiB"})
            project = ds.caddyfile(ctx, ds.LEVEL_STANDARDS)
            self.assertIn("\trequest_body {\n\t\tmax_size 4GiB\n\t}", project)
            self.assertEqual(project.count("request_body"), 1)  # the app's site only, not the catch-all

    def test_max_request_body_values(self):
        for ok in ("", "512", "10MB", "4GiB", "1TB", "100KiB"):
            self.assertFalse([e for e in ds.validate({**ds.defaults(), "caddy.max_request_body": ok})
                              if "max_request_body" in e], ok)
        for bad in ("0", "10 MB", "-1", "lots", "10mb;", "4GiB\n}"):
            self.assertTrue([e for e in ds.validate({**ds.defaults(), "caddy.max_request_body": bad})
                             if "max_request_body" in e], bad)

    def test_import_and_definition_detection(self):
        text = "# import devstack_same_origin\n(devstack_same_origin_old) {\n}\nx {\n\timport devstack_same_originx\n}\n"
        self.assertFalse(ds.caddyfile_imports(text, ds.SAME_ORIGIN_SNIPPET))
        self.assertFalse(ds.caddyfile_defines(text, ds.SAME_ORIGIN_SNIPPET))
        self.assertTrue(ds.caddyfile_imports("x {\n  import devstack_same_origin  # always\n}", ds.SAME_ORIGIN_SNIPPET))
        self.assertTrue(ds.caddyfile_defines("  (devstack_same_origin)  {\n}", ds.SAME_ORIGIN_SNIPPET))

    def test_owned_caddyfile_must_not_redefine_the_snippet(self):
        """Caddy refuses a redeclared snippet, so a project copy would stop Caddy from loading."""
        with tempfile.TemporaryDirectory() as d:
            runner = FakeRunner()
            ctx = make_ctx(Path(d), runner, **{"caddy.manage_caddyfile": False})
            path = ctx.project / "infra" / "Caddyfile"
            path.parent.mkdir(parents=True)
            path.write_text("(devstack_same_origin) {\n}\nexample.com {\n\timport devstack_same_origin\n}\n")
            with self.assertRaises(ds.DevstackError) as cm:
                ds.apply_caddyfile(ctx, ds.LEVEL_ISOLATION)
            self.assertIn("refuses a second definition", str(cm.exception))
            self.assertEqual(runner.calls, [])

    def test_existing_container_gets_the_new_caddy_files(self):
        """All phases done, so no phase rewrites Caddy: up refreshes what differs, under the last phase."""
        with tempfile.TemporaryDirectory() as d:
            runner = FakeRunner()
            ctx = make_ctx(Path(d), runner, **{"network.acl": False})
            ctx.instance = lambda name=None: {"status": "Running", "devices": {}}
            self.assertEqual(ds.pending_caddy(ctx), [])  # before proxy: nothing of Caddy's yet
            for pid in ("base", "app", "proxy", "standards"):
                ctx.state.set_status(pid, "done")
            self.assertEqual(ds.caddy_level(ctx), ds.LEVEL_STANDARDS)
            current = ds.caddy_global(ctx, ds.LEVEL_STANDARDS)
            ctx.cread = lambda path, **kw: current.replace("(devstack_same_origin)", "(older)")
            stale = ds.pending_caddy(ctx)
            self.assertEqual(stale, ["/etc/caddy/Caddyfile", str(ctx.project / "infra" / "Caddyfile")])
            self.assertTrue(any("rewrite /etc/caddy/Caddyfile" in ln for ln in ds.up_pending(ctx, [])))
            self.assertFalse([ln for ln in ds.up_pending(ctx, [ds.PHASE_BY_ID["standards"]])
                              if "Caddy" in ln])  # the phase rewrites them itself
            self.assertTrue(ds.refresh_caddy(ctx))
            self.assertEqual(ctx.phase, "standards")
            self.assertEqual((ctx.project / "infra" / "Caddyfile").read_text(), ds.caddyfile(ctx, ds.LEVEL_STANDARDS))
            self.assertTrue(any("caddy validate" in " ".join(c) for c in runner.calls))
            ctx.cread = lambda path, **kw: current
            self.assertEqual(ds.pending_caddy(ctx), [])
            self.assertFalse(ds.refresh_caddy(ctx))

    def test_existing_container_gets_the_new_devstack_sync(self):
        with tempfile.TemporaryDirectory() as d:
            runner = FakeRunner()
            ctx = make_ctx(Path(d), runner, **{"network.acl": False})
            ctx.instance = lambda name=None: {"status": "Running", "devices": {}}
            ctx.cread = lambda path, **kw: "#!/bin/bash\n# an older devstack-sync\n"
            self.assertFalse(ds.sync_script_stale(ctx))  # isolation not done: it installs it itself
            ctx.state.set_status("isolation", "done")
            self.assertTrue(any(ds.SYNC_PATH in ln for ln in ds.up_pending(ctx, [])))
            self.assertTrue(ds.refresh_sync(ctx))
            self.assertEqual(ctx.phase, "isolation")
            self.assertTrue(any("install -D -m 0755" in " ".join(c) for c in runner.calls))
            ctx.cread = lambda path, **kw: ds.devstack_sync_script(ctx.cfg)
            self.assertFalse(ds.refresh_sync(ctx))

    def test_same_origin_is_a_project_requirement(self):
        """A project that needs OAuth redirects says so in git, and a clone gets that default back."""
        req = ds.requirements(make_config(**{"caddy.same_origin": "allow-navigation",
                                             "caddy.max_request_body": "10MB"}).v)
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "req.toml"
            path.write_text(ds.requirements_to_toml(req))
            back = ds.load_requirements(path)
        self.assertEqual(back["caddy.same_origin"], "allow-navigation")
        self.assertEqual(back["caddy.max_request_body"], "10MB")


class DevServerTests(unittest.TestCase):
    def test_values(self):
        def errs(servers, **kw):
            return [e for e in ds.validate({**ds.defaults(), "caddy.dev_servers": servers, **kw})
                    if "dev_servers" in e]
        self.assertEqual(errs({"vite": "5173", "story-book": "6006"}), [])
        for bad in ({"Vite": "5173"}, {"vite": "80"}, {"vite": "70000"}, {"vite": "5173 "}, {"a.b": "5173"},
                    {"-x": "5173"}):
            self.assertTrue(errs(bad), bad)
        self.assertTrue(errs({"vite": "8080"}))  # the app's port
        self.assertTrue(errs({"vite": "5432"}))  # Postgres
        self.assertTrue(errs({"vite": "9101"}, **{"app.runners": [{**ds.RUNNER_DEFAULTS, **RUNNER}]}))

    def test_vhosts_in_the_root_file(self):
        """In /etc/caddy/Caddyfile so a project with its own Caddyfile gets them too; before the project's
        import, using only the snippet defined above them."""
        with tempfile.TemporaryDirectory() as d:
            ctx = make_ctx(Path(d), FakeRunner())
            self.assertNotIn("reverse_proxy localhost:", ds.caddy_global(ctx, ds.LEVEL_ISOLATION))
            ctx = make_ctx(Path(d), FakeRunner(), **{"caddy.dev_servers": {"vite": "5173"}})
            glob = ds.caddy_global(ctx, ds.LEVEL_ISOLATION)
            block = glob[glob.index("vite.app.example.com.webstack {"):]
            block = block[:block.index("\n}\n")]
            self.assertLess(glob.index("(devstack_same_origin)"), glob.index("vite.app.example.com.webstack {"))
            self.assertLess(glob.index("vite.app.example.com.webstack {"), glob.index("import /"))
            self.assertIn("\timport devstack_same_origin", block)
            self.assertIn("reverse_proxy /api/* 127.0.0.1:8080 {", block)
            self.assertIn("X-Internal-Token", block)
            self.assertIn("reverse_proxy localhost:5173 {\n\t\theader_up Host {upstream_hostport}", block)
            self.assertNotIn("security_headers", block)
            self.assertNotIn("import common", block)  # defined later, in the project's file
            proxy_level = ds.caddy_global(ctx, ds.LEVEL_PROXY)
            self.assertIn("reverse_proxy /api/* 127.0.0.1:8080\n", proxy_level)  # no token before isolation

    def test_dns_records_when_not_wildcard(self):
        with tempfile.TemporaryDirectory() as d:
            ctx = make_ctx(Path(d), FakeRunner(), **{"caddy.dev_servers": {"vite": "5173"}})
            self.assertEqual(ds.ProxyPhase._dns_lines(ctx, "10.0.0.2"), ["address=/webstack/10.0.0.2"])
            ctx = make_ctx(Path(d), FakeRunner(), **{"caddy.dev_servers": {"vite": "5173"}, "dns.wildcard": False})
            self.assertIn("host-record=vite.app.example.com.webstack,10.0.0.2",
                          ds.ProxyPhase._dns_lines(ctx, "10.0.0.2"))


GIT_SETUP_ENV = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
                 "GIT_COMMITTER_EMAIL": "t@t", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"}


@unittest.skipUnless(shutil.which("git"), "needs git")
class CheckpointProjectTests(unittest.TestCase):
    """Real git: the project part of a checkpoint, captured and restored."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.ctx = make_ctx(self.tmp, FakeRunner())
        self.root = self.ctx.project
        self.git("init", "-q")
        (self.root / ".gitignore").write_text(".env\nnode_modules/\nbig/\n")
        (self.root / "a.txt").write_text("a1\n")
        (self.root / "b.txt").write_text("b1\n")
        (self.root / "dir").mkdir()
        (self.root / "dir" / "d.txt").write_text("d1\n")
        (self.root / "run.sh").write_text("#!/bin/sh\n")
        os.chmod(self.root / "run.sh", 0o755)
        os.symlink("a.txt", self.root / "link")
        self.git("add", "-A")
        self.git("commit", "-qm", "one")
        (self.root / "b.txt").write_text("b2 staged\n")
        self.git("add", "b.txt")
        (self.root / "c.txt").write_text("untracked\n")
        (self.root / ".env").write_text("SECRET=1\n")
        (self.root / "node_modules" / "pkg").mkdir(parents=True)
        (self.root / "node_modules" / "pkg" / "x.js").write_text("v1\n")
        (self.root / "big").mkdir()
        (self.root / "big" / "blob.bin").write_bytes(b"x" * (2 * 1024 * 1024))
        self.ckdir = self.tmp / "ck"
        self.ckdir.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.root), *args], check=True, capture_output=True, text=True,
                              env=GIT_SETUP_ENV).stdout

    def capture(self, **cfg):
        self.ctx.cfg.v.update({"checkpoint.capture_max_mb": 1, **cfg})
        return {"name": "t", "project": ds.capture_project(self.ctx, "t", self.ckdir)}

    def test_round_trip(self):
        head, branches = self.git("rev-parse", "HEAD"), self.git("branch")
        meta = self.capture()
        p = meta["project"]
        self.assertEqual(p["head"], head.strip())
        self.assertEqual(self.git("rev-parse", "HEAD"), head)  # HEAD, branches untouched
        self.assertEqual(self.git("branch"), branches)
        self.assertEqual(self.git("diff", "--cached", "--name-only"), "b.txt\n")  # the user's index too
        self.assertEqual(self.git("rev-parse", "refs/devstack/checkpoints/t").strip(), p["commit"])
        self.assertEqual(p["ignored_files"], 1)  # .env; node_modules derived, big/ over budget
        why = dict(p["uncaptured"])
        self.assertIn("derived", why["node_modules/"])
        self.assertIn("over checkpoint.capture_max_mb", why["big/"])

        # what an agent might do afterwards
        (self.root / "a.txt").write_text("a2\n")
        (self.root / "c.txt").unlink()
        (self.root / "e.txt").write_text("new\n")
        (self.root / ".env").unlink()
        (self.root / "node_modules" / "pkg" / "x.js").write_text("v2\n")
        os.chmod(self.root / "run.sh", 0o644)
        (self.root / "link").unlink()
        (self.root / "link").write_text("not a link\n")
        self.git("add", "a.txt")

        r = ds.restore_project(self.ctx, meta, self.ckdir)
        self.assertEqual((self.root / "a.txt").read_text(), "a1\n")
        self.assertEqual((self.root / "b.txt").read_text(), "b2 staged\n")
        self.assertEqual((self.root / "c.txt").read_text(), "untracked\n")
        self.assertFalse((self.root / "e.txt").exists())
        self.assertEqual((self.root / ".env").read_text(), "SECRET=1\n")
        self.assertEqual((self.root / "node_modules" / "pkg" / "x.js").read_text(), "v2\n")  # restore_command's job
        self.assertTrue(os.stat(self.root / "run.sh").st_mode & 0o100)
        self.assertEqual(os.readlink(self.root / "link"), "a.txt")
        self.assertTrue(r["index"])
        self.assertEqual(self.git("diff", "--cached", "--name-only"), "b.txt\n")  # staged state of then
        self.assertEqual(r["removed"], 1)

    def test_restore_never_writes_through_a_symlink(self):
        """The container replaces dir/ with a symlink to a host folder; restoring dir/d.txt must replace
        the symlink with a real folder, not write into the host folder."""
        meta = self.capture()
        outside = self.tmp / "outside"
        outside.mkdir()
        shutil.rmtree(self.root / "dir")
        os.symlink(outside, self.root / "dir")
        ds.restore_project(self.ctx, meta, self.ckdir)
        self.assertEqual(list(outside.iterdir()), [])
        self.assertFalse((self.root / "dir").is_symlink())
        self.assertEqual((self.root / "dir" / "d.txt").read_text(), "d1\n")

    def test_removal_never_follows_a_symlinked_folder(self):
        outside = self.tmp / "outside"
        outside.mkdir()
        (outside / "keep.txt").write_text("host file\n")
        os.symlink(outside, self.root / "sneaky")
        self.assertFalse(ds.remove_project_file(self.root, "sneaky/keep.txt"))
        self.assertTrue((outside / "keep.txt").exists())
        for bad in ("../x", "/etc/passwd", ".git/config", ""):
            self.assertFalse(ds.remove_project_file(self.root, bad), bad)
            self.assertFalse(ds.write_project_file(self.root, bad, b"x", "100644"), bad)

    def test_capture_runs_no_git_config_commands(self):
        """Repo config, global config and .gitattributes can name commands (fsmonitor, filters); the
        container could have written the attributes. None of them may run on the host."""
        marker = self.tmp / "ran"
        script = self.tmp / "evil.sh"
        script.write_text(f"#!/bin/sh\ntouch {marker}\ncat\n")
        os.chmod(script, 0o755)
        fake_home = self.tmp / "home"
        fake_home.mkdir()
        (fake_home / ".gitconfig").write_text(f"[core]\n\tfsmonitor = {script}\n[filter \"evil\"]\n"
                                              f"\tclean = {script}\n\tsmudge = {script}\n")
        self.git("config", "core.fsmonitor", str(script))
        (self.root / ".gitattributes").write_text("* filter=evil\n")
        old = os.environ.get("HOME")
        os.environ["HOME"] = str(fake_home)
        try:
            meta = self.capture()
            (self.root / "a.txt").write_text("changed\n")
            ds.restore_project(self.ctx, meta, self.ckdir)
        finally:
            os.environ["HOME"] = old or ""
        self.assertFalse(marker.exists())
        self.assertEqual((self.root / "a.txt").read_text(), "a1\n")

    def test_head_moved_keeps_commits_and_index(self):
        meta = self.capture()
        self.git("commit", "-qm", "two")
        (self.root / "a.txt").write_text("a3\n")
        r = ds.restore_project(self.ctx, meta, self.ckdir)
        self.assertNotEqual(r["head"], meta["project"]["head"])
        self.assertFalse(r["index"])  # the index belongs to the new commit now
        self.assertEqual((self.root / "a.txt").read_text(), "a1\n")
        self.assertIn("two", self.git("log", "--oneline", "-1"))


class CheckpointOrchestrationTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.runner = FakeRunner()
        self.ctx = make_ctx(Path(self._tmp.name), self.runner, **{"network.acl": False, "postgres.enabled": True})
        for p in ds.PHASES:
            self.ctx.state.set_status(p.id, "done")
        (self.ctx.project / ".git").mkdir()
        self.running = True
        self.ctx.instance = lambda name=None: {"status": "Running" if self.running else "Stopped", "devices": {}}
        self.ctx.instance_running = lambda: self.running
        self.ctx.stop_instance = lambda: (self.runner.calls.append(["STOP"]), setattr(self, "running", False))
        self.ctx.wait_ipv4 = lambda: "10.0.0.2"
        self.ctx.args.yes = True
        self.saved = {k: getattr(ds, k) for k in ("capture_project", "pool_space", "checkpoint_volumes",
                                                  "volume_snapshot_exists", "git_run")}
        ds.capture_project = lambda ctx, name, dest: (self.runner.calls.append(["CAPTURE", str(self.running)]) or {
            "commit": "c" * 40, "head": "h" * 40, "branch": "main", "files": 3, "skipped": [],
            "ignored_files": 0, "ignored_bytes": 0, "uncaptured": []})
        ds.pool_space = lambda ctx: (1000, 10**12)
        ds.checkpoint_volumes = lambda ctx: ["webstack-pgdata"]
        ds.volume_snapshot_exists = lambda ctx, v, s: True
        ds.git_run = lambda ctx, *a, **kw: b""

        orig = self.runner.run

        def run(argv, **kw):
            if argv[:2] == ["incus", "start"]:
                self.running = True
            return orig(argv, **kw)
        self.runner.run = run
        self.ctx.snapshot_names = lambda name=None: []

    def tearDown(self):
        for k, v in self.saved.items():
            setattr(ds, k, v)
        self._tmp.cleanup()

    def incus(self):
        return [c[:4] for c in self.runner.calls if c[0] in ("incus", "STOP", "CAPTURE")]

    def test_create_stops_captures_snapshots_starts(self):
        self.assertEqual(ds.checkpoint_create(self.ctx, "one"), 0)
        self.assertEqual(self.incus(), [
            ["STOP"], ["CAPTURE", "False"],
            ["incus", "snapshot", "create", "webstack"],
            ["incus", "storage", "volume", "snapshot"],
            ["incus", "start", "webstack"]])
        meta = ds.checkpoint_metas(self.ctx)[0]
        self.assertEqual(meta["phases"], [p.id for p in ds.PHASES])
        self.assertEqual(meta["volumes"], ["webstack-pgdata"])
        self.assertEqual((self.ctx.state_dir / "checkpoints" / "one").stat().st_mode & 0o777, 0o700)

    def test_keep_one_makes_the_new_one_before_deleting_the_old(self):
        ds.checkpoint_create(self.ctx, "one")
        self.ctx.snapshot_names = lambda name=None: ["checkpoint-one"]
        self.runner.calls.clear()
        ds.checkpoint_create(self.ctx, "two")
        cmds = [" ".join(c[:4]) for c in self.runner.calls if c[0] == "incus"]
        self.assertLess(cmds.index("incus snapshot create webstack"), cmds.index("incus snapshot delete webstack"))
        self.assertEqual([m["name"] for m in ds.checkpoint_metas(self.ctx)], ["two"])

    def test_dropping_an_old_one_needs_a_yes(self):
        ds.checkpoint_create(self.ctx, "one")
        self.ctx.args.yes = False
        with self.assertRaises(ds.NeedsInput):  # non-interactive without --yes
            ds.checkpoint_create(self.ctx, "two")
        self.assertEqual([m["name"] for m in ds.checkpoint_metas(self.ctx)], ["one"])

    def test_failure_cleans_up_and_restarts(self):
        orig = self.runner.run

        def run(argv, **kw):
            if argv[:3] == ["incus", "storage", "volume"] and "create" in argv:
                raise ds.CommandError(argv, 1, "no space left")
            return orig(argv, **kw)
        self.runner.run = run
        with self.assertRaises(ds.CommandError):
            ds.checkpoint_create(self.ctx, "one")
        self.assertTrue(self.running)
        self.assertFalse((self.ctx.state_dir / "checkpoints" / "one").exists())
        self.assertEqual(ds.checkpoint_metas(self.ctx), [])

    def test_not_enough_space(self):
        ds.checkpoint_create(self.ctx, "one")
        meta_file = self.ctx.state_dir / "checkpoints" / "one" / "meta.json"
        meta = json.loads(meta_file.read_text())
        meta["bytes"] = 5 * 10**9
        meta_file.write_text(json.dumps(meta))
        ds.pool_space = lambda ctx: (1000, 10**9)
        with self.assertRaises(ds.DevstackError) as cm:
            ds.checkpoint_create(self.ctx, "two")
        self.assertIn("not enough space", str(cm.exception))

    def test_restore_refuses_when_phases_differ(self):
        ds.checkpoint_create(self.ctx, "one")
        self.ctx.state.set_status("postgres", "pending")
        with self.assertRaises(ds.DevstackError) as cm:
            ds.checkpoint_restore(self.ctx, "one")
        self.assertIn("journal", str(cm.exception))

    def test_names(self):
        for bad in ("Has-Caps", "-x", "a b", "x" * 42, "../x"):
            with self.assertRaises(ds.ConfigError, msg=bad):
                ds.checkpoint_create(self.ctx, bad)

    def test_config(self):
        cfg = make_config()
        self.assertEqual(cfg["checkpoint.keep"], 1)
        self.assertIn("node_modules", cfg["checkpoint.derived"])
        self.assertTrue([e for e in ds.validate({**ds.defaults(), "checkpoint.keep": 0}) if "keep" in e])
        self.assertIn("checkpoint.restore_command", ds.PROJECT_KEYS)


class DnsRefreshTests(unittest.TestCase):
    def test_dev_server_added_later_gets_its_record_without_a_phase_rerun(self):
        """learn-sys: dns.wildcard = false, proxy done, then vite added. Only app.<tld> resolved."""
        with tempfile.TemporaryDirectory() as d:
            runner = FakeRunner()
            conf = Path(d) / "devstack-webstack.conf"
            ctx = make_ctx(Path(d), runner, **{"dns.wildcard": False, "dns.dnsmasq_dir": d, "dns.dnsmasq_file": str(conf),
                                                "caddy.dev_servers": {"vite": "5173"}})
            ctx.state.set_fact("ipv4", "10.0.0.2")
            conf.write_text("# devstack:webstack — generated\nhost-record=app.example.com.webstack,10.0.0.2\n")
            self.assertFalse(ds.pending_dns(ctx))  # proxy not done: the phase writes it
            ctx.state.set_status("proxy", "done")
            self.assertTrue(ds.pending_dns(ctx))
            self.assertIn("host-record=vite.app.example.com.webstack,10.0.0.2", ds.dns_body(ctx, "10.0.0.2"))
            self.assertTrue(ds.refresh_dns(ctx))
            self.assertEqual(ctx.phase, "proxy")
            self.assertTrue(any(c[:2] == ["sudo", "install"] and str(conf) in c for c in runner.calls))
            self.assertIn(["sudo", "systemctl", "restart", "dnsmasq"], runner.calls)
            self.assertTrue(ctx.journal.owns("host_file", path=str(conf)))
            conf.write_text(ds.dns_body(ctx, "10.0.0.2"))
            self.assertFalse(ds.pending_dns(ctx))


class BrowseTests(unittest.TestCase):
    def ctx(self, d, runner=None, **kw):
        return make_ctx(Path(d), runner or FakeRunner(), **{"caddy.dev_servers": {"vite": "5173"}, **kw})

    def test_confinement_flags(self):
        with tempfile.TemporaryDirectory() as d:
            ctx = self.ctx(d)
            argv = ds.browser_argv(ctx, "chromium", "https://app.example.com.webstack/", False)
            self.assertEqual(argv[-1], "https://app.example.com.webstack/")  # a normal window by default
            self.assertIn("--proxy-server=http://127.0.0.1:9", argv)
            self.assertIn("--proxy-bypass-list=*.webstack;<-loopback>", argv)  # loopback is NOT bypassed
            self.assertIn("--force-webrtc-ip-handling-policy=disable_non_proxied_udp", argv)
            self.assertIn("--disable-extensions", argv)
            self.assertIn(f"--user-data-dir={ctx.state_dir / 'browser' / 'profile'}", argv)
            self.assertEqual(ds.browser_argv(ctx, "chromium", "https://x.webstack/", True)[-1], "--app=https://x.webstack/")
            single = self.ctx(d, **{"dns.tld": "", "dns.extra_names": ["api.example.com"]})
            self.assertEqual(ds.dev_domains(single.cfg), ["app.example.com", "*.app.example.com", "api.example.com"])

    def test_targets_stay_in_the_dev_domain(self):
        with tempfile.TemporaryDirectory() as d:
            ctx = self.ctx(d)
            self.assertEqual(ds.browser_target(ctx, None), "https://app.example.com.webstack/")
            self.assertEqual(ds.browser_target(ctx, "vite"), "https://vite.app.example.com.webstack/")
            self.assertEqual(ds.browser_target(ctx, "other.webstack/x"), "https://other.webstack/x")
            for bad in ("example.com", "https://webstack.evil.com/", "file:///etc/passwd", "http://127.0.0.1:5173/",
                        "https://evilwebstack/", "javascript:alert(1)"):
                with self.assertRaises(ds.ConfigError, msg=bad):
                    ds.browser_target(ctx, bad)

    def test_env_has_its_own_home_and_no_xdg_dirs(self):
        old = dict(os.environ)
        try:
            os.environ.update({"XDG_CONFIG_HOME": "/home/me/.config", "XDG_RUNTIME_DIR": "/run/user/1000",
                               "WAYLAND_DISPLAY": "wayland-0"})
            env = ds.browser_env(Path("/state/browser"))
        finally:
            os.environ.clear()
            os.environ.update(old)
        self.assertEqual(env["HOME"], "/state/browser")  # Chromium's NSS db is $HOME/.pki/nssdb
        self.assertNotIn("XDG_CONFIG_HOME", env)
        self.assertEqual(env["XDG_RUNTIME_DIR"], "/run/user/1000")
        self.assertEqual(env["WAYLAND_DISPLAY"], "wayland-0")

    def test_trust_goes_into_the_browsers_own_db_once(self):
        ca_pem = "-----BEGIN CERTIFICATE-----\nMIIBroot\n-----END CERTIFICATE-----\n"

        class Runner(FakeRunner):
            listed = ""

            def run(self, argv, **kw):
                p = super().run(argv, **kw)
                return subprocess.CompletedProcess(p.args, 0, self.listed if "-L" in argv else "", "")

        with tempfile.TemporaryDirectory() as d:
            runner = Runner()
            ctx = self.ctx(d, runner)
            ca = Path(d) / "root.crt"
            ca.write_text(ca_pem)
            db = ctx.state_dir / "browser" / ".pki" / "nssdb"
            ds.ensure_browser_trust(ctx, ca)
            self.assertEqual([c[:2] for c in runner.calls if c[0] == "certutil"],
                             [["certutil", "-N"], ["certutil", "-L"], ["certutil", "-D"], ["certutil", "-A"]])
            self.assertIn(f"sql:{db}", runner.calls[0])
            self.assertNotIn(str(Path.home() / ".pki"), " ".join(" ".join(c) for c in runner.calls))
            (db / "cert9.db").write_text("")
            runner.calls.clear()
            runner.listed = ca_pem.replace("\n", "\r\n")  # what certutil -L -a prints
            ds.ensure_browser_trust(ctx, ca)
            self.assertEqual([c[:2] for c in runner.calls], [["certutil", "-L"]])  # already trusted

    def test_browse_launches_detached_with_checks(self):
        with tempfile.TemporaryDirectory() as d:
            ctx = self.ctx(d)
            args = argparse.Namespace(target="vite", app=False)
            with self.assertRaises(ds.DevstackError):
                ds.cmd_browse(ctx, args)  # no proxy phase yet
            ctx.state.set_status("proxy", "done")
            (ctx.state_dir / "ca").mkdir()
            (ctx.state_dir / "ca" / "root.crt").write_text("pem")
            launched = []
            saved = (ds.launch_detached, ds.dead_proxy_free, ds.ensure_browser_trust, ds.shutil.which)
            try:
                ds.launch_detached = lambda argv, env, log_path: launched.append((argv, env, log_path))
                ds.ensure_browser_trust = lambda ctx, ca: None
                ds.shutil.which = lambda b: f"/usr/bin/{b}"
                ds.dead_proxy_free = lambda: False
                with self.assertRaises(ds.DevstackError) as cm:
                    ds.cmd_browse(ctx, args)
                self.assertIn("127.0.0.1:9", str(cm.exception))
                ds.dead_proxy_free = lambda: True
                self.assertEqual(ds.cmd_browse(ctx, args), 0)
            finally:
                ds.launch_detached, ds.dead_proxy_free, ds.ensure_browser_trust, ds.shutil.which = saved
            argv, env, log_path = launched[0]
            self.assertEqual(argv[0], "chromium")
            self.assertEqual(argv[-1], "https://vite.app.example.com.webstack/")
            self.assertEqual(env["HOME"], str(ctx.state_dir / "browser"))
            self.assertEqual((ctx.state_dir / "browser").stat().st_mode & 0o777, 0o700)

    def test_dead_proxy_check(self):
        self.assertIsInstance(ds.dead_proxy_free(), bool)


@unittest.skipUnless(shutil.which("openssl"), "openssl not installed")
class CaTests(unittest.TestCase):
    def test_constrained_root_and_intermediate(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            ctx = make_ctx(tmp)  # real Runner
            root = ds.ensure_host_ca(ctx)
            ca = root.parent
            for name in ("root.key", "intermediate.key"):
                self.assertEqual((ca / name).stat().st_mode & 0o777, 0o600, name)
            text = subprocess.run(["openssl", "x509", "-in", root, "-noout", "-text"], capture_output=True,
                                  text=True, check=True).stdout
            self.assertIn("Name Constraints: critical", text)
            self.assertIn("DNS:.webstack", text)
            # leaf for the dev domain verifies, leaf for another site is rejected by the name constraint
            for host, ok in (("app.example.com.webstack", True), ("bank.example.com", False)):
                key, csr, crt = tmp / "k.pem", tmp / "r.csr", tmp / "l.crt"
                ext = tmp / "ext.cnf"
                ext.write_text(f"subjectAltName=DNS:{host}\nbasicConstraints=CA:FALSE\n")
                subprocess.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
                                "-out", key], check=True, capture_output=True)
                subprocess.run(["openssl", "req", "-new", "-key", key, "-subj", f"/CN={host}", "-out", csr],
                               check=True, capture_output=True)
                subprocess.run(["openssl", "x509", "-req", "-in", csr, "-CA", ca / "intermediate.crt", "-CAkey",
                                ca / "intermediate.key", "-set_serial", "7", "-days", "1", "-extfile", ext,
                                "-out", crt], check=True, capture_output=True)
                p = subprocess.run(["openssl", "verify", "-CAfile", root, "-untrusted", ca / "intermediate.crt",
                                    "-verify_hostname", host, crt], capture_output=True, text=True)
                self.assertEqual(p.returncode == 0, ok, f"{host}: {p.stdout}{p.stderr}")
                if not ok:
                    self.assertIn("permitted subtree violation", p.stdout + p.stderr)

    def test_reuse_and_regenerate_on_name_change(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            ctx = make_ctx(tmp)
            root = ds.ensure_host_ca(ctx)
            before = root.read_bytes()
            ds.ensure_host_ca(ctx)
            self.assertEqual(root.read_bytes(), before)  # unchanged config: same CA
            ctx2 = make_ctx(tmp, **{"dns.tld": "internal"})
            ds.ensure_host_ca(ctx2)
            self.assertNotEqual(root.read_bytes(), before)  # new constraints: new root
            self.assertEqual(json.loads((root.parent / "names.json").read_text()), [".internal"])


class LoggingTests(unittest.TestCase):
    def test_log_file_is_private(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "logs" / "devstack.log"
            f.parent.mkdir()
            f.write_text("old\n")
            os.chmod(f, 0o644)
            ds.setup_logging("file", str(f), "info")
            ds.log.info("hello")
            for h in ds.log.handlers:
                h.flush()
            self.assertEqual(f.stat().st_mode & 0o777, 0o600)
            self.assertIn("hello", f.read_text())
            ds.setup_logging()  # detach


RUNNER = {"name": "fetch", "command": "node scripts/runner.ts", "port": 9101}


class IsolationConfigTests(unittest.TestCase):
    def test_defaults(self):
        cfg = make_config()
        self.assertEqual(cfg["container.sudo"], "limited")
        self.assertEqual(cfg["app.profile"], "local")
        self.assertEqual(cfg["app.data"], "volume")
        self.assertEqual(cfg["app.data_volume"], "webstack-appdata")
        self.assertEqual(cfg["postgres.test_db"], "webstack_test")
        self.assertEqual(cfg["project.readonly_paths"], [])
        self.assertEqual(cfg["network.acl_name"], "devstack-webstack")
        self.assertEqual(ds.isolation_ids(cfg), {"app_uid": 510, "runner_uid": 511, "data_gid": 512, "dev_gid": 513})

    def test_runner_defaults_are_filled_in(self):
        cfg = make_config(**{"app.runners": [RUNNER]})
        self.assertEqual(cfg["app.runners"], [{**RUNNER, "memory_max": "1G", "runtime_max": "1h", "max_connections": 4}])

    def test_bad_runners_rejected(self):
        bad = [
            {**RUNNER, "name": "Fetch"},
            {**RUNNER, "command": "node $HOME/x.ts"},
            {**RUNNER, "command": "sh -c 'curl x'"},
            {**RUNNER, "command": "node %h/x"},
            {**RUNNER, "port": 8080},  # app.port
            {**RUNNER, "port": 5432},  # postgres.port
            {**RUNNER, "memory_max": "lots"},
            {**RUNNER, "runtime_max": "forever"},
            {**RUNNER, "max_connections": 0},
        ]
        for r in bad:
            with self.assertRaises(ds.ConfigError, msg=r):
                make_config(**{"app.runners": [r]})
        with self.assertRaises(ds.ConfigError):
            make_config(**{"app.runners": [RUNNER, {**RUNNER, "name": "other"}]})  # same port
        with self.assertRaises(ds.ConfigError):
            make_config(**{"app.runners": [{"name": "x", "port": 9000}]})  # no command

    def test_other_checks(self):
        with self.assertRaises(ds.ConfigError):
            make_config(**{"app.data": "host"})  # needs app.data_source
        with self.assertRaises(ds.ConfigError):
            make_config(**{"isolation.system_uid_base": 498})  # 498-501 overlaps postgres 500
        with self.assertRaises(ds.ConfigError):
            make_config(**{"postgres.test_db": "webstack"})
        with self.assertRaises(ds.ConfigError):
            make_config(**{"network.allow_private": ["192.168.1.300/32"]})
        with self.assertRaises(ds.ConfigError):
            make_config(**{"caddy.admin": "localhost:2019"})
        with self.assertRaises(ds.ConfigError):
            make_config(**{"isolation.data_group": "{stack.name}-dev"})
        self.assertEqual(make_config(**{"postgres.test_db": ""})["postgres.test_db"], "")

    def test_example_toml_roundtrip_with_runners(self):
        import tomllib
        values = {**ds.defaults(), "app.runners": [RUNNER]}
        data = tomllib.loads(ds.config_to_toml(values))
        self.assertEqual(data["app"]["runners"], [RUNNER])


class IsolationRiskTests(unittest.TestCase):
    def risks(self, **overrides):
        with tempfile.TemporaryDirectory() as d:
            ctx = make_ctx(Path(d), FakeRunner(), **overrides)
            rep = ds.Report()
            ds.preflight_isolation(ctx, rep, set())
            return rep.risks, ctx

    def test_defaults_have_no_risks(self):
        self.assertEqual(self.risks()[0], [])

    def test_widening_settings_are_risks(self):
        for key, val, word in (("container.sudo", "full", "root"), ("app.profile", "open", "anywhere"),
                               ("network.allow_private", ["192.168.1.20/32"], "192.168.1.20")):
            risks, _ = self.risks(**{key: val})
            self.assertEqual(len(risks), 1, key)
            self.assertIn(word, risks[0])

    def test_new_or_changed_runner_is_a_risk_until_applied(self):
        with tempfile.TemporaryDirectory() as d:
            ctx = make_ctx(Path(d), FakeRunner(), **{"app.runners": [RUNNER]})
            rep = ds.Report()
            ds.preflight_isolation(ctx, rep, set())
            self.assertTrue(any("fetch" in r for r in rep.risks))
            ctx.state.set_fact("runners", ctx.cfg["app.runners"])
            rep = ds.Report()
            ds.preflight_isolation(ctx, rep, set())
            self.assertEqual(rep.risks, [])
            ctx2 = make_ctx(Path(d), FakeRunner(), **{"app.runners": [{**RUNNER, "command": "node other.ts"}]})
            rep = ds.Report()
            ds.preflight_isolation(ctx2, rep, set())
            self.assertTrue(any("node other.ts" in r for r in rep.risks))


class IsolationRenderTests(unittest.TestCase):
    def ctx(self, d, **overrides):
        return make_ctx(Path(d), FakeRunner(), **overrides)

    def test_app_unit(self):
        with tempfile.TemporaryDirectory() as d:
            unit = ds.render("system/app.service", self.ctx(d).tvars())
            self.assertIn("User=webstack-app\n", unit)
            self.assertIn("Group=webstack-data\n", unit)
            self.assertIn("Requires=devstack-egress.service", unit)
            self.assertIn("StateDirectory=webstack-app\n", unit)
            self.assertIn("UMask=0027", unit)
            for directive in ("IPAddressDeny=", "IPAddressAllow=", "DynamicUser="):
                self.assertNotRegex(unit, rf"(?m)^{directive}", directive)
            self.assertNotIn("@@", unit)
            none = ds.render("system/app.service", self.ctx(d, **{"app.data": "none"}).tvars())
            self.assertNotIn("StateDirectory", none)

    def test_egress_profiles(self):
        with tempfile.TemporaryDirectory() as d:
            for runners in ([], [RUNNER], [RUNNER, {**RUNNER, "name": "convert", "port": 9102}]):
                for profile, chain in (("local", "jump local_only"), ("internet", "jump local_internet"),
                                       ("open", None)):
                    c = self.ctx(d, **{"app.profile": profile, "app.runners": runners}).cfg
                    nft = ds.egress_nft(c, ["127.0.0.53", "fd42::1"])
                    self.assertNotIn("@@", nft)
                    if chain:
                        self.assertIn(f"meta skuid 510 {chain}", nft)
                    else:
                        self.assertNotIn("meta skuid 510", nft)
                    self.assertIn("meta skuid 511 jump internet_only", nft)
                    self.assertIn("ip daddr 127.0.0.53 meta l4proto { tcp, udp } th dport 53 accept", nft)
                    self.assertIn("ip6 daddr fd42::1 meta l4proto", nft)
                    self.assertNotIn("flush ruleset", nft.split("\n#\n")[-1].replace("`flush ruleset`", ""))
            local = nft.split("chain local_only {")[1].split("chain local_internet")[0]
            self.assertLess(local.index("dport 53 reject"), local.index('oif "lo" accept'))  # no DNS tunnel
            out = nft.split("chain out {")[1].split("chain local_only")[0]
            self.assertIn("ct state established,related accept", out)
            # a resolver on the bridge gateway is a private address: both internet chains must allow it first
            for chain in ("local_internet", "internet_only"):
                body = nft.split(f"chain {chain} {{")[1]
                self.assertLess(body.index("ip daddr 127.0.0.53"), body.index("@blocked4"), chain)

    def test_nameservers(self):
        text = "# x\nnameserver 10.60.225.1\nnameserver fe80::1%eth0\nnameserver bogus\nsearch lan\n"
        self.assertEqual(ds.nameservers(text), ["10.60.225.1", "fe80::1"])

    def test_runner_units(self):
        with tempfile.TemporaryDirectory() as d:
            ctx = self.ctx(d, **{"app.runners": [RUNNER]})
            units = ds.runner_units(ctx.cfg, ctx.tvars())
            sock = units["/etc/systemd/system/webstack-fetch.socket"]
            svc = units["/etc/systemd/system/webstack-fetch@.service"]
            self.assertIn("ListenStream=127.0.0.1:9101", sock)
            self.assertIn("Accept=yes", sock)
            self.assertIn("MaxConnections=4", sock)
            self.assertIn("ExecStart=node scripts/runner.ts", svc)
            self.assertIn("User=webstack-runner", svc)
            self.assertIn("ReadWritePaths=/var/lib/webstack-app/incoming", svc)
            self.assertIn("InaccessiblePaths=-/srv/webstack/.git", svc)
            self.assertNotRegex(svc, r"(?m)^EnvironmentFile=")
            self.assertNotIn("webstack-data", svc)  # not in the data group
            for text in units.values():
                self.assertNotIn("@@", text)
            nodata = self.ctx(d, **{"app.runners": [RUNNER], "app.data": "none"})
            svc = ds.runner_units(nodata.cfg, nodata.tvars())["/etc/systemd/system/webstack-fetch@.service"]
            self.assertNotIn("ReadWritePaths", svc)

    def test_sudoers_line(self):
        script = ds.bash(ds.SUDO_APPLY, USER="alice", MODE="limited", DROPIN="/etc/sudoers.d/devstack-webstack")
        self.assertIn("ALL=(root) NOPASSWD: /usr/local/sbin/devstack-sync", script)
        self.assertIn("visudo -qcf", script)
        self.assertEqual(ds.sudoers_dropin(make_config()), "/etc/sudoers.d/devstack-webstack")


class DevstackSyncTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.script = Path(self._tmp.name) / "devstack-sync"
        cfg = make_config(**{"app.runners": [RUNNER]})
        self.script.write_text(ds.devstack_sync_script(cfg))

    def tearDown(self):
        self._tmp.cleanup()

    def run_sync(self, *args, stdin=""):
        return subprocess.run(["bash", self.script, *args], input=stdin, text=True, capture_output=True)

    def test_syntax_and_values(self):
        self.assertEqual(subprocess.run(["bash", "-n", self.script]).returncode, 0)
        text = self.script.read_text()
        self.assertNotIn("@@", text)
        self.assertIn("app_unit=webstack-app.service", text)
        self.assertIn("runner_sockets=(webstack-fetch.socket)", text)

    def test_validate_caddy_needs_root_and_takes_only_caddy(self):
        if os.getuid() == 0:
            self.skipTest("runs as root")
        p = self.run_sync("validate", "caddy")
        self.assertEqual(p.returncode, 1)
        self.assertIn("run it with sudo", p.stderr)
        self.assertEqual(self.run_sync("validate", "/etc/shadow").returncode, 2)
        self.assertIn("validate caddy", self.run_sync().stderr)  # listed in the usage

    def test_accepts_package_names(self):
        p = self.run_sync("check-packages", stdin="# tools\nwoff2\n  g++  # compiler\n\nlibnss3-tools\n")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.split(), ["woff2", "g++", "libnss3-tools"])
        self.assertEqual(self.run_sync("check-packages", stdin="").returncode, 0)

    def test_rejects_bad_names(self):
        for bad in ("-o", "foo;rm", "../x", "pkg=1.0", "pkg-", "lib.*", "a b", "pkg/trixie", "Pkg", "x",
                    "foo:amd64", "$(id)"):
            p = self.run_sync("check-packages", stdin=f"woff2\n{bad}\n")
            self.assertEqual(p.returncode, 1, bad)
            self.assertEqual(p.stdout, "", bad)  # all or nothing

    def test_rejects_oversized_input(self):
        p = self.run_sync("check-packages", stdin="a1\n" * 30000)
        self.assertEqual(p.returncode, 1)
        self.assertIn("larger than", p.stderr)

    def test_fixed_commands_only(self):
        for args in ((), ("restart", "caddy"), ("reload", "app"), ("packages", "extra"), ("shell",)):
            self.assertEqual(self.run_sync(*args).returncode, 2, args)
        if os.geteuid() != 0:
            p = self.run_sync("packages", stdin="woff2\n")
            self.assertEqual(p.returncode, 1)
            self.assertIn("sudo", p.stderr)


class AclTests(unittest.TestCase):
    GW = ["10.60.225.1", "fd42:1c01:fe6d:fbce::1"]

    def rules(self, host=("192.168.1.10", "203.0.113.5", "10.60.225.1"), allow=()):
        return ds.acl_rules(self.GW, list(host), list(allow))

    def covered(self, rules, addr, proto=None):
        import ipaddress
        a = ipaddress.ip_address(addr)
        return [r for r in rules if (proto is None or r.get("protocol") in (None, proto)) and
                any(a in ipaddress.ip_network(n) for n in r["destination"].split(","))]

    def test_only_rejects_and_gateway_keeps_dns_and_dhcp(self):
        rules = self.rules()
        self.assertTrue(all(r["action"] == "reject" for r in rules))
        for gw in self.GW:
            hits = self.covered(rules, gw)
            self.assertTrue(hits and all("destination_port" in r for r in hits), gw)  # never a blanket reject
            for r in hits:
                ports = r["destination_port"]
                self.assertNotIn(",53,", f",{ports},")
                for rng in ports.split(","):
                    lo, _, hi = rng.partition("-")
                    for keep in ((53,) if r["protocol"] == "tcp" else (53, 67, 547)):
                        self.assertFalse(int(lo) <= keep <= int(hi or lo), (gw, r))

    def test_lan_host_and_neighbours_rejected(self):
        rules = self.rules()
        for addr in ("192.168.1.10", "203.0.113.5", "10.60.225.7", "172.17.0.1", "169.254.169.254",
                     "fd42:1c01:fe6d:fbce::7"):
            self.assertTrue(self.covered(rules, addr), addr)
        self.assertTrue(self.covered(rules, "fe80::1", "tcp"))
        self.assertFalse(self.covered(rules, "1.1.1.1"))
        self.assertFalse(self.covered(rules, "2606:4700::1111"))

    def test_allow_private_is_carved_out(self):
        rules = self.rules(allow=["192.168.1.20/32"])
        self.assertFalse(self.covered(rules, "192.168.1.20"))
        self.assertTrue(self.covered(rules, "192.168.1.21"))

    def test_probe_ips(self):
        self.assertEqual(ds.acl_probe_ips(self.GW, ["192.168.1.10", "10.60.225.1", "2001:db8::5"]),
                         ["10.60.225.1", "192.168.1.10"])

    def acl_ctx(self, d, runner, acl_exists):
        ctx = make_ctx(Path(d), runner)
        devices = {"eth0": {"type": "nic", "network": "incusbr0"}}
        ctx.instance = lambda name=None: {"status": "Running", "devices": devices, "expanded_devices": devices}
        state = {"addresses": [{"family": "inet", "address": "10.60.225.1", "scope": "global"}]}
        ctx.iq = lambda path: (state if path.endswith("/state") else ({} if acl_exists and "network-acls" in path
                                                                       else None))
        return ctx

    def test_ensure_acl_creates_journals_and_attaches_with_allow_defaults(self):
        with tempfile.TemporaryDirectory() as d:
            runner = FakeRunner()
            ctx = self.acl_ctx(d, runner, acl_exists=False)
            ctx.phase = "base"
            ds.ensure_acl(ctx)
            self.assertEqual(runner.calls[1][:5], ["incus", "query", "-X", "POST", "/1.0/network-acls"])
            body = json.loads(runner.calls[1][6])
            self.assertEqual(body["name"], "devstack-webstack")
            self.assertEqual(body["ingress"], [])
            self.assertIn(["incus", "config", "device", "set", "webstack", "eth0", "security.acls=devstack-webstack",
                           "security.acls.default.ingress.action=allow", "security.acls.default.egress.action=allow"],
                          runner.calls)
            self.assertTrue(ctx.journal.owns("incus_acl", name="devstack-webstack"))

    def test_acl_undo_detaches_then_deletes_and_checks_name(self):
        with tempfile.TemporaryDirectory() as d:
            runner = FakeRunner()
            ctx = self.acl_ctx(d, runner, acl_exists=True)
            devices = {"eth0": {"type": "nic", "security.acls": "devstack-webstack",
                                "security.acls.default.ingress.action": "allow"}}
            ctx.instance = lambda name=None: {"devices": devices}
            args = {"name": "someone-elses", "instance": "webstack", "nic": "eth0"}
            self.assertEqual(ds.UNDO["incus_acl"](ctx, args, ds.UndoOpts()), "kept")
            self.assertEqual(runner.calls, [])
            args["name"] = "devstack-webstack"
            self.assertEqual(ds.UNDO["incus_acl"](ctx, args, ds.UndoOpts(whole=True)), "undone")
            self.assertEqual(runner.calls, [
                ["incus", "config", "device", "unset", "webstack", "eth0", "security.acls"],
                ["incus", "config", "device", "unset", "webstack", "eth0", "security.acls.default.ingress.action"],
                ["incus", "network", "acl", "delete", "devstack-webstack"],
            ])

    def test_ensure_git_repo(self):
        with tempfile.TemporaryDirectory() as d:
            runner = FakeRunner()
            ctx = make_ctx(Path(d), runner)  # make_ctx creates an empty project folder
            cfg_set = ["git", "config", "--file", str(ctx.project / ".git" / "config"), "core.useReplaceRefs", "false"]
            ds.ensure_git_repo(ctx)
            self.assertEqual(runner.calls, [["git", "init", "-q", str(ctx.project)], cfg_set])
            runner.calls.clear()
            (ctx.project / "notes.txt").write_text("someone's existing project\n")
            ds.ensure_git_repo(ctx)  # git is required: an existing project becomes a repo too
            self.assertEqual(runner.calls[0], ["git", "init", "-q", str(ctx.project)])
            runner.calls.clear()
            (ctx.project / ".git").mkdir()
            ds.ensure_git_repo(ctx)
            self.assertEqual(runner.calls, [cfg_set])  # already a repo: only the config

    def test_git_dir_must_be_a_plain_folder(self):
        with tempfile.TemporaryDirectory() as d:
            ctx = make_ctx(Path(d), FakeRunner())
            (ctx.project / ".git").write_text("gitdir: /elsewhere/.git/worktrees/x\n")
            with self.assertRaises(ds.DevstackError):
                ds.ensure_git_repo(ctx)
            (ctx.project / ".git").unlink()
            (Path(d) / "real").mkdir()
            (ctx.project / ".git").symlink_to(Path(d) / "real")
            self.assertIn("symlink", ds.git_dir_problem(ctx.project))
            self.assertEqual(ctx.r.calls, [])

    def test_readonly_devices_are_named_by_path(self):
        with tempfile.TemporaryDirectory() as d:
            ctx = make_ctx(Path(d), FakeRunner())
            devs = ds.readonly_devices(ctx)
            self.assertEqual([x[:2] for x in devs], [("git", ".git")])  # by default, and always first
            self.assertEqual(devs[0][2], {"source": str(ctx.project / ".git"), "path": f"{ctx.cproject}/.git",
                                          "readonly": "true", "shift": "true"})
            ctx = make_ctx(Path(d), FakeRunner(), **{
                "project.readonly_paths": ["a/b", ".git/hooks", "./.vscode/", "a", ".git/config"]})
            rels = [rel for _, rel, _ in ds.readonly_devices(ctx)]
            self.assertEqual(rels, [".git", ".vscode", "a", "a/b"])  # .git entries folded in, parents first
            names = {rel: dev for dev, rel, _ in ds.readonly_devices(ctx)}
            ctx2 = make_ctx(Path(d), FakeRunner(), **{"project.readonly_paths": ["a"]})
            self.assertEqual(ds.readonly_devices(ctx2)[1][0], names["a"])  # removing others doesn't rename it

    def test_extra_readonly_path_added_once_it_exists(self):
        with tempfile.TemporaryDirectory() as d:
            ctx = make_ctx(Path(d), FakeRunner(), **{"network.acl": False, "project.readonly_paths": [".vscode"]})
            git = dict(ds.readonly_devices(ctx)[0][2], type="disk")
            ctx.instance = lambda name=None: {"status": "Running", "devices": {"project": {}, "git": git}}
            self.assertEqual(ds.readonly_changes(ctx), ([], []))  # base not done
            ctx.state.set_status("base", "done")
            self.assertEqual(ds.readonly_changes(ctx), ([], []))
            (ctx.project / ".vscode").mkdir()
            self.assertEqual([x[:2] for x in ds.readonly_changes(ctx)[1]], [(ds.ro_device(".vscode"), ".vscode")])

    def test_old_numbered_devices_give_way_to_the_whole_git(self):
        """A container from before: ro1/ro2 protect .git/hooks and .git/config only. up stops it, removes
        them, mounts all of .git and starts it again -- never hot-unmounting under the new mount."""

        class Runner(FakeRunner):
            def run(self, argv, **kw):
                p = super().run(argv, **kw)
                return subprocess.CompletedProcess(p.args, 0, "ro,relatime\n" if "findmnt" in argv[-1] else "", "")

        with tempfile.TemporaryDirectory() as d:
            runner = Runner()
            ctx = make_ctx(Path(d), runner, **{"network.acl": False})
            devices = {"project": {}, "ro1": {"path": f"{ctx.cproject}/.git/hooks"},
                       "ro2": {"path": f"{ctx.cproject}/.git/config"}}
            ctx.instance = lambda name=None: {"status": "Running", "devices": devices}
            ctx.wait_ipv4 = lambda: "10.0.0.2"
            for dev in ("ro1", "ro2"):
                ctx.journal.mark(ctx.journal.add("base", "incus_device", instance=ctx.name, device=dev), "applied")
            ctx.state.set_status("base", "done")
            (ctx.project / ".git" / "refs" / "replace").mkdir(parents=True)
            (ctx.project / ".git" / "refs" / "replace" / ("a" * 40)).write_text("b" * 40 + "\n")
            plan = "\n".join(ds.pending_base(ctx))
            self.assertIn("remove incus device 'ro1'", plan)
            self.assertIn("incus device 'git'", plan)
            self.assertIn("stopped", plan)
            with self.assertLogs("devstack", "WARNING") as logs:
                self.assertTrue(ds.add_pending_mounts(ctx))
            order = [c[:5] for c in runner.calls if c[0] == "incus"]
            self.assertEqual(order[0], ["incus", "stop", ctx.name, "--timeout", "60"])
            self.assertEqual(order[1:3], [["incus", "config", "device", "remove", ctx.name]] * 2)
            self.assertEqual(order[3], ["incus", "config", "device", "add", ctx.name])
            self.assertEqual(order[4][:3], ["incus", "start", ctx.name])
            self.assertIn(["git", "config", "--file", str(ctx.project / ".git" / "config"), "core.useReplaceRefs",
                           "false"], runner.calls)
            self.assertEqual({e["args"]["device"]: e["status"] for e in ctx.journal.entries},
                             {"ro1": "undone", "ro2": "undone", "git": "applied"})
            self.assertTrue(any("review: replace refs refs/replace/" in m for m in logs.output))

    def test_stale_readonly_reads_the_container_not_the_journal(self):
        """Undoing a phase restores a snapshot from before the migration: ro1 is back on the container
        although the journal says it was removed. It must still count as stale."""
        with tempfile.TemporaryDirectory() as d:
            ctx = make_ctx(Path(d), FakeRunner())
            git = dict(ds.readonly_devices(ctx)[0][2], type="disk")
            inst = {"devices": {"project": {"path": ctx.cproject}, "git": git,
                                "ro1": {"path": f"{ctx.cproject}/.git/hooks"},
                                "store": {"path": "/srv/store"}}}
            self.assertEqual(ds.stale_readonly(ctx, inst), [("ro1", f"{ctx.cproject}/.git/hooks")])
            self.assertEqual(ds.missing_readonly(ctx, inst), [])
            errors = ds.validate({**ds.defaults(), "container.mounts": [
                {"name": "ro-0123456789ab", "source": "/srv/a", "path": "/srv/a"}]})
            self.assertTrue(any("ro-<hex>" in e for e in errors))  # the names stay devstack's

    def test_readonly_drift(self):
        with tempfile.TemporaryDirectory() as d:
            ctx = make_ctx(Path(d), FakeRunner())
            git = dict(ds.readonly_devices(ctx)[0][2], type="disk")
            self.assertEqual(ds.readonly_drift(ctx, {"devices": {"git": git}}), [])
            drift = ds.readonly_drift(ctx, {"devices": {"git": {**git, "readonly": "false"}}})
            self.assertEqual(len(drift), 1)
            self.assertIn("device 'git'", drift[0])

    def test_git_history_findings(self):
        with tempfile.TemporaryDirectory() as d:
            project = Path(d)
            g = project / ".git"
            (g / "objects" / "info").mkdir(parents=True)
            (g / "info").mkdir()
            self.assertEqual(ds.git_history_findings(project), [])
            (g / "objects" / "info" / "alternates").write_text("\n")  # empty: harmless
            (g / "packed-refs").write_text("# pack-refs with: peeled\n" + "c" * 40 + " refs/replace/" + "d" * 40
                                           + "\n" + "e" * 40 + " refs/heads/main\n")
            (g / "info" / "grafts").write_text("f" * 40 + "\n")
            found = ds.git_history_findings(project)
            self.assertEqual(len(found), 2)
            self.assertIn("refs/replace/" + "d" * 40, found[0])
            self.assertIn(".git/info/grafts", found[1])

    @unittest.skipUnless(shutil.which("git"), "needs git")
    def test_git_exec_findings(self):
        with tempfile.TemporaryDirectory() as d:
            ctx = make_ctx(Path(d), ds.Runner(False))
            subprocess.run(["git", "init", "-q", str(ctx.project)], check=True)
            cfg = str(ctx.project / ".git" / "config")
            for k, v in (("core.fsmonitor", "touch /tmp/pwned"), ("alias.st", "!sh -c x"),
                         ("user.name", "someone"), ('filter.x.clean', "cat"), ("include.path", "../evil")):
                subprocess.run(["git", "config", "--file", cfg, k, v], check=True)
            hooks = ctx.project / ".git" / "hooks"
            hooks.mkdir(exist_ok=True)
            (hooks / "pre-commit").write_text("#!/bin/sh\n")
            found = ds.git_exec_findings(ctx)
            self.assertEqual(len(found), 2)
            for k in ("core.fsmonitor", "alias.st", "filter.x.clean", "include.path"):
                self.assertIn(k, found[0])
            self.assertNotIn("user.name", found[0])
            self.assertIn("pre-commit", found[1])
            self.assertNotIn(".sample", found[1])

    def test_nested_git(self):
        with tempfile.TemporaryDirectory() as d:
            project = Path(d)
            for sub in (".git", "sub/.git", "node_modules/pkg/.git", "sub/.git/modules/inner/.git"):
                (project / sub).mkdir(parents=True)
            (project / "lib" / "x").mkdir(parents=True)
            (project / "lib" / "x" / ".git").write_text("gitdir: ../../.git/modules/x\n")
            self.assertEqual(ds.nested_git(project), ["lib/x/.git", "sub/.git"])


class ProjectKeysTests(unittest.TestCase):
    def load(self, body):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "req.toml"
            path.write_text(body)
            return ds.load_requirements(path)

    def test_runners_and_app_settings_accepted(self):
        want = self.load('[app]\nprofile = "internet"\ndata = "none"\n\n[[app.runners]]\nname = "fetch"\n'
                         'command = "node scripts/runner.ts"\nport = 9101\n')
        self.assertEqual(want["app.profile"], "internet")
        self.assertEqual(want["app.runners"][0]["memory_max"], "1G")  # normalized like the config

    def test_host_side_settings_refused(self):
        for body in ('[network]\nallow_private = ["192.168.1.0/24"]\n', '[caddy]\nadmin = "localhost:2019"\n',
                     '[app]\ndata_source = "/home/alice"\n', '[app]\ndata_volume = "other"\n'):
            with self.assertRaises(ds.ConfigError, msg=body):
                self.load(body)

    def test_roundtrip_with_runners(self):
        cfg = make_config(**{"app.runners": [RUNNER], "app.profile": "internet"})
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "req.toml"
            path.write_text(ds.requirements_to_toml(ds.requirements(cfg.v)))
            want = ds.load_requirements(path)
        self.assertEqual({"container.mounts": [], **want}, ds.requirements(cfg.v))


class IsolationScriptSyntaxTests(unittest.TestCase):
    def test_rendered_scripts_pass_bash_n(self):
        q = dict
        scripts = {
            "sudo": ds.bash(ds.SUDO_APPLY, USER="u", MODE="limited", DROPIN="/etc/sudoers.d/devstack-x"),
            "accounts": ds.bash(ds.ACCOUNTS, **q(STACK="s", USER="u", APP="s-app", RUNNER="s-runner", DATA="s-data",
                                                DEV="s-dev", APP_UID=510, RUNNER_UID=511, DATA_GID=512, DEV_GID=513)),
            "token": ds.bash(ds.TOKEN_WRITE, DIR="/etc/app-secrets", FILE="/etc/app-secrets/t.env", GROUP="s-dev"),
            "data": ds.bash(ds.DATA_SETUP, DIR="/var/lib/s-app", APP="s-app", DATA="s-data", RUNNER="s-runner"),
            "egress": ds.EGRESS_APPLY,
            "runners": ds.bash(ds.RUNNERS_APPLY, WANT=["s-fetch"]),
            "runners-none": ds.bash(ds.RUNNERS_APPLY, WANT=[]),
            "profile": ds.bash(ds.PROFILE_CHECK, APP="s-app", RUNNER="s-runner", USER="u", PROFILE="local",
                               SUDO="limited", DATADIR="/var/lib/s-app", RESOLVERS=["127.0.0.53"]),
            "acl-probe": ds.bash(ds.ACL_PROBE, USER="u", TARGETS=["10.0.0.1 22"]),
            "restore": ds.bash(ds.DATA_RESTORE, DIR="/var/lib/s-app", APP="s-app", DATA="s-data", RUNNER="s-runner",
                               UNIT="s-app.service", SOCKETS=["s-fetch.socket"]),
            "dev-env": ds.bash(ds.DEV_ENV_WRITE, DIR="/home/u/.config/devstack", FILE="/home/u/.config/devstack/s.env"),
            "caddy": ds.bash(ds.CADDY_APPLY, RESTART=True),
            "pg-verify": ds.bash(ds.PG_VERIFY, ENVFILE="/etc/app-secrets/postgres.env", TEST_DB="s_test"),
        }
        for name, script in scripts.items():
            p = subprocess.run(["bash", "-n"], input=script, text=True, capture_output=True)
            self.assertEqual(p.returncode, 0, f"{name}: {p.stderr}")
        self.assertIn("runuser -u caddy -- caddy validate", scripts["caddy"])


if __name__ == "__main__":
    unittest.main()


# A CycloneDX document shaped exactly like syft 1.54's output: the pieces below were taken from real
# runs against a Debian dpkg database and a pnpm v9 lockfile, then trimmed. Every feature that the
# normalizer has to handle is represented -- a deb purl with arch/distro/upstream qualifiers and
# percent-encoding, the separate operating-system component that carries syft:distro:* (and has no
# purl), an npm component, a "file" component whose name is an absolute host path, bom-refs with
# syft's package-id content hash, and a dependency graph that uses those refs.
def syft_doc(serial="urn:uuid:557c4fbb-f3c6-4da7-a390-386b5d67470b", timestamp="2026-10-05T12:14:34-04:00"):
    return {
        "$schema": "https://cyclonedx.org/schema/bom-1.7.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {"components": [{"type": "application", "author": "anchore",
                                      "name": "syft", "version": "1.54.0"}]},
            "component": {"bom-ref": "6a02b9ad31f4252f", "type": "file", "name": "webstack-container"},
        },
        "components": [
            {"bom-ref": "pkg:deb/debian/zlib1g@1%3A1.3.dfsg%2Breally1.3.1-1?arch=amd64&distro=debian-13"
                        "&package-id=e07b64e6535a8f77&upstream=zlib",
             "type": "library", "name": "zlib1g", "version": "1:1.3.dfsg+really1.3.1-1",
             "cpe": "cpe:2.3:a:zlib1g:zlib1g:1\\:1.3.dfsg\\+really1.3.1-1:*:*:*:*:*:*:*",
             "purl": "pkg:deb/debian/zlib1g@1%3A1.3.dfsg%2Breally1.3.1-1?arch=amd64&distro=debian-13"
                     "&upstream=zlib",
             "properties": [
                 {"name": "syft:package:foundBy", "value": "dpkg-db-cataloger"},
                 {"name": "syft:package:type", "value": "deb"},
                 {"name": "syft:package:metadataType", "value": "dpkg-db-entry"},
                 {"name": "syft:location:0:path", "value": "/var/lib/dpkg/status"},
                 {"name": "syft:metadata:installedSize", "value": "170"},
                 {"name": "syft:metadata:source", "value": "zlib"},
             ]},
            {"bom-ref": "pkg:npm/typescript@5.6.3?package-id=3e4ddcac3bb13f00",
             "type": "library", "name": "typescript", "version": "5.6.3",
             "cpe": "cpe:2.3:a:typescript:typescript:5.6.3:*:*:*:*:*:*:*",
             "purl": "pkg:npm/typescript@5.6.3",
             "properties": [
                 {"name": "syft:package:language", "value": "javascript"},
                 {"name": "syft:package:type", "value": "npm"},
                 {"name": "syft:cpe23", "value": "cpe:2.3:a:typescript:typescript:5.6.3:*:*:*:*:*:*:*"},
                 {"name": "syft:location:0:path", "value": "/pnpm-lock.yaml"},
             ]},
            {"bom-ref": "pkg:npm/undici-types@7.8.0?package-id=4cfe5f504996963b",
             "type": "library", "name": "undici-types", "version": "7.8.0",
             "purl": "pkg:npm/undici-types@7.8.0",
             "properties": [{"name": "syft:package:type", "value": "npm"},
                            {"name": "syft:location:0:path", "value": "/pnpm-lock.yaml"}]},
            {"bom-ref": "os:debian@13", "type": "operating-system", "name": "debian", "version": "13",
             "properties": [
                 {"name": "syft:distro:id", "value": "debian"},
                 {"name": "syft:distro:versionID", "value": "13"},
                 {"name": "syft:distro:prettyName", "value": "Debian GNU/Linux 13 (trixie)"},
             ]},
            # syft names a file component by its absolute path: this is the real leak vector.
            {"bom-ref": "c895fb8e872e275f", "type": "file",
             "name": "/home/alice/code/myproject/pnpm-lock.yaml",
             "hashes": [{"alg": "SHA-256", "content": "ab" * 32}]},
        ],
        "dependencies": [
            {"ref": "pkg:npm/typescript@5.6.3?package-id=3e4ddcac3bb13f00",
             "dependsOn": ["pkg:npm/undici-types@7.8.0?package-id=4cfe5f504996963b"]},
            {"ref": "c895fb8e872e275f", "dependsOn": []},
        ],
    }


class SbomPinTests(unittest.TestCase):
    def test_pin_constants_look_right(self):
        for ver in (ds.SYFT_VERSION, ds.GRYPE_VERSION, ds.GITLEAKS_VERSION):
            self.assertRegex(ver, r"^\d+\.\d+\.\d+$")
        for shas in (ds.SYFT_SHA256, ds.GRYPE_SHA256, ds.GITLEAKS_SHA256):
            self.assertEqual(set(shas), {"amd64", "arm64"})
            for arch, sha in shas.items():
                self.assertRegex(sha, r"^[0-9a-f]{64}$", arch)
        self.assertNotEqual(ds.SYFT_SHA256["amd64"], ds.SYFT_SHA256["arm64"])
        self.assertEqual(set(ds.GITLEAKS_ARCH), set(ds.GITLEAKS_SHA256))

    def test_syft_install_script_carries_the_pins(self):
        out = ds.bash(ds.SYFT_INSTALL, VER=ds.SYFT_VERSION,
                      SHA_AMD64=ds.SYFT_SHA256["amd64"], SHA_ARM64=ds.SYFT_SHA256["arm64"])
        self.assertIn(ds.SYFT_VERSION, out)
        self.assertIn(ds.SYFT_SHA256["amd64"], out)
        self.assertIn(ds.SYFT_SHA256["arm64"], out)
        self.assertIn("sha256sum -c -", out)  # the download is checked, not just fetched
        p = subprocess.run(["bash", "-n"], input=out, text=True, capture_output=True)
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_host_arch_maps_or_refuses(self):
        self.assertIn(ds.host_arch(), ("amd64", "arm64"))

    def test_trust_roots_are_documented(self):
        """A pin that is not written down anywhere is a pin nobody can review. The docs carry the
        table of trust roots, and this test is what keeps them honest."""
        docs = (ROOT / "README.md").read_text() + (ROOT / "DESIGN.md").read_text()
        for name, value in (("CADDY_KEY_FPR", ds.CADDY_KEY_FPR), ("PGDG_KEY_FPR", ds.PGDG_KEY_FPR),
                            ("NODE_KEYRING_COMMIT", ds.NODE_KEYRING_COMMIT),
                            ("NODE_KEYRING_SHA256", ds.NODE_KEYRING_SHA256),
                            ("SYFT_VERSION", ds.SYFT_VERSION), ("GRYPE_VERSION", ds.GRYPE_VERSION),
                            ("SYFT_SHA256/amd64", ds.SYFT_SHA256["amd64"]),
                            ("SYFT_SHA256/arm64", ds.SYFT_SHA256["arm64"]),
                            ("GRYPE_SHA256/amd64", ds.GRYPE_SHA256["amd64"]),
                            ("GRYPE_SHA256/arm64", ds.GRYPE_SHA256["arm64"]),
                            ("GITLEAKS_VERSION", ds.GITLEAKS_VERSION),
                            ("GITLEAKS_SHA256/amd64", ds.GITLEAKS_SHA256["amd64"]),
                            ("GITLEAKS_SHA256/arm64", ds.GITLEAKS_SHA256["arm64"])):
            self.assertIn(value, docs, f"{name} = {value} appears in no doc; bump the pin and the docs together")


class SbomNormalizeTests(unittest.TestCase):
    def norm(self, doc=None, **kw):
        kw.setdefault("kind", "container")
        kw.setdefault("stack", "webstack")
        return ds.normalize_cdx(doc if doc is not None else syft_doc(), **kw)

    def test_two_runs_normalize_to_the_same_bytes(self):
        a = ds.cdx_bytes(self.norm(syft_doc()))
        b = ds.cdx_bytes(self.norm(syft_doc(serial="urn:uuid:" + "0" * 8 + "-1111-2222-3333-444444444444",
                                            timestamp="2027-01-01T00:00:00Z")))
        self.assertEqual(a, b, "a different serialNumber/timestamp changed the committed bytes")

    def test_component_order_does_not_matter(self):
        shuffled = syft_doc()
        shuffled["components"] = list(reversed(shuffled["components"]))
        self.assertEqual(ds.cdx_bytes(self.norm(syft_doc())), ds.cdx_bytes(self.norm(shuffled)))

    def test_idempotent(self):
        once = self.norm()
        self.assertEqual(ds.cdx_bytes(self.norm(once)), ds.cdx_bytes(once))

    def test_grype_matching_inputs_survive(self):
        """The dangerous failure mode: normalize too much and grype silently matches nothing, so the
        gate goes green while meaning nothing. These are the fields it matches on."""
        out = self.norm()
        comps = {c["bom-ref"]: c for c in out["components"]}
        deb = comps["pkg:deb/debian/zlib1g@1%3A1.3.dfsg%2Breally1.3.1-1?arch=amd64&distro=debian-13&upstream=zlib"]
        self.assertIn("arch=amd64", deb["purl"])
        self.assertIn("distro=debian-13", deb["purl"])
        self.assertIn("upstream=zlib", deb["purl"])
        self.assertIn("%3A", deb["purl"])  # percent-encoding must not be "tidied"
        self.assertTrue(deb["cpe"])
        ts = comps["pkg:npm/typescript@5.6.3"]
        self.assertIn("syft:cpe23", [p["name"] for p in ts["properties"]])
        # the operating-system component has no purl but is how grype picks the Debian feed
        os_comp = comps["os:debian@13"]
        self.assertEqual(os_comp["type"], "operating-system")
        props = {p["name"]: p["value"] for p in os_comp["properties"]}
        self.assertEqual(props["syft:distro:id"], "debian")
        self.assertEqual(props["syft:distro:versionID"], "13")

    def test_file_components_are_dropped(self):
        out = self.norm()
        self.assertNotIn("file", [c["type"] for c in out["components"]])
        self.assertNotIn("/home/alice", ds.cdx_bytes(out))

    def test_churny_and_leaky_properties_are_dropped(self):
        names = {p["name"] for c in self.norm()["components"] for p in c.get("properties", [])}
        for gone in ("syft:location:0:path", "syft:package:foundBy",
                     "syft:metadata:installedSize", "syft:metadata:source"):
            self.assertNotIn(gone, names)

    def test_unknown_future_property_is_dropped_not_fatal(self):
        doc = syft_doc()
        doc["components"][1]["properties"].append({"name": "syft:brandnew:thing", "value": "x"})
        names = {p["name"] for c in self.norm(doc)["components"] for p in c.get("properties", [])}
        self.assertNotIn("syft:brandnew:thing", names)

    def test_unstable_ids_are_gone(self):
        out = self.norm()
        text = ds.cdx_bytes(out)
        self.assertNotIn("serialNumber", text)
        self.assertNotIn("timestamp", text)
        self.assertNotIn("package-id=", text)
        self.assertEqual(out["metadata"]["component"]["bom-ref"], "root")
        self.assertEqual(out["metadata"]["component"]["name"], "webstack-container")
        # the syft version stays: it is the honest explanation for a document-wide diff
        self.assertEqual(out["metadata"]["tools"]["components"][0]["version"], "1.54.0")

    def test_dependency_refs_are_rewritten_and_resolve(self):
        out = self.norm()
        known = {c["bom-ref"] for c in out["components"]} | {"root"}
        self.assertTrue(out["dependencies"])
        for d in out["dependencies"]:
            self.assertIn(d["ref"], known)
            for on in d.get("dependsOn", []):
                self.assertIn(on, known)
        self.assertEqual(out["dependencies"][0]["dependsOn"], ["pkg:npm/undici-types@7.8.0"])

    def test_dangling_dependency_ref_is_fatal(self):
        doc = syft_doc()
        doc["components"] = [c for c in doc["components"] if c.get("purl") != "pkg:npm/undici-types@7.8.0"]
        doc["dependencies"] = [{"ref": "pkg:npm/typescript@5.6.3?package-id=3e4ddcac3bb13f00",
                                "dependsOn": ["pkg:npm/ghost@1.0.0?package-id=ffffffffffffffff"]}]
        out = self.norm(doc)  # the unknown dependsOn is filtered, not silently kept
        self.assertEqual(out["dependencies"][0].get("dependsOn"), None)

    def test_duplicate_components_collapse(self):
        doc = syft_doc()
        dup = json.loads(json.dumps(doc["components"][1]))
        dup["bom-ref"] = "pkg:npm/typescript@5.6.3?package-id=aaaaaaaaaaaaaaaa"
        dup["properties"] = [{"name": "syft:location:0:path", "value": "/package.json"},
                             *doc["components"][1]["properties"]]
        doc["components"].append(dup)
        names = [c["name"] for c in self.norm(doc)["components"]]
        self.assertEqual(names.count("typescript"), 1, "the same package found twice should collapse")

    def test_wrong_spec_version_is_fatal(self):
        doc = syft_doc()
        doc["specVersion"] = "1.9"
        with self.assertRaises(ds.DevstackError) as cm:
            self.norm(doc)
        self.assertIn("1.9", str(cm.exception))

    def test_not_cyclonedx_is_fatal(self):
        with self.assertRaises(ds.DevstackError):
            self.norm({"bomFormat": "SPDX", "specVersion": "1.7"})

    def test_bytes_are_canonical(self):
        text = ds.cdx_bytes(self.norm())
        self.assertTrue(text.endswith("\n"))
        self.assertEqual(json.loads(text), self.norm())  # round-trips
        self.assertEqual(text, json.dumps(json.loads(text), indent=2, sort_keys=True,
                                          ensure_ascii=False) + "\n")

    def test_inventory_is_sorted_name_version_purl(self):
        inv = ds.cdx_inventory(self.norm())
        self.assertEqual(inv, sorted(inv))
        self.assertIn(("typescript", "5.6.3", "pkg:npm/typescript@5.6.3"), inv)


class SbomLeakTests(unittest.TestCase):
    def test_host_paths_are_fatal(self):
        for bad in ('{"name": "/home/alice/x"}', '{"name": "/root/x"}', '{"name": "/Users/alice/x"}',
                    '{"serialNumber": "urn:uuid:1234"}', '{"p": "file:///home/x"}'):
            with self.assertRaises(ds.DevstackError, msg=bad):
                ds.assert_no_sbom_leaks(bad, [])

    def test_path_literals_are_fatal(self):
        with self.assertRaises(ds.DevstackError) as cm:
            ds.assert_no_sbom_leaks('{"name": "/home/alice/code/x/lock.yaml"}', ["/home/alice/code/x"])
        self.assertIn("/home/alice/code/x", str(cm.exception))

    def test_a_username_is_only_a_leak_in_path_position(self):
        """Regression: the first real run refused to write because 'user' is a substring of the
        package name adduser. Measured on a 3179-package Debian inventory, matching a username as a
        bare substring gives 144 false positives for 'user', 54 for 'louis' (liblouis) and 25478 for
        'al'. Only a username in path position is evidence of a leak."""
        for fine in ('{"bom-ref": "pkg:deb/debian/adduser@3.152?arch=all&distro=debian-13"}',
                     '{"bom-ref": "pkg:deb/debian/dbus-user-session@1.14.10-1"}',
                     '{"bom-ref": "pkg:deb/debian/liblouis20@3.24.0-1?upstream=liblouis"}',
                     '{"bom-ref": "pkg:npm/home/thing@1.0.0"}',
                     '{"name": "kuserfeedback-doc"}'):
            ds.assert_no_sbom_leaks(fine, [], names=["user", "louis", "al"])
        for leak in ('{"p": "/srv/louis/app"}', '{"p": "/home/louis/x"}', '{"p": "/opt/louis"}'):
            with self.assertRaises(ds.DevstackError, msg=leak):
                ds.assert_no_sbom_leaks(leak, [], names=["louis"])

    def test_container_paths_are_fine(self):
        ds.assert_no_sbom_leaks('{"a": "/srv/webstack/pnpm-lock.yaml", "b": "/var/lib/dpkg/status"}',
                                [], names=["bob"])

    def test_the_real_normalized_document_passes(self):
        ds.assert_no_sbom_leaks(ds.cdx_bytes(ds.normalize_cdx(syft_doc(), kind="app", stack="webstack")), [])

    def test_empty_literal_does_not_match_everything(self):
        ds.assert_no_sbom_leaks('{"a": "b"}', ["", None], names=["", None])


class SbomGateTests(unittest.TestCase):
    def report(self, *sevs, fix="fixed"):
        """By default every finding is fixable, so the severity logic can be tested on its own."""
        return {"matches": [{"vulnerability": {"id": f"CVE-2026-{i:04d}", "severity": s,
                                               "fix": {"state": fix}}}
                            for i, s in enumerate(sevs)]}

    def test_counts_by_severity(self):
        counts, fixable, tripped = ds.gate_findings(self.report("Critical", "High", "High", "Low"), "", [])
        self.assertEqual(counts, {"critical": 1, "high": 2, "low": 1})
        self.assertEqual(fixable, counts)
        self.assertEqual(tripped, [])

    def test_empty_fail_on_never_trips(self):
        self.assertEqual(ds.gate_findings(self.report("Critical", "Critical"), "", [])[2], [])

    def test_fail_on_is_a_floor(self):
        rep = self.report("negligible", "low", "medium", "high", "critical")
        self.assertEqual(len(ds.gate_findings(rep, "high", [])[2]), 2)
        self.assertEqual(len(ds.gate_findings(rep, "critical", [])[2]), 1)
        self.assertEqual(len(ds.gate_findings(rep, "negligible", [])[2]), 5)

    def test_unfixable_findings_are_counted_but_do_not_trip(self):
        """The reason only_fixed defaults to true: measured on a 3214-package Debian system, all
        554 critical findings were not-fixed or wont-fix. Gating on those is a permanently red
        gate, which is worse than no gate because people switch it off."""
        for state in ("not-fixed", "wont-fix", "unknown", ""):
            rep = self.report("Critical", "Critical", fix=state)
            counts, fixable, tripped = ds.gate_findings(rep, "critical", [])
            self.assertEqual(counts, {"critical": 2}, state)   # still reported
            self.assertEqual(fixable, {}, state)
            self.assertEqual(tripped, [], state)               # but not actionable, so no failure

    def test_only_fixed_false_gates_on_everything(self):
        rep = self.report("Critical", fix="wont-fix")
        self.assertEqual(len(ds.gate_findings(rep, "critical", [], only_fixed=False)[2]), 1)

    def test_a_mixed_report_trips_only_on_the_fixable_one(self):
        rep = {"matches": [
            {"vulnerability": {"id": "CVE-A", "severity": "Critical", "fix": {"state": "not-fixed"}}},
            {"vulnerability": {"id": "CVE-B", "severity": "Critical", "fix": {"state": "fixed"}}},
        ]}
        counts, fixable, tripped = ds.gate_findings(rep, "critical", [])
        self.assertEqual((counts, fixable), ({"critical": 2}, {"critical": 1}))
        self.assertEqual(tripped, ["CVE-B"])

    def test_missing_fix_block_is_treated_as_unfixable(self):
        rep = {"matches": [{"vulnerability": {"id": "CVE-X", "severity": "Critical"}}]}
        self.assertEqual(ds.gate_findings(rep, "critical", [])[2], [])

    def test_ignore_filters_and_is_case_insensitive(self):
        rep = {"matches": [{"vulnerability": {"id": "CVE-1", "severity": "Critical", "fix": {"state": "fixed"}}},
                           {"vulnerability": {"id": "GHSA-xyz", "severity": "Critical", "fix": {"state": "fixed"}}}]}
        counts, _fixable, tripped = ds.gate_findings(rep, "high", ["cve-1"])
        self.assertEqual(tripped, ["GHSA-xyz"])
        self.assertEqual(counts, {"critical": 1})

    def test_unknown_severity_counts_but_never_trips(self):
        counts, _f, tripped = ds.gate_findings(self.report("Apocalyptic"), "negligible", [])
        self.assertEqual(counts, {"apocalyptic": 1})
        self.assertEqual(tripped, [])

    def test_same_id_twice_trips_once(self):
        rep = {"matches": [{"vulnerability": {"id": "CVE-1", "severity": "High",
                                             "fix": {"state": "fixed"}}}] * 3}
        self.assertEqual(ds.gate_findings(rep, "high", [])[2], ["CVE-1"])

    def test_empty_and_malformed_reports(self):
        self.assertEqual(ds.gate_findings({}, "low", []), ({}, {}, []))
        self.assertEqual(ds.gate_findings({"matches": [{"vulnerability": {}}]}, "low", []), ({}, {}, []))


class UpgradeTests(unittest.TestCase):
    """Patching is host-side, so the login user gains no capability: devstack-sync's verb set is
    unchanged. These lock in the three guards that keep an apt upgrade from weakening a policy."""

    def script(self, upgrade="yes"):
        return ds.bash(ds.APT_UPGRADE, UPGRADE=upgrade)

    def test_scripts_pass_bash_n(self):
        for mode in ("yes", "no"):
            p = subprocess.run(["bash", "-n"], input=self.script(mode), text=True, capture_output=True)
            self.assertEqual(p.returncode, 0, f"{mode}: {p.stderr}")

    def test_devstack_sync_gains_no_verb(self):
        """The whole point of putting this on the host: the container user's only root command
        keeps exactly the verbs it had, so DESIGN 1.3 needs no amendment."""
        sync = ds.devstack_sync_script(make_config())
        self.assertNotIn("upgrade", sync.split("case \"$1:$#\"")[1])

    def test_guard_1_devstack_conffiles_are_not_replaced(self):
        """/etc/caddy/Caddyfile is a caddy package conffile and holds the admin unix socket. Without
        confold a caddy upgrade could restore the vendor file and put the admin API back on TCP."""
        self.assertIn("-o Dpkg::Options::=--force-confold", self.script())

    def test_guard_2_only_already_active_services_may_be_touched(self):
        sc = self.script()
        self.assertIn("policy-rc.d", sc)
        self.assertIn("--state=active", sc)
        self.assertIn("exit 101", sc)        # everything not already running is denied
        self.assertIn("restore_policy", sc)  # and the guard is always put back

    def test_guard_3_new_units_are_masked_and_nothing_is_unmasked(self):
        sc = self.script()
        self.assertIn("systemctl mask --now", sc)
        self.assertNotIn("systemctl unmask", sc)
        self.assertIn("units_now", sc)  # compares unit *files*: a package can gain a unit

    def test_never_removes_a_package(self):
        for line in self.script().splitlines():
            t = line.strip()
            if t.startswith("apt-get") and "-s" not in t:
                self.assertNotIn("full-upgrade", t)
                self.assertNotIn("dist-upgrade", t)
                self.assertNotIn("autoremove", t)

    def test_dry_run_only_simulates(self):
        """Behavioural, not textual: the script is one template with a runtime branch, so run it
        with apt-get stubbed and check what it actually invoked."""
        with tempfile.TemporaryDirectory() as d:
            binv, log = Path(d) / "bin", Path(d) / "calls"
            binv.mkdir()
            (binv / "apt-get").write_text(f'#!/bin/sh\necho "$@" >> {log}\nexit 0\n')
            (binv / "apt-get").chmod(0o755)
            env = {**os.environ, "PATH": f"{binv}:{os.environ['PATH']}"}
            p = subprocess.run(["bash", "-c", self.script("no")], env=env, capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            calls = log.read_text().splitlines() if log.exists() else []
        self.assertTrue(any(c.startswith("update") for c in calls), calls)
        self.assertTrue(all("-s" in c for c in calls if "upgrade" in c),
                        f"the simulation ran a real upgrade: {calls}")

    def test_snapshot_name_is_not_an_undo_point(self):
        """A pre-upgrade snapshot must stay out of the reserved prefix: journaled phase snapshots
        are undo points, and preflight errors on a prefixed snapshot it did not take."""
        cfg = make_config()
        self.assertFalse("pre-upgrade".startswith(cfg["snapshots.prefix"]))

    def test_cli_flags_are_backfilled(self):
        src = (ROOT / "devstack.py").read_text()
        loop = src.split("for k, d in ((")[1].split("))")[0]
        self.assertIn('"no_snapshot"', loop)
        args = ds.build_parser().parse_args(["upgrade", "--dry-run", "--no-snapshot"])
        self.assertEqual((args.command, args.dry_run, args.no_snapshot), ("upgrade", True, True))


class SbomScopeTests(unittest.TestCase):
    def ctx(self, **over):
        d = tempfile.mkdtemp()
        return make_ctx(Path(d), **over)

    def test_rootfs_excludes_cover_privacy_data_and_mounts(self):
        ctx = self.ctx(**{"container.mounts": [{"name": "shared", "source": "/home/alice/shared",
                                                "path": "/srv/shared", "readonly": False}]})
        ex = ds.rootfs_excludes(ctx)
        # /home and /root are the privacy ones: container.user is settable to the host login name
        for must in ("./home", "./root", "./proc", "./sys", "./var/lib/postgresql", "./srv/shared"):
            self.assertIn(must, ex)
        self.assertIn("./" + ctx.cproject.lstrip("/"), ex)
        self.assertEqual(ex, sorted(set(ex)), "excludes should be sorted and deduplicated")

    def test_app_excludes_node_modules_only_with_a_lockfile(self):
        ctx = self.ctx()
        self.assertNotIn("./node_modules", ds.app_excludes(ctx))  # no lockfile in a fresh dir
        (ctx.project / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n")
        self.assertIn("./node_modules", ds.app_excludes(ctx))
        ctx2 = self.ctx(**{"sbom.app_source": "tree"})
        (ctx2.project / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n")
        self.assertNotIn("./node_modules", ds.app_excludes(ctx2), "tree mode should scan node_modules")

    def test_syft_argv_shape(self):
        ctx = self.ctx()
        argv = ds.syft_argv(ctx, "container")
        self.assertEqual(argv[:3], ["syft", "scan", "dir:/"])
        self.assertIn("--source-name", argv)  # what keeps metadata.component.name path-free
        self.assertIn(f"{ctx.cfg['stack.name']}-container", argv)
        self.assertIn(f"cyclonedx-json={ds.SBOM_DIR_CONTAINER}/container.cdx.json", argv)
        self.assertEqual(argv.count("--exclude"), len(ds.rootfs_excludes(ctx)))
        app = ds.syft_argv(ctx, "app")
        self.assertEqual(app[2], f"dir:{ctx.cproject}")
        self.assertNotIn("--parallelism", app)


class ContainerIdentityTests(unittest.TestCase):
    """The login user's *name* is host-independent; only its uid is tied to the host."""

    def test_container_user_default_is_generic(self):
        self.assertEqual(ds.FIELDS["container.user"].default, "dev")
        self.assertNotIn("env.", str(ds.FIELDS["container.user"].default))

    def test_uid_is_the_only_host_derived_part(self):
        self.assertEqual(ds.FIELDS["container.uid"].default, "auto")   # auto = the host uid

    def test_no_committed_scaffold_file_names_the_host_user(self):
        """Regression: with a host-derived default, the scaffolded README.md -- which the project
        commits -- rendered the host login name into git. Every service account is stack-derived,
        so nothing devstack writes into the project should depend on who is logged in.
        The host identity is a sentinel: a real login can be an ordinary word (GitHub Actions
        runs as `runner`, which the README uses for app runners)."""
        host_login = "hostlogin-q7zx"
        fake_env = {"env.user": host_login, "env.uid": str(os.getuid()),
                    "env.home": f"/home/{host_login}"}
        with unittest.mock.patch.object(ds, "computed_values", return_value=fake_env), \
                tempfile.TemporaryDirectory() as d:
            tv = make_ctx(Path(d)).tvars()
            rendered = {rel: ds.render(tpl, tv) for tpl, rel, _mode in ds.SCAFFOLD}
        self.assertNotEqual(tv["USER"], host_login,
                            "the default container user still resolves to the host login name")
        for rel, text in rendered.items():
            self.assertNotIn(host_login, text, f"{rel} names the host user")

    def test_the_name_is_still_overridable(self):
        cfg = make_config(**{"container.user": "louis"})
        self.assertEqual(cfg["container.user"], "louis")
        self.assertEqual(cfg.user_home, "/home/louis")


class GpuRequirementTests(unittest.TestCase):
    """Whether the code needs a GPU is the project's business; which GPU, and whether the host has
    the NVIDIA toolkit, is the host's. Regression: with no [gpu] key in the requirements file, a
    rebuild elsewhere (or a fresh `init --project`) came up without passthrough and nothing said so."""

    def test_only_enabled_crosses_into_the_project(self):
        self.assertIn("gpu.enabled", ds.PROJECT_KEYS)
        for host_only in ("gpu.pci", "gpu.nvidia_runtime"):
            self.assertNotIn(host_only, ds.PROJECT_KEYS, host_only)

    def test_round_trips_and_shows_up_as_a_difference(self):
        v = ds.resolve(ds.defaults())
        v["gpu.enabled"] = True
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / ds.REQUIRES_FILE.rsplit("/", 1)[-1]
            path.write_text(ds.requirements_to_toml(ds.requirements(v)))
            want = ds.load_requirements(path)
        self.assertIs(want["gpu.enabled"], True)
        # a config without the GPU must not silently satisfy a project that asked for it
        _missing, diffs = ds.requirements_diff(want, ds.resolve(ds.defaults()))
        self.assertTrue([d for d in diffs if d.startswith("gpu.enabled:")], diffs)

    def test_a_repo_cannot_name_a_host_device(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "devstack-requires.toml"
            path.write_text('[gpu]\nenabled = true\npci = "0000:01:00.0"\n')
            with self.assertRaises(ds.ConfigError) as cm:
                ds.load_requirements(path)
        self.assertIn("gpu.pci", str(cm.exception))


class SbomConfigTests(unittest.TestCase):
    def test_section_is_registered(self):
        """A field whose section is missing from SECTIONS silently vanishes from the example config."""
        self.assertIn("sbom", ds.SECTIONS)
        self.assertTrue([f for f in ds.SCHEMA if f.section == "sbom"])

    def test_project_keys_boundary(self):
        """The project may say where its inventory lives; it may not lower the host owner's gate."""
        self.assertLessEqual({"sbom.dir", "sbom.app_source"}, set(ds.PROJECT_KEYS))
        for host_only in ("sbom.enabled", "sbom.fail_on", "sbom.ignore", "sbom.db_dir"):
            self.assertNotIn(host_only, ds.PROJECT_KEYS, host_only)

    def test_sbom_dir_must_stay_inside_the_project(self):
        for bad in ("/abs", "../x", "infra/../../x", "~/x", ""):
            self.assertIsNotNone(ds._rel_subpath(bad), bad)
        for good in ("infra/sbom", "sbom", "a/b/c"):
            self.assertIsNone(ds._rel_subpath(good), good)

    def test_db_dir_is_not_in_the_project(self):
        with tempfile.TemporaryDirectory() as d:
            ctx = make_ctx(Path(d))
            self.assertFalse(str(Path(ctx.cfg["sbom.db_dir"])).startswith(str(ctx.project)))


class SbomStalenessTests(unittest.TestCase):
    """A container-free hint, deliberately not a gate: it catches the common case (someone changed
    a declared input and forgot to regenerate) and cannot catch a hand-installed package. Only
    `sbom check` compares against the real container."""

    def ctx(self):
        d = tempfile.mkdtemp()
        return make_ctx(Path(d))

    def test_unknown_until_something_was_generated(self):
        ctx = self.ctx()
        self.assertEqual(ds.sbom_stale_inputs(ctx), [], "with no recorded state there is nothing to compare")

    def test_detects_a_changed_declared_input(self):
        ctx = self.ctx()
        apt = ctx.project / "infra" / "apt-packages.txt"
        apt.parent.mkdir(parents=True, exist_ok=True)
        apt.write_text("# none\n")
        ctx.state.set_fact("sbom_inputs", ds.sbom_input_hashes(ctx))
        self.assertEqual(ds.sbom_stale_inputs(ctx), [])
        apt.write_text("# none\ncowsay\n")
        self.assertEqual(ds.sbom_stale_inputs(ctx), ["infra/apt-packages.txt"])

    def test_detects_a_changed_lockfile(self):
        ctx = self.ctx()
        ctx.state.set_fact("sbom_inputs", ds.sbom_input_hashes(ctx))
        (ctx.project / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'\n")
        self.assertEqual(ds.sbom_stale_inputs(ctx), ["pnpm-lock.yaml"])

    def test_a_deleted_input_also_counts(self):
        ctx = self.ctx()
        lock = ctx.project / "pnpm-lock.yaml"
        lock.write_text("lockfileVersion: '9.0'\n")
        ctx.state.set_fact("sbom_inputs", ds.sbom_input_hashes(ctx))
        lock.unlink()
        self.assertEqual(ds.sbom_stale_inputs(ctx), ["pnpm-lock.yaml"])

    def test_missing_inputs_are_recorded_as_absent_not_skipped(self):
        """Recording "" for a missing file is what makes its later appearance detectable."""
        ctx = self.ctx()
        self.assertEqual(set(ds.sbom_input_hashes(ctx)), set(ds.SBOM_INPUT_FILES))
        self.assertEqual(set(ds.sbom_input_hashes(ctx).values()), {""})

    def test_sync_env_tells_you_to_regenerate(self):
        with tempfile.TemporaryDirectory() as d:
            out = ds.render("project/scripts/sync-env.sh", make_ctx(Path(d)).tvars())
        self.assertIn("sbom generate", out)
        self.assertIn("infra/sbom/", out)
        self.assertNotIn("@@", out)


class SbomCliTests(unittest.TestCase):
    def test_scan_only_flags_are_rejected_elsewhere(self):
        for argv in (["sbom", "generate", "--fail-on", "high"], ["sbom", "check", "--offline"],
                     ["sbom", "show", "--fail-on", "low"]):
            # main() turns a ConfigError into its exit code rather than letting it escape
            rc = ds.main([*argv, "-c", str(ROOT / "devstack.example.toml")])
            self.assertEqual(rc, ds.ConfigError.exit_code, argv)

    def test_bad_action_and_bad_which(self):
        for argv in (["sbom", "nope"], ["sbom", "scan", "bogus"]):
            with self.assertRaises(SystemExit):
                ds.build_parser().parse_args(argv)

    def test_new_flags_are_backfilled_for_other_commands(self):
        """Every common flag uses argparse.SUPPRESS, so a new one that is not in main()'s backfill
        loop makes unrelated commands raise AttributeError."""
        src = (ROOT / "devstack.py").read_text()
        loop = src.split('for k, d in ((')[1].split('))')[0]
        for name in ('"which"', '"fail_on"', '"offline"'):
            self.assertIn(name, loop, f"{name} is missing from main()'s default backfill loop")


class LeaksConfigTests(unittest.TestCase):
    def test_section_is_registered(self):
        self.assertIn("leaks", ds.SECTIONS)
        self.assertTrue([f for f in ds.SCHEMA if f.section == "leaks"])

    def test_no_leaks_key_is_a_project_key(self):
        """A cloned repo must not be able to narrow the scan or silence a finding."""
        self.assertFalse([k for k in ds.PROJECT_KEYS if k.startswith("leaks.")])

    def test_tool_dir_is_not_in_the_project(self):
        with tempfile.TemporaryDirectory() as d:
            ctx = make_ctx(Path(d))
            self.assertFalse(str(Path(ctx.cfg["leaks.tool_dir"])).startswith(str(ctx.project)))

    def test_destroy_removes_the_binary(self):
        with tempfile.TemporaryDirectory() as d:
            ctx = make_ctx(Path(d))
            binary = Path(ctx.cfg["leaks.tool_dir"]) / "bin" / f"gitleaks-{ds.GITLEAKS_VERSION}"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"x")
            self.assertEqual(ds._u_host_tool(ctx, {"path": str(binary)}, None), "undone")
            self.assertFalse(binary.exists())


class LeaksArgvTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.ctx = make_ctx(Path(self._tmp.name))

    def tearDown(self):
        self._tmp.cleanup()

    def argv(self, mode="git"):
        w = self.ctx.state_dir / "leaks"
        return ds.gitleaks_argv(Path("/bin/gitleaks"), mode, w / "scan" / "src", w / "r.json",
                                w / "gitleaks.toml", w / "empty.gitleaksignore")

    def test_every_project_input_is_replaced(self):
        for mode in ("git", "dir"):
            a = self.argv(mode)
            self.assertEqual(a[1], mode)
            for flag in ("--config", "--gitleaks-ignore-path"):  # the project's own files are writable
                self.assertTrue(a[a.index(flag) + 1].startswith(str(self.ctx.state_dir)), flag)
            self.assertIn("--ignore-gitleaks-allow", a)
            self.assertIn("--redact", a)
            self.assertEqual(a[a.index("--exit-code") + 1], "0")  # non-zero = the tool broke, nothing else
            self.assertTrue(a[-1].startswith(str(self.ctx.state_dir)), "source must never be the project")
            self.assertNotIn(str(self.ctx.project), a)

    def test_env_is_hermetic(self):
        os.environ["GITLEAKS_CONFIG"] = "/tmp/evil.toml"
        os.environ["GITLEAKS_CONFIG_TOML"] = "[allowlist]"
        try:
            env = ds.gitleaks_env(self.ctx)
        finally:
            del os.environ["GITLEAKS_CONFIG"], os.environ["GITLEAKS_CONFIG_TOML"]
        self.assertFalse([k for k in env if k.startswith("GITLEAKS_")])
        self.assertEqual(env["GIT_DIR"], str(self.ctx.project / ".git"))
        pairs = {env[f"GIT_CONFIG_KEY_{i}"]: env[f"GIT_CONFIG_VALUE_{i}"] for i in range(int(env["GIT_CONFIG_COUNT"]))}
        self.assertEqual(pairs, {"core.fsmonitor": "false", "core.hooksPath": "/dev/null"})
        self.assertEqual(env["GIT_CONFIG_GLOBAL"], "/dev/null")

    def test_error_lines_are_recognised(self):
        """gitleaks exits 0 with an empty report when git fails; the log line is the only sign."""
        out = ds.ANSI_RX.sub("", "\x1b[90m10:45AM\x1b[0m \x1b[31mERR\x1b[0m \x1b[1m[git] fatal: bad object\x1b[0m\n")
        self.assertTrue(ds.LEAKS_ERROR_RX.search(out))
        for fine in ("10:45AM INF no leaks found\n", "10:45AM WRN leaks found: 2\n", "10:45AM INF 3 commits scanned.\n"):
            self.assertIsNone(ds.LEAKS_ERROR_RX.search(fine), fine)


class LeaksFindingsTests(unittest.TestCase):
    RAW = [{"RuleID": "github-pat", "File": "/s/scan-x/tree/working/src/a.ts", "StartLine": 3, "Commit": "",
            "Secret": "ghp_realsecret", "Match": "token = ghp_realsecret", "Date": ""},
           {"RuleID": "aws-access-token", "File": "cfg.json", "StartLine": 1,
            "Commit": "351df59a4d82d8b8ef038c286d882ae03aa3697a", "Date": "2026-10-01T10:00:00Z",
            "Secret": "AKIAREAL", "Match": "AKIAREAL"}]

    def test_normalized_and_secret_free(self):
        got = ds.leaks_findings(self.RAW, strip="/s/scan-x/tree/")
        self.assertEqual([f["fingerprint"] for f in got],
                         ["351df59a4d82d8b8ef038c286d882ae03aa3697a:cfg.json:aws-access-token:1",
                          "working/src/a.ts:github-pat:3"])
        self.assertEqual(got[0]["date"], "2026-10-01")
        self.assertNotIn("realsecret", json.dumps(got))
        self.assertNotIn("AKIAREAL", json.dumps(got))

    def test_not_a_list_is_an_error(self):
        for bad in ({}, None, "[]"):
            with self.assertRaises(ds.DevstackError):
                ds.leaks_findings(bad)

    def test_gate(self):
        got = ds.leaks_findings(self.RAW, strip="/s/scan-x/tree/")
        counted, ignored = ds.leaks_gate(got, ["working/src/a.ts:github-pat:3"])
        self.assertEqual([f["rule"] for f in counted], ["aws-access-token"])
        self.assertEqual([f["rule"] for f in ignored], ["github-pat"])
        self.assertEqual(ds.leaks_gate([], ["x"]), ([], []))


@unittest.skipUnless(shutil.which("git"), "needs git")
class LeaksStageTreeTests(unittest.TestCase):
    """Real git: what `leaks scan` copies out of the project for `gitleaks dir`."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.ctx = make_ctx(self.tmp, FakeRunner())
        self.root = self.ctx.project
        self.git("init", "-q")
        (self.root / ".gitignore").write_text(".env\n")
        (self.root / "a.txt").write_text("a1\n")
        (self.root / "b.txt").write_text("b1\n")
        (self.root / "gone.txt").write_text("g\n")
        (self.root / "fifo.txt").write_text("f\n")
        os.symlink("a.txt", self.root / "link")
        self.git("add", "-A")
        self.git("commit", "-qm", "one")
        (self.root / "a.txt").write_text("a2 unstaged\n")
        (self.root / "b.txt").write_text("b2 staged\n")
        self.git("add", "b.txt")
        (self.root / "b.txt").write_text("b3 working\n")
        (self.root / "c.txt").write_text("untracked\n")
        (self.root / ".env").write_text("SECRET=1\n")
        (self.root / "gone.txt").unlink()
        (self.root / "fifo.txt").unlink()
        os.mkfifo(self.root / "fifo.txt")  # tracked path, now a FIFO: must not block the scan
        (self.root / ".gitattributes").write_text("* -diff\n")  # irrelevant to a folder scan
        self.dest = self.tmp / "dest"
        self.dest.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.root), *args], check=True, capture_output=True, text=True,
                              env=GIT_SETUP_ENV).stdout

    def test_copies_what_is_about_to_be_committed(self):
        copied, skipped = ds.leaks_stage_tree(self.ctx, self.dest)
        files = sorted(str(p.relative_to(self.dest)) for p in self.dest.rglob("*") if p.is_file())
        self.assertEqual(files, ["staged/b.txt", "working/.gitattributes", "working/.gitignore",
                                 "working/a.txt", "working/b.txt", "working/c.txt"])
        self.assertEqual(copied, len(files))
        self.assertEqual((self.dest / "working" / "a.txt").read_text(), "a2 unstaged\n")
        self.assertEqual((self.dest / "staged" / "b.txt").read_text(), "b2 staged\n")
        self.assertEqual((self.dest / "working" / "b.txt").read_text(), "b3 working\n")
        self.assertEqual(skipped, ["fifo.txt (not a regular file)"])  # .env, link, gone.txt: silently out

    def test_symlinked_parent_is_not_followed(self):
        outside = self.tmp / "outside"
        outside.mkdir()
        (outside / "x.txt").write_text("host file\n")
        (self.root / "sub").mkdir()
        (self.root / "sub" / "x.txt").write_text("in project\n")
        self.git("add", "sub/x.txt")
        shutil.rmtree(self.root / "sub")
        os.symlink(outside, self.root / "sub")  # the container swaps a folder for a link
        _copied, skipped = ds.leaks_stage_tree(self.ctx, self.dest)
        self.assertFalse((self.dest / "working" / "sub" / "x.txt").exists())
        self.assertIn("sub/x.txt (a parent folder leads outside the project)", skipped)

    def test_too_large_is_reported(self):
        with unittest.mock.patch.object(ds, "LEAKS_MAX_FILE", 4):
            _copied, skipped = ds.leaks_stage_tree(self.ctx, self.dest)
        self.assertTrue(any(s.startswith("c.txt (larger than") for s in skipped), skipped)
        self.assertTrue(any(s.startswith("b.txt (staged, larger than") for s in skipped), skipped)


class LeaksCliTests(unittest.TestCase):
    def test_bad_action(self):
        with self.assertRaises(SystemExit):
            ds.build_parser().parse_args(["leaks", "nope"])

    def test_no_history_is_backfilled(self):
        src = (ROOT / "devstack.py").read_text()
        loop = src.split('for k, d in ((')[1].split('))')[0]
        self.assertIn('"no_history"', loop)


class ProjectToolchainTests(unittest.TestCase):
    """The lint/type-check/pnpm scaffold. Nothing here runs pnpm or ESLint; these keep the files
    consistent with each other and with what PNPM_SETUP installs."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.ctx = make_ctx(Path(self._tmp.name))
        self.tv = self.ctx.tvars()

    def tearDown(self):
        self._tmp.cleanup()

    def test_pnpm_version_check(self):
        check = ds.FIELDS["node.pnpm_version"].check
        for ok in ("latest", "10.26.0", "11.0.0", "12.8.2", ds.FIELDS["node.pnpm_version"].default):
            self.assertIsNone(check(ok), ok)
        for bad in ("10.25.9", "9.15.0", "12", "12.8", "^12.8.2", "next-11", ""):
            self.assertIsNotNone(check(bad), bad)

    def test_dev_packages(self):
        pkgs = ds.dev_packages(make_config(**{"node.version": "24.20.0"}))
        self.assertIn("@types/node@24", pkgs)  # the runtime's major, not whatever is newest
        self.assertIn(ds.TYPESCRIPT_SPEC, pkgs)
        self.assertRegex(ds.TYPESCRIPT_SPEC, r"^typescript@~6\.0\.")  # typescript-eslint 8: <6.1.0
        out = ds.bash(ds.PNPM_SETUP, PROJECT="/srv/p", PNPM="12.8.2", DEV_PACKAGES=pkgs)
        self.assertEqual(subprocess.run(["bash", "-n"], input=out, text=True).returncode, 0)
        self.assertIn(" @types/node@24 ", out)

    def test_eslint_config_imports_only_what_is_installed(self):
        text = ds.render("project/eslint.config.js", self.tv)
        imported = set(re.findall(r'^import .* from "([^"]+)";$', text, re.M))
        self.assertEqual(imported - {"eslint/config", "@eslint-community/eslint-plugin-eslint-comments/configs"},
                         set(ds.DEV_TOOLCHAIN) - {"eslint", "@eslint-community/eslint-plugin-eslint-comments"})

    def test_eslint_config_carries_the_required_rules(self):
        text = ds.render("project/eslint.config.js", self.tv)
        for needle in ("strictTypeChecked", "projectService: true", "no-unsafe-type-assertion",
                       "no-floating-promises", "no-misused-promises", "no-explicit-any",
                       'objectLiteralTypeAssertions: "never"', "require-description",
                       "nounsanitized.configs.recommended", "security.configs.recommended",
                       '"no-eval"', '"no-new-func"', "node:child_process", "src/lib/child-process.ts",
                       "reportUnusedDisableDirectives"):
            self.assertIn(needle, text, needle)

    def test_pnpm_workspace_settings(self):
        lines = ds.render("project/pnpm-workspace.yaml", self.tv).splitlines()
        settings = dict(ln.split(": ", 1) for ln in lines if ln and not ln.startswith((" ", "#")))
        self.assertEqual(settings, {"minimumReleaseAge": "10080", "blockExoticSubdeps": "true",
                                    "trustPolicy": "no-downgrade", "strictDepBuilds": "true"})

    def test_tsconfig_and_package_json(self):
        ts = json.loads(ds.render("project/tsconfig.json", self.tv))["compilerOptions"]
        self.assertTrue(ts["strict"])
        self.assertTrue(ts["noUncheckedIndexedAccess"])
        scripts = json.loads(ds.render("project/package.json", self.tv))["scripts"]
        self.assertEqual(scripts["typecheck"], "tsc --noEmit")
        self.assertIn("--max-warnings 0", scripts["lint"])
        self.assertEqual(scripts["check"], "pnpm typecheck && pnpm lint")
        self.assertTrue(Path(ds.TEMPLATES / "project" / scripts["lint:changed"]).exists())

    def test_no_ci_files_are_scaffolded(self):
        """CI-agnostic (DESIGN §1.5): the project README carries the command, not a workflow."""
        for _tpl, rel, _mode in ds.SCAFFOLD:
            self.assertFalse(rel.startswith((".github/", ".gitlab", ".forgejo/", ".woodpecker")), rel)
        with tempfile.TemporaryDirectory() as d:
            text = ds.render("project/README.md", make_ctx(Path(d)).tvars())
        self.assertIn("pnpm install --frozen-lockfile", text)
        self.assertIn("pnpm check", text)
