#!/usr/bin/env python3
"""devstack: build a reproducible incus-based dev + local app environment.

Phases (see DESIGN.md §8): base, app, proxy, standards, isolation, postgres.
Stdlib only, Python >= 3.11 (tomllib). Run it through the ./devstack launcher.

Layout of this file:
  1. errors, small helpers          5. host/journal helpers (write + undo)
  2. config schema + load/resolve    6. phases
  3. logging                         7. preflight, undo orchestration
  4. command runner, state, journal  8. commands + CLI
"""
from __future__ import annotations

import argparse
import base64
import dataclasses
import datetime as dt
import difflib
import errno
import fcntl
import functools
import hashlib
import ipaddress
import json
import logging
import logging.handlers
import os
import platform
import pwd
import re
import secrets
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import time
import tomllib
import urllib.parse
from pathlib import Path, PurePosixPath
from typing import Any, Callable

VERSION = "1.0.0"
HERE = Path(__file__).resolve().parent
TEMPLATES = HERE / "templates"
TLD_FILE = HERE / "data" / "iana-tlds.txt"

# Trust roots checked in code. README.md and DESIGN.md describe each one; a unit test asserts
# every value below appears in those docs, so a bumped pin cannot silently go undocumented.
# Caddy: fingerprint of the signing key served at https://dl.cloudsmith.io/public/caddy/stable/gpg.key
#   (install docs: https://caddyserver.com/docs/install#debian-ubuntu-raspbian).
CADDY_KEY_FPR = "65760C51EDEA2017CEA2CA15155B6D79CA56EA34"
# PGDG: https://www.postgresql.org/media/keys/ACCC4CF8.asc ("PostgreSQL Debian Repository"; the
#   key id ACCC4CF8 is what https://wiki.postgresql.org/wiki/Apt tells you to import).
PGDG_KEY_FPR = "B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8"
# Node.js release keyring: pinned commit of https://github.com/nodejs/release-keys and the sha256 of
#   gpg/pubring.kbx at that commit (a release signed by a newer releaser needs a bump).
NODE_KEYRING_COMMIT = "481637f813e912c4aa3622d7964ab426c97b8e8d"
NODE_KEYRING_SHA256 = "610b8d249da3d5733f5a128def2dd0294dbbf5b5713e6ca2529db8db419dee00"
# syft (SBOM generator, installed in the container) and grype (scanner, host-side). Pinned release
#   plus the sha256 of each release tarball, from <tool>_<ver>_checksums.txt in the same GitHub release.
#   A pinned hash is a smaller trust root than cosign would be (which needs a Fulcio/Rekor root and
#   another binary), and strictly better than anchore's `curl | sh` installer.
SYFT_VERSION = "1.54.0"
SYFT_SHA256 = {"amd64": "54a87372498168b2d033e876fd41fa4e8035b872699e525a57046e1f2f09c860",
               "arm64": "ee6d4566373a05b344bc6b5f1706f14419bf9338ba39ff686e247deefe9b8818"}
GRYPE_VERSION = "0.120.0"
GRYPE_SHA256 = {"amd64": "a5a1218dce63acdac152a6b3b5bb366e7267e36f4069848cf455543b3fa5700e",
                "arm64": "bc0e52b1a0de37e2ff021c4924d689dce7dcff2e7d74b39aea16c0453e69be18"}
# gitleaks (secret scanner, host-side), pinned the same way. Its release tarballs say linux_x64, not
#   amd64; GITLEAKS_ARCH maps host_arch() onto that name.
GITLEAKS_VERSION = "8.30.1"
GITLEAKS_SHA256 = {"amd64": "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
                   "arm64": "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080"}
GITLEAKS_ARCH = {"amd64": "x64", "arm64": "arm64"}
# The project's dev toolchain, added by the app phase when it creates package.json. TypeScript is held at
#   6.0: typescript-eslint 8 (type-aware linting) supports `>=4.8.4 <6.1.0`, and plain `typescript` is
#   7.x now. @types/node follows node.version's major so the types match the runtime. The rest are
#   left to pnpm, whose minimumReleaseAge (pnpm-workspace.yaml) keeps them at least a week old.
TYPESCRIPT_SPEC = "typescript@~6.0.3"
DEV_TOOLCHAIN = ("eslint", "@eslint/js", "typescript-eslint", "globals", "eslint-plugin-no-unsanitized",
                 "eslint-plugin-security", "@eslint-community/eslint-plugin-eslint-comments")
# Oldest pnpm with every setting the scaffolded pnpm-workspace.yaml uses (allowBuilds and
#   blockExoticSubdeps arrived in 10.26).
PNPM_MIN = (10, 26, 0)
LEAKS_REPORT_KEEP = 10                          # newest gitleaks reports kept in the state dir
LEAKS_MAX_FILE = 10 * 1024 * 1024               # working-tree files larger than this are not copied

# CycloneDX / SBOM handling. SBOM_CDX_VERSION is asserted on the parsed document: a syft upgrade that
#   changes the spec version is a deliberate decision, not something to absorb silently.
SBOM_CDX_VERSION = "1.7"
SBOM_DIR_CONTAINER = "/var/tmp/devstack-sbom"   # where syft writes inside the container
SBOM_KINDS = ("container", "app")
SBOM_REPORT_KEEP = 10                           # newest grype reports kept in the state dir
GRYPE_DB_STALE_DAYS = 7
SEVERITIES = ("negligible", "low", "medium", "high", "critical")

log = logging.getLogger("devstack")


# ---------------------------------------------------------------------------
# 1. errors and small helpers
# ---------------------------------------------------------------------------


class DevstackError(Exception):
    exit_code = 1


class ConfigError(DevstackError):
    exit_code = 2


class PreflightError(DevstackError):
    exit_code = 3


class NeedsInput(DevstackError):
    exit_code = 4


class GateError(DevstackError):
    """A gate said no: `sbom check` found drift, or `sbom scan` found findings at sbom.fail_on.
    Its own exit code so CI can tell "the gate says no" from "the tool broke"."""
    exit_code = 5


class VerifyError(DevstackError):
    pass


class CommandError(DevstackError):
    def __init__(self, argv: list[str], returncode: int, output: str):
        self.argv, self.returncode, self.output = argv, returncode, output
        tail = "\n".join(output.strip().splitlines()[-30:])
        super().__init__(
            f"command failed (exit {returncode}): {short_cmd(argv)}" + (f"\n{tail}" if tail else "")
        )


def now() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def short_cmd(argv: list[str]) -> str:
    if "-c" in argv:
        i = argv.index("-c")
        script = argv[i + 1] if i + 1 < len(argv) else ""
        first = next((ln.strip() for ln in script.splitlines() if ln.strip()), "")
        return shlex.join(argv[:i]) + f" -c '{first[:80]} …'"
    return shlex.join(argv)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def atomic_write(path: Path, content: str | bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.devstack-tmp")
    data = content.encode() if isinstance(content, str) else content
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def bash(script: str, **vals: Any) -> str:
    """Fill @@KEY@@ placeholders in a bash script with shell-quoted values.

    Lists become space-separated quoted words (use inside `arr=(@@X@@)`).
    """

    def sub(m: re.Match) -> str:
        key = m.group(1)
        if key not in vals:
            raise DevstackError(f"internal: script placeholder @@{key}@@ has no value")
        v = vals[key]
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, (list, tuple)):
            return " ".join(shlex.quote(str(x)) for x in v)
        return shlex.quote(str(v))

    return re.sub(r"@@([A-Z0-9_]+)@@", sub, textwrap.dedent(script).strip() + "\n")


def render(template: str, values: dict[str, Any]) -> str:
    """Render templates/<template>, replacing @@KEY@@ verbatim. Fails on unknown keys."""
    text = (TEMPLATES / template).read_text()

    def sub(m: re.Match) -> str:
        key = m.group(1)
        if key not in values:
            raise DevstackError(f"template {template}: no value for @@{key}@@")
        return str(values[key])

    return re.sub(r"@@([A-Z0-9_]+)@@", sub, text)


def url_host(addr: str) -> str:
    return f"[{addr}]" if ":" in addr else addr


# ---------------------------------------------------------------------------
# 2. configuration schema
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Field:
    key: str
    kind: str  # str | int | bool | strlist | intlist | strmap | mounts | runners
    default: Any
    help: str
    choices: tuple = ()
    path: bool = False
    check: Callable[[Any], str | None] | None = None

    @property
    def section(self) -> str:
        return self.key.split(".", 1)[0]

    @property
    def name(self) -> str:
        return self.key.split(".", 1)[1]


def _match(pattern: str, what: str) -> Callable[[Any], str | None]:
    rx = re.compile(pattern)
    return lambda v: None if rx.fullmatch(str(v)) else f"must be {what}"


def _pnpm_version(v: str) -> str | None:
    if v == "latest":
        return None
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", str(v))
    if not m:
        return "must be an exact version like 12.8.2 (or 'latest')"
    if tuple(int(x) for x in m.groups()) < PNPM_MIN:
        return (f"must be {'.'.join(map(str, PNPM_MIN))} or later: the scaffolded pnpm-workspace.yaml "
                "uses allowBuilds and blockExoticSubdeps")
    return None


def _rel_subpath(v: str) -> str | None:
    pp = PurePosixPath(v)
    return None if (v and not pp.is_absolute() and ".." not in pp.parts and not v.startswith("~")) \
        else "must be a relative path inside the project (no '..', no leading '/' or '~')"


def _port(v: int) -> str | None:
    return None if 1 <= v <= 65535 else "must be a TCP port (1-65535)"


def _ports(v: list[int]) -> str | None:
    bad = [p for p in v if not 1 <= p <= 65535]
    return f"invalid ports: {bad}" if bad else None


def _ipv4_or_auto(v: str) -> str | None:
    if v == "auto":
        return None
    try:
        ipaddress.IPv4Address(v)
        return None
    except ValueError:
        return 'must be "auto" or an IPv4 address'


def _rel_paths(v: list[str]) -> str | None:
    for x in v:
        parts = x.split("/")
        if not x or x.startswith("/") or ".." in parts:
            return f"{x!r}: must be a relative path inside the project (no '..')"
    return None


def _dev_servers(v: dict[str, str]) -> str | None:
    for name, port in v.items():
        if not re.fullmatch(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?", name):
            return f"{name!r}: must be a DNS label (lowercase letters, digits, '-')"
        if not re.fullmatch(r"[0-9]{1,5}", port) or not 1024 <= int(port) <= 65535:
            return f'{name} = {port!r}: must be a port from 1024 to 65535, as a string ("5173")'
    return None


def _cidrs(v: list[str]) -> str | None:
    for x in v:
        try:
            ipaddress.ip_network(x, strict=False)
        except ValueError:
            return f"{x!r} is not an IP network (CIDR)"
    return None


HOSTNAME_RX = r"(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*"
SQL_IDENT_RX = r"[a-z_][a-z0-9_]{0,62}"

SECTIONS: dict[str, str] = {
    "stack": "Identity of this environment. Every name below derives from stack.name by default, "
    "so a second stack only needs a different name.",
    "host": "Host-side state and dependency policy.",
    "run": "Behaviour when something goes wrong.",
    "logging": "Where log output goes. The log file always receives full debug output "
    "(every command and its output, secrets redacted).",
    "project": "The project folder, shared between host (you edit it) and container (it runs there).",
    "container": "The incus container that holds the whole stack.",
    "network": "The incus network ACL that keeps the whole container off the host and the LAN. Enforced "
    "on the host, so nothing inside the container (not even root) can change it.",
    "gpu": "Optional GPU passthrough into the container. Off by default.",
    "snapshots": "incus snapshots taken before each phase; they are what makes container changes undoable.",
    "ssh": "ssh access from the host (and VSCode Remote-SSH) into the container.",
    "node": "Node.js inside the container (download verified with gpg + sha256).",
    "dns": "Host DNS through dnsmasq. The host must already resolve through dnsmasq "
    "(see index.html); devstack only adds/removes one drop-in file per stack.",
    "site": "The app's public identity.",
    "tls": "The local CA: its root key stays on the host and is limited to the dev domain; "
    "Caddy only gets an intermediate. How the host trusts the root.",
    "browser": "`devstack browse`: a Chromium confined to the dev domain, with its own profile and its own "
    "trust in the dev CA. Pages the container serves are untrusted; open them here, not in your browser.",
    "caddy": "Reverse proxy / static file server inside the container.",
    "app": "The app service (scaffolded smoke-test server, systemd hardened), its network profile, its "
    "data folder, and runners: socket-activated tools that may use the internet.",
    "firewall": "ufw inside the container (phase isolation): what may come in. What services may reach "
    "going out is app.profile.",
    "isolation": "Fixed system users and groups for the services (phase isolation). Fixed ids keep file "
    "owners on persistent volumes and let the egress profiles match a uid that never changes.",
    "secrets": "Where generated secrets live inside the container (root-only, except that the dev group "
    "can read the internal token).",
    "checkpoint": "`devstack checkpoint`: undo everything after provisioning (an agent's changes, a bad "
    "install) by restoring the container, its data volumes and the project together.",
    "postgres": "Postgres, local-only, with its data on a separate incus volume that survives "
    "undo/destroy/rebuild.",
    "sbom": "Software bill of materials: a CycloneDX inventory generated by syft inside the container "
    "and committed with the project, plus vulnerability scanning by grype on the host (its database "
    "never enters the container).",
    "leaks": "`devstack leaks scan`: secret scanning by gitleaks on the host, over the project's git "
    "history and its uncommitted files. Only devstack's own gitleaks config is used; the project's "
    "is writable from the container and is never read.",
}

DEFAULT_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; style-src 'self'; worker-src 'self' blob:; script-src 'self'; "
        "img-src 'self' data:; frame-src 'self'; connect-src 'self'; font-src 'self'; "
        "base-uri 'self'; form-action 'self'; frame-ancestors 'self'; media-src blob: 'self'; "
        "object-src 'none'; upgrade-insecure-requests;"
    ),
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": (
        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), "
        "microphone=(), payment=(), usb=(), interest-cohort=()"
    ),
}

SCHEMA: list[Field] = [
    # stack
    Field("stack.name", "str", "webstack",
          "Short name of this environment (lowercase, digits, '-'). Used to derive container, "
          "TLD, file and volume names. Must not clash with other containers, TLDs or files "
          "already on the host.",
          check=_match(r"[a-z][a-z0-9-]{1,29}", "2-30 chars: a-z, 0-9, '-', starting with a letter")),
    # host
    Field("host.state_dir", "str", "~/.local/state/devstack/{stack.name}",
          "Journal, state, backups of replaced files, CA copy, lock file. Deleting it makes devstack "
          "forget what it owns, so undo would no longer work.", path=True),
    Field("host.install_missing", "bool", False,
          "Non-interactive mode only: apt-install missing host tools instead of failing. "
          "(Interactive mode asks.) Host packages are never removed by undo."),
    # run
    Field("run.on_failure", "str", "rollback",
          "What to do when a step or verification fails in non-interactive mode. 'rollback' undoes "
          "the failed phase (earlier phases stay); 'stop' leaves it for debugging "
          "(clean up later with `devstack undo`). Interactive mode asks.",
          choices=("rollback", "stop")),
    # logging
    Field("logging.target", "str", "both",
          "Where logs go: 'stderr', 'file', 'both', or 'journald' (journalctl -t devstack-<name>). "
          "With 'file' or 'journald' the terminal still shows warnings and errors.",
          choices=("stderr", "file", "both", "journald")),
    Field("logging.file", "str", "{host.state_dir}/devstack.log",
          "Log file (appended). Always gets debug detail.", path=True),
    Field("logging.level", "str", "info", "Terminal log level.",
          choices=("debug", "info", "warning", "error")),
    # project
    Field("project.host_path", "str", "~/code/{stack.name}",
          "Project folder on the host. Created if missing; existing files are never overwritten.",
          path=True),
    Field("project.container_path", "str", "/srv/{stack.name}",
          "Where the project folder is mounted inside the container (idmapped, so files keep your "
          "uid). Kept outside /home so Caddy and the hardened service can read it.", path=True),
    Field("project.readonly_paths", "strlist", [],
          "Extra files and folders inside the project to mount read-only in the container, so code running "
          "there cannot edit what the host later runs, e.g. '.vscode' if you open the project on the host. "
          "The whole .git is always read-only (the host runs git on it) and needs no entry here. Relative to "
          "project.host_path. A path that doesn't exist yet is mounted by the next `up` once it does.",
          check=_rel_paths),
    Field("project.scaffold", "bool", True,
          "Create the smoke-test app (server.ts, static/, error/, package.json, ...) in phase 'app'. "
          "Existing files are kept."),
    # container
    Field("container.name", "str", "{stack.name}", "incus instance name.",
          check=_match(r"[a-z][a-z0-9-]{0,62}", "a valid incus instance name")),
    Field("container.image", "str", "images:debian/13",
          "Image to launch. Debian 13 (trixie) by default: current stable. The container "
          "shares the host kernel (and GPU driver, if passed through) whatever the image."),
    Field("container.profiles", "strlist", ["default"], "incus profiles applied to the container."),
    Field("container.storage_pool", "str", "default",
          "Storage pool for the root disk and the Postgres data volume."),
    Field("container.network", "str", "incusbr0", "Managed bridge the container's NIC is on."),
    Field("container.nic_device", "str", "auto",
          "Name of the NIC device to pin the IP on ('auto' = the nic device from the profile(s))."),
    Field("container.ipv4", "str", "auto",
          "Static IPv4 for the container. 'auto' keeps whatever DHCP hands out first and pins it.",
          check=_ipv4_or_auto),
    Field("container.user", "str", "dev",
          "Login user inside the container (VSCode server, terminals, agents). Its sudo rights: "
          "container.sudo. Deliberately a generic name, not your host login: only container.uid has "
          "to line up with the host, and a host-derived name would end up in files you commit. "
          "You never type it (the ssh config block carries it), so `ssh <ssh.host_alias>` just works.",
          check=_match(r"[a-z_][a-z0-9_-]{0,31}", "a valid Linux user name")),
    Field("container.uid", "str", "auto",
          "uid of that user. 'auto' = your host uid, which makes the shared folder's ownership line up.",
          check=_match(r"auto|[0-9]{1,7}", '"auto" or a number')),
    Field("container.sudo", "str", "limited",
          "What the container user may do as root. 'limited': only `sudo devstack-sync` (install listed apt "
          "packages, restart the app/runners, reload Caddy), so nothing the user or an agent can edit runs as "
          "root. 'full': passwordless sudo for everything (the user, and every agent running as it, is "
          "root in the container; needs your OK). 'none': no sudo. Root for you is always "
          "`incus exec <container> -- bash` from the host.",
          choices=("limited", "full", "none")),
    Field("container.cpu_limit", "str", "", "incus limits.cpu (e.g. '4'); empty = no limit."),
    Field("container.memory_limit", "str", "", "incus limits.memory (e.g. '8GiB'); empty = no limit."),
    Field("container.mounts", "mounts", [],
          "Extra host folders to mount, e.g. a shared data folder. Each entry: name, source "
          "(host path), path (container path), readonly (default false), shift (default true). "
          "Entries added after the container exists are added by the next `up`."),
    # network
    Field("network.acl", "bool", True,
          "Attach an incus network ACL to the container's NIC that rejects traffic to the host (except DNS and "
          "DHCP on the bridge gateway), the LAN and other private ranges. Internet access stays."),
    Field("network.acl_name", "str", "devstack-{stack.name}", "Name of that incus network ACL.",
          check=_match(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}", "a valid incus ACL name")),
    Field("network.allow_private", "strlist", [],
          "CIDRs the container may still reach despite the ACL, e.g. ['192.168.1.20/32'] for a NAS. "
          "Anything here needs your OK.", check=_cidrs),
    # gpu
    Field("gpu.enabled", "bool", False, "Pass the host GPU into the container."),
    Field("gpu.pci", "str", "", "PCI address of one GPU (from `incus info --resources`); empty = all."),
    Field("gpu.nvidia_runtime", "bool", True,
          "Set nvidia.runtime=true so the host's NVIDIA userspace libs are injected "
          "(requires nvidia-container-toolkit on the host)."),
    # snapshots
    Field("snapshots.mode", "str", "per-phase",
          "'per-phase': snapshot before every phase after 'base' so it can be undone. "
          "'off': no snapshots; then only `undo --all` can revert container changes.",
          choices=("per-phase", "off")),
    Field("snapshots.cleanup", "str", "manual",
          "'manual': keep phase snapshots until `devstack snapshot prune`. 'auto': prune once `up` "
          "finishes with everything verified. Pruned phases can only be undone with `undo --all`. "
          "On the 'dir' storage driver every snapshot is a full rootfs copy.",
          choices=("manual", "auto")),
    Field("snapshots.prefix", "str", "devstack-pre-", "Name prefix of phase snapshots.",
          check=_match(r"[a-z0-9][a-z0-9-]*", "lowercase letters, digits, '-'")),
    # ssh
    Field("ssh.key_path", "str", "~/.ssh/{container.name}_ed25519",
          "Private key used for this container (created if missing).", path=True),
    Field("ssh.key_passphrase", "str", "none",
          "'none': key without passphrase (it only opens this local container). 'prompt': ssh-keygen "
          "asks (interactive only; add it to your agent with ssh-add).",
          choices=("none", "prompt")),
    Field("ssh.reuse_existing_key", "bool", False,
          "Allow using a key at ssh.key_path that devstack did not create (it is then never deleted)."),
    Field("ssh.host_alias", "str", "{container.name}",
          "Host alias for `ssh <alias>` and VSCode Remote-SSH.",
          check=_match(r"[A-Za-z0-9._-]+", "letters, digits, '.', '_', '-'")),
    Field("ssh.config_file", "str", "~/.ssh/config",
          "ssh client config that gets a marked block for this stack.", path=True),
    Field("ssh.known_hosts_file", "str", "~/.ssh/known_hosts.d/devstack-{stack.name}",
          "Per-stack known_hosts file (pinned from incus, so no trust-on-first-use).", path=True),
    # node
    Field("node.version", "str", "24.20.0", "Exact Node.js version (verified with the release keys).",
          check=_match(r"[0-9]+\.[0-9]+\.[0-9]+", "an exact version like 24.20.0")),
    Field("node.pnpm_version", "str", "12.8.2",
          "pnpm version for corepack (`corepack use pnpm@<v>` pins it, with its hash, in package.json's "
          "packageManager). Exact and at least a week old, like the dependencies pnpm-workspace.yaml lets "
          "in; 'latest' takes whatever was published last. 10.26.0 or later.", check=_pnpm_version),
    Field("node.install_prefix", "str", "/usr/local", "Where the Node tarball is unpacked.", path=True),
    # dns
    Field("dns.tld", "str", "{container.name}",
          "Dev TLD appended to site.hostname: app.example.com -> app.example.com.<tld>. "
          "Empty = use site.hostname itself (single-domain override).",
          check=_match(r"([a-z0-9-]+(\.[a-z0-9-]+)*)?", "a domain suffix like 'webstack' (or empty)")),
    Field("dns.allow_public_tld", "bool", False,
          "Allow dns.tld to be a real, delegated top-level domain (com, dev, app, ...). Off by default: "
          "the wildcard would then stop every site under that TLD from resolving on this host. "
          "Prefer 'internal' (reserved for private use) or any unused name."),
    Field("dns.wildcard", "bool", True,
          "address=/<tld>/ip: every name under the TLD goes to the container. False = exact "
          "host-record lines only."),
    Field("dns.extra_names", "strlist", [],
          "Extra exact host names that should resolve to the container (host-record)."),
    Field("dns.dnsmasq_dir", "str", "/etc/dnsmasq.d", "dnsmasq drop-in directory.", path=True),
    Field("dns.dnsmasq_file", "str", "{dns.dnsmasq_dir}/devstack-{stack.name}.conf",
          "The one file devstack writes for this stack.", path=True),
    Field("dns.dnsmasq_service", "str", "dnsmasq", "systemd unit restarted after changes."),
    # site
    Field("site.hostname", "str", "app.example.com",
          "The app's intended production hostname. Dev URL = https://<hostname>.<dns.tld>.",
          check=_match(HOSTNAME_RX, "a lowercase hostname")),
    # tls
    Field("tls.host_ca_file", "str", "/usr/local/share/ca-certificates/devstack-{stack.name}.crt",
          "Where devstack's local root CA (name-constrained to the dev domain) is installed on the host "
          "(system trust store).", path=True,
          check=_match(r"/usr/local/share/ca-certificates/.+\.crt",
                       "a .crt file under /usr/local/share/ca-certificates/")),
    Field("tls.browser_trust", "str", "no",
          "Also import the CA into your everyday browser's NSS db (~/.pki/nssdb, used by Chromium/Chrome). "
          "'no' (default): only the dev browser (`devstack browse`) trusts it, from its own NSS db, so your "
          "browser shows a certificate error on dev sites, a reminder that their pages are untrusted. "
          "'auto' = import if certutil and the db exist, else print manual steps; 'yes' = import or fail.",
          choices=("auto", "yes", "no")),
    Field("tls.nss_db", "str", "~/.pki/nssdb", "NSS database directory.", path=True),
    Field("tls.nss_nickname", "str", "devstack-{stack.name}", "Certificate nickname in the NSS db."),
    # browser
    Field("browser.binary", "str", "",
          "Chromium (or Chrome) for `devstack browse`. Empty = the first of chromium, chromium-browser, "
          "google-chrome-stable, google-chrome on PATH."),
    # caddy
    Field("caddy.manage_caddyfile", "bool", True,
          "Generate <project>/infra/Caddyfile. Set false to maintain it yourself "
          "(it must then exist before phase 'proxy')."),
    Field("caddy.static_dir", "str", "{project.container_path}/static", "Static root.", path=True),
    Field("caddy.error_dir", "str", "{project.container_path}/error", "Error / catch-all page root.",
          path=True),
    Field("caddy.admin", "str", "unix//run/caddy/admin.sock",
          "Caddy's admin API (phase isolation). A unix socket in /run/caddy (mode 0700: caddy and root only), "
          "so no local process can replace Caddy's config through the unauthenticated 127.0.0.1:2019.",
          check=_match(r"unix//run/caddy/[A-Za-z0-9_.-]+\.sock",
                       "a socket under /run/caddy, e.g. unix//run/caddy/admin.sock")),
    Field("caddy.headers", "strmap", DEFAULT_HEADERS,
          "Security headers (phase standards). The error page's inline <style> hash is added to "
          "style-src automatically."),
    Field("caddy.same_origin", "str", "strict",
          "Which browser requests the site accepts: the snippet devstack_same_origin, defined in the "
          "root-owned /etc/caddy/Caddyfile and imported by every site block. 'strict': only the site's own "
          "pages; a request a browser marks as coming from another site (a foreign Origin, or Sec-Fetch-Site "
          "cross-site or same-site) gets a bare 403. Typed URLs, bookmarks and tools that send no browser "
          "headers (curl, agents) pass. 'allow-navigation': also top-level GET navigations from other sites "
          "(links in, OAuth or payment redirects back). 'off': no check. No CORS headers in any mode.",
          choices=("strict", "allow-navigation", "off")),
    Field("caddy.max_request_body", "str", "",
          "Largest request body the site accepts (Caddy request_body max_size, e.g. '10MB', '4GiB'); "
          "bigger requests get 413. Empty = no limit. Written into the generated Caddyfile only.",
          check=_match(r"(|[1-9][0-9]*(B|[KMGT]i?B)?)", "empty or a size like 10MB or 4GiB")),
    Field("caddy.dev_servers", "strmap", {},
          "Dev servers in the container (Vite, Storybook, ...), each served by Caddy at https://<name>.<dev host>/ "
          "with /api/* going to the app, so the page and its API share one origin. name = \"port\", e.g. "
          "{ vite = \"5173\" }; the server listens on localhost in the container. Reach them with the dev "
          "browser (`devstack browse vite`), not a forwarded port: it can't reach your host's loopback. No "
          "security headers there: a dev server's inline scripts and HMR websocket would break the CSP.",
          check=_dev_servers),
    # app
    Field("app.service_name", "str", "{stack.name}-app", "systemd unit name (without .service).",
          check=_match(r"[a-zA-Z0-9_.@-]+", "a valid unit name")),
    Field("app.bind", "str", "127.0.0.1", "Listen address. Loopback only, by design.",
          choices=("127.0.0.1", "::1")),
    Field("app.port", "int", 8080, "Listen port.", check=_port),
    Field("app.entry", "str", "server.ts", "Entry file, relative to the project folder.",
          check=_match(r"[A-Za-z0-9_./-]+", "a relative path")),
    Field("app.profile", "str", "local",
          "What the app may reach going out, enforced by nftables on its uid. 'local': loopback only "
          "(Caddy, Postgres, runners), no DNS. 'internet': loopback plus the public internet (never the host "
          "or private ranges). 'open': no restriction (needs your OK).",
          choices=("local", "internet", "open")),
    Field("app.data", "str", "volume",
          "The app's writable data folder at /var/lib/<isolation.app_user> ($STATE_DIRECTORY in the app). "
          "'volume': an incus custom volume (app.data_volume) that survives rebuilds like the Postgres data. "
          "'host': a host folder (app.data_source); files in it belong to the service uid, so your host user "
          "can't read them without sudo. 'none': the app has no writable folder.",
          choices=("volume", "host", "none")),
    Field("app.data_volume", "str", "{stack.name}-appdata",
          "incus custom volume for app.data = 'volume'. Survives undo/destroy; only `--purge-data` deletes it.",
          check=_match(r"[a-z0-9][a-z0-9-]*", "a valid volume name")),
    Field("app.data_source", "str", "", "Host folder for app.data = 'host'.", path=True),
    Field("app.data_adopt", "bool", False,
          "Use an existing app.data_volume devstack did not create. Adopted volumes are never deleted."),
    Field("app.data_backup_dir", "str", "~/.local/share/devstack/{stack.name}/backups",
          "Host folder for `devstack data backup` archives.", path=True),
    Field("app.data_backup_before_undo", "bool", True,
          "Archive the app data automatically before undoing the isolation phase or destroying the container."),
    Field("app.runners", "runners", [],
          "Runners: tools that need the internet or parse untrusted files, without a daemon. Each entry: "
          "name, command (project-relative, run as isolation.runner_user), port (127.0.0.1 only), and optionally "
          "memory_max (default '1G'), runtime_max (default '1h'), max_connections (default 4). Every "
          "connection to the port starts one job with the connection as stdin/stdout. Runners get the public "
          "internet, no loopback, no secrets, and can only write <app data>/incoming. A new or changed "
          "runner needs your OK."),
    # firewall
    Field("firewall.enabled", "bool", True, "Enable ufw in the container."),
    Field("firewall.allow", "intlist", [22, 80, 443], "TCP ports allowed in.", check=_ports),
    Field("firewall.deny", "intlist", [],
          "Extra TCP ports denied (app.port, postgres.port and runner ports are always denied).", check=_ports),
    # isolation
    Field("isolation.system_uid_base", "int", 510,
          "First of four fixed ids: app uid = base, runner uid/gid = base+1, data gid = base+2, dev gid = base+3. "
          "Mid-range on purpose, like postgres.system_uid: Debian hands out system ids downward from 999.",
          check=lambda v: None if 100 <= v <= 990 else "must be a system id (100-990)"),
    Field("isolation.app_user", "str", "{stack.name}-app", "System user the app runs as.",
          check=_match(r"[a-z_][a-z0-9_-]{0,31}", "a valid Linux user name (at most 32 chars)")),
    Field("isolation.runner_user", "str", "{stack.name}-runner", "System user runner jobs run as.",
          check=_match(r"[a-z_][a-z0-9_-]{0,31}", "a valid Linux user name (at most 32 chars)")),
    Field("isolation.data_group", "str", "{stack.name}-data",
          "Group that can read the app data (the app's group; the container user is a member).",
          check=_match(r"[a-z_][a-z0-9_-]{0,31}", "a valid Linux group name (at most 32 chars)")),
    Field("isolation.dev_group", "str", "{stack.name}-dev",
          "Group that can read the internal token (for dev servers that call the API directly).",
          check=_match(r"[a-z_][a-z0-9_-]{0,31}", "a valid Linux group name (at most 32 chars)")),
    # secrets
    Field("secrets.dir", "str", "/etc/app-secrets", "Root-only secrets folder in the container.",
          path=True),
    Field("secrets.token_file", "str", "internal-token.env",
          "Caddy -> app shared token (INTERNAL_TOKEN=...).",
          check=_match(r"[A-Za-z0-9_.-]+", "a file name")),
    # checkpoint
    Field("checkpoint.keep", "int", 1,
          "How many checkpoints to keep. `checkpoint create` makes the new one first, then deletes the oldest "
          "beyond this (after asking). On the 'dir' storage driver each one is a full copy of the container "
          "and the data volumes.", check=lambda v: None if v >= 1 else "must be at least 1"),
    Field("checkpoint.derived", "strlist", ["node_modules", "dist", "build", ".next", ".turbo", ".cache"],
          "Ignored folders (any depth) a checkpoint leaves out because checkpoint.restore_command rebuilds them."),
    Field("checkpoint.capture_max_mb", "int", 20,
          "Ignored files outside checkpoint.derived (.env, local scratch data) are copied into the checkpoint "
          "up to this many MB in all; the rest is listed as not captured.",
          check=lambda v: None if v >= 0 else "must be 0 or more"),
    Field("checkpoint.restore_command", "str", "test ! -f package.json || pnpm install --frozen-lockfile",
          "Run in the project folder in the container (as the container user) after a restore, to rebuild "
          "checkpoint.derived. Empty = nothing."),
    # postgres
    Field("postgres.enabled", "bool", True, "Run the postgres phase."),
    Field("postgres.version", "int", 18, "Major version from apt.postgresql.org.",
          check=lambda v: None if 13 <= v <= 40 else "must be a Postgres major version"),
    Field("postgres.port", "int", 5432, "Port (loopback only).", check=_port),
    Field("postgres.volume", "str", "{stack.name}-pgdata",
          "incus custom volume mounted at /var/lib/postgresql. Survives undo/destroy; only "
          "`--purge-data` deletes it.",
          check=_match(r"[a-z0-9][a-z0-9-]*", "a valid volume name")),
    Field("postgres.adopt_volume", "bool", False,
          "Use an existing volume devstack did not create (e.g. after deleting the state dir). "
          "Adopted volumes are never deleted by devstack."),
    Field("postgres.system_uid", "int", 500,
          "Fixed uid/gid of the postgres OS user, so data on a reused volume keeps its owner. "
          "Mid-range on purpose: Debian hands out system ids downward from 999.",
          check=lambda v: None if 100 <= v <= 999 else "must be a system uid (100-999)"),
    Field("postgres.db", "str", "{stack.name_sql}", "App database name.",
          check=_match(SQL_IDENT_RX, "a lowercase SQL identifier")),
    Field("postgres.role", "str", "{stack.name_sql}_app", "App login role.",
          check=_match(SQL_IDENT_RX, "a lowercase SQL identifier")),
    Field("postgres.test_db", "str", "{postgres.db}_test",
          "Empty database for integration tests, owned by the app role (\"\" = none). Not backed up. The "
          "container user gets its URL as TEST_DATABASE_URL in ~/.config/devstack/<stack>.env.",
          check=_match(f"({SQL_IDENT_RX})?", "a lowercase SQL identifier or empty")),
    Field("postgres.env_file", "str", "postgres.env",
          "Credentials file in secrets.dir (DATABASE_URL, PG* vars), given to the app unit.",
          check=_match(r"[A-Za-z0-9_.-]+", "a file name")),
    Field("postgres.write_pgpass", "bool", True,
          "Write ~/.pgpass for the container user so `psql` just works."),
    Field("postgres.backup_dir", "str", "~/.local/share/devstack/{stack.name}/backups",
          "Host folder for `devstack db backup` dumps.", path=True),
    Field("postgres.backup_before_undo", "bool", True,
          "pg_dump automatically before undoing the postgres phase or destroying the container."),
    # sbom
    Field("sbom.enabled", "bool", True,
          "Install syft in the container (phase base) and keep the CycloneDX files in sbom.dir current. "
          "false = no download from GitHub during base, and no SBOM at all."),
    Field("sbom.generate_on_up", "bool", True,
          "Regenerate the SBOM at the end of a successful `up`. A failure there is a warning, never a "
          "failed phase: `devstack sbom generate` redoes it."),
    Field("sbom.dir", "str", "infra/sbom",
          "Folder inside the project for the generated CycloneDX files (container.cdx.json, "
          "app.cdx.json). Relative to the project folder, and committed with it.", check=_rel_subpath),
    Field("sbom.app_source", "str", "lockfile",
          "How the app inventory is taken. 'lockfile': scan the project without node_modules "
          "(pnpm-lock.yaml is authoritative and deterministic). 'tree': also scan node_modules, for a "
          "project whose packages the lockfile parser misses.", choices=("lockfile", "tree")),
    Field("sbom.fail_on", "str", "",
          "Lowest grype severity that makes `devstack sbom scan` exit 5. Empty = report only, never fail.",
          choices=("", *SEVERITIES)),
    Field("sbom.only_fixed", "bool", True,
          "Count only vulnerabilities that have a fix available towards sbom.fail_on. On by default: "
          "a finding with no fix is not actionable (Debian carries many), and gating on those makes "
          "the gate permanently red. Everything is still reported either way."),
    Field("sbom.ignore", "strlist", [],
          "Vulnerability ids (CVE/GHSA) that `sbom scan` must not count towards sbom.fail_on. Each one "
          "is a decision: record why in the project's README."),
    Field("sbom.db_dir", "str", "{host.state_dir}/grype",
          "Host folder for the grype binary and its vulnerability database (~1 GB). Never in the "
          "project, and it survives undo/destroy like the other caches.", path=True),
    # leaks
    Field("leaks.history", "bool", True,
          "`devstack leaks scan` covers every commit, not only the files as they are now. false = "
          "uncommitted and current files only (faster on a long history)."),
    Field("leaks.ignore", "strlist", [],
          "Finding fingerprints (as `leaks scan` prints them) that must not fail the scan. Only for "
          "false positives: a real secret is rotated, not ignored."),
    Field("leaks.tool_dir", "str", "{host.state_dir}/gitleaks",
          "Host folder for the gitleaks binary. Never in the project.", path=True),
]

FIELDS = {f.key: f for f in SCHEMA}
MOUNT_KEYS = {"name": str, "source": str, "path": str, "readonly": bool, "shift": bool}
RUNNER_KEYS = {"name": str, "command": str, "port": int, "memory_max": str, "runtime_max": str,
               "max_connections": int}
RUNNER_DEFAULTS = {"memory_max": "1G", "runtime_max": "1h", "max_connections": 4}
RESERVED_DEVICES = {"project", "git", "pgdata", "appdata", "gpu"}
RO_DEVICE = re.compile(r"ro[0-9]+|ro-[0-9a-f]{12}")  # project.readonly_paths devices (ro<N>: older devstack)
PLACEHOLDER = re.compile(r"\{([a-z_]+)\.([a-z_]+)\}")


def defaults() -> dict[str, Any]:
    return {f.key: json.loads(json.dumps(f.default)) for f in SCHEMA}


@functools.lru_cache(maxsize=1)
def delegated_tlds() -> frozenset[str]:
    try:
        lines = TLD_FILE.read_text().split()
    except OSError as e:
        raise ConfigError(f"cannot read the bundled TLD list {TLD_FILE}: {e}") from None
    tlds = frozenset(x.lower() for x in lines if not x.startswith("#"))
    if len(tlds) < 1000:
        raise ConfigError(f"{TLD_FILE} looks truncated ({len(tlds)} entries)")
    return tlds


def public_tld_problem(tld: str) -> str | None:
    """Why `tld` would shadow real DNS names, or None. 'home.arpa' is reserved for home networks."""
    tld = tld.lower().rstrip(".")
    if not tld or tld == "home.arpa":
        return None
    last = tld.rsplit(".", 1)[-1]
    if last in delegated_tlds():
        what = "is a real top-level domain" if tld == last else f"ends in the real top-level domain '.{last}'"
        return (f"{tld!r} {what}: the wildcard would make that name (and everything under it) resolve "
                "to the container on this host. Use 'internal' or an unused name, or set "
                "dns.allow_public_tld = true if you really mean it")
    return None


def home_dir() -> Path:  # noqa: N802
    return Path(computed_values()["env.home"])


def computed_values() -> dict[str, str]:
    pw = pwd.getpwuid(os.getuid())
    return {"env.user": pw.pw_name, "env.uid": str(pw.pw_uid), "env.home": pw.pw_dir}


def type_check(f: Field, v: Any) -> str | None:
    if f.kind == "str":
        return None if isinstance(v, str) else "must be a string"
    if f.kind == "int":
        return None if isinstance(v, int) and not isinstance(v, bool) else "must be an integer"
    if f.kind == "bool":
        return None if isinstance(v, bool) else "must be true or false"
    if f.kind == "strlist":
        return None if isinstance(v, list) and all(isinstance(x, str) for x in v) else "must be a list of strings"
    if f.kind == "intlist":
        ok = isinstance(v, list) and all(isinstance(x, int) and not isinstance(x, bool) for x in v)
        return None if ok else "must be a list of integers"
    if f.kind == "strmap":
        ok = isinstance(v, dict) and all(isinstance(k, str) and isinstance(x, str) for k, x in v.items())
        return None if ok else "must be a table of strings"
    if f.kind == "mounts":
        if not isinstance(v, list):
            return "must be an array of tables ([[container.mounts]])"
        for i, m in enumerate(v):
            if not isinstance(m, dict):
                return f"entry {i} must be a table"
            for k, x in m.items():
                if k not in MOUNT_KEYS:
                    return f"entry {i}: unknown key '{k}' (allowed: {', '.join(MOUNT_KEYS)})"
                if not isinstance(x, MOUNT_KEYS[k]):
                    return f"entry {i}: '{k}' has the wrong type"
            for k in ("name", "source", "path"):
                if k not in m:
                    return f"entry {i}: missing '{k}'"
        return None
    if f.kind == "runners":
        if not isinstance(v, list):
            return "must be an array of tables ([[app.runners]])"
        for i, r in enumerate(v):
            if not isinstance(r, dict):
                return f"entry {i} must be a table"
            for k, x in r.items():
                if k not in RUNNER_KEYS:
                    return f"entry {i}: unknown key '{k}' (allowed: {', '.join(RUNNER_KEYS)})"
                if not isinstance(x, RUNNER_KEYS[k]) or isinstance(x, bool):
                    return f"entry {i}: '{k}' has the wrong type"
            for k in ("name", "command", "port"):
                if k not in r:
                    return f"entry {i}: missing '{k}'"
        return None
    raise AssertionError(f.kind)


def normalize_runners(v: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Runner entries with every optional key filled in, in a fixed key order (so they compare equal)."""
    return [{k: x[k] for k in RUNNER_KEYS if k in x} for x in ({**RUNNER_DEFAULTS, **r} for r in v)]


def parse_toml(path: Path) -> dict[str, Any]:
    try:
        data = tomllib.loads(path.read_text())
    except FileNotFoundError:
        raise ConfigError(f"config file not found: {path}") from None
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"{path}: invalid TOML: {e}") from None
    values = defaults()
    errors = []
    for section, table in data.items():
        if section not in SECTIONS:
            hint = difflib.get_close_matches(section, SECTIONS, n=1)
            errors.append(f"unknown section [{section}]" + (f" (did you mean [{hint[0]}]?)" if hint else ""))
            continue
        if not isinstance(table, dict):
            errors.append(f"'{section}' must be a table")
            continue
        for key, v in table.items():
            full = f"{section}.{key}"
            if full not in FIELDS:
                hint = difflib.get_close_matches(full, FIELDS, n=1)
                errors.append(f"unknown key {full}" + (f" (did you mean {hint[0]}?)" if hint else ""))
                continue
            err = type_check(FIELDS[full], v)
            if err:
                errors.append(f"{full}: {err}")
                continue
            values[full] = v
    if errors:
        raise ConfigError(f"{path}:\n  " + "\n  ".join(errors))
    return values


def resolve(values: dict[str, Any]) -> dict[str, Any]:
    """Expand {section.key} placeholders (recursively, cycle-checked) and ~ in paths."""
    computed = computed_values()
    out: dict[str, Any] = {}
    resolving: set[str] = set()

    def get(key: str) -> Any:
        if key in out:
            return out[key]
        if key in computed:
            return computed[key]
        if key == "stack.name_sql":
            return str(get("stack.name")).replace("-", "_")
        if key not in values:
            raise ConfigError(f"unknown placeholder {{{key}}}")
        if key in resolving:
            raise ConfigError(f"placeholder cycle involving {key}")
        resolving.add(key)
        val = expand(values[key])
        resolving.discard(key)
        out[key] = val
        return val

    def expand(val: Any) -> Any:
        if isinstance(val, str):
            def sub(m: re.Match) -> str:
                if m.group(1) not in SECTIONS and m.group(1) != "env":
                    return m.group(0)  # not ours (e.g. a Caddy placeholder)
                return str(get(f"{m.group(1)}.{m.group(2)}"))
            return PLACEHOLDER.sub(sub, val)
        if isinstance(val, list):
            return [expand(x) for x in val]
        if isinstance(val, dict):
            return {k: expand(x) for k, x in val.items()}
        return val

    for key in values:
        get(key)
    for f in SCHEMA:
        if f.path and out[f.key]:
            out[f.key] = str(Path(out[f.key]).expanduser())
    out["container.mounts"] = [
        {**m, "source": str(Path(m["source"]).expanduser())} for m in out["container.mounts"]
    ]
    out["app.runners"] = normalize_runners(out["app.runners"])
    return out


def validate(v: dict[str, Any]) -> list[str]:
    errors = []
    for f in SCHEMA:
        val = v[f.key]
        if f.choices and val not in f.choices:
            errors.append(f"{f.key} = {val!r}: must be one of {', '.join(f.choices)}")
        if f.check:
            err = f.check(val)
            if err:
                errors.append(f"{f.key} = {val!r}: {err}")
        if f.path and val and not val.startswith("/"):
            errors.append(f"{f.key} = {val!r}: must be an absolute path (after ~ expansion)")
    taken = {v["app.port"]: "app.port", v["postgres.port"]: "postgres.port",
             **{r["port"]: f"runner {r['name']}" for r in v["app.runners"] if isinstance(r, dict) and "port" in r}}
    for name, port in v["caddy.dev_servers"].items():
        if str(port).isdigit() and int(port) in taken:
            errors.append(f"caddy.dev_servers: {name} = {port} is {taken[int(port)]}'s port")
    names = [m["name"] for m in v["container.mounts"]]
    if len(names) != len(set(names)) or RESERVED_DEVICES & set(names) or any(
            RO_DEVICE.fullmatch(n) for n in names):
        errors.append("container.mounts: names must be unique and not 'project', 'git', 'pgdata', 'appdata', "
                      "'gpu', 'ro<N>' or 'ro-<hex>'")
    for m in v["container.mounts"]:
        if not m["source"].startswith("/") or not m["path"].startswith("/"):
            errors.append(f"container.mounts '{m['name']}': source and path must be absolute")
    if Path(v["dns.dnsmasq_file"]).parent != Path(v["dns.dnsmasq_dir"]):
        errors.append("dns.dnsmasq_file must be directly inside dns.dnsmasq_dir")
    if not v["dns.dnsmasq_file"].endswith(".conf"):
        errors.append("dns.dnsmasq_file should end in .conf")
    if v["postgres.enabled"] and v["app.port"] == v["postgres.port"]:
        errors.append("app.port and postgres.port must differ")
    special = {v["app.port"]} | ({v["postgres.port"]} if v["postgres.enabled"] else set())
    if special & set(v["firewall.allow"]):
        errors.append("firewall.allow must not contain app.port or postgres.port (they stay internal)")
    for name in v["dns.extra_names"]:
        if not re.fullmatch(HOSTNAME_RX, name):
            errors.append(f"dns.extra_names: {name!r} is not a valid hostname")
    if v["project.container_path"] in ("/", "/srv", "/home", "/usr", "/etc", "/var"):
        errors.append("project.container_path must be a dedicated folder")
    if not v["dns.allow_public_tld"]:
        problem = public_tld_problem(v["dns.tld"])
        if problem:
            errors.append(f"dns.tld = {problem}")
    if v["app.data"] == "host" and not v["app.data_source"]:
        errors.append('app.data = "host" needs app.data_source (a host folder)')
    accounts = [v[k] for k in ("isolation.app_user", "isolation.runner_user", "isolation.data_group",
                               "isolation.dev_group")]
    if len(set(accounts)) != len(accounts):
        errors.append("isolation: app_user, runner_user, data_group and dev_group must all differ")
    base = v["isolation.system_uid_base"]
    if base <= v["postgres.system_uid"] <= base + 3:
        errors.append(f"isolation.system_uid_base {base} overlaps postgres.system_uid {v['postgres.system_uid']} "
                      f"(the isolation ids are {base}-{base + 3})")
    if v["postgres.test_db"] and v["postgres.test_db"] == v["postgres.db"]:
        errors.append("postgres.test_db must differ from postgres.db (tests wipe it)")
    errors += validate_runners(v)
    return errors


RUNNER_NAME_RX = r"[a-z][a-z0-9-]{0,19}"
# Words of safe characters: nothing systemd's ExecStart= would expand ($, %), quote or split.
RUNNER_COMMAND_RX = r"[A-Za-z0-9_./=:@+-]+( [A-Za-z0-9_./=:@+-]+)*"
MEMORY_RX = r"[0-9]+[KMGT]?|[0-9]{1,2}%|infinity"
TIMESPAN_RX = r"[0-9]+(us|ms|s|min|m|h|d|w)?"


def validate_runners(v: dict[str, Any]) -> list[str]:
    errors = []
    runners = v["app.runners"]
    reserved = {v["app.port"]: "app.port", 22: "ssh", 80: "Caddy", 443: "Caddy", 2019: "Caddy's default admin port"}
    if v["postgres.enabled"]:
        reserved[v["postgres.port"]] = "postgres.port"
    seen_names: set[str] = set()
    seen_ports: set[int] = set()
    for r in runners:
        missing = [k for k in ("name", "command", "port") if k not in r]
        if missing:
            errors.append(f"app.runners: an entry is missing {', '.join(missing)}")
            continue
        label = f"app.runners '{r['name']}'"
        if not re.fullmatch(RUNNER_NAME_RX, r["name"]):
            errors.append(f"{label}: name must be 1-20 chars: a-z, 0-9, '-', starting with a letter")
        if r["name"] in seen_names:
            errors.append(f"{label}: duplicate name")
        seen_names.add(r["name"])
        if not re.fullmatch(RUNNER_COMMAND_RX, r["command"]):
            errors.append(f"{label}: command must be words of [A-Za-z0-9_./=:@+-] separated by single spaces "
                          "(no quotes, $ or %; put anything fancier in a script)")
        if _port(r["port"]):
            errors.append(f"{label}: port must be 1-65535")
        elif r["port"] in reserved:
            errors.append(f"{label}: port {r['port']} is already {reserved[r['port']]}")
        elif r["port"] in seen_ports:
            errors.append(f"{label}: port {r['port']} is used by another runner")
        seen_ports.add(r["port"])
        if not re.fullmatch(MEMORY_RX, r["memory_max"]):
            errors.append(f"{label}: memory_max must look like '512M', '2G' or '50%'")
        if not re.fullmatch(TIMESPAN_RX, r["runtime_max"]):
            errors.append(f"{label}: runtime_max must look like '90s', '30min' or '2h'")
        if not 1 <= r["max_connections"] <= 64:
            errors.append(f"{label}: max_connections must be 1-64")
    if runners and set(seen_ports) & set(v["firewall.allow"]):
        errors.append("firewall.allow must not contain a runner port (runners stay internal)")
    return errors


class Config:
    def __init__(self, raw: dict[str, Any], source: Path | None):
        self.raw = raw
        self.source = source
        self.v = resolve(raw)
        errors = validate(self.v)
        if errors:
            where = f"{source}: " if source else ""
            raise ConfigError(where + "invalid configuration:\n  " + "\n  ".join(errors))

    def __getitem__(self, key: str) -> Any:
        return self.v[key]

    @property
    def dev_host(self) -> str:
        tld = self.v["dns.tld"]
        return f"{self.v['site.hostname']}.{tld}" if tld else self.v["site.hostname"]

    @property
    def uid(self) -> int:
        u = self.v["container.uid"]
        return os.getuid() if u == "auto" else int(u)

    @property
    def user_home(self) -> str:
        return f"/home/{self.v['container.user']}"

    def digest(self) -> str:
        return sha256_text(json.dumps(self.v, sort_keys=True))[:10]


def load_config(path: Path) -> Config:
    return Config(parse_toml(path), path)


# --- TOML writer (only what the schema needs) ---


def toml_value(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        return "[" + ", ".join(toml_value(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{ " + ", ".join(f"{toml_key(k)} = {toml_value(x)}" for k, x in v.items()) + " }" if v else "{}"
    raise TypeError(type(v))


def toml_key(k: str) -> str:
    return k if re.fullmatch(r"[A-Za-z0-9_-]+", k) else json.dumps(k)


def comment(text: str, width: int = 88) -> list[str]:
    return ["# " + ln for ln in textwrap.wrap(text, width - 2)]


def field_comment(f: Field) -> list[str]:
    lines = comment(f.help)
    if f.choices:
        lines.append("# choices: " + ", ".join(f.choices))
    if f.kind not in TABLE_KINDS:
        lines.append(f"# default: {toml_value(f.default)}")
    return lines


TABLE_KINDS = ("strmap", "mounts", "runners")
EXAMPLE_TABLES = {
    "mounts": ['name = "data"', 'source = "~/data"', 'path = "/srv/data"', "readonly = false"],
    "runners": ['name = "fetch"', 'command = "node scripts/runner.ts"', "port = 9101", 'memory_max = "2G"',
                'runtime_max = "2h"', "max_connections = 2"],
}


def array_of_tables(key: str, entries: list[dict[str, Any]], kind: str) -> list[str]:
    out = []
    if not entries:
        out += [f"# [[{key}]]", *(f"# {ln}" for ln in EXAMPLE_TABLES[kind])]
    for m in entries:
        out.append(f"[[{key}]]")
        out += [f"{toml_key(k)} = {toml_value(x)}" for k, x in m.items()]
    return out


def config_to_toml(values: dict[str, Any]) -> str:
    out = [
        "# devstack configuration. Every key is optional; missing keys use the default shown.",
        "# {section.key} placeholders refer to other keys; {env.user}, {env.uid}, {env.home} and",
        "# {stack.name_sql} (stack.name with '-' -> '_') are computed. `./devstack config explain`",
        "# prints these docs, `./devstack config show` the resolved values.",
    ]
    for section, intro in SECTIONS.items():
        out += ["", *comment(intro), f"[{section}]"]
        tables = []
        for f in (f for f in SCHEMA if f.section == section):
            if f.kind in TABLE_KINDS:
                tables.append(f)
                continue
            out += field_comment(f)
            out.append(f"{f.name} = {toml_value(values[f.key])}")
            out.append("")
        if out[-1] == "":
            out.pop()
        for f in tables:
            out.append("")
            out += comment(f.help)
            if f.kind == "strmap":
                out.append(f"[{f.key}]")
                for k, x in values[f.key].items():
                    out.append(f"{toml_key(k)} = {toml_value(x)}")
            else:
                out += array_of_tables(f.key, values[f.key], f.kind)
    return "\n".join(out) + "\n"


# --- the project's share of the config (infra/devstack-requires.toml) ---

REQUIRES_FILE = "infra/devstack-requires.toml"
# Container-side settings that belong to the project, not to one host. They are the only
# keys written to REQUIRES_FILE (committed with the project) and the only keys read back
# from it (it may come from someone else's repo), so the file neither reveals nor steers
# anything on the host. Mounts are listed without their host source.
# Host details (LAN CIDRs, the Caddy admin address, volume names, host folders) stay out: a
# public repo must neither learn them nor be able to, say, put Caddy's admin API back on TCP.
# Requests that widen access (container.sudo, app.profile, app.runners, gpu.enabled) still need
# the developer's OK: a file that differs from what this stack last wrote is a preflight risk.
# Of the [gpu] keys only gpu.enabled is here -- whether the code needs a GPU at all is the
# project's to state, and leaving it out meant a rebuild elsewhere (or from a fresh `init`)
# silently came up without one. gpu.pci names a device on one host and gpu.nvidia_runtime
# depends on that host's toolkit, so both stay host-side.
# Of the [sbom] keys only the two the project legitimately decides are here. sbom.fail_on and
# sbom.ignore are the host owner's audit policy: a cloned repo must not be able to lower the gate or
# silence a CVE. sbom.enabled stays out so a repo cannot add a GitHub download to someone's base
# phase, and sbom.db_dir is a host path that can never leave. No [leaks] key is here either: what the
# secret scan covers and ignores is the host owner's audit policy too.
PROJECT_KEYS = (
    "project.container_path", "project.readonly_paths", "container.image", "container.sudo",
    "node.version", "node.pnpm_version", "node.install_prefix", "site.hostname",
    "caddy.manage_caddyfile", "caddy.static_dir", "caddy.error_dir", "caddy.headers",
    "caddy.same_origin", "caddy.max_request_body", "caddy.dev_servers",
    "checkpoint.derived", "checkpoint.restore_command",
    "app.service_name", "app.bind", "app.port", "app.entry", "app.profile", "app.data", "app.runners",
    "firewall.enabled", "firewall.allow", "firewall.deny", "secrets.dir", "secrets.token_file",
    "gpu.enabled",
    "postgres.enabled", "postgres.version", "postgres.port", "postgres.system_uid",
    "postgres.db", "postgres.role", "postgres.test_db", "postgres.env_file", "postgres.write_pgpass",
    "sbom.dir", "sbom.app_source",
)
REQUIRED_MOUNT_KEYS = {"name": str, "path": str, "readonly": bool}


def requirements(v: dict[str, Any]) -> dict[str, Any]:
    """The project's share of resolved config values v."""
    out = {k: v[k] for k in PROJECT_KEYS}
    out["container.mounts"] = [{"name": m["name"], "path": m["path"], "readonly": m.get("readonly", False)}
                               for m in v["container.mounts"]]
    return out


def requirements_to_toml(req: dict[str, Any]) -> str:
    out = [
        "# What this project needs from its devstack container. Generated by `devstack up`; commit it.",
        "# It holds container-side settings only: nothing about the host it was built on.",
        "#",
        "# To build the environment on your machine, write your own config (keep it outside",
        "# this repo) with these values as its defaults:",
        "#   ./devstack init --project <this folder>",
        "# then read it, and run `./devstack up -c <your config>`.",
    ]
    for section in SECTIONS:
        fields = [f for f in SCHEMA if f.section == section and f.key in req and f.kind != "mounts"]
        if not fields:
            continue
        out += ["", f"[{section}]"]
        for f in fields:
            if f.kind in TABLE_KINDS and not (f.kind == "runners" and not req[f.key]):
                continue
            out += comment(f.help)
            out.append(f"{f.name} = {toml_value(req[f.key])}")  # no runners: `runners = []`, stated explicitly
        for f in (f for f in fields if f.kind == "strmap"):
            out += ["", *comment(f.help), f"[{f.key}]"]
            out += [f"{toml_key(k)} = {toml_value(x)}" for k, x in req[f.key].items()]
        for f in (f for f in fields if f.kind == "runners" and req[f.key]):
            out += ["", *comment(f.help), *array_of_tables(f.key, req[f.key], f.kind)]
    out += [""]
    mounts = req.get("container.mounts", [])
    if not mounts:
        out.append("# Host folders: none required.")
    else:
        out += comment("Host folders this project expects. Your config must mount each one, under the same "
                       "name and container path, from a folder on your host:")
        out += ["#   [[container.mounts]]", f"#   name = {toml_value(mounts[0]['name'])}",
                '#   source = "~/folder/on/your/host"', f"#   path = {toml_value(mounts[0]['path'])}"]
        for m in mounts:
            out += ["[[container.mounts]]", *(f"{k} = {toml_value(m[k])}" for k in REQUIRED_MOUNT_KEYS)]
    return "\n".join(out) + "\n"


# --- the CycloneDX inventory (infra/sbom/*.cdx.json), normalized so the committed diff is honest ---
#
# syft's output is not stable run to run: it carries a random serialNumber, a fresh timestamp, and
# bom-refs with a content hash in them. Committed raw, the file would churn on every single `up` and
# the diff would be worthless. normalize_cdx() makes the bytes a pure function of the dependency set.
#
# The dangerous mistake here is normalizing too much. grype matches on the purl qualifiers
# (arch, distro, epoch, upstream), on each component's cpe/syft:cpe23, and on the separate
# "operating-system" component that carries syft:distro:* -- strip any of those and grype quietly
# finds nothing and reports a clean bill of health, which is far worse than a noisy diff. So
# properties are filtered by an allowlist of names (a denylist would leak whatever the next syft
# version adds) and the result is asserted, rather than trusted.

# Properties worth keeping: what the package is, and what grype matches on. Everything else goes --
# syft:location:* (churns when a file moves), syft:package:foundBy (churns when a cataloger is
# renamed), syft:metadata:installedSize (churns on every upgrade), syft:metadata:source (already in
# the purl's upstream= qualifier).
SBOM_KEEP_PROPS = ("syft:cpe23", "syft:package:type", "syft:package:language",
                   "syft:package:metadataType")
SBOM_KEEP_PROP_PREFIXES = ("syft:distro:",)
# Component keys worth keeping. "evidence" is dropped because its occurrences carry file locations,
# and "author"/"supplier" are noisy and not matched on.
SBOM_COMPONENT_KEYS = ("type", "name", "version", "group", "publisher", "description", "scope",
                       "licenses", "cpe", "purl", "hashes", "externalReferences", "properties")
SBOM_URL_SCHEMES = ("http://", "https://", "git://", "git+https://", "git+ssh://")
# A hash syft uses as a bom-ref when it has nothing better (the scan root, file components).
_SBOM_OPAQUE_REF = re.compile(r"^[0-9a-f]{16}$")
_SBOM_PKG_ID = re.compile(r"[?&]package-id=[0-9a-fA-F]+")
# Absolute paths that must never reach a committed file. container.user defaults to a generic name,
# so /home/<user> is normally no secret -- but it is settable, and someone who points it at their
# host login should not have that published. urn:uuid: catches a serialNumber we failed to drop.
# The lookbehind keeps this to path-shaped matches: a purl like pkg:npm/home/x contains "/home/" but
# is a package name, not a path. A real path is preceded by a quote, a space or another slash.
_SBOM_DENY = re.compile(r"(?<![A-Za-z0-9_%+.~-])(?:/home/|/root/|/Users/)|urn:uuid:")
# A username is matched only in path position. A bare substring match is useless here: "user" is in
# adduser and dbus-user-session, "louis" is in liblouis, and a user called "al" matches a quarter of
# a real Debian inventory. Measured on 3179 packages: 144, 54 and 25478 false positives.
_SBOM_NAME_IN_PATH = r"/{}(?=[/\"']|$)"


def _sbom_strip_pkg_id(ref: str) -> str:
    """Drop syft's package-id qualifier, which is a content hash and not part of the identity.
    What is left is exactly the component's purl (verified against syft 1.54 output)."""
    out = _SBOM_PKG_ID.sub("", ref, count=1)
    if "?" not in out and "&" in out:  # we removed the first qualifier; promote the next one
        out = out.replace("&", "?", 1)
    return out


def _sbom_props(props: Any) -> list[dict[str, Any]]:
    keep = [p for p in (props or [])
            if isinstance(p, dict) and isinstance(p.get("name"), str)
            and (p["name"] in SBOM_KEEP_PROPS or p["name"].startswith(SBOM_KEEP_PROP_PREFIXES))]
    return sorted(keep, key=lambda p: (p["name"], str(p.get("value", ""))))


def _sbom_component(c: dict[str, Any]) -> dict[str, Any]:
    out = {k: c[k] for k in SBOM_COMPONENT_KEYS if k in c}
    if "purl" in out:
        out["purl"] = _sbom_strip_pkg_id(out["purl"])
    if "properties" in out:
        props = _sbom_props(out["properties"])
        if props:
            out["properties"] = props
        else:
            del out["properties"]
    if "hashes" in out:
        out["hashes"] = sorted((h for h in out["hashes"] if isinstance(h, dict)),
                               key=lambda h: (str(h.get("alg")), str(h.get("content"))))
    if "licenses" in out:
        out["licenses"] = sorted(out["licenses"], key=lambda e: json.dumps(e, sort_keys=True))
    if "externalReferences" in out:
        refs = [{k: r[k] for k in ("type", "url", "comment") if k in r}
                for r in out["externalReferences"]
                if isinstance(r, dict) and str(r.get("url", "")).startswith(SBOM_URL_SCHEMES)]
        if refs:
            out["externalReferences"] = sorted(refs, key=lambda r: json.dumps(r, sort_keys=True))
        else:
            del out["externalReferences"]
    return out


def _sbom_ref_for(c: dict[str, Any], old: str) -> str:
    if c.get("purl"):
        return str(c["purl"])
    if old and not _SBOM_OPAQUE_REF.match(old):
        return old  # a meaningful ref syft chose, e.g. "os:debian@13" for the distro component
    return f"{c.get('type', 'library')}/{c.get('name', '')}@{c.get('version', '')}"


def normalize_cdx(doc: dict[str, Any], *, kind: str, stack: str, source_version: str = "") -> dict[str, Any]:
    """Turn one syft CycloneDX document into the canonical form that gets committed.

    Pure: same dependency set in, same bytes out, whatever the run. Raises DevstackError on anything
    it does not recognise, rather than writing a file whose meaning it is unsure of."""
    if doc.get("bomFormat") != "CycloneDX":
        raise DevstackError(f"not a CycloneDX document (bomFormat = {doc.get('bomFormat')!r})")
    if str(doc.get("specVersion")) != SBOM_CDX_VERSION:
        raise DevstackError(
            f"CycloneDX {doc.get('specVersion')!r} from syft {SYFT_VERSION}, expected {SBOM_CDX_VERSION}. "
            "A new spec version is a deliberate decision: check what moved, then update SBOM_CDX_VERSION.")

    root = "root"
    refmap: dict[str, str] = {}
    meta_ref = (doc.get("metadata") or {}).get("component", {}).get("bom-ref")
    if isinstance(meta_ref, str):
        refmap[meta_ref] = root

    # Components. Drop "file" components outright: syft names them by their absolute path (so they
    # would publish the host path, and the scan root's own name), they carry no purl, and grype has
    # nothing to match them against. Note this is deliberately not "drop components without a purl":
    # the operating-system component has no purl either and is what tells grype which distro feed to
    # use. Keep every other type.
    comps: list[tuple[str, dict[str, Any]]] = []
    for c in doc.get("components") or []:
        if not isinstance(c, dict) or c.get("type") == "file":
            continue
        norm = _sbom_component(c)
        comps.append((_sbom_ref_for(norm, str(c.get("bom-ref", ""))), norm))
        if isinstance(c.get("bom-ref"), str):
            refmap[c["bom-ref"]] = comps[-1][0]

    # Collapse exact duplicates (the same package found by two catalogers differs only in the
    # location properties we just dropped), then disambiguate any ref still shared.
    seen: dict[str, dict[str, Any]] = {}
    for ref, norm in comps:
        body = json.dumps(norm, sort_keys=True)
        key, n = ref, 1
        while key in seen and json.dumps(seen[key], sort_keys=True) != body:
            n += 1
            key = f"{ref}#{n}"
        seen[key] = norm
    out_comps = []
    for ref in sorted(seen):
        out_comps.append({"bom-ref": ref, **seen[ref]})
    for old, new in list(refmap.items()):
        if new not in seen and new != root:
            refmap.pop(old)
    out_comps.sort(key=lambda c: (str(c.get("purl", "")), str(c.get("name", "")),
                                  str(c.get("version", "")), str(c.get("type", "")), c["bom-ref"]))

    known = {c["bom-ref"] for c in out_comps} | {root}
    deps = []
    for d in doc.get("dependencies") or []:
        if not isinstance(d, dict):
            continue
        ref = refmap.get(str(d.get("ref")), str(d.get("ref")))
        if ref not in known:
            continue  # a dependency of something we dropped (a file component)
        on = sorted({refmap.get(str(x), str(x)) for x in (d.get("dependsOn") or [])} & known)
        entry: dict[str, Any] = {"ref": ref}
        if on:
            entry["dependsOn"] = on
        deps.append(entry)
    deps.sort(key=lambda d: d["ref"])
    for d in deps:  # a dangling ref means the rewrite above is wrong; never ship a broken graph
        for x in [d["ref"], *d.get("dependsOn", [])]:
            if x not in known:
                raise DevstackError(f"SBOM dependency ref {x!r} resolves to nothing after normalization")

    tools = (doc.get("metadata") or {}).get("tools") or {}
    tool_comps = tools.get("components") if isinstance(tools, dict) else tools
    out: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": doc["specVersion"],
        "version": 1,
        "metadata": {
            # No timestamp: it would be the only thing changing in most commits. The syft version
            # stays, because it is the honest explanation for a document-wide diff.
            "tools": {"components": sorted(
                ({k: t[k] for k in ("type", "author", "name", "version") if k in t}
                 for t in (tool_comps or []) if isinstance(t, dict)),
                key=lambda t: (str(t.get("name")), str(t.get("version"))))},
            "component": {"bom-ref": root, "type": "application",
                          "name": f"{stack}-{kind}", "version": source_version},
        },
        "components": out_comps,
    }
    if deps:
        out["dependencies"] = deps
    return out


def cdx_bytes(doc: dict[str, Any]) -> str:
    """Canonical serialization. sort_keys makes a key-order change between syft versions invisible."""
    return json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def cdx_inventory(doc: dict[str, Any]) -> list[tuple[str, str, str]]:
    """(name, version, purl) per component: what `sbom check` diffs and `sbom show` prints."""
    return sorted((str(c.get("name", "")), str(c.get("version", "")), str(c.get("purl", "")))
                  for c in doc.get("components") or [])


def assert_no_sbom_leaks(text: str, paths: list[str], names: list[str] | None = None) -> None:
    """Last line of defence before a generated SBOM is committed. The property allowlist should have
    made this unreachable; it exists so that a future syft putting a path in a field we keep fails
    the build instead of publishing it.

    paths: absolute host paths (the project, the state dir, the home dir, mount sources). Matched as
        substrings, which is unambiguous because they are full paths.
    names: usernames. Matched *only* in path position, because a username is a substring of real
        package names -- see _SBOM_NAME_IN_PATH for the measured false-positive counts.
    """
    name_rx = [(n, re.compile(_SBOM_NAME_IN_PATH.format(re.escape(n)))) for n in (names or []) if n]
    for lineno, line in enumerate(text.splitlines(), 1):
        def refuse(what: str, why: str) -> DevstackError:
            return DevstackError(f"refusing to write the SBOM: line {lineno} contains {what} ({why})."
                                 f"\n  {line.strip()[:200]}\n"
                                 "This is devstack's own guard, not syft's: the document is not written.")
        m = _SBOM_DENY.search(line)
        if m:
            raise refuse(repr(m.group(0)), "a host path, or an id that would churn every run")
        for lit in paths:
            if lit and lit in line:  # an empty literal would match every line
                raise refuse(repr(lit), "a host path")
        for name, rx in name_rx:
            m = rx.search(line)
            if m:
                raise refuse(repr(m.group(0)), f"the container user {name!r} in a path")


def _host_placeholder(val: Any) -> bool:
    if isinstance(val, str):
        return any(m.group(1) in SECTIONS or m.group(1) == "env" for m in PLACEHOLDER.finditer(val))
    if isinstance(val, list):
        return any(_host_placeholder(x) for x in val)
    if isinstance(val, dict):
        return any(_host_placeholder(x) for x in val.values())
    return False


def load_requirements(path: Path) -> dict[str, Any] | None:
    """Read a project's REQUIRES_FILE (None if absent). Only PROJECT_KEYS and mounts without a
    source are accepted, as literal values: the file may come from someone else's repo."""
    try:
        data = tomllib.loads(path.read_text())
    except FileNotFoundError:
        return None
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"{path}: invalid TOML: {e}") from None
    values: dict[str, Any] = {}
    errors = []
    for section, table in data.items():
        if not isinstance(table, dict):
            errors.append(f"'{section}' must be a table")
            continue
        for key, v in table.items():
            full = f"{section}.{key}"
            if full == "container.mounts":
                ok = isinstance(v, list) and all(
                    isinstance(m, dict) and {"name", "path"} <= m.keys()
                    and all(k in REQUIRED_MOUNT_KEYS and isinstance(x, REQUIRED_MOUNT_KEYS[k]) for k, x in m.items())
                    for m in v)
                if not ok:
                    errors.append(f"{full}: each entry needs name and path (and optionally readonly), "
                                  "nothing else: the host source belongs in your own config")
                    continue
                values[full] = [{"readonly": False, **m} for m in v]
            elif full not in PROJECT_KEYS:
                errors.append(f"{full} is not a project setting (host-side settings belong in your own config)")
            elif type_check(FIELDS[full], v):
                errors.append(f"{full}: {type_check(FIELDS[full], v)}")
            elif _host_placeholder(v):
                errors.append(f"{full}: {{placeholders}} are not allowed here, write the value itself")
            elif full == "app.runners":
                values[full] = normalize_runners(v)
            else:
                values[full] = v
    if errors:
        raise ConfigError(f"{path}:\n  " + "\n  ".join(errors))
    return values


def requirements_diff(want: dict[str, Any], v: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Where resolved config v departs from a project's requirements: (missing mounts, other differences)."""
    have = requirements(v)

    def show(x: Any) -> str:
        return "(a different table)" if isinstance(x, dict) else toml_value(x)

    diffs = [f"{k}: project {show(want[k])}, your config {show(have[k])}"
             for k in want if k != "container.mounts" and want[k] != have[k]]
    missing = []
    mine = {m["name"]: m for m in have["container.mounts"]}
    for m in want.get("container.mounts", []):
        got = mine.get(m["name"])
        if got is None:
            missing.append(f"{REQUIRES_FILE} requires a host folder mounted at {m['path']}"
                           f"{' (read-only)' if m['readonly'] else ''}; add to your config:\n"
                           f'    [[container.mounts]]\n    name = {toml_value(m["name"])}\n'
                           f'    source = "~/folder/on/your/host"\n    path = {toml_value(m["path"])}'
                           + ("\n    readonly = true" if m["readonly"] else ""))
        elif got != m:
            diffs.append(f"mount '{m['name']}': project {m['path']}{' read-only' if m['readonly'] else ''}, "
                         f"your config {got['path']}{' read-only' if got['readonly'] else ''}")
    return missing, diffs


# ---------------------------------------------------------------------------
# 3. logging
# ---------------------------------------------------------------------------

LEVELS = {"debug": logging.DEBUG, "info": logging.INFO, "warning": logging.WARNING, "error": logging.ERROR}


class Redactor(logging.Filter):
    """Replace registered secret values with *** in every record."""

    def __init__(self) -> None:
        super().__init__()
        self.values: set[str] = set()

    def add(self, value: str) -> None:
        if value and len(value) >= 6:
            self.values.add(value)

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        for s in self.values:
            msg = msg.replace(s, "***")
        record.msg, record.args = msg, None
        return True


REDACT = Redactor()


class ConsoleFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        prefix = {logging.WARNING: "warning: ", logging.ERROR: "error: ", logging.DEBUG: "  · "}
        return prefix.get(record.levelno, "") + record.getMessage()


class PrivateFileHandler(logging.FileHandler):
    """Log file that is created (and kept) mode 0600, wherever it lives."""

    def _open(self):  # type: ignore[no-untyped-def]
        fd = os.open(self.baseFilename, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.fchmod(fd, 0o600)
        except OSError:
            pass
        return os.fdopen(fd, "a", encoding=self.encoding)


def setup_logging(target: str = "stderr", file: str | None = None, level: str = "info", ident: str = "devstack") -> None:
    for h in list(log.handlers):
        log.removeHandler(h)
        h.close()
    log.setLevel(logging.DEBUG)
    log.propagate = False
    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(ConsoleFormatter())
    console.setLevel(LEVELS[level] if target in ("stderr", "both") else max(LEVELS[level], logging.WARNING))
    handlers: list[logging.Handler] = [console]
    if target in ("file", "both") and file:
        Path(file).parent.mkdir(parents=True, exist_ok=True)
        fh = PrivateFileHandler(file)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(message)s"))
        handlers.append(fh)
    if target == "journald":
        try:
            sh = logging.handlers.SysLogHandler(address="/dev/log")
            sh.ident = f"{ident}: "
            sh.setLevel(logging.DEBUG)
            handlers.append(sh)
        except OSError as e:
            console.setLevel(LEVELS[level])
            log.warning("journald logging unavailable (%s); logging to the terminal only", e)
    for h in handlers:
        h.addFilter(REDACT)
        log.addHandler(h)


# ---------------------------------------------------------------------------
# 4. command runner, state, journal
# ---------------------------------------------------------------------------


class Runner:
    def __init__(self, interactive: bool):
        self.interactive = interactive

    def run(
        self,
        argv: list[Any],
        *,
        input: str | None = None,
        check: bool = True,
        sudo: bool = False,
        stream: bool = False,
        tty: bool = False,
        timeout: float | None = None,
        secret_input: bool = False,
        secret_output: bool = False,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess:
        """Run a command, logging argv and output at debug level.

        env: a complete replacement environment (not a merge), for a tool that must not inherit
        ambient settings -- grype reads a dozen GRYPE_* variables that would change what it reports.

        stream: merge stderr into stdout and log lines as they arrive (long apt runs).
        tty: inherit the terminal (prompts like ssh-keygen passphrases, psql shells).
        """
        argv = [str(a) for a in argv]
        if sudo:
            argv = ["sudo", *([] if self.interactive else ["-n"]), *argv]
        log.debug("$ %s", shlex.join(argv))
        if input is not None:
            log.debug("  stdin: %s", f"<secret, {len(input)} bytes>" if secret_input else input.rstrip()[:4000])
        start = time.monotonic()
        try:
            if tty:
                p = subprocess.run(argv, timeout=timeout, env=env)
                p.stdout = p.stderr = ""
            elif stream:
                proc = subprocess.Popen(
                    argv, stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, env=env,
                )
                if input is not None:
                    assert proc.stdin
                    proc.stdin.write(input)
                    proc.stdin.close()
                lines = []
                assert proc.stdout
                for line in proc.stdout:
                    lines.append(line)
                    if not secret_output:
                        log.debug("  | %s", line.rstrip())
                proc.wait()
                p = subprocess.CompletedProcess(argv, proc.returncode, "".join(lines), "")
            else:
                p = subprocess.run(argv, input=input, capture_output=True, text=True, timeout=timeout,
                                   env=env)
                if not secret_output:
                    for stream_name, text in (("out", p.stdout), ("err", p.stderr)):
                        if text and text.strip():
                            log.debug("  %s| %s", stream_name, text.rstrip()[:20000])
        except FileNotFoundError:
            raise DevstackError(f"command not found: {argv[0]}") from None
        except subprocess.TimeoutExpired:
            raise DevstackError(f"command timed out after {timeout}s: {short_cmd(argv)}") from None
        log.debug("  exit %s in %.1fs", p.returncode, time.monotonic() - start)
        if check and p.returncode != 0:
            output = "" if secret_output else (p.stdout or "") + (p.stderr or "")
            raise CommandError(argv, p.returncode, output)
        return p


class State:
    """state.json: phase statuses and facts (container IP, node path, ...)."""

    def __init__(self, path: Path):
        self.path = path
        self.data: dict[str, Any] = {"version": 1, "phases": {}, "facts": {}}
        if path.exists():
            self.data = json.loads(path.read_text())

    def status(self, pid: str) -> str:
        return self.data["phases"].get(pid, {}).get("status", "pending")

    def set_status(self, pid: str, status: str) -> None:
        if status == "pending":
            self.data["phases"].pop(pid, None)
        else:
            self.data["phases"][pid] = {"status": status, "ts": now()}
        self.save()

    def fact(self, key: str, default: Any = None) -> Any:
        return self.data["facts"].get(key, default)

    def set_fact(self, key: str, value: Any) -> None:
        self.data["facts"][key] = value
        self.save()

    def save(self) -> None:
        atomic_write(self.path, json.dumps(self.data, indent=2) + "\n", 0o600)


ACTIVE = ("pending", "applied")  # still needs undo
OWNED = ("pending", "applied", "kept", "pruned")  # devstack still owns the resource


class Journal:
    """Write-ahead journal of every change outside the container rootfs (DESIGN.md §7.2)."""

    def __init__(self, path: Path):
        self.path = path
        self.entries: list[dict[str, Any]] = []
        if path.exists():
            self.entries = [json.loads(ln) for ln in path.read_text().splitlines() if ln.strip()]

    def add(self, phase: str, kind: str, **args: Any) -> dict[str, Any]:
        seq = (self.entries[-1]["seq"] + 1) if self.entries else 1
        e = {"seq": seq, "ts": now(), "phase": phase, "kind": kind, "args": args, "status": "pending"}
        self.entries.append(e)
        self.save()
        log.debug("journal +%s %s %s", seq, kind, args)
        return e

    def mark(self, e: dict[str, Any], status: str, **args: Any) -> None:
        e["status"] = status
        e[f"ts_{status}"] = now()
        e["args"].update(args)
        self.save()

    def find(self, kind: str, statuses: tuple = OWNED, **match: Any) -> dict[str, Any] | None:
        for e in reversed(self.entries):
            if e["kind"] == kind and e["status"] in statuses and all(e["args"].get(k) == v for k, v in match.items()):
                return e
        return None

    def owns(self, kind: str, **match: Any) -> bool:
        return self.find(kind, OWNED, **match) is not None

    def for_phase(self, pid: str, statuses: tuple = ACTIVE) -> list[dict[str, Any]]:
        return [e for e in self.entries if e["phase"] == pid and e["status"] in statuses]

    def save(self) -> None:
        atomic_write(self.path, "".join(json.dumps(e) + "\n" for e in self.entries), 0o600)


# ---------------------------------------------------------------------------
# 5. context: host, project and container helpers (all journaled)
# ---------------------------------------------------------------------------


class Ctx:
    def __init__(self, cfg: Config, args: argparse.Namespace, interactive: bool):
        self.cfg = cfg
        self.args = args
        self.interactive = interactive
        self.r = Runner(interactive)
        self.state_dir = Path(cfg["host.state_dir"])
        self.state_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.state_dir, 0o700)
        self.state = State(self.state_dir / "state.json")
        self.journal = Journal(self.state_dir / "journal.jsonl")
        self.phase = "host"
        self.name = cfg["container.name"]
        self.project = Path(cfg["project.host_path"])
        self.cproject = cfg["project.container_path"]

    # --- prompts ---

    def confirm(self, question: str, *, default: bool = False, destructive: bool = False) -> bool:
        if self.args.yes:
            return True
        if not self.interactive:
            if destructive:
                raise NeedsInput(f"{question} — refusing in non-interactive mode without --yes")
            return True
        suffix = " [Y/n] " if default else " [y/N] "
        try:
            ans = input(question + suffix).strip().lower()
        except EOFError:
            ans = ""
        return default if not ans else ans in ("y", "yes")

    # --- incus queries (read-only) ---

    def iq(self, path: str) -> Any:
        p = self.r.run(["incus", "query", path], check=False)
        if p.returncode != 0:
            if "not found" in (p.stderr or "").lower():
                return None
            raise CommandError(["incus", "query", path], p.returncode, p.stderr or "")
        return json.loads(p.stdout)

    def instance(self, name: str | None = None) -> dict[str, Any] | None:
        return self.iq(f"/1.0/instances/{name or self.name}")

    def instance_running(self) -> bool:
        inst = self.instance()
        return bool(inst) and inst["status"] == "Running"

    def snapshot_names(self, name: str | None = None) -> list[str]:
        urls = self.iq(f"/1.0/instances/{name or self.name}/snapshots") or []
        return [u.rsplit("/", 1)[-1] for u in urls]

    def volume(self, name: str | None = None) -> dict[str, Any] | None:
        vol = name or self.cfg["postgres.volume"]
        return self.iq(f"/1.0/storage-pools/{self.cfg['container.storage_pool']}/volumes/custom/{vol}")

    def nic_device(self) -> str:
        want = self.cfg["container.nic_device"]
        if want != "auto":
            return want
        inst = self.instance()
        if inst:
            devices = inst["expanded_devices"]
        else:
            devices = {}
            for prof in self.cfg["container.profiles"]:
                devices.update((self.iq(f"/1.0/profiles/{prof}") or {}).get("devices", {}))
        nics = [n for n, d in devices.items() if d.get("type") == "nic"]
        preferred = [n for n in nics if devices[n].get("network") == self.cfg["container.network"]]
        if not (preferred or nics):
            raise PreflightError("no nic device found in the profile(s); set container.nic_device")
        return (preferred or nics)[0]

    def wait_ipv4(self, timeout: int = 90) -> str:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            st = self.iq(f"/1.0/instances/{self.name}/state") or {}
            for iface, net in (st.get("network") or {}).items():
                if iface == "lo":
                    continue
                for a in net.get("addresses", []):
                    if a.get("family") == "inet" and a.get("scope") == "global":
                        return a["address"]
            time.sleep(2)
        raise DevstackError(f"container {self.name} got no IPv4 address within {timeout}s")

    # --- container exec ---

    def cexec(self, script: str, *, user: str | None = None, input: str | None = None,
              stream: bool = False, check: bool = True, secret_input: bool = False,
              secret_output: bool = False, timeout: float | None = None) -> subprocess.CompletedProcess:
        argv = ["incus", "exec", self.name, "--env", "DEBIAN_FRONTEND=noninteractive", "--"]
        if user:
            argv += ["runuser", "-u", user, "--", "env", f"HOME=/home/{user}"]
        argv += ["bash", "-euo", "pipefail", "-c", script]
        return self.r.run(argv, input=input, stream=stream, check=check, secret_input=secret_input,
                          secret_output=secret_output, timeout=timeout)

    def cwrite(self, path: str, content: str, *, mode: str = "0644", owner: str = "root",
               group: str | None = None, secret: bool = False) -> None:
        script = bash(r"""
            path=@@PATH@@; owner=@@OWNER@@; group=@@GROUP@@
            [ -n "$group" ] || group=$(id -gn "$owner")
            umask 077
            t=$(mktemp)
            trap 'rm -f "$t"' EXIT
            cat > "$t"
            install -D -m @@MODE@@ -o "$owner" -g "$group" "$t" "$path"
        """, PATH=path, OWNER=owner, GROUP=group or "", MODE=mode)
        self.cexec(script, input=content, secret_input=secret)

    def cread(self, path: str, *, secret: bool = False) -> str | None:
        p = self.cexec(bash('if [ -f @@P@@ ]; then cat @@P@@; else exit 44; fi', P=path),
                       check=False, secret_output=secret)
        if p.returncode == 44:
            return None
        if p.returncode != 0:
            raise CommandError(["cat", path], p.returncode, "" if secret else p.stdout + p.stderr)
        return p.stdout

    def cpull(self, cpath: str, dest: Path) -> Path:
        """Copy a file out of the container straight onto a host path. Unlike cread this never goes
        through stdout, so a multi-MB SBOM is not captured in memory or logged at debug level."""
        dest.parent.mkdir(parents=True, exist_ok=True)
        self.r.run(["incus", "file", "pull", f"{self.name}{cpath}", str(dest)])
        return dest

    def apt_install(self, *packages: str) -> None:
        self.cexec(bash(r"""
            pkgs=(@@PKGS@@)
            apt-get update
            apt-get install -y --no-install-recommends "${pkgs[@]}"
        """, PKGS=list(packages)), stream=True)

    # --- journaled host changes ---

    def ensure_dir(self, path: Path, mode: int = 0o755) -> None:
        missing = []
        p = path
        while not p.exists():
            missing.append(p)
            p = p.parent
        for d in reversed(missing):
            e = self.journal.add(self.phase, "dir", path=str(d))
            d.mkdir(mode=mode)
            os.chmod(d, mode)
            self.journal.mark(e, "applied")

    def backup_copy(self, path: Path, sudo: bool) -> str:
        bdir = self.state_dir / "backups"
        bdir.mkdir(parents=True, exist_ok=True)
        dest = bdir / f"{dt.datetime.now():%Y%m%d-%H%M%S}-{secrets.token_hex(3)}-{path.name}"
        if os.access(path, os.R_OK):
            shutil.copy2(path, dest)
        else:
            dest.write_text(self.r.run(["cat", path], sudo=True).stdout)
        os.chmod(dest, 0o600)
        return str(dest)

    def write_host_file(self, path: Path, content: str, *, mode: int = 0o644, sudo: bool = False,
                        then_restart: str | None = None) -> None:
        """Write a host file; undo restores the previous file or deletes it."""
        e = self.journal.find("host_file", ACTIVE, path=str(path))
        if e is None:
            backup = self.backup_copy(path, sudo) if path.exists() else None
            e = self.journal.add(self.phase, "host_file", path=str(path), backup=backup, sudo=sudo,
                                 mode=oct(mode), then_restart=then_restart)
        if sudo:
            tmp = self.state_dir / "tmp-upload"
            atomic_write(tmp, content, 0o600)
            try:
                self.r.run(["install", "-m", oct(mode)[2:], "-o", "root", "-g", "root", tmp, path], sudo=True)
            finally:
                tmp.unlink(missing_ok=True)
        else:
            self.ensure_dir(path.parent, 0o700)
            atomic_write(path, content, mode)
        self.journal.mark(e, "applied")

    def set_marked_block(self, path: Path, body: str) -> None:
        """Add/replace this stack's marked block in a shared, user-owned file."""
        marker = f"devstack:{self.cfg['stack.name']}"
        begin, end = f"# >>> {marker} >>>", f"# <<< {marker} <<<"
        existed = path.exists()
        text = path.read_text() if existed else ""
        text = remove_block(text, begin, end)
        block = f"{begin}\n# Managed by devstack; removed by `devstack undo`.\n{body.rstrip()}\n{end}\n"
        new = (text.rstrip("\n") + "\n\n" if text.strip() else "") + block
        if not self.journal.find("marked_block", ACTIVE, path=str(path), begin=begin):
            backup = self.backup_copy(path, False) if existed else None
            e = self.journal.add(self.phase, "marked_block", path=str(path), begin=begin, end=end,
                                 created_file=not existed, backup=backup)
        else:
            e = self.journal.find("marked_block", ACTIVE, path=str(path), begin=begin)
        self.ensure_dir(path.parent, 0o700)
        atomic_write(path, new, (path.stat().st_mode & 0o777) if existed else 0o600)
        self.journal.mark(e, "applied")

    def project_file(self, rel: str, content: str, *, mode: int = 0o644, managed: bool = False) -> bool:
        """Create a project file. Unmanaged: never overwrite. Managed: overwrite our own
        generated file, backing up the previous version for undo. Returns True if written."""
        path = self.project / rel
        if path.exists():
            if not managed:
                log.info("  kept existing %s", rel)
                return False
            if sha256_file(path) == sha256_text(content):
                return False
        self.ensure_dir(path.parent, 0o755)
        own = self.journal.find("project_file", ACTIVE, path=str(path))
        if own is not None and own["phase"] == self.phase:
            e = own  # re-run of the same phase: keep the original backup
        else:
            backup = self.backup_copy(path, False) if path.exists() else None
            e = self.journal.add(self.phase, "project_file", path=str(path), sha256=None, backup=backup)
        atomic_write(path, content, mode)
        self.journal.mark(e, "applied", sha256=sha256_text(content))
        return True

    def track_generated(self, path: Path, *, tree: bool = False) -> None:
        """Record a file/folder created by a tool (pnpm, brotli) so undo can remove it."""
        if tree:
            if not self.journal.find("project_tree", ACTIVE, path=str(path)):
                e = self.journal.add(self.phase, "project_tree", path=str(path))
                self.journal.mark(e, "applied")
        else:
            e = self.journal.add(self.phase, "project_file", path=str(path), sha256=sha256_file(path), backup=None)
            self.journal.mark(e, "applied")

    def ensure_device(self, device: str, dtype: str, props: dict[str, str]) -> None:
        inst = self.instance()
        assert inst is not None
        if device in inst["devices"]:
            log.info("  device %s already present", device)
            return
        e = self.journal.add(self.phase, "incus_device", instance=self.name, device=device)
        self.r.run(["incus", "config", "device", "add", self.name, device, dtype,
                    *[f"{k}={v}" for k, v in props.items()]])
        self.journal.mark(e, "applied")

    def set_instance_config(self, key: str, value: str) -> None:
        e = self.journal.add(self.phase, "incus_config", instance=self.name, key=key)
        self.r.run(["incus", "config", "set", self.name, f"{key}={value}"])
        self.journal.mark(e, "applied")

    def stop_instance(self) -> None:
        if self.r.run(["incus", "stop", self.name, "--timeout", "60"], check=False).returncode != 0:
            self.r.run(["incus", "stop", self.name, "--force"], check=False)

    # --- template values ---

    def tvars(self) -> dict[str, Any]:
        c = self.cfg
        return {
            "STACK": c["stack.name"],
            "PKG_NAME": c["stack.name"],
            "DEV_HOST": c.dev_host,
            "SITE_HOSTNAME": c["site.hostname"],
            "APP_BIND": c["app.bind"],
            "APP_PORT": c["app.port"],
            "ENTRY": c["app.entry"],
            "PROJECT": self.cproject,
            "SERVICE": c["app.service_name"],
            "SSH_ALIAS": c["ssh.host_alias"],
            "USER": c["container.user"],
            "NODE_BIN": "/usr/local/bin/node",
            "TOKEN_ENV": f"{c['secrets.dir']}/{c['secrets.token_file']}",
            "PG_ENV": f"{c['secrets.dir']}/{c['postgres.env_file']}",
            "PG_PORT": c["postgres.port"],
            "IMAGE": c["container.image"],
            "NODE_VERSION": c["node.version"],
            "PNPM_VERSION": c["node.pnpm_version"],
            "PG_VERSION": c["postgres.version"],
            "APP_USER": c["isolation.app_user"],
            "RUNNER_USER": c["isolation.runner_user"],
            "DATA_GROUP": c["isolation.data_group"],
            "PROFILE": c["app.profile"],
            "DATA_LINES": app_data_lines(c),
            "SBOM_DIR": c["sbom.dir"],
        }


def app_data_dir(c: Config) -> str | None:
    """The app's StateDirectory (on the data volume or host folder), or None for app.data = "none"."""
    return None if c["app.data"] == "none" else f"/var/lib/{c['isolation.app_user']}"


def app_data_lines(c: Config) -> str:
    if c["app.data"] == "none":
        return '# app.data = "none": no writable folder.'
    return "\n".join([
        f"# App data: {app_data_dir(c)} (persistent; $STATE_DIRECTORY). o+x so runners can reach incoming/;",
        "# files below it are 0640 and folders 2750 (UMask), so nobody else can read them.",
        f"StateDirectory={c['isolation.app_user']}",
        "StateDirectoryMode=2751",
    ])


def isolation_ids(c: Config) -> dict[str, int]:
    base = c["isolation.system_uid_base"]
    return {"app_uid": base, "runner_uid": base + 1, "data_gid": base + 2, "dev_gid": base + 3}


def runner_unit(c: Config, r: dict[str, Any]) -> str:
    """Unit base name of a runner: <unit>.socket + <unit>@.service."""
    return f"{c['stack.name']}-{r['name']}"


def remove_block(text: str, begin: str, end: str) -> str:
    pattern = re.compile(rf"\n*{re.escape(begin)}\n.*?{re.escape(end)}\n?", re.S)
    return pattern.sub("\n", text).lstrip("\n") if begin in text else text


# --- undo actions (idempotent; return the new journal status) ---

UndoFn = Callable[[Ctx, dict[str, Any], "UndoOpts"], str]
UNDO: dict[str, UndoFn] = {}


@dataclasses.dataclass
class UndoOpts:
    purge_data: bool = False
    whole: bool = False  # the container is going to be deleted anyway


def undoer(kind: str) -> Callable[[UndoFn], UndoFn]:
    def deco(fn: UndoFn) -> UndoFn:
        UNDO[kind] = fn
        return fn
    return deco


def _norm_abs(path: Any) -> Path | None:
    if not isinstance(path, str) or not path.startswith("/"):
        return None
    return Path(os.path.normpath(path))


def _within(p: Path, base: Path) -> bool:
    return p == base or base in p.parents


def undo_path_ok(what: str, path: Any, expected: list[str], prefixes: list[str | Path]) -> bool:
    """The journal is just a file: before a privileged rm/install/rmtree, check that the stored path is
    one the current config would produce, or sits under a folder devstack is allowed to touch."""
    p = _norm_abs(path)
    ok = p is not None and (
        any(p == _norm_abs(e) for e in expected) or any(_within(p, Path(os.path.normpath(str(b)))) for b in prefixes))
    if not ok:
        log.warning("kept %s: %r is not a path devstack would manage here (edited journal?)", what, path)
    return ok


def undo_backup_ok(ctx: Ctx, backup: Any) -> bool:
    p = _norm_abs(backup)
    ok = p is not None and _within(p, ctx.state_dir / "backups")
    if not ok:
        log.warning("kept: backup %r is outside %s (edited journal?)", backup, ctx.state_dir / "backups")
    return ok


@undoer("dir")
def _u_dir(ctx: Ctx, a: dict, o: UndoOpts) -> str:
    p = Path(a["path"])
    try:
        p.rmdir()
    except FileNotFoundError:
        pass
    except OSError:
        log.warning("kept %s (not empty)", p)
        return "kept"
    return "undone"


@undoer("host_file")
def _u_host_file(ctx: Ctx, a: dict, o: UndoOpts) -> str:
    path, sudo = a["path"], a["sudo"]
    c = ctx.cfg
    if not undo_path_ok("host file", path, [c["dns.dnsmasq_file"], c["ssh.known_hosts_file"]],
                        [c["dns.dnsmasq_dir"], home_dir() / ".ssh"]):
        return "kept"
    if a.get("backup") and not undo_backup_ok(ctx, a["backup"]):
        return "kept"
    path = os.path.normpath(path)
    if a.get("backup"):
        mode = a.get("mode", "0o644")[2:]
        if sudo:
            ctx.r.run(["install", "-m", mode, "-o", "root", "-g", "root", a["backup"], path], sudo=True)
        else:
            shutil.copy2(a["backup"], path)
        log.info("  restored %s", path)
    else:
        if sudo:
            ctx.r.run(["rm", "-f", path], sudo=True)
        else:
            Path(path).unlink(missing_ok=True)
        log.info("  removed %s", path)
    if a.get("then_restart"):
        ctx.r.run(["systemctl", "restart", a["then_restart"]], sudo=True, check=False)
    return "undone"


@undoer("marked_block")
def _u_marked_block(ctx: Ctx, a: dict, o: UndoOpts) -> str:
    p = Path(a["path"])
    if p.exists():
        text = remove_block(p.read_text(), a["begin"], a["end"])
        if a.get("created_file") and not text.strip():
            p.unlink()
        else:
            atomic_write(p, text, p.stat().st_mode & 0o777)
        log.info("  removed devstack block from %s", p)
    return "undone"


@undoer("project_file")
def _u_project_file(ctx: Ctx, a: dict, o: UndoOpts) -> str:
    if not undo_path_ok("project file", a["path"], [], [ctx.project]) or (
            a.get("backup") and not undo_backup_ok(ctx, a["backup"])):
        return "kept"
    p = Path(os.path.normpath(a["path"]))
    if not p.exists():
        return "undone"
    if a.get("sha256") and sha256_file(p) != a["sha256"]:
        log.warning("kept %s: changed since devstack wrote it", p)
        return "kept"
    if a.get("backup"):
        shutil.copy2(a["backup"], p)
    else:
        p.unlink()
    return "undone"


@undoer("project_tree")
def _u_project_tree(ctx: Ctx, a: dict, o: UndoOpts) -> str:
    norm = _norm_abs(a["path"])
    if norm is None or norm == Path(os.path.normpath(ctx.project)) or not undo_path_ok(
            "project folder", a["path"], [], [ctx.project]):
        return "kept"
    p = norm
    if p.exists():
        shutil.rmtree(p)
        log.info("  removed %s", p)
    return "undone"


@undoer("ssh_key")
def _u_ssh_key(ctx: Ctx, a: dict, o: UndoOpts) -> str:
    if not undo_path_ok("ssh key", a["path"], [ctx.cfg["ssh.key_path"]], [home_dir() / ".ssh"]):
        return "kept"
    keyfile = os.path.normpath(a["path"])
    for p in (Path(keyfile), Path(keyfile + ".pub")):
        p.unlink(missing_ok=True)
    log.info("  removed ssh key %s", a["path"])
    return "undone"


@undoer("incus_instance")
def _u_instance(ctx: Ctx, a: dict, o: UndoOpts) -> str:
    if ctx.instance(a["name"]) is not None:
        ctx.r.run(["incus", "delete", "--force", a["name"]])
        log.info("  deleted container %s (and its snapshots)", a["name"])
    return "undone"


@undoer("incus_device")
def _u_device(ctx: Ctx, a: dict, o: UndoOpts) -> str:
    inst = ctx.instance(a["instance"])
    if o.whole or inst is None or a["device"] not in inst["devices"]:
        return "undone"
    ctx.r.run(["incus", "config", "device", "remove", a["instance"], a["device"]])
    return "undone"


@undoer("incus_config")
def _u_config(ctx: Ctx, a: dict, o: UndoOpts) -> str:
    if not o.whole and ctx.instance(a["instance"]) is not None:
        ctx.r.run(["incus", "config", "unset", a["instance"], a["key"]], check=False)
    return "undone"


@undoer("incus_snapshot")
def _u_snapshot(ctx: Ctx, a: dict, o: UndoOpts) -> str:
    name, snap = a["instance"], a["snapshot"]
    if o.whole or ctx.instance(name) is None:
        return "undone"
    if snap not in ctx.snapshot_names(name):
        log.warning("snapshot %s/%s is gone; container state not rolled back", name, snap)
        return "undone"
    log.info("  restoring %s to snapshot %s", name, snap)
    ctx.stop_instance()
    ctx.r.run(["incus", "snapshot", "restore", name, snap], stream=True)
    ctx.r.run(["incus", "start", name])
    ctx.r.run(["incus", "snapshot", "delete", name, snap])
    return "undone"


@undoer("incus_volume")
def _u_volume(ctx: Ctx, a: dict, o: UndoOpts) -> str:
    if not o.purge_data:
        log.info("  kept data volume %s/%s (use --purge-data to delete it)", a["pool"], a["volume"])
        return "kept"
    if a.get("adopted"):
        log.warning("kept adopted volume %s/%s; delete it yourself: incus storage volume delete %s %s",
                    a["pool"], a["volume"], a["pool"], a["volume"])
        return "undone"
    vol = ctx.iq(f"/1.0/storage-pools/{a['pool']}/volumes/custom/{a['volume']}")
    if vol is not None:
        used_by = vol.get("used_by") or []
        if o.whole and f"/1.0/instances/{ctx.name}" in used_by:
            # A whole undo leaves devices alone (the container goes anyway), so the volume is still
            # attached here. cmd_undo's final pass deletes it once base has deleted the container.
            log.info("  data volume %s/%s: deleted after the container", a["pool"], a["volume"])
            return "kept"
        if used_by:
            raise DevstackError(f"volume {a['pool']}/{a['volume']} is still used by {', '.join(used_by)}; "
                                "detach it there first, then re-run")
        ctx.r.run(["incus", "storage", "volume", "delete", a["pool"], a["volume"]])
        log.info("  deleted data volume %s/%s", a["pool"], a["volume"])
    return "undone"


@undoer("incus_acl")
def _u_acl(ctx: Ctx, a: dict, o: UndoOpts) -> str:
    if a.get("name") != ctx.cfg["network.acl_name"]:
        log.warning("kept network ACL %r: not the ACL this config manages (edited journal?)", a.get("name"))
        return "kept"
    inst = ctx.instance(a["instance"])
    if inst is not None and a["nic"] in inst["devices"]:
        for key in ACL_NIC_KEYS:  # detach first: incus refuses to delete an ACL in use
            if key in inst["devices"][a["nic"]]:
                ctx.r.run(["incus", "config", "device", "unset", a["instance"], a["nic"], key], check=False)
    if ctx.iq(f"/1.0/network-acls/{a['name']}") is not None:
        ctx.r.run(["incus", "network", "acl", "delete", a["name"]])
        log.info("  deleted network ACL %s", a["name"])
    return "undone"


@undoer("host_ca")
def _u_host_ca(ctx: Ctx, a: dict, o: UndoOpts) -> str:
    if not undo_path_ok("host CA", a["path"], [ctx.cfg["tls.host_ca_file"]], ["/usr/local/share/ca-certificates"]):
        return "kept"
    ctx.r.run(["rm", "-f", os.path.normpath(a["path"])], sudo=True)
    ctx.r.run(["update-ca-certificates", "--fresh"], sudo=True, stream=True)
    log.info("  removed CA %s from the host trust store", a["path"])
    return "undone"


@undoer("nss_cert")
def _u_nss(ctx: Ctx, a: dict, o: UndoOpts) -> str:
    ctx.r.run(["certutil", "-D", "-d", f"sql:{a['db']}", "-n", a["nickname"]], check=False)
    return "undone"


@undoer("host_pkg")
def _u_host_pkg(ctx: Ctx, a: dict, o: UndoOpts) -> str:
    log.info("  host packages %s stay installed (remove manually if unwanted)", " ".join(a["packages"]))
    return "kept"


@undoer("host_tool")
def _u_host_tool(ctx: Ctx, a: dict, o: UndoOpts) -> str:
    """A pinned binary devstack downloaded itself (grype, gitleaks). Unlike host_pkg this one is ours
    alone, so it goes away again; its cache folder (the vulnerability database) is left like other caches."""
    if not undo_path_ok("host tool", a["path"], [],
                        [ctx.state_dir, ctx.cfg["sbom.db_dir"], ctx.cfg["leaks.tool_dir"]]):
        return "kept"
    Path(os.path.normpath(a["path"])).unlink(missing_ok=True)
    log.info("  removed %s", a["path"])
    return "undone"


# ---------------------------------------------------------------------------
# 6. phases
# ---------------------------------------------------------------------------


class Phase:
    id = ""
    title = ""
    layer = ""
    snapshot = True  # take a container snapshot before applying

    def enabled(self, cfg: Config) -> bool:
        return True

    def describe(self, ctx: Ctx) -> list[str]:
        raise NotImplementedError

    def apply(self, ctx: Ctx) -> None:
        raise NotImplementedError

    def verify(self, ctx: Ctx) -> None:
        raise NotImplementedError


def expect(cond: bool, msg: str) -> None:
    if not cond:
        raise VerifyError(msg)


def host_curl(ctx: Ctx, url: str, *extra: str) -> subprocess.CompletedProcess:
    return ctx.r.run(["curl", "-sS", "--max-time", "15", *extra, url], check=False)


# The container user's root rights (container.sudo), applied in base and again in isolation
# (idempotent), so `up --redo isolation` also takes sudo away from an older container's user.
SUDO_APPLY = r"""
user=@@USER@@; mode=@@MODE@@; dropin=@@DROPIN@@
install_sudoers() {  # line file: validate before it can take effect
  local t
  t=$(mktemp)
  printf '%s\n' "$1" > "$t"
  visudo -qcf "$t"
  install -m 0440 -o root -g root "$t" "$2"
  rm -f "$t"
}
rm -f /etc/sudoers.d/90-devstack "$dropin"
if [ "$mode" = full ]; then
  usermod -aG sudo "$user"
  install_sudoers "$user ALL=(ALL) NOPASSWD:ALL" /etc/sudoers.d/90-devstack
else
  if id -nG "$user" | tr ' ' '\n' | grep -qx sudo; then gpasswd -d "$user" sudo >/dev/null; fi
fi
if [ "$mode" = limited ]; then
  install_sudoers "$user ALL=(root) NOPASSWD: /usr/local/sbin/devstack-sync" "$dropin"
fi
"""

BASE_PROVISION = r"""
user=@@USER@@; uid=@@UID@@
for i in $(seq 1 60); do getent hosts deb.debian.org >/dev/null && break; sleep 1; done
getent hosts deb.debian.org >/dev/null || { echo "container has no working DNS/network after 60s" >&2; exit 1; }
apt-get update
apt-get install -y --no-install-recommends openssh-server sudo curl ca-certificates gnupg gpgv xz-utils iproute2 procps
if id -u "$user" >/dev/null 2>&1; then
  [ "$(id -u "$user")" = "$uid" ] || { echo "user $user exists with uid $(id -u "$user"), expected $uid" >&2; exit 1; }
else
  if getent passwd "$uid" >/dev/null; then
    echo "uid $uid is already used by $(getent passwd "$uid" | cut -d: -f1) in the container" >&2; exit 1
  fi
  if ! getent group "$user" >/dev/null; then
    if getent group "$uid" >/dev/null; then groupadd "$user"; else groupadd --gid "$uid" "$user"; fi
  fi
  useradd --create-home --uid "$uid" --gid "$user" --shell /bin/bash "$user"
fi
# Read service logs (journalctl -u ...) without sudo.
usermod -aG systemd-journal "$user"
"""

SSHD_APPLY = r"""
sshd -t
systemctl enable ssh >/dev/null 2>&1 || true
systemctl restart ssh
"""

AUTHORIZED_KEY = r"""
user=@@USER@@
home=$(getent passwd "$user" | cut -d: -f6)
group=$(id -gn "$user")
key=$(cat)
install -d -m 700 -o "$user" -g "$group" "$home/.ssh"
f="$home/.ssh/authorized_keys"
touch "$f"
grep -qxF "$key" "$f" || printf '%s\n' "$key" >> "$f"
chown "$user:$group" "$f"
chmod 600 "$f"
"""

SYFT_INSTALL = r"""
ver=@@VER@@; sha_amd64=@@SHA_AMD64@@; sha_arm64=@@SHA_ARM64@@
arch=$(dpkg --print-architecture)
case "$arch" in
  amd64) sha=$sha_amd64 ;;
  arm64) sha=$sha_arm64 ;;
  *) echo "no pinned syft build for architecture $arch" >&2; exit 1 ;;
esac
if [ -x /usr/local/bin/syft ] && /usr/local/bin/syft version 2>/dev/null | grep -q "^Version:[[:space:]]*$ver$"; then
  echo "$ver"; exit 0
fi
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
tar="syft_${ver}_linux_${arch}.tar.gz"
curl -fsSLO "https://github.com/anchore/syft/releases/download/v$ver/$tar"
echo "$sha  $tar" | sha256sum -c -
tar -xzf "$tar" syft
install -m 0755 -o root -g root syft /usr/local/bin/syft
echo "$ver"
"""

NODE_INSTALL = r"""
ver=@@VER@@; prefix=@@PREFIX@@; keyring_commit=@@KEYRING_COMMIT@@; keyring_sha=@@KEYRING_SHA@@
case "$(dpkg --print-architecture)" in
  amd64) arch=x64 ;;
  arm64) arch=arm64 ;;
  *) echo "unsupported architecture $(dpkg --print-architecture)" >&2; exit 1 ;;
esac
name="node-v$ver-linux-$arch"
dir="$prefix/$name"
if [ ! -x "$dir/bin/node" ]; then
  work=$(mktemp -d)
  trap 'rm -rf "$work"' EXIT
  cd "$work"
  curl -fsSLo nodejs-keyring.kbx "https://github.com/nodejs/release-keys/raw/$keyring_commit/gpg/pubring.kbx"
  echo "$keyring_sha  nodejs-keyring.kbx" | sha256sum -c -
  curl -fsSLO "https://nodejs.org/dist/v$ver/SHASUMS256.txt.asc"
  curl -fsSLO "https://nodejs.org/dist/v$ver/$name.tar.xz"
  gpgv --keyring=./nodejs-keyring.kbx --output SHASUMS256.txt < SHASUMS256.txt.asc
  grep " $name.tar.xz\$" SHASUMS256.txt | sha256sum -c -
  tar -xf "$name.tar.xz"
  install -d "$prefix"
  mv "$name" "$prefix/"
fi
for b in node npm npx corepack; do ln -sf "$dir/bin/$b" "/usr/local/bin/$b"; done
COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack enable --install-directory /usr/local/bin pnpm
echo "$dir/bin/node"
"""


def ensure_syft(ctx: Ctx) -> str:
    """Install the pinned syft in the container if it is not already there. Called from base, and
    again from the sbom commands so that a container built before syft existed picks it up without
    a full `up --redo base`."""
    log.info("  installing syft %s (sha256 verified)", SYFT_VERSION)
    out = ctx.cexec(bash(SYFT_INSTALL, VER=SYFT_VERSION,
                         SHA_AMD64=SYFT_SHA256["amd64"], SHA_ARM64=SYFT_SHA256["arm64"]), stream=True)
    ver = out.stdout.strip().splitlines()[-1] if out.stdout.strip() else SYFT_VERSION
    ctx.state.set_fact("syft_version", ver)
    return ver


# Patching the container's Debian packages. Host-side on purpose: DESIGN 1.3 says
# security-relevant changes are applied from the host, and keeping it here means the login user
# gains no new capability at all -- devstack-sync keeps its fixed verb set.
#
# Three guards, each protecting a policy that a plain `apt-get upgrade` would weaken:
#  1. --force-confold. /etc/caddy/Caddyfile is a *caddy package conffile* and is where devstack
#     puts `admin unix//run/caddy/admin.sock`. Without this, a caddy upgrade could restore the
#     vendor file and put the admin API back on TCP:2019. (The same flag is already used for the
#     Postgres install.) It is the only package-owned file devstack writes: the sshd and caddy
#     unit settings are drop-ins and the rest sit on paths no package owns.
#  2. A policy-rc.d that allows only units already active. `apt-get upgrade` must be able to
#     restart what it patches -- otherwise the new binary is on disk while the vulnerable process
#     keeps running -- but a service that exists and is stopped, or one that arrives with the
#     upgrade, must stay down. That keeps "a long-running root service needs the host's approval".
#  3. A before/after diff of unit *files*, not of packages: an already-installed package can gain
#     a unit in a new version. Anything new is masked, and nothing is ever unmasked.
APT_UPGRADE = r"""
upgrade=@@UPGRADE@@
policy=/usr/sbin/policy-rc.d
unit_dirs="/lib/systemd/system /usr/lib/systemd/system /etc/systemd/system"
units_now() {
  find $unit_dirs -maxdepth 1 \( -name '*.service' -o -name '*.socket' -o -name '*.timer' \
    -o -name '*.path' \) -printf '%f\n' 2>/dev/null | sort -u
}
pkgs_now() { dpkg-query -W -f='${Package} ${Version}\n' 2>/dev/null | sort; }

apt-get update -q
if [ "$upgrade" != yes ]; then
  echo "--- would upgrade (simulation) ---"
  apt-get -s upgrade | sed -n '/^The following packages will be upgraded/,/^[0-9]* upgraded/p'
  apt-get -s upgrade | sed -n '/kept back/,/^$/p'
  exit 0
fi

units_before=$(units_now)
pkgs_before=$(pkgs_now)
# Only what is running now may be acted on by a maintainer script.
active=$(systemctl list-units --state=active --no-legend --plain \
  --type=service,socket,timer,path 2>/dev/null | awk '{print $1}' | sed 's/\.[a-z]*$//' | sort -u)
policy_saved=
if [ -e "$policy" ]; then policy_saved=$(mktemp); cp -a "$policy" "$policy_saved"; fi
restore_policy() { if [ -n "$policy_saved" ]; then mv -f "$policy_saved" "$policy"; else rm -f "$policy"; fi; }
trap restore_policy EXIT
{
  echo '#!/bin/sh'
  echo '# devstack: during an upgrade only already-running services may be acted on.'
  echo 'case "$1" in'
  for a in $active; do printf '  %s) exit 0 ;;\n' "$a"; done
  echo '  *) exit 101 ;;'
  echo 'esac'
} >"$policy"
chmod 755 "$policy"

# 'upgrade', never full-upgrade: it must not remove a package to satisfy an upgrade.
apt-get upgrade -y -q --no-install-recommends -o Dpkg::Options::=--force-confold
restore_policy
trap - EXIT

echo "--- upgraded ---"
comm -13 <(printf '%s\n' "$pkgs_before") <(printf '%s\n' "$(pkgs_now)") || true
echo "--- held back ---"
apt-get -s upgrade | sed -n '/kept back/,/^$/p'
echo "--- new units (masked: a new root service needs the host, not an apt transaction) ---"
for u in $(comm -13 <(printf '%s\n' "$units_before") <(printf '%s\n' "$(units_now)")); do
  if systemctl mask --now "$u" >/dev/null 2>&1; then echo "masked $u"; else echo "could not mask $u" >&2; fi
done
echo "--- active services ---"
systemctl list-units --state=active --no-legend --plain --type=service 2>/dev/null | awk '{print $1}'
"""


def cmd_upgrade(ctx: Ctx, args: argparse.Namespace) -> int:
    """Patch the container's Debian packages, from the host.

    The alternative is a rebuild (`destroy` then `up`), which picks up a fresh base image and is
    often the better answer for a disposable dev container; `sbom scan` names both."""
    c = ctx.cfg
    with Lock(ctx):
        if ctx.state.status("base") != "done":
            raise DevstackError("the base phase is not done: run `devstack up --to base` first")
        if not ctx.instance_running():
            raise DevstackError(f"container {ctx.name} is not running")
        if args.dry_run:
            log.info("simulating an upgrade in %s (nothing is changed)", ctx.name)
            ctx.cexec(bash(APT_UPGRADE, UPGRADE="no"), stream=True, timeout=900)
            return 0
        # A plain, unjournaled snapshot: manual names are not undo points, and only the
        # snapshots.prefix namespace is reserved, so this neither confuses undo nor trips preflight.
        if c["snapshots.mode"] != "off" and not args.no_snapshot:
            snap = f"pre-upgrade-{dt.datetime.now():%Y%m%d-%H%M%S}"
            log.info("snapshot %s/%s (revert: incus snapshot restore %s %s)", ctx.name, snap, ctx.name, snap)
            ctx.r.run(["incus", "snapshot", "create", ctx.name, snap], stream=True)
        log.info("upgrading Debian packages in %s", ctx.name)
        ctx.cexec(bash(APT_UPGRADE, UPGRADE="yes"), stream=True, timeout=1800)
        if c["sbom.enabled"]:
            try:
                generate_sboms(ctx)
            except DevstackError as e:
                log.warning("SBOM not regenerated (%s); run `./devstack sbom generate`", e)
        log.info("")
        log.info("done. `./devstack sbom scan` to re-check; anything still reported with a fix "
                 "available needs a newer base image (`destroy` then `up`).")
    return 0


def rootfs_excludes(ctx: Ctx) -> list[str]:
    """Paths the container rootfs scan must not walk.

    /proc, /sys, /dev, /run are kernel or volatile. /tmp, /var/tmp, /var/cache, /var/log are
    scratch. /home and /root are excluded for privacy as much as size: container.user is settable to
    the host login name, and a component named after a file under it would then publish that name in
    a committed file. The project folder and every extra mount are host folders shared in -- their
    contents are
    not this container's inventory, and the project gets its own document. The Postgres volume and
    the app's state directory are data, not packages."""
    rel = lambda path: "./" + str(path).lstrip("/")
    out = ["./proc", "./sys", "./dev", "./run", "./tmp", "./var/tmp", "./var/cache", "./var/log",
           "./home", "./root", "./var/lib/postgresql", rel(ctx.cproject)]
    out += [rel(m["path"]) for m in ctx.cfg["container.mounts"]]
    out.append(rel(f"/var/lib/{ctx.cfg['isolation.app_user']}"))
    return sorted(dict.fromkeys(out))


def app_excludes(ctx: Ctx) -> list[str]:
    """The project scan covers dependency manifests, not the app's own content or our own output."""
    out = ["./.git", "./" + ctx.cfg["sbom.dir"].strip("/"), "./static", "./error", "./infra"]
    if ctx.cfg["sbom.app_source"] == "lockfile" and (ctx.project / "pnpm-lock.yaml").exists():
        out.append("./node_modules")  # the lockfile is authoritative and far more stable
    return sorted(dict.fromkeys(out))


def syft_argv(ctx: Ctx, kind: str) -> list[str]:
    """The syft command line for one document. --source-name is what keeps metadata.component.name
    a fixed string instead of the scan path, which removes most of the churn before the normalizer
    ever sees the document."""
    c = ctx.cfg
    target, excludes, version = {
        "container": (f"dir:{'/'}", rootfs_excludes(ctx), c["container.image"]),
        "app": (f"dir:{ctx.cproject}", app_excludes(ctx), ""),
    }[kind]
    argv = ["syft", "scan", target, "-q",
            "--source-name", f"{c['stack.name']}-{kind}", "--source-version", version,
            "-o", f"cyclonedx-json={SBOM_DIR_CONTAINER}/{kind}.cdx.json"]
    if kind == "container":
        argv += ["--parallelism", "2"]  # a shared dev box should stay usable while this runs
    for e in excludes:
        argv += ["--exclude", e]
    return argv


def mount_props(m: dict[str, Any]) -> dict[str, str]:
    """incus disk-device properties for one [[container.mounts]] entry."""
    props = {"source": m["source"], "path": m["path"], "shift": str(m.get("shift", True)).lower()}
    if m.get("readonly"):
        props["readonly"] = "true"
    return props


def pending_mounts(ctx: Ctx) -> list[dict[str, Any]]:
    """[[container.mounts]] entries missing on a container whose base phase is already done.

    Mounts are otherwise only added by `base`, which `up` skips once done; this lets a
    mount added to the config later reach the existing container without a rebuild."""
    if ctx.state.status("base") != "done":
        return []
    inst = ctx.instance()
    if inst is None:
        return []
    return [m for m in ctx.cfg["container.mounts"] if m["name"] not in inst["devices"]]


def mount_drift(ctx: Ctx, inst: dict[str, Any]) -> list[str]:
    """Configured mounts whose device on the container has different properties."""
    out = []
    for m in ctx.cfg["container.mounts"]:
        dev = inst["devices"].get(m["name"])
        if dev is None:
            continue
        want = {**mount_props(m), "type": "disk"}
        have = {"readonly": "false", "shift": "false", **dev}
        want.setdefault("readonly", "false")
        diff = [k for k in want if have.get(k) != want[k]]
        if diff:
            out.append(f"container.mounts '{m['name']}': device on {ctx.name} differs in {', '.join(diff)} "
                       f"(devstack does not change existing devices; to apply: incus config device remove "
                       f"{ctx.name} {m['name']}, then devstack up)")
    return out


def readonly_drift(ctx: Ctx, inst: dict[str, Any]) -> list[str]:
    """Read-only devices present on the container with other properties than the config produces."""
    out = []
    for dev, rel, props in readonly_devices(ctx):
        have = inst["devices"].get(dev)
        if have is not None and any(have.get(k) != v for k, v in props.items()):
            out.append(f"device '{dev}' on {ctx.name} is not the read-only mount of {ctx.project / rel} "
                       f"devstack expects (to fix: incus config device remove {ctx.name} {dev}, then devstack up)")
    return out


def is_git_path(rel: str) -> bool:
    rel = PurePosixPath(rel).as_posix()
    return rel == ".git" or rel.startswith(".git/")


GIT_DEVICE = "git"  # the project's whole .git, always read-only in the container
# Repo config keys under which git runs a command or loads config from elsewhere. A review aid for a .git the
# container could write until now, not a complete list.
GIT_EXEC_KEY = re.compile(
    r"core\.(fsmonitor|hookspath|sshcommand|editor|pager|askpass|gitproxy|worktree)|sequence\.editor|"
    r"diff\.external|(diff|filter|merge)\..+\.(textconv|command|clean|smudge|process|driver)|"
    r"credential\.(.+\.)?helper|gpg\.(.+\.)?program|include\.path|includeif\..+\.path|alias\..+|pager\..+")


def readonly_extra(c: Config) -> list[str]:
    """project.readonly_paths minus entries inside .git (covered by the whole-.git device), shallowest
    first so a nested entry mounts on top of its parent."""
    rels = {PurePosixPath(r).as_posix() for r in c["project.readonly_paths"]}
    return sorted((r for r in rels if not is_git_path(r)), key=lambda r: (r.count("/"), r))


def ro_device(rel: str) -> str:
    """Device name for one read-only path, stable per path. Numbered by position, removing an entry
    made the next entry's device look present already, so its path was never mounted."""
    return GIT_DEVICE if rel == ".git" else "ro-" + hashlib.sha256(rel.encode()).hexdigest()[:12]


def readonly_devices(ctx: Ctx) -> list[tuple[str, str, dict[str, str]]]:
    """(device, relative path, disk props): the whole .git first, then each extra project.readonly_paths entry."""
    return [(ro_device(rel), rel, {"source": str(ctx.project / rel), "path": f"{ctx.cproject}/{rel}",
                                   "readonly": "true", "shift": "true"})
            for rel in [".git", *readonly_extra(ctx.cfg)]]


def git_dir_problem(project: Path) -> str | None:
    """Why the project's .git can't be the read-only mount devstack needs, if it can't."""
    g = project / ".git"
    if g.is_symlink() or (g.exists() and not g.is_dir()):
        return (f"{g} is not a folder (a worktree, submodule or symlink): devstack needs a plain repository "
                "whose .git is inside the project, so it can mount it read-only in the container")
    return None


def ensure_git_repo(ctx: Ctx) -> None:
    """git is required: the host runs it on the project, so the container may only read .git. Make sure
    there is one, and that the host's git ignores replace refs (an entry in refs/replace/ swaps what
    `git log` and `git diff` show for an object, so a reviewed commit could differ from the pushed one).
    Neither is undone: the repository is the user's."""
    if prob := git_dir_problem(ctx.project):
        raise DevstackError(prob)
    if not (ctx.project / ".git").exists():
        ctx.r.run(["git", "init", "-q", ctx.project])
        log.info("  git init %s (on the host)", ctx.project)
    # --file: only this file; no repository discovery, no includes followed
    ctx.r.run(["git", "config", "--file", ctx.project / ".git" / "config", "core.useReplaceRefs", "false"])


def git_history_findings(project: Path) -> list[str]:
    """Files in .git that change which history or objects the host's git shows, without changing a commit."""
    g, out = project / ".git", []
    replace = g / "refs" / "replace"
    refs = sorted(p.relative_to(g).as_posix() for p in replace.rglob("*") if p.is_file()) if replace.is_dir() else []
    if (g / "packed-refs").is_file():
        refs += [w[1] for w in (ln.split() for ln in (g / "packed-refs").read_text(errors="replace").splitlines())
                 if len(w) == 2 and w[1].startswith("refs/replace/")]
    if refs:
        out.append(f"replace refs {', '.join(refs[:5])}{', ...' if len(refs) > 5 else ''} (inert while "
                   "core.useReplaceRefs = false; remove them with `git replace -d`)")
    for rel in ("info/grafts", "objects/info/alternates", "objects/info/http-alternates"):
        f = g / rel
        if f.is_file() and f.read_text(errors="replace").strip():
            out.append(f".git/{rel} changes which history or objects git uses: delete it unless you made it")
    return out


def git_exec_findings(ctx: Ctx) -> list[str]:
    """Repo config keys and hooks under which the host's git runs commands."""
    g, out = ctx.project / ".git", []
    p = ctx.r.run(["git", "config", "--file", g / "config", "--null", "--list"], check=False)
    keys = sorted({kv.split("\n", 1)[0] for kv in (p.stdout or "").split("\0") if kv})
    if hits := [k for k in keys if GIT_EXEC_KEY.fullmatch(k)]:
        out.append(f".git/config sets {', '.join(hits)}: each runs a command or loads other config on the host")
    hooks = sorted(h.name for h in (g / "hooks").iterdir()
                   if h.is_file() and not h.name.endswith(".sample")) if (g / "hooks").is_dir() else []
    if hooks:
        out.append(f".git/hooks has {', '.join(hooks)}: the host's git runs these")
    return out


def nested_git(project: Path, limit: int = 20) -> list[str]:
    """`.git` folders or files below the project root (node_modules skipped). The container can write
    them, and the host's git uses one -- its config, hooks and fsmonitor included -- whenever it runs in
    that folder, e.g. an editor scanning subfolders for repositories."""
    found: list[str] = []
    for root, dirs, files in os.walk(project):
        here = Path(root)
        if here != project and (".git" in dirs or ".git" in files):
            found.append((here / ".git").relative_to(project).as_posix())
            if len(found) >= limit:
                break
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules")]
    return sorted(found)


def stale_readonly(ctx: Ctx, inst: dict[str, Any]) -> list[tuple[str, str]]:
    """(device, container path) of read-only devices on the container that the config no longer produces:
    ro1..roN from older devstack (.git/hooks and .git/config among them, now covered by the whole .git)
    and entries removed from project.readonly_paths. Read from the container, not the journal: undoing a
    phase restores a snapshot, and with it the devices the container had when it was taken. The names
    are reserved (container.mounts can't use them), and only those inside the project mount count."""
    want = {dev for dev, _, _ in readonly_devices(ctx)}
    return [(dev, d.get("path", "")) for dev, d in sorted(inst["devices"].items())
            if RO_DEVICE.fullmatch(dev) and dev not in want and d.get("path", "").startswith(f"{ctx.cproject}/")]


def missing_readonly(ctx: Ctx, inst: dict[str, Any]) -> list[tuple[str, str, dict[str, str]]]:
    """Read-only devices to add: .git always (base `git init`s it first), other paths once they exist."""
    return [d for d in readonly_devices(ctx)
            if d[0] not in inst["devices"] and (d[1] == ".git" or (ctx.project / d[1]).exists())]


def readonly_changes(ctx: Ctx) -> tuple[list[tuple[str, str]], list[tuple[str, str, dict[str, str]]]]:
    """(stale, missing) read-only devices on a container whose base phase is already done."""
    if ctx.state.status("base") != "done":
        return [], []
    inst = ctx.instance()
    if inst is None:
        return [], []
    return stale_readonly(ctx, inst), missing_readonly(ctx, inst)


def sync_readonly(ctx: Ctx, stale: list[tuple[str, str]],
                  missing: list[tuple[str, str, dict[str, str]]], review: bool = False) -> None:
    """Remove stale read-only devices and add missing ones, with the container stopped: no moment in
    which .git is writable, and no unmounting .git/hooks from under a whole-.git mount.

    review: the container ran before with .git writable (an existing container from an older devstack),
    so point at what in it the host's git would act on."""
    if not (stale or missing):
        return
    running = ctx.instance_running()
    if running:
        log.info("  stopping %s to change its read-only mounts", ctx.name)
        ctx.stop_instance()
    for dev, path in stale:
        ctx.r.run(["incus", "config", "device", "remove", ctx.name, dev])
        if e := ctx.journal.find("incus_device", ACTIVE, instance=ctx.name, device=dev):
            ctx.journal.mark(e, "undone")
        log.info("  removed device %s (%s)", dev, path)
    had_git = (ctx.project / ".git").exists()
    ensure_git_repo(ctx)
    for dev, rel, props in missing:
        ctx.ensure_device(dev, "disk", props)
        log.info("  %s read-only in the container", props["path"])
    if running:
        ctx.r.run(["incus", "start", ctx.name])
        ctx.wait_ipv4()
        if any(rel == ".git" for _, rel, _ in missing):
            verify_git_readonly(ctx)
    for _, rel, _ in missing:
        if rel != ".git":
            log.warning("%s is read-only in the container from now on; until now the container could write it, "
                        "so review it before the host runs anything from it", ctx.project / rel)
        elif review and had_git:
            found = git_history_findings(ctx.project) + git_exec_findings(ctx)
            log.warning("%s/.git is read-only in the container from now on. Until now the container could write "
                        "all of it except what project.readonly_paths covered (refs, the index, packed-refs, "
                        "objects). Check `git log` and `git status` on the host before you push.", ctx.project)
            for f in found:
                log.warning("  review: %s", f)


def verify_git_readonly(ctx: Ctx) -> None:
    git = f"{ctx.cproject}/.git"
    opts = ctx.cexec(bash("findmnt -no OPTIONS --mountpoint @@P@@ || true", P=git)).stdout.strip()
    expect("ro" in opts.split(","), f"{git} is not a read-only mount in the container (findmnt: {opts or 'not a mount'})")


def pending_base(ctx: Ctx) -> list[str]:
    """What `up` adds to an existing container whose base phase is done (for the plan)."""
    lines = [f"incus device '{m['name']}': {m['source']} -> {m['path']} "
             f"({'read-only' if m.get('readonly') else 'read-write'}); undone with base" for m in pending_mounts(ctx)]
    stale, missing = readonly_changes(ctx)
    lines += [f"remove incus device '{dev}' ({path}): no longer configured, or covered by the whole-.git mount"
              for dev, path in stale]
    if missing and not (ctx.project / ".git").exists():
        lines.append(f"git init {ctx.project} (on the host; devstack requires git)")
    lines += [f"incus device '{dev}': {ctx.cproject}/{rel} read-only in the container" for dev, rel, _ in missing]
    if stale or missing:
        lines.append(f"{ctx.name} is stopped for these device changes and started again")
    if acl_pending(ctx):
        lines.append(f"network ACL {ctx.cfg['network.acl_name']} on {ctx.name} (host + LAN rejected)")
    return lines


def add_pending_mounts(ctx: Ctx) -> bool:
    """Bring an existing container up to date with mounts, read-only paths and the ACL."""
    mounts, acl = pending_mounts(ctx), acl_pending(ctx)  # re-read after undo/redo
    stale, missing = readonly_changes(ctx)
    if not (mounts or stale or missing or acl):
        return False
    ctx.phase = "base"  # journaled under base, so undoing base removes them
    log.info("")
    log.info("==> base: updating %s", ctx.name)
    for m in mounts:
        ctx.ensure_device(m["name"], "disk", mount_props(m))
        log.info("  %s -> %s (%s)", m["source"], m["path"], "read-only" if m.get("readonly") else "read-write")
    sync_readonly(ctx, stale, missing, review=True)
    if acl:
        ensure_acl(ctx)
    return True


# --- host protection: incus network ACL on the container's NIC ---

ACL_NIC_KEYS = ("security.acls", "security.acls.default.ingress.action", "security.acls.default.egress.action")
ACL_REJECT = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "224.0.0.0/4",
              "fc00::/7")
ACL_LINK_LOCAL6 = "fe80::/10"  # TCP/UDP only: NDP (ICMPv6) to the router's link-local address must keep working
GATEWAY_TCP_REJECT = "1-52,54-65535"            # DNS stays open
GATEWAY_UDP_REJECT = "1-52,54-66,68-546,548-65535"  # DNS, DHCP (67) and DHCPv6 (547) stay open

Net = ipaddress.IPv4Network | ipaddress.IPv6Network


def subtract_networks(nets: list[Net], holes: list[Net]) -> list[Net]:
    """nets minus holes, as CIDRs."""
    out = list(nets)
    for h in holes:
        nxt: list[Net] = []
        for n in out:
            if n.version != h.version or not n.overlaps(h):
                nxt.append(n)
            elif not n.subnet_of(h):  # type: ignore[arg-type]
                nxt.extend(n.address_exclude(h))  # type: ignore[arg-type]
        out = nxt
    return out


def acl_rules(gateways: list[str], host_addrs: list[str], allow_private: list[str]) -> list[dict[str, str]]:
    """Egress reject rules for the container's NIC (the default actions are allow).

    incus doesn't evaluate ACL rules in order (drop, then reject, then allow), so "allow DNS to the
    gateway, reject 10/8" can't be two rules: the gateway is carved out of the reject ranges instead
    and gets its own port-limited rejects."""
    gws = [ipaddress.ip_network(g) for g in gateways]
    allowed = [ipaddress.ip_network(x, strict=False) for x in allow_private]
    reject = [ipaddress.ip_network(x) for x in ACL_REJECT]
    for a in host_addrs:  # the host's public addresses (private ones are already covered)
        n = ipaddress.ip_network(a)
        if not any(n.version == r.version and n.subnet_of(r) for r in reject):  # type: ignore[arg-type]
            reject.append(n)
    reject = subtract_networks(reject, gws + allowed)
    rules = []

    def rule(desc: str, dest: list[Any], **extra: str) -> None:
        if dest:
            rules.append({"action": "reject", "state": "enabled", "description": desc,
                          "destination": ",".join(str(d) for d in dest), **extra})

    for version in (4, 6):
        rule(f"host, LAN and private IPv{version}", sorted(n for n in reject if n.version == version))
    link_local = subtract_networks([ipaddress.ip_network(ACL_LINK_LOCAL6)], allowed)
    rule("TCP to IPv6 link-local", link_local, protocol="tcp")
    rule("UDP to IPv6 link-local", link_local, protocol="udp")
    for g in gws:
        if any(g.version == a.version and g.subnet_of(a) for a in allowed):  # type: ignore[arg-type]
            continue
        rule("bridge gateway: DNS only", [g.network_address], protocol="tcp", destination_port=GATEWAY_TCP_REJECT)
        rule("bridge gateway: DNS and DHCP only", [g.network_address], protocol="udp",
             destination_port=GATEWAY_UDP_REJECT)
    return rules


def bridge_gateways(ctx: Ctx) -> list[str]:
    st = ctx.iq(f"/1.0/networks/{ctx.cfg['container.network']}/state") or {}
    return [a["address"] for a in st.get("addresses", []) if a.get("scope") == "global"]


def host_addresses(ctx: Ctx) -> list[str]:
    """The host's global addresses (`ip -j addr`)."""
    p = ctx.r.run(["ip", "-j", "addr", "show"], check=False)
    try:
        data = json.loads(p.stdout or "[]")
    except json.JSONDecodeError:
        return []
    return [a["local"] for iface in data for a in iface.get("addr_info", [])
            if a.get("scope") == "global" and a.get("local")]


def acl_nic_values(c: Config) -> dict[str, str]:
    return dict(zip(ACL_NIC_KEYS, (c["network.acl_name"], "allow", "allow")))


def acl_pending(ctx: Ctx) -> bool:
    """network.acl is on but the done container's NIC doesn't carry it (yet)."""
    if not ctx.cfg["network.acl"] or ctx.state.status("base") != "done":
        return False
    inst = ctx.instance()
    if inst is None:
        return False
    try:
        nic = ctx.nic_device()
    except PreflightError:
        return False
    dev = inst["devices"].get(nic, {})
    return any(dev.get(k) != v for k, v in acl_nic_values(ctx.cfg).items())


def ensure_acl(ctx: Ctx) -> None:
    """Create or update the ACL, then attach it with explicit allow defaults: once a NIC has any ACL,
    incus rejects unmatched traffic in both directions, which would cut ssh and HTTPS in."""
    c = ctx.cfg
    name, nic = c["network.acl_name"], ctx.nic_device()
    body = {"description": f"devstack {c['stack.name']}: keep {ctx.name} off the host and LAN (reject rules only)",
            "egress": acl_rules(bridge_gateways(ctx), host_addresses(ctx), c["network.allow_private"]),
            "ingress": [], "config": {}}
    if ctx.iq(f"/1.0/network-acls/{name}") is None:
        e = ctx.journal.add(ctx.phase, "incus_acl", name=name, instance=ctx.name, nic=nic)
        ctx.r.run(["incus", "query", "-X", "POST", "/1.0/network-acls", "--data", json.dumps({"name": name, **body})])
        ctx.journal.mark(e, "applied")
    else:  # ours (preflight checked): refresh the rules, the host's addresses may have changed
        ctx.r.run(["incus", "query", "-X", "PUT", f"/1.0/network-acls/{name}", "--data", json.dumps(body)])
    dev = (ctx.instance() or {}).get("devices", {}).get(nic, {})
    want = acl_nic_values(c)
    if any(dev.get(k) != v for k, v in want.items()):
        ctx.r.run(["incus", "config", "device", "set", ctx.name, nic, *[f"{k}={v}" for k, v in want.items()]])
    log.info("  network ACL %s on %s: host and LAN rejected (%d rules), internet allowed", name, nic, len(body["egress"]))


ACL_PROBE = r"""
user=@@USER@@; targets=(@@TARGETS@@)
for t in "${targets[@]}"; do
  ip=${t% *}; port=${t#* }
  if runuser -u "$user" -- timeout 4 bash -c 'exec 3<>"/dev/tcp/$0/$1"' "$ip" "$port" 2>/dev/null; then
    echo "$ip:$port"
  fi
done
"""


def acl_probe_ips(gateways: list[str], host_addrs: list[str]) -> list[str]:
    """IPv4 addresses of the host the container must not reach: the bridge gateway, then the host's others."""
    gw4 = [g for g in gateways if ipaddress.ip_address(g).version == 4]
    return gw4 + [a for a in host_addrs if ipaddress.ip_address(a).version == 4 and a not in gw4]


def verify_acl(ctx: Ctx) -> None:
    """The container must not reach a host listener. devstack opens its own (all addresses, random port) for
    the probe: existing services may be firewalled on the host anyway, which would hide a missing ACL."""
    c = ctx.cfg
    ips = acl_probe_ips(bridge_gateways(ctx), host_addresses(ctx))[:6]
    if not ips:
        raise VerifyError("no host IPv4 address to test the network ACL against")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.bind(("0.0.0.0", 0))
        srv.listen(8)  # the kernel completes handshakes into the backlog: a connect that gets through succeeds
        port = srv.getsockname()[1]
        targets = [f"{ip} {port}" for ip in ips]
        p = ctx.cexec(bash(ACL_PROBE, USER=c["container.user"], TARGETS=targets), check=False)
    reached = p.stdout.split()
    expect(not reached, f"the container reached a test listener on the host at {', '.join(reached)} despite network "
           f"ACL {c['network.acl_name']}: the ACL doesn't cover traffic to the host on this incus. Set "
           "network.acl = false to build without it (and protect the host another way), or report it")
    log.info("  ACL: a host listener on port %d is unreachable from the container (%s)", port, ", ".join(ips))


class BasePhase(Phase):
    id = "base"
    title = "container, user, ssh, Node"
    layer = "contain"
    snapshot = False  # undo = delete the container

    def describe(self, ctx: Ctx) -> list[str]:
        c = ctx.cfg
        mounts = ", ".join(f"{m['source']} -> {m['path']}" for m in c["container.mounts"]) or "none"
        return [
            f"create project folder {ctx.project} (if missing)"
            + ("" if (ctx.project / ".git").exists() else "; `git init` it on the host (devstack requires git)")
            + "; set core.useReplaceRefs = false in its .git/config",
            f"incus init {c['container.image']} {ctx.name} (profiles {', '.join(c['container.profiles'])}, pool {c['container.storage_pool']})",
            f"mount {ctx.project} -> {ctx.cproject} (shift=true); extra mounts: {mounts}",
            "read-only inside the container: .git" + "".join(f", {r}" for r in readonly_extra(c))
            + (" (those that exist)" if readonly_extra(c) else ""),
            f"GPU passthrough: {'yes' if c['gpu.enabled'] else 'no'}",
            f"start, pin IPv4 ({c['container.ipv4']}) on nic device ({c['container.nic_device']})",
            (f"network ACL {c['network.acl_name']} on the NIC: reject the host (except DNS/DHCP), the LAN and "
             f"private ranges{'; except ' + ', '.join(c['network.allow_private']) if c['network.allow_private'] else ''}"
             if c["network.acl"] else "network ACL: off (network.acl = false): the container can reach the host and LAN"),
            f"in container: openssh-server, sudo, curl, gnupg; user {c['container.user']} (uid {c.uid}, "
            f"systemd-journal, sudo: {c['container.sudo']}); sshd key-only",
            f"ssh key {c['ssh.key_path']}; known_hosts {c['ssh.known_hosts_file']}; block 'Host {c['ssh.host_alias']}' in {c['ssh.config_file']}",
            f"Node {c['node.version']} (gpg + sha256 verified) under {c['node.install_prefix']}, corepack pnpm",
            *([f"syft {SYFT_VERSION} (sha256 verified) at /usr/local/bin/syft, for the CycloneDX "
               f"inventory in {c['sbom.dir']}/"] if c["sbom.enabled"] else
              ["SBOM: off (sbom.enabled = false): no syft, no inventory"]),
            "verify: ssh login works, node version, shared folder ownership, host listeners unreachable",
        ]

    def apply(self, ctx: Ctx) -> None:
        c = ctx.cfg
        ctx.ensure_dir(ctx.project, 0o755)

        if ctx.instance() is None:
            log.info("  creating container %s from %s (first image download can take a while)", ctx.name, c["container.image"])
            e = ctx.journal.add(ctx.phase, "incus_instance", name=ctx.name)
            argv = ["incus", "init", c["container.image"], ctx.name, "--storage", c["container.storage_pool"]]
            for prof in c["container.profiles"]:
                argv += ["--profile", prof]
            if c["container.cpu_limit"]:
                argv += ["--config", f"limits.cpu={c['container.cpu_limit']}"]
            if c["container.memory_limit"]:
                argv += ["--config", f"limits.memory={c['container.memory_limit']}"]
            ctx.r.run(argv, stream=True)
            ctx.journal.mark(e, "applied")
        else:
            log.info("  container %s already exists (owned by this stack)", ctx.name)

        ctx.ensure_device("project", "disk", {"source": str(ctx.project), "path": ctx.cproject, "shift": "true"})
        for m in c["container.mounts"]:
            ctx.ensure_device(m["name"], "disk", mount_props(m))
        inst = ctx.instance()
        assert inst is not None
        # Before the first start (`git init` included), so .git is never writable in the container.
        sync_readonly(ctx, stale_readonly(ctx, inst), missing_readonly(ctx, inst))
        for rel in readonly_extra(c):
            if not (ctx.project / rel).exists():
                log.info("  %s doesn't exist yet: mounted read-only by the next `up` once it does", rel)
        if c["gpu.enabled"]:
            props = {"gputype": "physical"}
            if c["gpu.pci"]:
                props["pci"] = c["gpu.pci"]
            ctx.ensure_device("gpu", "gpu", props)
            if c["gpu.nvidia_runtime"]:
                inst = ctx.instance() or {}
                if inst.get("config", {}).get("nvidia.runtime") != "true":
                    ctx.set_instance_config("nvidia.runtime", "true")

        nic = ctx.nic_device()
        inst = ctx.instance()
        assert inst is not None
        pinned = inst["devices"].get(nic, {}).get("ipv4.address")
        if c["container.ipv4"] != "auto" and pinned != c["container.ipv4"]:
            self._pin(ctx, nic, c["container.ipv4"], inst)
            pinned = c["container.ipv4"]
        if not ctx.instance_running():
            ctx.r.run(["incus", "start", ctx.name])
        ip = ctx.wait_ipv4()
        if not pinned:
            self._pin(ctx, nic, ip, inst)
            ctx.r.run(["incus", "restart", ctx.name])
            ip2 = ctx.wait_ipv4()
            if ip2 != ip:
                raise DevstackError(f"pinned {ip} but container came back with {ip2}")
        ctx.state.set_fact("ipv4", ip)
        log.info("  container IPv4: %s (pinned on device %s)", ip, nic)
        if c["network.acl"]:
            ensure_acl(ctx)

        log.info("  installing base packages, creating user %s", c["container.user"])
        ctx.cexec(bash(BASE_PROVISION, USER=c["container.user"], UID=c.uid), stream=True)
        apply_sudo(ctx)
        ctx.cwrite("/etc/ssh/sshd_config.d/10-devstack.conf", render("system/sshd-devstack.conf", ctx.tvars()))
        ctx.cexec(SSHD_APPLY)

        self._ssh(ctx, ip)

        log.info("  installing Node %s (verified)", c["node.version"])
        out = ctx.cexec(bash(NODE_INSTALL, VER=c["node.version"], PREFIX=c["node.install_prefix"],
                                  KEYRING_COMMIT=NODE_KEYRING_COMMIT, KEYRING_SHA=NODE_KEYRING_SHA256), stream=True)
        ctx.state.set_fact("node_bin", out.stdout.strip().splitlines()[-1])
        if c["sbom.enabled"]:
            ensure_syft(ctx)

    def _pin(self, ctx: Ctx, nic: str, ip: str, inst: dict) -> None:
        if nic in inst["devices"]:
            ctx.r.run(["incus", "config", "device", "set", ctx.name, nic, f"ipv4.address={ip}"])
        else:
            e = ctx.journal.add(ctx.phase, "incus_device", instance=ctx.name, device=nic)
            ctx.r.run(["incus", "config", "device", "override", ctx.name, nic, f"ipv4.address={ip}"])
            ctx.journal.mark(e, "applied")

    def _ssh(self, ctx: Ctx, ip: str) -> None:
        c = ctx.cfg
        key = Path(c["ssh.key_path"])
        if not key.exists():
            ctx.ensure_dir(key.parent, 0o700)
            e = ctx.journal.add(ctx.phase, "ssh_key", path=str(key))
            argv = ["ssh-keygen", "-t", "ed25519", "-f", key, "-C", f"devstack-{c['stack.name']}"]
            if c["ssh.key_passphrase"] == "none":
                ctx.r.run([*argv, "-N", ""])
            else:
                if not ctx.interactive:
                    raise NeedsInput("ssh.key_passphrase = 'prompt' needs interactive mode")
                ctx.r.run(argv, tty=True)
            ctx.journal.mark(e, "applied")
        pub = Path(str(key) + ".pub").read_text().strip()
        ctx.cexec(bash(AUTHORIZED_KEY, USER=c["container.user"]), input=pub + "\n")

        hostkey = ctx.cread("/etc/ssh/ssh_host_ed25519_key.pub")
        if not hostkey:
            raise DevstackError("container has no ed25519 host key")
        ktype, kdata = hostkey.split()[:2]
        alias = c["ssh.host_alias"]
        ctx.write_host_file(Path(c["ssh.known_hosts_file"]), f"{alias} {ktype} {kdata}\n", mode=0o600)

        q = lambda s: f'"{s}"' if " " in s else s  # noqa: E731
        ctx.set_marked_block(Path(c["ssh.config_file"]), "\n".join([
            f"Host {alias}",
            f"    HostName {ip}",
            f"    User {c['container.user']}",
            f"    IdentityFile {q(str(key))}",
            "    IdentitiesOnly yes",
            f"    HostKeyAlias {alias}",
            f"    UserKnownHostsFile {q(c['ssh.known_hosts_file'])}",
            "    StrictHostKeyChecking yes",
        ]))

    def verify(self, ctx: Ctx) -> None:
        c = ctx.cfg
        ssh = ["ssh", "-F", c["ssh.config_file"], "-o", "ConnectTimeout=10"]
        if c["ssh.key_passphrase"] == "none":
            p = ctx.r.run([*ssh, "-o", "BatchMode=yes", c["ssh.host_alias"], "true"], check=False)
            expect(p.returncode == 0, f"ssh {c['ssh.host_alias']} failed:\n{p.stderr}")
        else:
            log.info("  skipping non-interactive ssh check (key has a passphrase); try: ssh %s", c["ssh.host_alias"])
        v = ctx.cexec("node --version").stdout.strip()
        expect(v == f"v{c['node.version']}", f"node --version is {v!r}, expected v{c['node.version']}")
        owner = ctx.cexec(bash("stat -c %u @@P@@", P=ctx.cproject)).stdout.strip()
        expect(owner == str(c.uid), f"{ctx.cproject} is owned by uid {owner} in the container, expected {c.uid} "
               "(idmapped mount / uid mismatch)")
        verify_git_readonly(ctx)
        if c["sbom.enabled"]:  # cheap: a real scan here would double this phase's runtime
            expect(ctx.cexec("syft version", check=False).returncode == 0, "syft is not runnable in the container")
        if c["network.acl"]:
            verify_acl(ctx)


def sudoers_dropin(c: Config) -> str:
    return f"/etc/sudoers.d/devstack-{c['stack.name']}"


def apply_sudo(ctx: Ctx) -> None:
    c = ctx.cfg
    ctx.cexec(bash(SUDO_APPLY, USER=c["container.user"], MODE=c["container.sudo"], DROPIN=sudoers_dropin(c)))


PNPM_SETUP = r"""
cd @@PROJECT@@
export COREPACK_ENABLE_DOWNLOAD_PROMPT=0
pnpm_ver=@@PNPM@@
corepack use "pnpm@$pnpm_ver"
pnpm add -D @@DEV_PACKAGES@@
"""


def dev_packages(c: Config) -> list[str]:
    """What PNPM_SETUP adds as devDependencies: the type checker, Node's types for the pinned major, and
    the lint toolchain eslint.config.js imports."""
    return [TYPESCRIPT_SPEC, f"@types/node@{c['node.version'].split('.')[0]}", *DEV_TOOLCHAIN]

# An existing project (a clone, or a rebuild: undo removes the node_modules devstack created) still needs
# its dependencies before the app can start. Frozen when there is a lockfile: install exactly what it pins.
PNPM_INSTALL = r"""
cd @@PROJECT@@
export COREPACK_ENABLE_DOWNLOAD_PROMPT=0
if [ -f pnpm-lock.yaml ]; then pnpm install --frozen-lockfile; else pnpm install; fi
"""

APP_SMOKE = r"""
cd @@PROJECT@@
port=@@PORT@@; hostport=@@HOSTPORT@@; entry=@@ENTRY@@
if ss -Htln "sport = :$port" | grep -q .; then echo "port $port is already in use in the container" >&2; exit 1; fi
log=$(mktemp)
node "$entry" >"$log" 2>&1 &
pid=$!
trap 'kill "$pid" 2>/dev/null || true; rm -f "$log"' EXIT
for i in $(seq 1 50); do
  if curl -fsS "http://$hostport/api/health"; then exit 0; fi
  sleep 0.2
done
cat "$log" >&2
exit 1
"""

SCAFFOLD = [
    ("project/package.json", "package.json", 0o644),
    ("project/tsconfig.json", "tsconfig.json", 0o644),
    ("project/pnpm-workspace.yaml", "pnpm-workspace.yaml", 0o644),  # before `pnpm add`: it reads it
    ("project/eslint.config.js", "eslint.config.js", 0o644),
    ("project/server.ts", "server.ts", 0o644),
    ("project/gitignore", ".gitignore", 0o644),
    ("project/README.md", "README.md", 0o644),
    ("project/AGENTS.md", "AGENTS.md", 0o644),
    ("project/static/index.html", "static/index.html", 0o644),
    ("project/static/style.css", "static/style.css", 0o644),
    ("project/static/main.js", "static/main.js", 0o644),
    ("project/error/index.html", "error/index.html", 0o644),
    ("project/infra/apt-packages.txt", "infra/apt-packages.txt", 0o644),
    ("project/scripts/sync-env.sh", "scripts/sync-env.sh", 0o755),
    ("project/scripts/lint-changed.sh", "scripts/lint-changed.sh", 0o755),
]
# Created only together with a new package.json, never added to an existing project: they assume the
# devDependencies PNPM_SETUP installs and the scripts in the scaffolded package.json, and a
# pnpm-workspace.yaml appearing under an existing lockfile would make the next `pnpm install
# --frozen-lockfile` re-check every locked version against its release-age and trust rules.
SCAFFOLD_NEW_PROJECT_ONLY = frozenset({"pnpm-workspace.yaml", "eslint.config.js", "scripts/lint-changed.sh"})


class AppPhase(Phase):
    id = "app"
    title = "smoke-test app scaffold"
    layer = "serve"

    def describe(self, ctx: Ctx) -> list[str]:
        c = ctx.cfg
        if not c["project.scaffold"]:
            return ["project.scaffold = false: nothing to create; verify that the entry file exists"]
        return [
            f"create (never overwrite) in {ctx.project}: " + ", ".join(rel for _, rel, _ in SCAFFOLD)
            + f" ({', '.join(sorted(SCAFFOLD_NEW_PROJECT_ONLY))} only along with a new package.json)",
            f"as {c['container.user']}: corepack use pnpm@{c['node.pnpm_version']}; pnpm add -D "
            f"{' '.join(dev_packages(c))} "
            "(if package.json was just created), else `pnpm install --frozen-lockfile` if node_modules is missing",
            f"verify: start {c['app.entry']} briefly, GET http://{url_host(c['app.bind'])}:{c['app.port']}/api/health inside the container",
        ]

    def apply(self, ctx: Ctx) -> None:
        c = ctx.cfg
        if not c["project.scaffold"]:
            return
        tv = ctx.tvars()
        new_project = not (ctx.project / "package.json").exists()
        created = {rel: ctx.project_file(rel, render(tpl, tv), mode=mode) for tpl, rel, mode in SCAFFOLD
                   if new_project or rel not in SCAFFOLD_NEW_PROJECT_ONLY}
        node_modules, lock = ctx.project / "node_modules", ctx.project / "pnpm-lock.yaml"
        had_nm, had_lock = node_modules.exists(), lock.exists()
        if created["package.json"]:
            log.info("  pnpm: installing typescript, @types/node and the eslint toolchain")
            script = bash(PNPM_SETUP, PROJECT=ctx.cproject, PNPM=c["node.pnpm_version"],
                          DEV_PACKAGES=dev_packages(c))
        elif not had_nm:
            log.info("  pnpm: installing the project's dependencies (%s)",
                     "frozen to pnpm-lock.yaml" if had_lock else "no lockfile")
            script = bash(PNPM_INSTALL, PROJECT=ctx.cproject)
        else:
            log.info("  package.json and node_modules exist: dependencies left as they are")
            return
        try:
            ctx.cexec(script, user=c["container.user"], stream=True)
        finally:
            if not had_nm and node_modules.exists():
                ctx.track_generated(node_modules, tree=True)
            if not had_lock and lock.exists():
                ctx.track_generated(lock)
            pkg = ctx.journal.find("project_file", ACTIVE, path=str(ctx.project / "package.json"))
            if pkg is not None:  # pnpm rewrote it; undo should still recognise it as ours
                ctx.journal.mark(pkg, "applied", sha256=sha256_file(ctx.project / "package.json"))

    def verify(self, ctx: Ctx) -> None:
        c = ctx.cfg
        entry = ctx.project / c["app.entry"]
        expect(entry.exists(), f"{entry} does not exist")
        if ctx.state.status("isolation") == "done":
            return  # the systemd unit owns the port now; the isolation phase verifies it
        p = ctx.cexec(bash(APP_SMOKE, PROJECT=ctx.cproject, PORT=c["app.port"], ENTRY=c["app.entry"],
                           HOSTPORT=f"{url_host(c['app.bind'])}:{c['app.port']}"),
                      user=c["container.user"], check=False)
        expect(p.returncode == 0, f"smoke test of {c['app.entry']} failed:\n{p.stdout}{p.stderr}")
        log.info("  /api/health -> %s", p.stdout.strip())


KEY_FPR_CHECK = r"""
check_key_fpr() {  # file expected-fingerprint: abort unless the file holds exactly that primary key
  local got
  got=$(gpg --show-keys --with-colons "$1" | awk -F: '$1=="pub"{p=1;next} $1=="fpr"&&p{print $10;p=0}')
  [ "$got" = "$2" ] || { echo "signing key fingerprint mismatch for $1: got '${got:-none}', expected $2" >&2; exit 1; }
}
"""

CADDY_INSTALL = KEY_FPR_CHECK + r"""
apt-get update
apt-get install -y --no-install-recommends curl gnupg ca-certificates
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' -o "$tmp/caddy.key"
check_key_fpr "$tmp/caddy.key" @@FPR@@
gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg < "$tmp/caddy.key"
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > /etc/apt/sources.list.d/caddy-stable.list
chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg /etc/apt/sources.list.d/caddy-stable.list
apt-get update
apt-get install -y --no-install-recommends caddy
systemctl enable caddy
"""

# Validate as caddy, not root: the project's Caddyfile is the dev user's, and as root a parse error
# would print the first token of any file root can read (`import /etc/shadow`).
CADDY_APPLY = r"""
restart=@@RESTART@@
runuser -u caddy -- caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
if [ "$restart" = true ] || ! systemctl is-active --quiet caddy; then
  systemctl restart caddy
else
  systemctl reload caddy
fi
"""

# --- local CA: the root key never leaves the host; Caddy only gets a name-constrained intermediate ---

CADDY_PKI_DIR = "/etc/caddy/pki"  # in the container: intermediate.crt (0644) + intermediate.key (root:caddy 0640)
CA_ROOT_DAYS, CA_INTERMEDIATE_DAYS, CA_RENEW_SECONDS = 3650, 1825, 30 * 86400
CA_EC_CURVE = "P-256"  # accepted by Caddy and by NSS


def ca_names(c: Config) -> list[str]:
    """DNS name constraints of the root: the dev domain (and any extra names), nothing else."""
    base = f".{c['dns.tld']}" if c["dns.tld"] else c["site.hostname"]
    return [base, *sorted(set(c["dns.extra_names"]))]


def ca_openssl_config(stack: str, names: list[str]) -> str:
    permitted = ",".join(f"permitted;DNS:{n}" for n in names)
    return textwrap.dedent(f"""\
        [req]
        distinguished_name = dn
        prompt = no
        [dn]
        CN = devstack {stack} root CA
        [v3_root]
        basicConstraints = critical,CA:TRUE
        keyUsage = critical,keyCertSign,cRLSign
        subjectKeyIdentifier = hash
        nameConstraints = critical,{permitted}
        [v3_int]
        basicConstraints = critical,CA:TRUE,pathlen:0
        keyUsage = critical,keyCertSign,cRLSign
        subjectKeyIdentifier = hash
        authorityKeyIdentifier = keyid
        """)


def ensure_host_ca(ctx: Ctx) -> Path:
    """Create (or reuse) the host-side CA in state_dir/ca; returns the root certificate path.

    A new root is made when it is missing, near expiry, or its name constraints no longer match
    the config. The intermediate is re-signed when it is missing or near expiry."""
    c = ctx.cfg
    d = ctx.state_dir / "ca"
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    names = ca_names(c)
    root_crt, root_key = d / "root.crt", d / "root.key"
    int_crt, int_key = d / "intermediate.crt", d / "intermediate.key"
    stamp, conf = d / "names.json", d / "openssl.cnf"

    def alive(cert: Path) -> bool:
        return cert.exists() and ctx.r.run(["openssl", "x509", "-noout", "-checkend", str(CA_RENEW_SECONDS),
                                            "-in", cert], check=False).returncode == 0

    def genkey(path: Path) -> None:
        ctx.r.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", f"ec_paramgen_curve:{CA_EC_CURVE}",
                   "-out", path])

    old_umask = os.umask(0o077)
    try:
        atomic_write(conf, ca_openssl_config(c["stack.name"], names), 0o600)
        same_names = stamp.exists() and json.loads(stamp.read_text()) == names
        if not (root_key.exists() and same_names and alive(root_crt)):
            if root_crt.exists():
                log.info("  creating a new local root CA (name constraints changed, or the old one is expiring)")
            for f in (root_crt, root_key, int_crt, int_key, stamp):
                f.unlink(missing_ok=True)
            genkey(root_key)
            ctx.r.run(["openssl", "req", "-new", "-x509", "-sha256", "-days", CA_ROOT_DAYS, "-key", root_key,
                       "-config", conf, "-extensions", "v3_root", "-out", root_crt])
            atomic_write(stamp, json.dumps(names), 0o600)
            log.info("  local root CA created in %s (key stays on the host; limited to %s)", d, ", ".join(names))
        if not (int_key.exists() and alive(int_crt)):
            csr = d / "intermediate.csr"
            genkey(int_key)
            ctx.r.run(["openssl", "req", "-new", "-key", int_key, "-config", conf, "-out", csr,
                       "-subj", f"/CN=devstack {c['stack.name']} intermediate CA"])
            ctx.r.run(["openssl", "x509", "-req", "-in", csr, "-CA", root_crt, "-CAkey", root_key,
                       "-set_serial", str(secrets.randbits(120) + 1), "-sha256", "-days", CA_INTERMEDIATE_DAYS,
                       "-extfile", conf, "-extensions", "v3_int", "-out", int_crt])
            csr.unlink(missing_ok=True)
        ctx.r.run(["openssl", "verify", "-CAfile", root_crt, int_crt])
    finally:
        os.umask(old_umask)
    return root_crt

LEVEL_PROXY, LEVEL_STANDARDS, LEVEL_ISOLATION = 3, 4, 5
LEVEL_NAMES = {LEVEL_PROXY: "proxy", LEVEL_STANDARDS: "standards", LEVEL_ISOLATION: "isolation"}

SAME_ORIGIN_SNIPPET = "devstack_same_origin"
# A request a browser marks as coming from another site. Sec-Fetch-Site same-site counts: sibling names under
# the dev TLD are one "site" to a browser, but each may be a different project.
SAME_ORIGIN_FOREIGN = ('{http.request.header.Sec-Fetch-Site} in ["cross-site", "same-site"] || '
                       '({http.request.header.Origin} != "" && '
                       '{http.request.header.Origin} != {http.request.scheme} + "://" + {http.request.hostport})')
# A top-level GET navigation: a link click or a redirect back. Not a frame (X-Frame-Options blocks those anyway),
# not a form POST.
SAME_ORIGIN_NAVIGATION = ('{http.request.method} == "GET" && {http.request.header.Sec-Fetch-Mode} == "navigate" '
                          '&& {http.request.header.Sec-Fetch-Dest} == "document"')


def same_origin_snippet(mode: str) -> list[str]:
    """(devstack_same_origin) for /etc/caddy/Caddyfile. Root-owned so a fix reaches every project; a
    project imports it rather than copying it (Caddy refuses a second snippet of the same name).

    It guards the app against other sites' pages in the browser, not the host against the container:
    the dev user can rewrite the app anyway. Defined, empty, for 'off' too, so imports keep parsing."""
    head = [f"# caddy.same_origin = {mode}. Every site block imports this snippet."]
    if mode == "off":
        return head + [f"({SAME_ORIGIN_SNIPPET}) {{", "}", ""]
    expr = SAME_ORIGIN_FOREIGN if mode == "strict" else f"!({SAME_ORIGIN_NAVIGATION}) && ({SAME_ORIGIN_FOREIGN})"
    return head + [
        "# Only the site's own pages may make requests to it: a foreign Origin, or Sec-Fetch-Site cross-site",
        "# or same-site, gets a bare 403" + (", except a top-level GET navigation." if mode != "strict" else "."),
        "# Typed URLs, bookmarks and tools (curl, agents) send neither header and pass. No CORS headers.",
        f"({SAME_ORIGIN_SNIPPET}) {{",
        f"\t@foreign expression `{expr}`",
        "\trespond @foreign 403",
        "}",
        "",
    ]


def inline_style_hashes(html: str) -> list[str]:
    blocks = re.findall(r"<style[^>]*>(.*?)</style>", html, re.S | re.I)
    return [base64.b64encode(hashlib.sha256(b.encode()).digest()).decode() for b in blocks]


def csp_with_hashes(csp: str, hashes: list[str]) -> str:
    if not hashes:
        return csp
    extra = " ".join(f"'sha256-{h}'" for h in hashes)
    parts = [p.strip() for p in csp.split(";") if p.strip()]
    for i, p in enumerate(parts):
        if p.split()[0] == "style-src":
            parts[i] = f"{p} {extra}"
            break
    else:
        parts.append(f"style-src 'self' {extra}")
    return "; ".join(parts) + ";"


def caddy_global(ctx: Ctx, level: int) -> str:
    """/etc/caddy/Caddyfile: devstack's global options, then the project's file.

    The global block lives here, root-owned, in both caddy.manage_caddyfile modes. Caddy only accepts
    a global block as the first block of the config, so a project file that brings its own (say, to put
    the admin API back on TCP) fails to parse instead of taking effect."""
    c = ctx.cfg
    out = [
        f"# GENERATED by devstack for stack '{c['stack.name']}' (level: {LEVEL_NAMES[level]}). Root-owned:",
        "# the global options are devstack's. The project's routes are in the imported file.",
        "{",
    ]
    if level >= LEVEL_ISOLATION:
        out += ["\t# Admin API on a unix socket in /run/caddy (0700): caddy and root only, nothing on TCP.",
                f"\tadmin {c['caddy.admin']}"]
    out += [
        "\tlocal_certs",
        "\t# The root CA lives on the host (name-constrained to the dev domain); Caddy only holds this",
        "\t# intermediate, so don't add Caddy's own, unused root to the container's trust store.",
        "\tskip_install_trust",
        "\tpki {",
        "\t\tca local {",
        "\t\t\tintermediate {",
        f"\t\t\t\tcert {CADDY_PKI_DIR}/intermediate.crt",
        f"\t\t\t\tkey {CADDY_PKI_DIR}/intermediate.key",
        "\t\t\t}",
        "\t\t}",
        "\t}",
        "}",
        "",
        *same_origin_snippet(c["caddy.same_origin"]),
        *dev_server_blocks(ctx, level),
        f"import {ctx.cproject}/infra/Caddyfile",
        "",
    ]
    return "\n".join(out)


def caddyfile_defines(text: str, snippet: str) -> bool:
    return re.search(rf"^\s*\({re.escape(snippet)}\)\s*\{{", text, re.M) is not None


def caddyfile_imports(text: str, snippet: str) -> bool:
    return re.search(rf"^\s*import\s+{re.escape(snippet)}\s*(#.*)?$", text, re.M) is not None


def caddyfile_has_global_block(text: str) -> bool:
    """Does a Caddyfile start with a global options block (a bare '{')?"""
    for ln in text.splitlines():
        ln = ln.split("#", 1)[0].strip()
        if ln:
            return ln.startswith("{")
    return False


def api_proxy(c: Config, level: int) -> list[str]:
    """The site's /api/* route to the app (with the internal token from the isolation level on)."""
    upstream = f"{url_host(c['app.bind'])}:{c['app.port']}"
    if level < LEVEL_ISOLATION:
        return [f"\treverse_proxy /api/* {upstream}"]
    return [
        f"\treverse_proxy /api/* {upstream} {{",
        "\t\theader_up X-Internal-Token {env.INTERNAL_TOKEN}",
        "",
        "\t\t# Don't leak an internal credential failure.",
        "\t\t@upstream_internal_error status 500",
        "\t\thandle_response @upstream_internal_error {",
        "\t\t\trespond 500",
        "\t\t}",
        "\t}",
    ]


def dev_server_blocks(ctx: Ctx, level: int) -> list[str]:
    """A site block per caddy.dev_servers entry, in the root file so projects that own their Caddyfile get
    them too. Snippets from the project file aren't defined yet here, hence header -Server inline."""
    c = ctx.cfg
    if not c["caddy.dev_servers"]:
        return []
    out = ["# caddy.dev_servers: each at https://<name>.<dev host>/, its /api/* going to the app, so the page",
           "# and its API share one origin. No security headers: a dev server's inline scripts and HMR",
           "# websocket would break the CSP. Host is rewritten so the dev server's host check passes.", ""]
    for name, port in sorted(c["caddy.dev_servers"].items()):
        out += [f"{name}.{c.dev_host} {{", f"\timport {SAME_ORIGIN_SNIPPET}"]
        if level >= LEVEL_ISOLATION:
            out += ["\theader -Server", "\theader -Via"]
        out += [*api_proxy(c, level), f"\treverse_proxy localhost:{port} {{",
                "\t\theader_up Host {upstream_hostport}", "\t}", "}", ""]
    return out


def caddyfile(ctx: Ctx, level: int) -> str:
    c = ctx.cfg
    static, error = c["caddy.static_dir"], c["caddy.error_dir"]
    out = [
        f"# GENERATED by devstack for stack '{c['stack.name']}' (level: {LEVEL_NAMES[level]}).",
        "# Change devstack.toml and re-run, or set caddy.manage_caddyfile = false to own this file.",
        "# Apply edits with: sudo devstack-sync reload caddy (after the isolation phase).",
        "# Snippets and site blocks only: the global options are in /etc/caddy/Caddyfile, which",
        "# imports this file, and a global block here would stop Caddy from loading it.",
        "",
    ]
    if level >= LEVEL_ISOLATION:
        out += ["(common) {", "\theader -Server", "\theader -Via", "}", ""]
    if level >= LEVEL_STANDARDS:
        error_html = ctx.project / Path(error).relative_to(ctx.cproject) / "index.html" \
            if Path(error).is_relative_to(ctx.cproject) else None
        hashes = inline_style_hashes(error_html.read_text()) if error_html and error_html.exists() else []
        out += ["(security_headers) {", "\theader {"]
        for name, value in c["caddy.headers"].items():
            if name.lower() == "content-security-policy":
                value = csp_with_hashes(value, hashes)
            out.append(f'\t\t{name} "{value.replace(chr(34), chr(92) + chr(34))}"')
        out += ["\t}", "}", ""]
        out += ["(error_page) {", f"\troot * {error}", "\trewrite * /index.html",
                "\tfile_server {", "\t\tprecompressed br gzip", "\t}", "}", ""]
    out += [f"{c.dev_host} {{", f"\timport {SAME_ORIGIN_SNIPPET}"]
    if c["caddy.max_request_body"]:
        out += ["\trequest_body {", f"\t\tmax_size {c['caddy.max_request_body']}", "\t}"]
    if level >= LEVEL_ISOLATION:
        out.append("\timport common")
    if level >= LEVEL_STANDARDS:
        out += ["\timport security_headers", "\tencode zstd gzip"]
    out.append(f"\troot * {static}")
    out += api_proxy(c, level)
    if level >= LEVEL_STANDARDS:
        out += ["\thandle_errors {", "\t\timport error_page", "\t}",
                "\tfile_server {", "\t\tprecompressed br gzip", "\t}"]
    else:
        out.append("\tfile_server")
    out += ["}", "", "http:// {", f"\timport {SAME_ORIGIN_SNIPPET}"]
    if level >= LEVEL_ISOLATION:
        out.append("\timport common")
    if level >= LEVEL_STANDARDS:
        out += ["\timport security_headers", "\timport error_page"]
    else:
        out += [f"\troot * {error}", "\trewrite * /index.html", "\tfile_server"]
    out += ["}", ""]
    return "\n".join(out)


def apply_caddyfile(ctx: Ctx, level: int, *, restart: bool = False) -> None:
    c = ctx.cfg
    path = ctx.project / "infra" / "Caddyfile"
    if c["caddy.manage_caddyfile"]:
        ctx.project_file("infra/Caddyfile", caddyfile(ctx, level), managed=True)
    elif not path.exists():
        raise DevstackError(f"caddy.manage_caddyfile = false but {path} does not exist")
    elif caddyfile_has_global_block(path.read_text()):
        raise DevstackError(f"{path} starts with a global options block; devstack owns those in /etc/caddy/Caddyfile "
                            "(which imports your file). Move the block out of it")
    elif caddyfile_defines(path.read_text(), SAME_ORIGIN_SNIPPET):
        raise DevstackError(f"{path} defines ({SAME_ORIGIN_SNIPPET}), which /etc/caddy/Caddyfile already does, and "
                            "Caddy refuses a second definition: delete it and keep the `import`")
    ctx.cwrite("/etc/caddy/Caddyfile", caddy_global(ctx, level))
    ctx.cexec(bash(CADDY_APPLY, RESTART=restart))


def dns_body(ctx: Ctx, ip: str) -> str:
    return (f"# devstack:{ctx.cfg['stack.name']} — generated by devstack, removed by `devstack undo`. Do not edit.\n"
            + "\n".join(ProxyPhase._dns_lines(ctx, ip)) + "\n")


def write_dns(ctx: Ctx, ip: str) -> None:
    c = ctx.cfg
    ctx.write_host_file(Path(c["dns.dnsmasq_file"]), dns_body(ctx, ip), sudo=True, then_restart=c["dns.dnsmasq_service"])
    ctx.r.run(["systemctl", "restart", c["dns.dnsmasq_service"]], sudo=True)


def pending_dns(ctx: Ctx) -> bool:
    """The stack's dnsmasq drop-in differs from what proxy would write now: a dev server added with
    dns.wildcard = false needs its host-record, and the proxy phase is already done."""
    ip = ctx.state.fact("ipv4")
    if ctx.state.status("proxy") != "done" or not ip:
        return False
    try:
        return Path(ctx.cfg["dns.dnsmasq_file"]).read_text() != dns_body(ctx, ip)
    except OSError:
        return False


def refresh_dns(ctx: Ctx) -> bool:
    """Rewrite the drop-in and restart dnsmasq, journaled under proxy like the original (undo restores it)."""
    if not pending_dns(ctx):
        return False
    ctx.phase = "proxy"
    log.info("")
    log.info("==> proxy: updating %s", ctx.cfg["dns.dnsmasq_file"])
    write_dns(ctx, ctx.state.fact("ipv4"))
    return True


CADDY_PHASES = {"proxy": LEVEL_PROXY, "standards": LEVEL_STANDARDS, "isolation": LEVEL_ISOLATION}


def caddy_level(ctx: Ctx) -> int | None:
    """The Caddyfile level the done phases have reached, or None before proxy."""
    done = [lvl for pid, lvl in CADDY_PHASES.items() if ctx.state.status(pid) == "done"]
    return max(done, default=None)


def pending_caddy(ctx: Ctx) -> list[str]:
    """Caddy files on an existing container that differ from what its done phases would write now: devstack
    changed them (the same-origin snippet, say) or caddy.same_origin / caddy.max_request_body did."""
    level = caddy_level(ctx)
    if level is None or not ctx.instance_running():
        return []
    out = []
    if ctx.cread("/etc/caddy/Caddyfile") != caddy_global(ctx, level):
        out.append("/etc/caddy/Caddyfile")
    path = ctx.project / "infra" / "Caddyfile"
    if ctx.cfg["caddy.manage_caddyfile"] and (not path.exists() or path.read_text() != caddyfile(ctx, level)):
        out.append(str(path))
    return out


def refresh_caddy(ctx: Ctx) -> bool:
    """Rewrite the Caddy files pending_caddy lists, validate as caddy and reload. Journaled under the last
    phase that wrote them, so undoing it puts the old managed Caddyfile back."""
    stale = pending_caddy(ctx)
    if not stale:
        return False
    level = caddy_level(ctx)
    assert level is not None
    ctx.phase = LEVEL_NAMES[level]
    log.info("")
    log.info("==> %s: updating Caddy (%s)", ctx.phase, ", ".join(stale))
    apply_caddyfile(ctx, level)
    return True


SYNC_PATH = "/usr/local/sbin/devstack-sync"


def sync_script_stale(ctx: Ctx) -> bool:
    """devstack-sync on an existing container differs from what isolation would install now (a new verb)."""
    return (ctx.state.status("isolation") == "done" and ctx.instance_running()
            and ctx.cread(SYNC_PATH) != devstack_sync_script(ctx.cfg))


def refresh_sync(ctx: Ctx) -> bool:
    """Reinstall devstack-sync from its template. Same verbs for the same config as a fresh isolation
    phase would give, so no capability beyond what the config already grants."""
    if not sync_script_stale(ctx):
        return False
    ctx.phase = "isolation"
    log.info("")
    log.info("==> isolation: updating %s", SYNC_PATH)
    ctx.cwrite(SYNC_PATH, devstack_sync_script(ctx.cfg), mode="0755")
    return True


SAME_ORIGIN_PROBE = "https://devstack-check.invalid"


def verify_same_origin(ctx: Ctx) -> None:
    """A foreign fetch gets 403 and the site's own doesn't: the snippet is imported, and still matches."""
    c = ctx.cfg
    url = f"https://{c.dev_host}/"

    def status(*headers: str) -> str:
        args = [a for h in headers for a in ("-H", h)]
        return host_curl(ctx, url, "-o", "/dev/null", "-w", "%{http_code}", *args).stdout.strip()

    foreign = status("Sec-Fetch-Site: cross-site", "Sec-Fetch-Mode: cors", f"Origin: {SAME_ORIGIN_PROBE}")
    expect(foreign == "403", f"a cross-site fetch to {url} got {foreign or 'no answer'}, expected 403: is "
           f"`import {SAME_ORIGIN_SNIPPET}` in the site block? (caddy.same_origin = {c['caddy.same_origin']})")
    own = status("Sec-Fetch-Site: same-origin", "Sec-Fetch-Mode: cors", f"Origin: https://{c.dev_host}")
    expect(own not in ("403", ""), f"a same-origin fetch to {url} got {own or 'no answer'}: the same-origin rule "
           "blocks the site's own pages")


def container_ca_file(c: Config) -> str:
    return f"/usr/local/share/ca-certificates/devstack-{c['stack.name']}.crt"


CONTAINER_TLS_CHECK = r"""
host=@@HOST@@
curl -sS -o /dev/null --max-time 15 "https://$host/" || { echo "curl inside the container doesn't trust https://$host/" >&2; exit 1; }
NODE_EXTRA_CA_CERTS=@@CA@@ node -e 'fetch(process.argv[1]).then(r => process.exit(r.ok ? 0 : 1), e => { console.error(String(e.cause ?? e)); process.exit(1); })' "https://$host/"
"""


class ProxyPhase(Phase):
    id = "proxy"
    title = "Caddy, local TLS, host DNS + CA trust"
    layer = "proxy"

    def describe(self, ctx: Ctx) -> list[str]:
        c = ctx.cfg
        return [
            "in container: Caddy apt repo (signing key fingerprint checked) + caddy",
            f"host: local root CA in {ctx.state_dir}/ca (openssl, key stays on the host, name-constrained to "
            f"{', '.join(ca_names(c))}); intermediate CA signed there and copied to {CADDY_PKI_DIR} in the container",
            f"generate {ctx.project}/infra/Caddyfile (local_certs, {c.dev_host}: static + /api/* proxy, http:// catch-all)",
            f"/etc/caddy/Caddyfile: global options (local_certs, pki) + import {ctx.cproject}/infra/Caddyfile; "
            "validate as the caddy user; reload caddy",
            f"host: install the root CA as {c['tls.host_ca_file']} (sudo update-ca-certificates); the container "
            f"trusts it too ({container_ca_file(c)}, NODE_EXTRA_CA_CERTS for login shells)",
            f"host: browser NSS trust ({c['tls.browser_trust']}) as '{c['tls.nss_nickname']}' in {c['tls.nss_db']}",
            f"host: {c['dns.dnsmasq_file']} -> {self._dns_lines(ctx, '<ip>')!r}; restart {c['dns.dnsmasq_service']}",
            f"verify: https://{c.dev_host}/ from the host (real DNS + system CA store)",
        ]

    @staticmethod
    def _dns_lines(ctx: Ctx, ip: str) -> list[str]:
        c = ctx.cfg
        lines = []
        if c["dns.wildcard"]:
            lines.append(f"address=/{c['dns.tld'] or c['site.hostname']}/{ip}")
        else:
            lines.append(f"host-record={c.dev_host},{ip}")
            lines += [f"host-record={n}.{c.dev_host},{ip}" for n in sorted(c["caddy.dev_servers"])]
        lines += [f"host-record={n},{ip}" for n in c["dns.extra_names"]]
        return lines

    def apply(self, ctx: Ctx) -> None:
        c = ctx.cfg
        log.info("  installing Caddy")
        ctx.cexec(bash(CADDY_INSTALL, FPR=CADDY_KEY_FPR), stream=True)

        ca_copy = ensure_host_ca(ctx)
        ca_dir = ca_copy.parent
        ctx.cwrite(f"{CADDY_PKI_DIR}/intermediate.crt", (ca_dir / "intermediate.crt").read_text())
        ctx.cwrite(f"{CADDY_PKI_DIR}/intermediate.key", (ca_dir / "intermediate.key").read_text(),
                   mode="0640", group="caddy", secret=True)
        apply_caddyfile(ctx, LEVEL_PROXY)
        # Pick up the intermediate even if Caddy already ran: drop leaves issued by an older one.
        ctx.cexec("rm -rf /var/lib/caddy/.local/share/caddy/certificates/local; systemctl restart caddy")
        self._trust_ca(ctx, ca_copy, ca_copy.read_text())
        # The container trusts the root too (only its certificate; the key never leaves the host, and it is
        # name-constrained to the dev domain), so curl and Node inside can call the app through Caddy.
        ctx.cwrite(container_ca_file(c), ca_copy.read_text())
        ctx.cwrite("/etc/profile.d/devstack-ca.sh",
                   f"# GENERATED by devstack: Node uses its own CA list; add the devstack root (dev domain only).\n"
                   f"export NODE_EXTRA_CA_CERTS={container_ca_file(c)}\n")
        ctx.cexec("update-ca-certificates >/dev/null")

        write_dns(ctx, ctx.state.fact("ipv4"))

    def _trust_ca(self, ctx: Ctx, ca_copy: Path, ca: str) -> None:
        c = ctx.cfg
        dest = Path(c["tls.host_ca_file"])
        same = False
        try:
            same = dest.exists() and dest.read_text() == ca
        except OSError:
            pass
        if not same:
            if not ctx.journal.find("host_ca", ACTIVE, path=str(dest)):
                e = ctx.journal.add(ctx.phase, "host_ca", path=str(dest))
            else:
                e = ctx.journal.find("host_ca", ACTIVE, path=str(dest))
            ctx.r.run(["install", "-D", "-m", "644", "-o", "root", "-g", "root", ca_copy, dest], sudo=True)
            ctx.r.run(["update-ca-certificates"], sudo=True, stream=True)
            ctx.journal.mark(e, "applied")
            log.info("  host trusts the devstack root CA (%s)", dest)

        mode, db, nick = c["tls.browser_trust"], c["tls.nss_db"], c["tls.nss_nickname"]
        possible = shutil.which("certutil") is not None and Path(db).is_dir()
        if mode == "no":
            log.info("  your everyday browser doesn't trust the dev CA (tls.browser_trust = no): open the site "
                     "with `devstack browse`")
            return
        if mode == "auto" and not possible:
            log.warning("everyday browser trust not configured (no certutil or %s). Prefer `devstack browse`; "
                        "otherwise in Chromium: chrome://certificate-manager/localcerts/usercerts -> Trusted "
                        "Certificates -> Import -> %s", db, ca_copy)
            return
        if not possible:
            raise DevstackError(f"tls.browser_trust = 'yes' but certutil or {db} is missing (apt install libnss3-tools)")
        ctx.r.run(["certutil", "-D", "-d", f"sql:{db}", "-n", nick], check=False)
        if not ctx.journal.find("nss_cert", ACTIVE, db=db, nickname=nick):
            e = ctx.journal.add(ctx.phase, "nss_cert", db=db, nickname=nick)
        else:
            e = ctx.journal.find("nss_cert", ACTIVE, db=db, nickname=nick)
        ctx.r.run(["certutil", "-A", "-d", f"sql:{db}", "-t", "C,,", "-n", nick, "-i", ca_copy])
        ctx.journal.mark(e, "applied")
        log.info("  browser NSS db trusts the CA as '%s' (restart Chromium to pick it up)", nick)

    def verify(self, ctx: Ctx) -> None:
        c = ctx.cfg
        ip = ctx.state.fact("ipv4")
        resolved = ""
        for _ in range(10):
            resolved = ctx.r.run(["getent", "ahostsv4", c.dev_host], check=False).stdout.split()[:1]
            resolved = resolved[0] if resolved else ""
            if resolved == ip:
                break
            time.sleep(1)
        expect(resolved == ip, f"{c.dev_host} resolves to {resolved or 'nothing'} on the host, expected {ip}. "
               "Is the host really resolving through dnsmasq? (index.html, 'Host DNS')")
        p = host_curl(ctx, f"https://{c.dev_host}/", "-f")
        expect(p.returncode == 0, f"https://{c.dev_host}/ failed from the host: {p.stderr.strip()}")
        expect("devstack-smoke" in p.stdout or not c["project.scaffold"],
               "the page served is not the scaffolded static/index.html")
        if c["dns.wildcard"] and c["dns.tld"]:
            p = host_curl(ctx, f"http://devstack-check.{c['dns.tld']}/")
            expect("devstack-error" in p.stdout or not c["project.scaffold"],
                   "http:// catch-all did not serve the error page")
        p = ctx.cexec(bash(CONTAINER_TLS_CHECK, HOST=c.dev_host, CA=container_ca_file(c)), user=c["container.user"],
                      check=False)
        expect(p.returncode == 0, f"https://{c.dev_host}/ from inside the container: {p.stderr.strip()}")
        log.info("  https://%s/ OK (host, and curl + Node inside the container)", c.dev_host)
        owned = ctx.project / "infra" / "Caddyfile"
        if c["caddy.same_origin"] != "off" and (
                c["caddy.manage_caddyfile"] or caddyfile_imports(owned.read_text(), SAME_ORIGIN_SNIPPET)):
            verify_same_origin(ctx)
            log.info("  cross-site requests get 403, same-origin ones pass (caddy.same_origin = %s)",
                     c["caddy.same_origin"])


class StandardsPhase(Phase):
    id = "standards"
    title = "compression + security headers"
    layer = "standards"

    def describe(self, ctx: Ctx) -> list[str]:
        return [
            "in container: apt install brotli",
            f"write {ctx.project}/infra/compress-static.sh and precompress static/ and error/ (.br, .gz)",
            "Caddyfile: encode zstd gzip, precompressed br gzip, (error_page) + handle_errors, "
            "security headers (caddy.headers) with the error page's <style> hash in the CSP",
            "verify: CSP header present, brotli served for /style.css",
        ]

    def apply(self, ctx: Ctx) -> None:
        c = ctx.cfg
        ctx.apt_install("brotli")
        ctx.project_file("infra/compress-static.sh", (TEMPLATES / "project/infra/compress-static.sh").read_text(),
                         mode=0o755, managed=True)
        dirs = [c["caddy.static_dir"], c["caddy.error_dir"]]
        host_dirs = [ctx.project / Path(d).relative_to(ctx.cproject) for d in dirs if Path(d).is_relative_to(ctx.cproject)]
        before = {p for d in host_dirs if d.exists() for p in d.rglob("*") if p.suffix in (".br", ".gz")}
        ctx.cexec(bash(r'''
            cd @@P@@
            dirs=(@@DIRS@@)
            ./infra/compress-static.sh "${dirs[@]}"
        ''', P=ctx.cproject, DIRS=dirs), user=c["container.user"])
        after = {p for d in host_dirs if d.exists() for p in d.rglob("*") if p.suffix in (".br", ".gz")}
        for p in sorted(after - before):
            ctx.track_generated(p)
        apply_caddyfile(ctx, LEVEL_STANDARDS)

    def verify(self, ctx: Ctx) -> None:
        c = ctx.cfg
        p = host_curl(ctx, f"https://{c.dev_host}/", "-o", "/dev/null", "-D", "-")
        expect(p.returncode == 0, f"https://{c.dev_host}/ failed: {p.stderr.strip()}")
        expect("content-security-policy:" in p.stdout.lower(), "no Content-Security-Policy header")
        if c["project.scaffold"]:
            p = host_curl(ctx, f"https://{c.dev_host}/style.css", "-f", "-o", "/dev/null", "-D", "-",
                          "-H", "Accept-Encoding: br")
            expect("content-encoding: br" in p.stdout.lower(), "style.css was not served brotli-compressed")
        log.info("  headers + compression OK")


UFW_APPLY = r"""
allow=(@@ALLOW@@); deny=(@@DENY@@)
ufw default deny incoming
ufw default allow outgoing
for p in "${allow[@]}"; do ufw allow "$p/tcp"; done
for p in "${deny[@]}"; do ufw deny "$p/tcp"; done
ufw --force enable
ufw status verbose
"""

# Fixed ids (isolation.system_uid_base) so owners on persistent volumes and the egress profiles'
# uid matches never change. The app's primary group is the data group; runners get their own group
# and are deliberately not in the data group (they can only reach incoming/).
ACCOUNTS = r"""
stack=@@STACK@@; user=@@USER@@
app=@@APP@@; runner=@@RUNNER@@; data=@@DATA@@; dev=@@DEV@@
app_uid=@@APP_UID@@; runner_uid=@@RUNNER_UID@@; data_gid=@@DATA_GID@@; dev_gid=@@DEV_GID@@
ensure_group() {  # name gid
  if getent group "$1" >/dev/null; then
    [ "$(getent group "$1" | cut -d: -f3)" = "$2" ] || { echo "group $1 exists with gid $(getent group "$1" | cut -d: -f3), expected $2" >&2; exit 1; }
  else
    if getent group "$2" >/dev/null; then
      echo "gid $2 is taken by $(getent group "$2" | cut -d: -f1); change isolation.system_uid_base" >&2; exit 1
    fi
    groupadd --system --gid "$2" "$1"
  fi
}
ensure_user() {  # name uid primary-group what
  if id -u "$1" >/dev/null 2>&1; then
    [ "$(id -u "$1")" = "$2" ] || { echo "user $1 exists with uid $(id -u "$1"), expected $2" >&2; exit 1; }
    usermod -g "$3" "$1"
  else
    if getent passwd "$2" >/dev/null; then
      echo "uid $2 is taken by $(getent passwd "$2" | cut -d: -f1); change isolation.system_uid_base" >&2; exit 1
    fi
    useradd --system --uid "$2" --gid "$3" --no-create-home --home-dir /nonexistent \
      --shell /usr/sbin/nologin --comment "devstack $stack $4" "$1"
  fi
}
ensure_group "$data" "$data_gid"
ensure_group "$dev" "$dev_gid"
ensure_group "$runner" "$runner_uid"
ensure_user "$app" "$app_uid" "$data" "app"
ensure_user "$runner" "$runner_uid" "$runner" "runner jobs"
if id -nG "$runner" | tr ' ' '\n' | grep -qx "$data"; then gpasswd -d "$runner" "$data" >/dev/null; fi
usermod -aG "$data,$dev" "$user"
"""

# Readable by the dev group, so dev servers that call the API directly can use the token.
TOKEN_WRITE = r"""
dir=@@DIR@@; file=@@FILE@@; group=@@GROUP@@
install -d -m 710 -o root -g "$group" "$dir"
chown root:"$group" "$dir"
chmod 710 "$dir"
umask 077
if [ -s "$file" ]; then cat >/dev/null; echo kept; else cat > "$file"; echo created; fi
chown root:"$group" "$file"
chmod 640 "$file"
"""

# The data folder is o+x (runners traverse to incoming/, nobody lists it); what the app writes below
# it is 0640/2750 (UMask=0027). incoming/ is the runners', readable and cleanable by the app's group.
DATA_SETUP = r"""
dir=@@DIR@@; app=@@APP@@; data=@@DATA@@; runner=@@RUNNER@@
mountpoint -q "$dir" || { echo "$dir is not the app data mount" >&2; exit 1; }
chown "$app:$data" "$dir"
chmod 2751 "$dir"
install -d "$dir/incoming"
chown "$runner:$data" "$dir/incoming"
chmod 2770 "$dir/incoming"
"""

EGRESS_APPLY = r"""
nft -c -f /etc/devstack/egress.nft
# Debian's nftables.service flushes the whole ruleset (ufw's included) when it starts or stops.
systemctl disable nftables.service >/dev/null 2>&1 || true
systemctl daemon-reload
systemctl enable devstack-egress.service >/dev/null 2>&1
systemctl restart devstack-egress.service
nft list table inet devstack_egress >/dev/null
"""

RUNNERS_APPLY = r"""
want=(@@WANT@@)
list=/etc/devstack/runners
install -d -m 755 /etc/devstack
if [ -f "$list" ]; then
  while IFS= read -r old; do
    [ -n "$old" ] || continue
    keep=false
    for w in "${want[@]}"; do [ "$w" = "$old" ] && keep=true; done
    if [ "$keep" = false ]; then
      systemctl disable --now "$old.socket" >/dev/null 2>&1 || true
      systemctl stop "$old@*.service" >/dev/null 2>&1 || true
      rm -f "/etc/systemd/system/$old.socket" "/etc/systemd/system/$old@.service"
      echo "removed runner $old"
    fi
  done < "$list"
fi
printf '%s\n' "${want[@]}" > "$list"
systemctl daemon-reload
for w in "${want[@]}"; do
  systemctl enable "$w.socket" >/dev/null 2>&1
  systemctl restart "$w.socket"
done
"""

TOKEN_ENV_DROPIN = """\
# Managed by devstack
[Service]
EnvironmentFile={token}
# Admin API socket lives here (caddy.admin); 0700 keeps everyone but caddy and root out.
RuntimeDirectory=caddy
RuntimeDirectoryMode=0700
"""

UNIT_START = r"""
unit=@@UNIT@@
systemctl daemon-reload
systemctl enable "$unit"
systemctl restart "$unit"
sleep 1
if ! systemctl is-active --quiet "$unit"; then journalctl -u "$unit" -n 50 --no-pager >&2; exit 1; fi
"""

LOOPBACK_ONLY = r"""
port=@@PORT@@
lines=$(ss -Htln "sport = :$port")
[ -n "$lines" ] || { echo "nothing listens on port $port" >&2; exit 1; }
if echo "$lines" | awk '{print $4}' | grep -vqE '^(127\.0\.0\.1|\[::1\]):'; then
  echo "port $port is listening on a non-loopback address:" >&2; echo "$lines" >&2; exit 1
fi
"""

ISOLATION_CHECK = r"""
hostport=@@HOSTPORT@@; unit=@@UNIT@@; fw=@@FW@@
code=$(curl -s -o /dev/null -w '%{http_code}' "http://$hostport/api/health")
[ "$code" = 500 ] || { echo "direct request without the token returned $code, expected 500" >&2; exit 1; }
if [ "$fw" = true ]; then ufw status | grep -q '^Status: active' || { echo "ufw is not active" >&2; exit 1; }; fi
systemd-analyze security --no-pager "$unit" | tail -n 1
"""

# Run as root; each probe runs as the service user, which is what the egress profiles match on.
# Security properties fail the phase; "should reach the internet" only warns.
PROFILE_CHECK = r"""
app=@@APP@@; runner=@@RUNNER@@; user=@@USER@@; profile=@@PROFILE@@; sudo_mode=@@SUDO@@
datadir=@@DATADIR@@; resolvers=(@@RESOLVERS@@)
fail() { echo "$*" >&2; exit 1; }
probe() { runuser -u "$1" -- timeout 4 bash -c 'exec 3<>"/dev/tcp/$0/$1"' "$2" "$3" 2>/dev/null; }
nft list table inet devstack_egress >/dev/null 2>&1 || fail "egress profiles are not loaded (table inet devstack_egress)"
if [ "$profile" != open ]; then
  probe "$app" 127.0.0.1 443 || fail "$app can't reach 127.0.0.1:443 (Caddy) although its profile allows loopback"
fi
if [ "$profile" = local ]; then
  ! probe "$app" 1.1.1.1 443 || fail "$app reached 1.1.1.1:443 although app.profile = local"
  for r in "${resolvers[@]}"; do
    ! probe "$app" "$r" 53 || fail "$app reached the DNS resolver $r:53 (a way out through DNS)"
  done
fi
! probe "$runner" 127.0.0.1 443 || fail "$runner reached 127.0.0.1:443: runners must not reach loopback"
probe "$runner" 1.1.1.1 443 || echo "warning: $runner can't reach 1.1.1.1:443 (no internet from the container?)" >&2
! timeout 3 bash -c 'exec 3<>/dev/tcp/127.0.0.1/2019' 2>/dev/null || fail "Caddy's admin API still listens on 127.0.0.1:2019"
if [ "$sudo_mode" != full ]; then
  [[ " $(id -nG "$user") " != *" sudo "* ]] || fail "$user is still in the sudo group"
  extra=$(sudo -n -l -U "$user" 2>/dev/null | sed -n '/may run the following commands/,$p' | tail -n +2 \
    | grep -v '/usr/local/sbin/devstack-sync' | grep -v '^[[:space:]]*$' || true)
  [ -z "$extra" ] || fail "sudo lets $user run more than devstack-sync: $extra"
fi
if [ -n "$datadir" ]; then
  f="$datadir/.devstack-check"
  runuser -u "$app" -- bash -c 'umask 0027; echo ok > "$0"' "$f" || fail "$app can't write $datadir"
  runuser -u "$user" -- cat "$f" >/dev/null 2>&1 || { rm -f "$f"; fail "$user can't read the app data in $datadir"; }
  if runuser -u "$user" -- bash -c ': > "$0"' "$datadir/.devstack-dev-check" 2>/dev/null; then
    rm -f "$f" "$datadir/.devstack-dev-check"; fail "$user can write $datadir (it should only read it)"
  fi
  if runuser -u "$runner" -- cat "$f" >/dev/null 2>&1; then rm -f "$f"; fail "$runner can read the app data"; fi
  rm -f "$f"
  runuser -u "$runner" -- bash -c ': > "$0" && rm -f "$0"' "$datadir/incoming/.devstack-check" \
    || fail "$runner can't write $datadir/incoming"
fi
"""


def nameservers(resolv_conf: str) -> list[str]:
    """The nameserver addresses in a resolv.conf."""
    out = []
    for ln in resolv_conf.splitlines():
        parts = ln.split()
        if len(parts) >= 2 and parts[0] == "nameserver":
            try:
                out.append(str(ipaddress.ip_address(parts[1].split("%")[0])))
            except ValueError:
                pass
    return out


def egress_nft(c: Config, resolvers: list[str]) -> str:
    ids = isolation_ids(c)
    app, runner, profile = c["isolation.app_user"], c["isolation.runner_user"], c["app.profile"]
    chain = {"local": "local_only", "internet": "local_internet"}.get(profile)
    rules = [f"\t\tmeta skuid {ids['app_uid']} jump {chain}  # {app}: app.profile = \"{profile}\"" if chain else
             f"\t\t# {app} ({ids['app_uid']}): app.profile = \"open\", not restricted",
             f"\t\tmeta skuid {ids['runner_uid']} jump internet_only  # {runner}: runner jobs"]
    dns = [f"\t\t{'ip' if ipaddress.ip_address(r).version == 4 else 'ip6'} daddr {r} "
           "meta l4proto { tcp, udp } th dport 53 accept" for r in resolvers]
    return render("system/egress.nft", {
        "STACK": c["stack.name"], "USER_RULES": "\n".join(rules),
        "RESOLVER_RULES": "\n".join(dns) or "\t\t# no nameserver in /etc/resolv.conf: runners get no DNS",
    })


def runner_units(c: Config, tv: dict[str, Any]) -> dict[str, str]:
    """Container path -> content of every runner's socket and service unit."""
    data = app_data_dir(c)
    incoming = f"{data}/incoming" if data else ""
    out = {}
    for r in c["app.runners"]:
        unit = runner_unit(c, r)
        vals = {**tv, "NAME": r["name"], "UNIT": unit, "PORT": r["port"], "COMMAND": r["command"],
                "MAX_CONNECTIONS": r["max_connections"], "MEMORY_MAX": r["memory_max"],
                "RUNTIME_MAX": r["runtime_max"], "INCOMING": incoming,
                "INCOMING_LINES": f"ReadWritePaths={incoming}" if incoming else
                '# app.data = "none": nothing is writable.'}
        out[f"/etc/systemd/system/{unit}.socket"] = render("system/runner.socket", vals)
        out[f"/etc/systemd/system/{unit}@.service"] = render("system/runner@.service", vals)
    return out


def devstack_sync_script(c: Config) -> str:
    return render("system/devstack-sync", {
        "STACK": c["stack.name"],
        "APP_UNIT": shlex.quote(f"{c['app.service_name']}.service"),
        "RUNNER_SOCKETS": " ".join(shlex.quote(f"{runner_unit(c, r)}.socket") for r in c["app.runners"]),
    })


def ensure_volume(ctx: Ctx, vol: str, adopt_ok: bool) -> None:
    """Create a custom volume (journaled, kept on undo), or reuse ours, or adopt one (preflight allowed it)."""
    pool = ctx.cfg["container.storage_pool"]
    own = ctx.journal.find("incus_volume", OWNED, pool=pool, volume=vol)
    if ctx.volume(vol) is None:
        e = ctx.journal.add(ctx.phase, "incus_volume", pool=pool, volume=vol, adopted=False)
        ctx.r.run(["incus", "storage", "volume", "create", pool, vol])
        ctx.journal.mark(e, "applied")
    elif own is not None:
        log.info("  reusing data volume %s/%s", pool, vol)
        if own["status"] == "kept":
            own["phase"] = ctx.phase
            ctx.journal.mark(own, "applied")
    else:
        assert adopt_ok, f"volume {vol} is not ours (preflight should have stopped this)"
        e = ctx.journal.add(ctx.phase, "incus_volume", pool=pool, volume=vol, adopted=True)
        ctx.journal.mark(e, "applied")
        log.info("  adopting existing volume %s/%s", pool, vol)


class IsolationPhase(Phase):
    id = "isolation"
    title = "firewall, egress profiles, service users, app data, runners, limited sudo"
    layer = "isolation"

    def deny_ports(self, c: Config) -> list[int]:
        ports = [*c["firewall.deny"], c["app.port"], *(r["port"] for r in c["app.runners"])]
        if c["postgres.enabled"]:
            ports.append(c["postgres.port"])
        return sorted(set(ports))

    def describe(self, ctx: Ctx) -> list[str]:
        c = ctx.cfg
        unit = c["app.service_name"]
        ids = isolation_ids(c)
        fw = (f"ufw: deny in by default, allow {c['firewall.allow']}, deny {self.deny_ports(c)}"
              if c["firewall.enabled"] else "ufw: disabled by config")
        data = {"volume": f"incus volume {c['container.storage_pool']}/{c['app.data_volume']} (kept on undo)",
                "host": f"host folder {c['app.data_source']}", "none": None}[c["app.data"]]
        runners = ", ".join(f"{r['name']} (127.0.0.1:{r['port']}: {r['command']})" for r in c["app.runners"])
        return [
            fw,
            f"users {c['isolation.app_user']} ({ids['app_uid']}), {c['isolation.runner_user']} ({ids['runner_uid']}); "
            f"groups {c['isolation.data_group']} ({ids['data_gid']}), {c['isolation.dev_group']} ({ids['dev_gid']}); "
            f"{c['container.user']} joins both groups",
            f"secret {c['secrets.dir']}/{c['secrets.token_file']} (INTERNAL_TOKEN, root:{c['isolation.dev_group']} "
            "640, generated once)",
            (f"app data: {data} at {app_data_dir(c)} (StateDirectory; {c['container.user']} reads, can't write)"
             if data else "app data: none"),
            f"nftables egress profiles (/etc/devstack/egress.nft, devstack-egress.service): app '{c['app.profile']}', "
            "runners 'internet' (no loopback, no private ranges)",
            f"Caddy: admin API on {c['caddy.admin']} (not TCP); drop-in EnvironmentFile=<token>; Caddyfile: (common) "
            "strips Server/Via, reverse_proxy adds X-Internal-Token, masks upstream 500s; restart caddy",
            f"systemd unit {unit}.service from templates/system/app.service (User={c['isolation.app_user']}, "
            "ProtectSystem=strict, ...); copy in infra/; enable --now",
            f"runners: {runners}" if runners else "runners: none",
            f"/usr/local/sbin/devstack-sync; sudo for {c['container.user']}: {c['container.sudo']}",
            f"verify: {c['app.port']} on loopback only, direct call without token -> 500, "
            f"https://{c.dev_host}/api/health -> 200, no Server header, egress profiles per user, "
            "Caddy admin off TCP, sudo, app data permissions",
        ]

    def apply(self, ctx: Ctx) -> None:
        c = ctx.cfg
        tv = ctx.tvars()
        ids = isolation_ids(c)
        ctx.apt_install("nftables", *(["ufw"] if c["firewall.enabled"] else []))
        if c["firewall.enabled"]:
            log.info("  configuring ufw")
            ctx.cexec(bash(UFW_APPLY, ALLOW=c["firewall.allow"], DENY=self.deny_ports(c)), stream=True)
        log.info("  service users and groups")
        ctx.cexec(bash(ACCOUNTS, STACK=c["stack.name"], USER=c["container.user"], APP=c["isolation.app_user"],
                       RUNNER=c["isolation.runner_user"], DATA=c["isolation.data_group"], DEV=c["isolation.dev_group"],
                       APP_UID=ids["app_uid"], RUNNER_UID=ids["runner_uid"], DATA_GID=ids["data_gid"],
                       DEV_GID=ids["dev_gid"]))

        token = secrets.token_hex(32)
        REDACT.add(token)
        res = ctx.cexec(bash(TOKEN_WRITE, DIR=c["secrets.dir"], FILE=tv["TOKEN_ENV"], GROUP=c["isolation.dev_group"]),
                        input=f"INTERNAL_TOKEN={token}\n", secret_input=True)
        log.info("  internal token %s", res.stdout.strip())

        if c["app.data"] != "none":
            self._app_data(ctx)

        log.info("  egress profiles (nftables)")
        resolvers = nameservers(ctx.cread("/etc/resolv.conf") or "")
        ctx.cwrite("/etc/devstack/egress.nft", egress_nft(c, resolvers))
        ctx.cwrite("/etc/systemd/system/devstack-egress.service", render("system/devstack-egress.service", tv))
        ctx.cexec(EGRESS_APPLY)

        ctx.cwrite("/etc/systemd/system/caddy.service.d/10-devstack.conf", TOKEN_ENV_DROPIN.format(token=tv["TOKEN_ENV"]))
        ctx.cexec("systemctl daemon-reload")
        # A restart, not a reload: `caddy reload` would look for the new admin socket before it exists.
        apply_caddyfile(ctx, LEVEL_ISOLATION, restart=True)

        unit_text = render("system/app.service", tv)
        unit = c["app.service_name"]
        ctx.cwrite(f"/etc/systemd/system/{unit}.service", unit_text)
        ctx.project_file(f"infra/{unit}.service", unit_text, managed=True)
        ctx.cexec(bash(UNIT_START, UNIT=f"{unit}.service"))

        units = runner_units(c, tv)
        for path, text in units.items():
            ctx.cwrite(path, text)
        ctx.cexec(bash(RUNNERS_APPLY, WANT=[runner_unit(c, r) for r in c["app.runners"]]))
        if c["app.runners"]:
            log.info("  runners: %s", ", ".join(f"{runner_unit(c, r)}.socket" for r in c["app.runners"]))

        ctx.cwrite(SYNC_PATH, devstack_sync_script(c), mode="0755")
        apply_sudo(ctx)
        log.info("  sudo for %s: %s", c["container.user"], c["container.sudo"])
        ctx.state.set_fact("runners", c["app.runners"])

    def _app_data(self, ctx: Ctx) -> None:
        c = ctx.cfg
        path = app_data_dir(c)
        if c["app.data"] == "volume":
            ensure_volume(ctx, c["app.data_volume"], c["app.data_adopt"])
            ctx.ensure_device("appdata", "disk", {"pool": c["container.storage_pool"], "source": c["app.data_volume"],
                                                  "path": path})
        else:
            ctx.ensure_device("appdata", "disk", {"source": c["app.data_source"], "path": path, "shift": "true"})
        ctx.cexec(bash(DATA_SETUP, DIR=path, APP=c["isolation.app_user"], DATA=c["isolation.data_group"],
                       RUNNER=c["isolation.runner_user"]))
        log.info("  app data at %s", path)

    def verify(self, ctx: Ctx) -> None:
        c = ctx.cfg
        unit = f"{c['app.service_name']}.service"
        p = ctx.cexec(bash(LOOPBACK_ONLY, PORT=c["app.port"]), check=False)
        expect(p.returncode == 0, p.stderr.strip())
        p = ctx.cexec(bash(ISOLATION_CHECK, HOSTPORT=f"{url_host(c['app.bind'])}:{c['app.port']}", UNIT=unit,
                           FW=c["firewall.enabled"]), check=False)
        expect(p.returncode == 0, p.stderr.strip())
        log.info("  systemd-analyze: %s", p.stdout.strip().splitlines()[-1] if p.stdout.strip() else "?")
        p = ctx.cexec(bash(PROFILE_CHECK, APP=c["isolation.app_user"], RUNNER=c["isolation.runner_user"],
                           USER=c["container.user"], PROFILE=c["app.profile"], SUDO=c["container.sudo"],
                           DATADIR=app_data_dir(c) or "",
                           RESOLVERS=nameservers(ctx.cread("/etc/resolv.conf") or "")), check=False)
        for ln in p.stderr.strip().splitlines():
            if ln.startswith("warning: "):
                log.warning("%s", ln[len("warning: "):])
        expect(p.returncode == 0, p.stderr.strip())
        log.info("  egress profiles, Caddy admin socket, sudo and app data permissions OK")
        p = host_curl(ctx, f"https://{c.dev_host}/api/health", "-f", "-D", "-")
        expect(p.returncode == 0, f"https://{c.dev_host}/api/health failed: {p.stderr.strip()}")
        expect('"ok":true' in p.stdout, f"unexpected /api/health response: {p.stdout[-300:]}")
        expect("\nserver:" not in p.stdout.lower(), "response still carries a Server header")
        log.info("  isolation OK")


PG_INSTALL = KEY_FPR_CHECK + r"""
ver=@@VER@@; port=@@PORT@@; pguid=@@PGUID@@
mirror=/var/lib/postgresql/devstack-etc
data="/var/lib/postgresql/$ver/main"
mountpoint -q /var/lib/postgresql || { echo "/var/lib/postgresql is not the data volume mount" >&2; exit 1; }
# Fixed uid/gid so a reused data volume keeps a matching owner.
if ! getent group postgres >/dev/null; then
  if getent group "$pguid" >/dev/null; then echo "gid $pguid is taken; change postgres.system_uid" >&2; exit 1; fi
  groupadd --system --gid "$pguid" postgres
fi
if ! id -u postgres >/dev/null 2>&1; then
  if getent passwd "$pguid" >/dev/null; then echo "uid $pguid is taken; change postgres.system_uid" >&2; exit 1; fi
  useradd --system --uid "$pguid" --gid postgres --home-dir /var/lib/postgresql --no-create-home \
    --shell /bin/bash --comment "PostgreSQL administrator" postgres
fi
[ "$(id -u postgres)" = "$pguid" ] || { echo "postgres has uid $(id -u postgres), expected $pguid" >&2; exit 1; }
chown postgres:postgres /var/lib/postgresql
chmod 755 /var/lib/postgresql
if [ -f "$data/PG_VERSION" ]; then
  have=$(cat "$data/PG_VERSION")
  [ "$have" = "$ver" ] || { echo "data volume holds Postgres $have data, config asks for $ver (major upgrade is manual)" >&2; exit 1; }
  [ "$(stat -c %u "$data")" = "$pguid" ] || chown -R postgres:postgres "/var/lib/postgresql/$ver"
  echo "reusing existing Postgres $ver data on the volume"
  # Restore the cluster config saved on the volume so the package doesn't try to create a new cluster.
  if [ -d "$mirror/$ver-main" ] && [ ! -d "/etc/postgresql/$ver/main" ]; then
    install -d "/etc/postgresql/$ver"
    cp -a "$mirror/$ver-main" "/etc/postgresql/$ver/main"
  fi
fi
# Never let the package auto-create a cluster: devstack decides.
install -d /etc/postgresql-common/createcluster.d
printf 'create_main_cluster = false\n' > /etc/postgresql-common/createcluster.d/10-devstack.conf
apt-get update
apt-get install -y --no-install-recommends curl ca-certificates gnupg
install -d /usr/share/postgresql-common/pgdg
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL -o "$tmp/pgdg.asc" https://www.postgresql.org/media/keys/ACCC4CF8.asc
check_key_fpr "$tmp/pgdg.asc" @@FPR@@
install -m 644 "$tmp/pgdg.asc" /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc
. /etc/os-release
printf 'deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt %s-pgdg main\n' \
  "$VERSION_CODENAME" > /etc/apt/sources.list.d/pgdg.list
apt-get update
apt-get install -y --no-install-recommends -o Dpkg::Options::=--force-confold "postgresql-$ver" "postgresql-client-$ver"
if [ ! -d "/etc/postgresql/$ver/main" ]; then
  if [ -f "$data/PG_VERSION" ]; then
    echo "data exists on the volume but its cluster config is missing ($mirror/$ver-main); restore it or use a fresh volume" >&2
    exit 1
  fi
  pg_createcluster -u postgres -p "$port" "$ver" main
fi
"""

PG_START = r"""
ver=@@VER@@; port=@@PORT@@
mirror=/var/lib/postgresql/devstack-etc
chown postgres:postgres "/etc/postgresql/$ver/main/conf.d/10-devstack.conf" "/etc/postgresql/$ver/main/pg_hba.conf"
chmod 640 "/etc/postgresql/$ver/main/pg_hba.conf"
# Keep a copy of the cluster config on the data volume (used when the container is rebuilt).
install -d -o postgres -g postgres -m 700 "$mirror"
rm -rf "$mirror/$ver-main.new"
cp -a "/etc/postgresql/$ver/main" "$mirror/$ver-main.new"
rm -rf "$mirror/$ver-main"
mv "$mirror/$ver-main.new" "$mirror/$ver-main"
systemctl enable postgresql >/dev/null
systemctl restart "postgresql@$ver-main"
for i in $(seq 1 30); do
  if pg_isready -q -h 127.0.0.1 -p "$port"; then exit 0; fi
  sleep 1
done
journalctl -u "postgresql@$ver-main" -n 50 --no-pager >&2
exit 1
"""

PG_RESTORE = r"""
envfile=@@ENVFILE@@
set -a; . "$envfile"; set +a
exec pg_restore --clean --if-exists --no-owner --single-transaction -d "$PGDATABASE"
"""

PG_VERIFY = r"""
envfile=@@ENVFILE@@; test_db=@@TEST_DB@@
set -a; . "$envfile"; set +a
pg_isready -h 127.0.0.1 -p "$PGPORT"
psql -X -At -c 'select current_user || chr(32) || current_database()'
if [ -n "$test_db" ]; then psql -X -At -d "$test_db" -c 'select 1' >/dev/null; fi
"""

DEV_ENV_WRITE = r"""
dir=@@DIR@@; file=@@FILE@@
umask 077
mkdir -p "$dir"
cat > "$file.tmp"
mv -f "$file.tmp" "$file"
"""


def dev_env_file(c: Config) -> str:
    return f"{c.user_home}/.config/devstack/{c['stack.name']}.env"


class PostgresPhase(Phase):
    id = "postgres"
    title = "Postgres on a persistent volume"
    layer = "data"

    def enabled(self, cfg: Config) -> bool:
        return cfg["postgres.enabled"]

    def describe(self, ctx: Ctx) -> list[str]:
        c = ctx.cfg
        return [
            f"host: incus volume {c['container.storage_pool']}/{c['postgres.volume']} (created if missing, kept on undo) "
            "attached at /var/lib/postgresql",
            f"in container: postgres user uid {c['postgres.system_uid']}; apt.postgresql.org; postgresql-{c['postgres.version']}",
            "reuse existing data on the volume if present, else create the cluster",
            f"listen_addresses=localhost, port {c['postgres.port']}, scram-sha-256 pg_hba (peer only for postgres)",
            f"secret {c['secrets.dir']}/{c['postgres.env_file']} (DATABASE_URL, PG*); role {c['postgres.role']}, db {c['postgres.db']}"
            + (f", empty test db {c['postgres.test_db']}" if c["postgres.test_db"] else ""),
            f"~/.pgpass for {c['container.user']}: {c['postgres.write_pgpass']}; {dev_env_file(c)} (DATABASE_URL"
            f"{', TEST_DATABASE_URL' if c['postgres.test_db'] else ''}); restart {c['app.service_name']}",
            f"verify: pg_isready, login as {c['postgres.role']}, loopback only, /api/health db=true",
        ]

    def apply(self, ctx: Ctx) -> None:
        c = ctx.cfg
        pool, vol = c["container.storage_pool"], c["postgres.volume"]
        ensure_volume(ctx, vol, c["postgres.adopt_volume"])
        ctx.ensure_device("pgdata", "disk", {"pool": pool, "source": vol, "path": "/var/lib/postgresql"})

        log.info("  installing Postgres %s", c["postgres.version"])
        ctx.cexec(bash(PG_INSTALL, VER=c["postgres.version"], PORT=c["postgres.port"],
                       PGUID=c["postgres.system_uid"], FPR=PGDG_KEY_FPR), stream=True)
        tv = ctx.tvars()
        confdir = f"/etc/postgresql/{c['postgres.version']}/main"
        ctx.cwrite(f"{confdir}/conf.d/10-devstack.conf", render("system/postgresql-devstack.conf", tv),
                   owner="postgres")
        ctx.cwrite(f"{confdir}/pg_hba.conf", render("system/pg_hba.conf", tv), mode="0640", owner="postgres")
        ctx.cexec(bash(PG_START, VER=c["postgres.version"], PORT=c["postgres.port"]))

        password = self._credentials(ctx)
        role, db = c["postgres.role"], c["postgres.db"]
        sql = textwrap.dedent(f"""\
            \\set ON_ERROR_STOP on
            SELECT format('CREATE ROLE %I LOGIN', '{role}') WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{role}') \\gexec
            ALTER ROLE "{role}" WITH LOGIN PASSWORD '{password}';
            SELECT format('CREATE DATABASE %I OWNER %I', '{db}', '{role}') WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '{db}') \\gexec
            ALTER DATABASE "{db}" OWNER TO "{role}";
        """)
        test_db = c["postgres.test_db"]
        if test_db:
            sql += textwrap.dedent(f"""\
                SELECT format('CREATE DATABASE %I OWNER %I', '{test_db}', '{role}') WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '{test_db}') \\gexec
                ALTER DATABASE "{test_db}" OWNER TO "{role}";
            """)
        ctx.cexec(bash("runuser -u postgres -- psql -X -q -v ON_ERROR_STOP=1 -p @@PORT@@ -f -", PORT=c["postgres.port"]),
                  input=sql, secret_input=True)
        if c["postgres.write_pgpass"]:
            dbs = [db, *([c["postgres.test_db"]] if c["postgres.test_db"] else [])]
            # As the user, like the dev env file: root never writes through a path the user controls.
            ctx.cexec(bash(DEV_ENV_WRITE, DIR=c.user_home, FILE=f"{c.user_home}/.pgpass"), user=c["container.user"],
                      input="".join(f"{h}:{c['postgres.port']}:{d}:{role}:{password}\n"
                                    for d in dbs for h in ("127.0.0.1", "localhost")), secret_input=True)
        self._dev_env(ctx, password)
        if ctx.state.status("isolation") == "done":
            ctx.cexec(bash(UNIT_START, UNIT=f"{c['app.service_name']}.service"))

    def _dev_env(self, ctx: Ctx, password: str) -> None:
        """~/.config/devstack/<stack>.env for dev tools (`node --env-file-if-exists=...`). Written as the
        user, into the user's own folder: root never writes through a path the user controls."""
        c = ctx.cfg
        role, port = c["postgres.role"], c["postgres.port"]
        url = lambda db: f"postgresql://{role}:{password}@127.0.0.1:{port}/{db}"  # noqa: E731
        env = [f"# GENERATED by devstack (stack {c['stack.name']}). Database URLs for dev tools; the app",
               f"# service gets its own copy from {c['secrets.dir']}/{c['postgres.env_file']}.",
               f"DATABASE_URL={url(c['postgres.db'])}"]
        if c["postgres.test_db"]:
            env += ["# Integration tests only: an empty database they may wipe. Refuse to run tests",
                    "# unless the database name ends in _test.",
                    f"TEST_DATABASE_URL={url(c['postgres.test_db'])}"]
        ctx.cexec(bash(DEV_ENV_WRITE, DIR=f"{c.user_home}/.config/devstack", FILE=dev_env_file(c)),
                  user=c["container.user"], input="\n".join(env) + "\n", secret_input=True)

    def _credentials(self, ctx: Ctx) -> str:
        c = ctx.cfg
        path = f"{c['secrets.dir']}/{c['postgres.env_file']}"
        existing = ctx.cread(path, secret=True)
        if existing:
            m = re.search(r"^PGPASSWORD=(\S+)$", existing, re.M)
            if m:
                REDACT.add(m.group(1))
                log.info("  keeping existing credentials in %s", path)
                return m.group(1)
        password = secrets.token_hex(32)
        REDACT.add(password)
        role, db, port = c["postgres.role"], c["postgres.db"], c["postgres.port"]
        env = (f"DATABASE_URL=postgresql://{role}:{password}@127.0.0.1:{port}/{db}\n"
               f"PGHOST=127.0.0.1\nPGPORT={port}\nPGDATABASE={db}\nPGUSER={role}\nPGPASSWORD={password}\n")
        ctx.cexec(bash("[ -d @@D@@ ] || install -d -m 700 -o root -g root @@D@@", D=c["secrets.dir"]))
        ctx.cwrite(path, env, mode="0600", secret=True)
        log.info("  generated credentials in %s", path)
        return password

    def verify(self, ctx: Ctx) -> None:
        c = ctx.cfg
        p = ctx.cexec(bash(PG_VERIFY, ENVFILE=f"{c['secrets.dir']}/{c['postgres.env_file']}",
                           TEST_DB=c["postgres.test_db"]), check=False)
        expect(p.returncode == 0, f"cannot log in as {c['postgres.role']}: {p.stderr.strip()}")
        expect(f"{c['postgres.role']} {c['postgres.db']}" in p.stdout, f"unexpected psql output: {p.stdout}")
        p = ctx.cexec(bash(LOOPBACK_ONLY, PORT=c["postgres.port"]), check=False)
        expect(p.returncode == 0, p.stderr.strip())
        if ctx.state.status("isolation") == "done":
            p = host_curl(ctx, f"https://{c.dev_host}/api/health", "-f")
            expect('"db":true' in p.stdout, f"/api/health does not report db=true: {p.stdout.strip()}")
        log.info("  postgres OK (%s)", p.stdout.strip().splitlines()[-1] if p.stdout.strip() else "")


PHASES: list[Phase] = [BasePhase(), AppPhase(), ProxyPhase(), StandardsPhase(), IsolationPhase(), PostgresPhase()]
PHASE_BY_ID = {p.id: p for p in PHASES}


# ---------------------------------------------------------------------------
# 7. preflight, running phases, undo orchestration
# ---------------------------------------------------------------------------

HOST_TOOLS = [  # (binary, apt package, needed for)
    ("incus", "incus", "everything"),
    ("ssh", "openssh-client", "base"),
    ("ssh-keygen", "openssh-client", "base"),
    ("curl", "curl", "verification"),
    ("getent", "libc-bin", "DNS check"),
    ("systemctl", "systemd", "dnsmasq restart"),
    ("update-ca-certificates", "ca-certificates", "CA trust"),
    ("openssl", "openssl", "the local CA"),
    ("ip", "iproute2", "network ACL (host addresses)"),
]


def risky_path_reason(path: str, home: str) -> str | None:
    """Why sharing `path` with the container is dangerous, or None (a project under ~/code is fine)."""
    p, h = Path(os.path.realpath(path)), Path(os.path.realpath(home))
    if p == Path("/"):
        return "this is the whole host filesystem"
    if p == h:
        return "this is your entire home folder (ssh keys, tokens, browser data)"
    if p in h.parents:
        return "this contains your home folder"
    for sub in (".ssh", ".gnupg"):
        if _within(p, h / sub) or _within(h / sub, p):
            return f"this is, contains or sits inside ~/{sub}"
    for sysdir in ("/etc", "/root", "/var"):
        if _within(p, Path(sysdir)) or _within(Path(sysdir), p):
            return f"this is, contains or sits inside {sysdir}"
    return None


@dataclasses.dataclass
class Report:
    errors: list[str] = dataclasses.field(default_factory=list)
    warnings: list[str] = dataclasses.field(default_factory=list)
    missing_pkgs: list[str] = dataclasses.field(default_factory=list)
    risks: list[str] = dataclasses.field(default_factory=list)  # need an explicit "yes" (or --yes) to proceed
    sudo_needs_input: bool = False


def preflight(ctx: Ctx, phases: list[Phase]) -> Report:
    c, rep = ctx.cfg, Report()
    ids = {p.id for p in phases}
    err, warn = rep.errors.append, rep.warnings.append

    if os.geteuid() == 0:
        err("do not run devstack as root; it uses sudo for the few host changes it needs")
    if not Path("/etc/debian_version").exists():
        warn("host is not Debian-based; package names in messages may not match")

    for binary, pkg, why in HOST_TOOLS:
        if shutil.which(binary) is None and not (binary in ("update-ca-certificates", "getent") and Path(f"/usr/sbin/{binary}").exists()):
            err(f"missing host tool '{binary}' (apt package {pkg}, needed for {why})")
            if pkg not in rep.missing_pkgs:
                rep.missing_pkgs.append(pkg)
    if shutil.which("sudo") is None:
        err("sudo is required")
    elif ctx.r.run(["sudo", "-n", "true"], check=False).returncode != 0:
        if ctx.interactive:
            warn("sudo will ask for your password (host DNS file, CA trust store)")
        else:
            rep.sudo_needs_input = True
            err("non-interactive mode needs working `sudo -n` (run `sudo -v` first or configure NOPASSWD)")
    check_requirements(ctx, rep)
    if shutil.which("incus") is None:
        return rep

    if ctx.r.run(["incus", "query", "/1.0"], check=False).returncode != 0:
        err("cannot talk to the incus daemon (is it running, are you in the incus-admin group?)")
        return rep
    pool = ctx.iq(f"/1.0/storage-pools/{c['container.storage_pool']}")
    if pool is None:
        err(f"storage pool '{c['container.storage_pool']}' does not exist (incus storage list)")
    elif pool.get("driver") == "dir" and c["snapshots.mode"] == "per-phase":
        warn("storage driver 'dir': each phase snapshot is a full copy of the container (a few hundred MB each)")
    net = ctx.iq(f"/1.0/networks/{c['container.network']}")
    if net is None:
        err(f"network '{c['container.network']}' does not exist (incus network list)")
    elif c["container.ipv4"] != "auto":
        subnet = net.get("config", {}).get("ipv4.address", "")
        if subnet and ipaddress.IPv4Address(c["container.ipv4"]) not in ipaddress.ip_network(subnet, strict=False):
            err(f"container.ipv4 {c['container.ipv4']} is outside {c['container.network']} ({subnet})")
    for prof in c["container.profiles"]:
        if ctx.iq(f"/1.0/profiles/{prof}") is None:
            err(f"incus profile '{prof}' does not exist")
    if not rep.errors:
        try:
            ctx.nic_device()
        except PreflightError as e:
            err(str(e))

    j = ctx.journal
    inst = ctx.instance()
    if inst is not None and not j.owns("incus_instance", name=ctx.name):
        err(f"an incus instance named '{ctx.name}' already exists and was not created by this stack "
            "(change stack.name or container.name)")
    if inst is not None and j.owns("incus_instance", name=ctx.name):
        for w in mount_drift(ctx, inst) + readonly_drift(ctx, inst):
            warn(w)
    if c.uid != os.getuid():
        warn(f"container.uid {c.uid} differs from your host uid {os.getuid()}: shared files will look foreign")

    if ctx.project.exists() and not ctx.project.is_dir():
        err(f"project.host_path {ctx.project} exists and is not a folder")
    elif ctx.project.exists() and any(ctx.project.iterdir()) and not j.owns("dir", path=str(ctx.project)):
        warn(f"{ctx.project} already has files; existing files are kept, missing scaffold files are added")
    for m in c["container.mounts"]:
        if not Path(m["source"]).is_dir():
            err(f"container.mounts '{m['name']}': {m['source']} is not a folder")
    if shutil.which("git") is None:
        err("git is not installed on the host (apt install git): devstack requires git for the project, "
            "and keeps its .git read-only in the container")
    if prob := git_dir_problem(ctx.project):
        err(prob)
    elif (ctx.project / ".git").is_dir():
        for f in git_history_findings(ctx.project):
            warn(f"{ctx.project}: {f}")
    if ctx.project.is_dir():
        nested = nested_git(ctx.project)
        if nested:
            warn(f"git repositories inside the project ({', '.join(nested)}): the container can write them, and "
                 "the host's git runs their config and hooks when it works in that folder (you `cd` there, or "
                 "an editor scans subfolders for repositories). Delete them on the host; a submodule's .git "
                 "file is no exception, since the container can point it anywhere")
    if redundant := [r for r in c["project.readonly_paths"] if is_git_path(r)]:
        warn(f"project.readonly_paths: {', '.join(redundant)} is covered by the whole .git, which is always "
             "read-only now; remove it")
    for rel in readonly_extra(c):
        if not (ctx.project / rel).exists():
            warn(f"project.readonly_paths: {ctx.project / rel} does not exist yet, so the container can create "
                 "and edit it until the next `up` after it exists mounts it read-only. Create it on the host "
                 "first")
    home = str(home_dir())
    shared = [("project.host_path", str(ctx.project))] + [
        (f"container.mounts '{m['name']}'", m["source"]) for m in c["container.mounts"]]
    if c["app.data"] == "host":
        shared.append(("app.data_source", c["app.data_source"]))
        if not Path(c["app.data_source"]).is_dir():
            err(f"app.data_source {c['app.data_source']} is not a folder")
    for label, path in shared:
        why = risky_path_reason(path, home)
        if why:
            rep.risks.append(f"{label} = {path} is shared read-write with the container; {why}")
    if c["container.profiles"] != ["default"]:
        warn(f"container.profiles = {c['container.profiles']}: profiles other than 'default' can add devices, "
             "privileges or mounts; read them (incus profile show <name>)")
    if not c["container.image"].startswith("images:"):
        warn(f"container.image = {c['container.image']!r} is not from the 'images:' remote; make sure you trust that source")
    if not c["dns.tld"]:
        warn(f"dns.tld is empty: {c['site.hostname']} (and everything under it) now resolves to the container for "
             "the whole host, overriding the real domain")
    if c["dns.allow_public_tld"] and public_tld_problem(c["dns.tld"]):
        warn(f"dns.tld {c['dns.tld']!r} is a real top-level domain (dns.allow_public_tld = true): "
             "it stops resolving normally on this host")
    preflight_isolation(ctx, rep, ids)
    if c["gpu.enabled"] and c["gpu.nvidia_runtime"] and shutil.which("nvidia-container-cli") is None:
        err("gpu.nvidia_runtime needs nvidia-container-toolkit on the host (nvidia-container-cli not found)")

    key = Path(c["ssh.key_path"])
    if key.exists() and not j.owns("ssh_key", path=str(key)) and not c["ssh.reuse_existing_key"]:
        err(f"ssh key {key} already exists (set ssh.reuse_existing_key = true or choose another ssh.key_path)")
    if c["ssh.key_passphrase"] == "prompt" and not ctx.interactive and not key.exists():
        err("ssh.key_passphrase = 'prompt' needs interactive mode")
    kh = Path(c["ssh.known_hosts_file"])
    if kh.exists() and not j.owns("host_file", path=str(kh)):
        err(f"{kh} already exists and is not owned by this stack")
    sshcfg = Path(c["ssh.config_file"])
    if sshcfg.exists():
        text = remove_block(sshcfg.read_text(), f"# >>> devstack:{c['stack.name']} >>>",
                            f"# <<< devstack:{c['stack.name']} <<<")
        for ln in text.splitlines():
            words = ln.strip().split()
            if len(words) > 1 and words[0].lower() == "host" and c["ssh.host_alias"] in words[1:]:
                err(f"{sshcfg} already defines 'Host {c['ssh.host_alias']}' (change ssh.host_alias)")
                break

    if "proxy" in ids:
        svc = c["dns.dnsmasq_service"]
        if ctx.r.run(["systemctl", "is-active", "--quiet", svc], check=False).returncode != 0:
            err(f"{svc} is not active on the host. devstack assumes the host already resolves through dnsmasq "
                "(index.html, 'Host DNS')")
        ddir, dfile = Path(c["dns.dnsmasq_dir"]), Path(c["dns.dnsmasq_file"])
        if not ddir.is_dir():
            err(f"dns.dnsmasq_dir {ddir} does not exist")
        else:
            if dfile.exists() and not j.owns("host_file", path=str(dfile)):
                err(f"{dfile} already exists and is not owned by this stack")
            claims = {c["dns.tld"] or c["site.hostname"], c.dev_host, *c["dns.extra_names"]}
            for f in sorted(ddir.iterdir()):
                if f == dfile or not f.is_file():
                    continue
                if f.name.endswith("~"):
                    warn(f"{f} looks like an editor backup; Debian's dnsmasq still loads it")
                try:
                    content = f.read_text()
                except OSError:
                    continue
                for ln in content.splitlines():
                    m = re.match(r"\s*(address|host-record)\s*=\s*(.+)", ln)
                    if not m:
                        continue
                    names = m.group(2).strip("/").split("/")[:-1] if m.group(1) == "address" else m.group(2).split(",")[:-1]
                    hit = claims & {n.strip().lstrip(".") for n in names}
                    if hit:
                        err(f"{f} already routes {', '.join(sorted(hit))} ({ln.strip()})")
        ca = Path(c["tls.host_ca_file"])
        if ca.exists() and not j.owns("host_ca", path=str(ca)):
            err(f"{ca} already exists and is not owned by this stack")
        if c["tls.browser_trust"] != "no" and shutil.which("certutil") and Path(c["tls.nss_db"]).is_dir():
            p = ctx.r.run(["certutil", "-L", "-d", f"sql:{c['tls.nss_db']}", "-n", c["tls.nss_nickname"]], check=False)
            if p.returncode == 0 and not j.owns("nss_cert", nickname=c["tls.nss_nickname"]):
                err(f"browser NSS db already has a cert named '{c['tls.nss_nickname']}' (change tls.nss_nickname)")
        elif c["tls.browser_trust"] == "yes":
            err("tls.browser_trust = 'yes' needs certutil (apt install libnss3-tools) and an NSS db at " + c["tls.nss_db"])
    if shutil.which("certutil") is None:
        warn("certutil is missing (sudo apt install libnss3-tools): `devstack browse` needs it to make the dev "
             "browser trust the dev CA")

    if "postgres" in ids and c["postgres.enabled"]:
        if ctx.volume() is not None and not j.owns("incus_volume", pool=c["container.storage_pool"],
                                                   volume=c["postgres.volume"]) and not c["postgres.adopt_volume"]:
            err(f"incus volume {c['postgres.volume']} exists but was not created by this stack "
                "(set postgres.adopt_volume = true to use its data, or change postgres.volume)")
    if "isolation" in ids and c["app.data"] == "volume":
        vol = c["app.data_volume"]
        if vol == c["postgres.volume"]:
            err("app.data_volume and postgres.volume must differ")
        elif ctx.volume(vol) is not None and not j.owns("incus_volume", pool=c["container.storage_pool"],
                                                        volume=vol) and not c["app.data_adopt"]:
            err(f"incus volume {vol} exists but was not created by this stack "
                "(set app.data_adopt = true to use its data, or change app.data_volume)")
    if (ids & {"proxy", "standards", "isolation"}) and not c["caddy.manage_caddyfile"]:
        owned = ctx.project / "infra" / "Caddyfile"
        if owned.exists() and caddyfile_has_global_block(owned.read_text()):
            err(f"{owned} starts with a global options block. devstack owns the global options in "
                "/etc/caddy/Caddyfile (which imports your file), and Caddy refuses a second one: move it out")
    owned = ctx.project / "infra" / "Caddyfile"
    if not c["caddy.manage_caddyfile"] and owned.exists():
        text = owned.read_text()
        if caddyfile_defines(text, SAME_ORIGIN_SNIPPET):
            err(f"{owned} defines ({SAME_ORIGIN_SNIPPET}); /etc/caddy/Caddyfile does, and Caddy refuses a second "
                "definition: delete it from your file and keep the `import`")
        elif c["caddy.same_origin"] != "off" and not caddyfile_imports(text, SAME_ORIGIN_SNIPPET):
            warn(f"{owned} never imports {SAME_ORIGIN_SNIPPET}: other sites' pages can make requests to the app "
                 f"from your browser. Add `import {SAME_ORIGIN_SNIPPET}` to each site block (caddy.same_origin = "
                 f"{c['caddy.same_origin']} decides what it does)")
    if c["caddy.same_origin"] == "off":
        rep.risks.append("caddy.same_origin = off: any site open in your browser can make requests to the app "
                         "with your cookies")

    if c["sbom.enabled"]:
        preflight_sbom(ctx, rep)

    if c["snapshots.mode"] == "per-phase" and inst is not None and j.owns("incus_instance", name=ctx.name):
        mine = {e["args"]["snapshot"] for e in j.entries if e["kind"] == "incus_snapshot" and e["status"] in OWNED}
        for s in ctx.snapshot_names():
            if s.startswith(c["snapshots.prefix"]) and s not in mine:
                err(f"snapshot {ctx.name}/{s} uses devstack's prefix but is not in the journal")
    return rep


def preflight_sbom(ctx: Ctx, rep: Report) -> None:
    c, warn = ctx.cfg, rep.warnings.append
    try:
        host_arch()
    except PreflightError as e:
        warn(f"{e}: `sbom generate` still works, but `sbom scan` will not")
    for kind in SBOM_KINDS:
        path = ctx.project / c["sbom.dir"] / f"{kind}.cdx.json"
        if not path.exists():
            if ctx.state.status("base") == "done" and c["sbom.generate_on_up"]:
                warn(f"{c['sbom.dir']}/{kind}.cdx.json does not exist yet; the next `up` writes it")
            continue
        try:  # only the tool version, not the whole document
            tools = ((json.loads(path.read_text()).get("metadata") or {}).get("tools") or {})
            for t in tools.get("components") or []:
                if t.get("name") == "syft" and t.get("version") != SYFT_VERSION:
                    warn(f"{c['sbom.dir']}/{kind}.cdx.json was generated by syft {t.get('version')}, "
                         f"this devstack pins {SYFT_VERSION}: the next `up` rewrites it")
        except (OSError, ValueError) as e:
            warn(f"{path} is not readable as CycloneDX JSON ({e}); `sbom generate` will replace it")
    stale = sbom_stale_inputs(ctx)
    if stale:
        warn(f"{', '.join(stale)} changed since the inventory was generated: run "
             "`devstack sbom generate` (or `sbom check` to be certain) and commit the result")
    if c["sbom.ignore"]:
        warn(f"sbom.ignore silences {len(c['sbom.ignore'])} vulnerability id(s) "
             f"({', '.join(c['sbom.ignore'][:5])}): each one should have a reason in the project README")
    if c["sbom.fail_on"] and not (Path(c["sbom.db_dir"]) / "db").exists():
        warn(f"sbom.fail_on = {c['sbom.fail_on']} but there is no vulnerability database yet: "
             f"the first `sbom scan` downloads about 1 GB into {c['sbom.db_dir']}")


def preflight_isolation(ctx: Ctx, rep: Report, ids: set[str]) -> None:
    """Risks that widen what the container user or a service can do, and the host ACL's prerequisites."""
    c, j = ctx.cfg, ctx.journal
    if c["container.sudo"] == "full":
        rep.risks.append('container.sudo = "full": the container user, and every agent or extension running as it, '
                         "is root in the container (it can change the egress rules and units devstack sets up)")
    if c["app.profile"] == "open":
        rep.risks.append('app.profile = "open": the app (and any dependency it loads) may connect anywhere the '
                         "container can: the public internet, any loopback service")
    if c["network.acl"] and c["network.allow_private"]:
        rep.risks.append(f"network.allow_private = {c['network.allow_private']}: the container may reach these "
                         "addresses on your host or LAN")
    if not c["network.acl"]:
        rep.warnings.append("network.acl = false: the container can reach your host's services and your LAN")
    applied = ctx.state.fact("runners")
    if c["app.runners"] and c["app.runners"] != applied:
        old = {r["name"]: r for r in applied or []}
        changed = [r for r in c["app.runners"] if old.get(r["name"]) != r]
        rep.risks.append("new or changed runners run project code as a service with internet access:\n      "
                         + "\n      ".join(f"{r['name']}: `{r['command']}` on 127.0.0.1:{r['port']}" for r in changed))
    if c["network.acl"] and "base" in ids or acl_pending(ctx):
        name = c["network.acl_name"]
        info = ctx.iq("/1.0") or {}
        if "network_bridge_acl_devices" not in info.get("api_extensions", []):
            rep.errors.append("this incus has no ACLs on bridged NICs (API extension network_bridge_acl_devices); "
                              "upgrade incus or set network.acl = false")
        elif info.get("environment", {}).get("firewall") != "nftables":
            rep.errors.append(f"incus uses the {info.get('environment', {}).get('firewall')!r} firewall driver; ACLs on "
                              "bridged NICs need nftables (or set network.acl = false)")
        net = ctx.iq(f"/1.0/networks/{c['container.network']}") or {}
        if net and net.get("type") != "bridge":
            rep.errors.append(f"network.acl supports managed bridges; {c['container.network']} is a {net.get('type')}")
        if ctx.iq(f"/1.0/network-acls/{name}") is not None and not j.owns("incus_acl", name=name):
            rep.errors.append(f"an incus network ACL named {name} already exists and was not created by this stack "
                              "(change network.acl_name)")


def check_requirements(ctx: Ctx, rep: Report) -> None:
    """The project's REQUIRES_FILE against this config."""
    req_path = ctx.project / REQUIRES_FILE
    try:
        want = load_requirements(req_path)
    except ConfigError as e:
        rep.errors.append(str(e))
        want = None
    if want is not None:
        mine = ctx.journal.find("project_file", ACTIVE, path=str(req_path))
        if not (mine and mine["args"].get("sha256") == sha256_file(req_path)):
            # From the repo, or edited since we wrote it (git pull): don't overwrite it silently.
            missing, diffs = requirements_diff(want, ctx.cfg.v)
            for m in missing:
                rep.errors.append(m)
            if diffs:
                rep.risks.append(f"{REQUIRES_FILE} (the project's requirements) differs from your config, "
                                 "and up rewrites it from your config:\n      " + "\n      ".join(diffs))


def report_preflight(rep: Report) -> None:
    for w in rep.warnings:
        log.warning(w)
    for r in rep.risks:
        log.warning("RISK: %s", r)
    for e in rep.errors:
        log.error(e)


def confirm_risks(ctx: Ctx, risks: list[str]) -> bool:
    """A devstack.toml acts like a script: dangerous host shares (and overwriting the project's
    requirements) need a typed "yes" (or --yes)."""
    if not risks:
        return True
    if ctx.args.yes:
        log.warning("--yes: accepting %d risky setting(s) listed above", len(risks))
        return True
    if not ctx.interactive:
        raise NeedsInput("risky settings (listed above) need an explicit --yes in non-interactive mode; "
                         "nothing was changed")
    print("\nThis run needs your explicit OK for:")
    for r in risks:
        print(f"  - {r}")
    try:
        return input('Type "yes" to continue anyway: ').strip().lower() == "yes"
    except EOFError:
        return False


def handle_missing_packages(ctx: Ctx, rep: Report) -> Report:
    """Offer/perform apt install of missing host tools; returns the re-run report needs."""
    if not rep.missing_pkgs:
        return rep
    cmd = ["apt-get", "install", "-y", *rep.missing_pkgs]
    if ctx.interactive:
        if not ctx.confirm(f"Install missing host packages with `sudo {shlex.join(cmd)}`?", default=True):
            return rep
    elif not ctx.cfg["host.install_missing"]:
        return rep
    e = ctx.journal.add("host", "host_pkg", packages=rep.missing_pkgs)
    ctx.r.run(cmd, sudo=True, tty=ctx.interactive, stream=not ctx.interactive)
    ctx.journal.mark(e, "applied")
    return Report()  # caller re-runs preflight


def active_phases(ctx: Ctx) -> list[Phase]:
    return [p for p in PHASES if ctx.state.status(p.id) in ("done", "failed", "running")]


def ensure_phase_snapshot(ctx: Ctx, pid: str) -> None:
    c = ctx.cfg
    if c["snapshots.mode"] == "off":
        return
    snap = c["snapshots.prefix"] + pid
    own = ctx.journal.find("incus_snapshot", ACTIVE, instance=ctx.name, snapshot=snap)
    exists = snap in ctx.snapshot_names()
    if exists and own:
        log.info("  reusing snapshot %s (from an earlier attempt)", snap)
        return
    if exists:
        raise DevstackError(f"snapshot {snap} exists but devstack did not take it; delete it or change snapshots.prefix")
    e = own or ctx.journal.add(pid, "incus_snapshot", instance=ctx.name, snapshot=snap)
    log.info("  snapshot %s/%s", ctx.name, snap)
    ctx.r.run(["incus", "snapshot", "create", ctx.name, snap], stream=True)
    ctx.journal.mark(e, "applied")


def run_phase(ctx: Ctx, phase: Phase, index: int, total: int) -> None:
    ctx.phase = phase.id
    log.info("")
    log.info("==> [%d/%d] %s: %s  (%s)", index, total, phase.id, phase.title, phase.layer)
    ctx.state.set_status(phase.id, "running")
    try:
        if phase.id != "base":
            inst = ctx.instance()
            if inst is None:
                raise DevstackError(f"container {ctx.name} does not exist; run the base phase first")
            if inst["status"] != "Running":
                log.info("  starting container %s", ctx.name)
                ctx.r.run(["incus", "start", ctx.name])
                ctx.wait_ipv4()
        if phase.snapshot:
            ensure_phase_snapshot(ctx, phase.id)
        phase.apply(ctx)
        log.info("  verifying")
        phase.verify(ctx)
    except (Exception, KeyboardInterrupt) as exc:
        ctx.state.set_status(phase.id, "failed")
        interrupted = isinstance(exc, KeyboardInterrupt)
        log.error("phase %s %s: %s", phase.id, "interrupted" if interrupted else "failed",
                  exc if not interrupted else "Ctrl-C")
        if not isinstance(exc, DevstackError) and not interrupted:
            log.debug("traceback", exc_info=True)
        log.error("full log: %s", ctx.cfg["logging.file"])
        if ctx.interactive:
            try:
                rollback = ctx.confirm(f"Roll back phase '{phase.id}' now? (no = keep it for debugging, "
                                       "clean up later with `devstack undo`)", default=True)
            except (KeyboardInterrupt, EOFError):
                rollback = True
        else:
            rollback = ctx.cfg["run.on_failure"] == "rollback"
        if rollback:
            try:
                undo_phase(ctx, phase, UndoOpts())
                ctx.state.set_status(phase.id, "rolled_back")
                log.info("phase %s rolled back; earlier phases are untouched", phase.id)
            except (Exception, KeyboardInterrupt) as e2:
                log.error("rollback did not finish (%s). Re-run `devstack undo` to complete it.", e2)
        else:
            log.info("left phase %s as failed. Inspect, then `devstack up` to retry or `devstack undo` to clean up.",
                     phase.id)
        if interrupted:
            raise SystemExit(130)
        raise DevstackError(f"phase {phase.id} failed") from None
    ctx.state.set_status(phase.id, "done")
    log.info("  phase %s done", phase.id)


def maybe_backup_db(ctx: Ctx, *, required: bool) -> None:
    """pg_dump before destructive undo. With required (purge), a failed backup aborts."""
    c = ctx.cfg
    if ctx.state.status("postgres") not in ("done", "failed"):
        if required:
            log.warning("no running database to back up; older dumps (if any) are in %s", c["postgres.backup_dir"])
        return
    if not c["postgres.backup_before_undo"]:
        if required:
            raise DevstackError("--purge-data wants a backup first but postgres.backup_before_undo = false; "
                                "run `devstack db backup` yourself, then set it back or pass it once")
        return
    try:
        if not ctx.instance_running():
            raise DevstackError("container is not running")
        db_backup(ctx, None)
    except DevstackError as e:
        if required:
            raise DevstackError(f"backup before purge failed ({e}); nothing was deleted") from None
        log.warning("automatic db backup failed (%s); the data volume is kept anyway", e)


def undo_phase(ctx: Ctx, phase: Phase, opts: UndoOpts) -> None:
    entries = [e for e in reversed(ctx.journal.entries) if e["phase"] == phase.id and
               (e["status"] in ACTIVE or (opts.purge_data and e["kind"] == "incus_volume" and e["status"] == "kept"))]
    log.info("  undoing %s (%d journal entries)", phase.id, len(entries))
    for e in entries:
        fn = UNDO[e["kind"]]
        log.debug("undo #%s %s %s", e["seq"], e["kind"], e["args"])
        status = fn(ctx, e["args"], opts)
        ctx.journal.mark(e, status)
    ctx.state.set_status(phase.id, "pending")


def check_undoable(ctx: Ctx, phases: list[Phase], whole: bool) -> None:
    if whole:
        return
    for p in phases:
        if not p.snapshot or p.id == "app":
            continue
        snaps = [e for e in ctx.journal.entries if e["phase"] == p.id and e["kind"] == "incus_snapshot"]
        if not snaps or snaps[-1]["status"] not in ACTIVE:
            raise DevstackError(f"phase {p.id} has no snapshot to restore (snapshots off or pruned); "
                                "only `devstack undo --all` can revert it")


def maybe_backup_data(ctx: Ctx, *, required: bool) -> None:
    """Archive the app data before destructive undo. With required (purge), a failed backup aborts."""
    c = ctx.cfg
    if c["app.data"] == "none" or ctx.state.status("isolation") not in ("done", "failed"):
        return
    inst = ctx.instance()
    if inst is None or "appdata" not in inst["devices"]:
        # Nothing attached to archive (e.g. isolation ran with an older devstack, or failed early). A volume
        # of ours that exists but isn't attached can't be archived from here: don't let a purge take it.
        pool, vol = c["container.storage_pool"], c["app.data_volume"]
        if required and c["app.data"] == "volume" and ctx.journal.owns("incus_volume", pool=pool, volume=vol) \
                and ctx.volume(vol) is not None:
            raise DevstackError(f"volume {pool}/{vol} is not attached to {ctx.name}, so it can't be archived "
                                f"before the purge; export it yourself (incus storage volume export {pool} {vol} "
                                "FILE) or run `devstack up` first; nothing was deleted")
        log.info("  no app data attached to %s: nothing to archive", ctx.name)
        return
    if not c["app.data_backup_before_undo"]:
        if required:
            raise DevstackError("--purge-data wants a backup first but app.data_backup_before_undo = false; "
                                "run `devstack data backup` yourself, then set it back or pass it once")
        return
    try:
        if not ctx.instance_running():
            raise DevstackError("container is not running")
        data_backup(ctx, None)
    except DevstackError as e:
        if required:
            raise DevstackError(f"app data backup before purge failed ({e}); nothing was deleted") from None
        log.warning("automatic app data backup failed (%s); the data is kept anyway", e)


def undo_phases(ctx: Ctx, phases: list[Phase], opts: UndoOpts) -> None:
    check_undoable(ctx, phases, opts.whole)
    if any(p.id in ("postgres", "base") for p in phases):
        maybe_backup_db(ctx, required=opts.purge_data)
    if any(p.id in ("isolation", "base") for p in phases):
        maybe_backup_data(ctx, required=opts.purge_data)
    for p in reversed(phases):
        ctx.phase = p.id
        undo_phase(ctx, p, opts)
    if opts.whole:
        ctx.phase = "host"
        for e in reversed(ctx.journal.entries):
            if e["phase"] == "host" and e["status"] in ACTIVE:
                ctx.journal.mark(e, UNDO[e["kind"]](ctx, e["args"], opts))


def db_backup(ctx: Ctx, dest: str | None) -> Path:
    c = ctx.cfg
    bdir = Path(c["postgres.backup_dir"])
    bdir.mkdir(parents=True, exist_ok=True)
    os.chmod(bdir, 0o700)
    out = Path(dest).expanduser() if dest else bdir / f"{c['postgres.db']}-{dt.datetime.now():%Y%m%d-%H%M%S}.dump"
    tmp = out.with_name(out.name + ".partial")
    argv = ["incus", "exec", ctx.name, "--", "runuser", "-u", "postgres", "--",
            "pg_dump", "-Fc", "-p", str(c["postgres.port"]), c["postgres.db"]]
    log.debug("$ %s > %s", shlex.join(argv), tmp)
    with open(tmp, "wb") as fh:
        p = subprocess.run(argv, stdout=fh, stderr=subprocess.PIPE)
    if p.returncode != 0:
        tmp.unlink(missing_ok=True)
        raise DevstackError(f"pg_dump failed: {p.stderr.decode(errors='replace').strip()}")
    os.chmod(tmp, 0o600)
    tmp.replace(out)
    log.info("db backup: %s (%.1f KiB)", out, out.stat().st_size / 1024)
    return out


DATA_RESTORE = r"""
dir=@@DIR@@; app=@@APP@@; data=@@DATA@@; runner=@@RUNNER@@; unit=@@UNIT@@; sockets=(@@SOCKETS@@)
mountpoint -q "$dir" || { echo "$dir is not the app data mount" >&2; exit 1; }
systemctl stop "$unit" "${sockets[@]}"
for s in "${sockets[@]}"; do systemctl stop "${s%.socket}@*.service" || true; done
find "$dir" -mindepth 1 -delete
# As the app user, not root: the archive can only create what the app itself could.
runuser -u "$app" -- bash -c 'umask 0027; exec tar -C "$0" -xzf - --no-same-owner' "$dir"
chown "$app:$data" "$dir"
chmod 2751 "$dir"
install -d "$dir/incoming"
chown -R "$runner:$data" "$dir/incoming"
chmod 2770 "$dir/incoming"
systemctl start "$unit" "${sockets[@]}"
"""


def data_backup(ctx: Ctx, dest: str | None) -> Path:
    c = ctx.cfg
    src = app_data_dir(c)
    if src is None:
        raise DevstackError('app.data = "none": there is no app data')
    bdir = Path(c["app.data_backup_dir"])
    bdir.mkdir(parents=True, exist_ok=True)
    os.chmod(bdir, 0o700)
    out = Path(dest).expanduser() if dest else bdir / f"{c['isolation.app_user']}-data-{dt.datetime.now():%Y%m%d-%H%M%S}.tar.gz"
    tmp = out.with_name(out.name + ".partial")
    argv = ["incus", "exec", ctx.name, "--", "tar", "-C", src, "--numeric-owner", "-czf", "-", "."]
    log.debug("$ %s > %s", shlex.join(argv), tmp)
    with open(tmp, "wb") as fh:
        p = subprocess.run(argv, stdout=fh, stderr=subprocess.PIPE)
    if p.returncode != 0:
        tmp.unlink(missing_ok=True)
        raise DevstackError(f"tar of {src} failed: {p.stderr.decode(errors='replace').strip()}")
    os.chmod(tmp, 0o600)
    tmp.replace(out)
    log.info("app data backup: %s (%.1f KiB)", out, out.stat().st_size / 1024)
    return out


# ---------------------------------------------------------------------------
# 8. commands
# ---------------------------------------------------------------------------


def make_ctx(args: argparse.Namespace, interactive: bool) -> Ctx:
    path = Path(args.config).expanduser()
    if not path.exists():
        if interactive and args.command == "up" and ask_create_config(path):
            cmd_init(args, interactive)
        else:
            raise ConfigError(f"no config at {path}. Create one with `./devstack init` "
                              "(or `./devstack init -n` for all defaults).")
    cfg = load_config(path)
    setup_logging(args.log_target or cfg["logging.target"], args.log_file or cfg["logging.file"],
                  args.log_level or cfg["logging.level"], f"devstack-{cfg['stack.name']}")
    log.debug("devstack %s, config %s (%s), %s mode, argv %s", VERSION, path, cfg.digest(),
              "interactive" if interactive else "non-interactive", sys.argv[1:])
    return Ctx(cfg, args, interactive)


def ask_create_config(path: Path) -> bool:
    ans = input(f"No config at {path}. Create one now with an explained walk-through? [Y/n] ").strip().lower()
    return ans in ("", "y", "yes")


class Lock:
    def __init__(self, ctx: Ctx):
        self.path = ctx.state_dir / "lock"

    def __enter__(self) -> "Lock":
        self.fh = open(self.path, "w")
        try:
            fcntl.flock(self.fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise DevstackError(f"another devstack run holds {self.path}") from None
        return self

    def __exit__(self, *exc: Any) -> None:
        fcntl.flock(self.fh, fcntl.LOCK_UN)
        self.fh.close()


def cmd_init(args: argparse.Namespace, interactive: bool) -> int:
    path = Path(args.config).expanduser()
    if path.exists() and not getattr(args, "force", False):
        raise ConfigError(f"{path} already exists (use --force to overwrite)")
    values = defaults()
    if getattr(args, "project", None):
        values["project.host_path"] = tilde_path(Path(args.project).expanduser().resolve())
    required: list[dict[str, Any]] = []
    if interactive:
        print("devstack init: press Enter to accept a default. {placeholders} refer to other keys.\n")
        for section, intro in SECTIONS.items():
            print(f"[{section}]")
            print(textwrap.fill(intro, 88, initial_indent="  ", subsequent_indent="  "))
            for f in (f for f in SCHEMA if f.section == section):
                if f.kind == "mounts" and required:
                    values[f.key] = ask_mount_sources(required)
                    continue
                if f.kind in ("strmap", "mounts"):
                    print(f"  {f.key}: keeping the default; edit the file to change it.")
                    continue
                while True:
                    preview = resolve(values)[f.key]
                    print()
                    print(textwrap.fill(f.help, 88, initial_indent="  # ", subsequent_indent="  # "))
                    if f.choices:
                        print(f"  # choices: {', '.join(f.choices)}")
                    shown = toml_value(values[f.key])
                    resolved = f"  (= {toml_value(preview)})" if toml_value(preview) != shown else ""
                    try:
                        ans = input(f"  {f.key} [{shown}]{resolved}: ").strip()
                    except EOFError:
                        ans = ""
                    if not ans:
                        break
                    prev = values[f.key]
                    try:
                        values[f.key] = parse_answer(f, ans)
                        problems = [p for p in validate(resolve(values)) if p.startswith(f.key)]
                        if problems:
                            raise ConfigError("; ".join(problems))
                        break
                    except (ValueError, ConfigError) as e:
                        print(f"  ! {e}")
                        values[f.key] = prev
                if f.key == "project.host_path":
                    required = adopt_requirements(values)
            print()
    else:
        required = adopt_requirements(values)
        if required:
            print("warning: the project needs host folders this config can't guess; add them before `up`:",
                  file=sys.stderr)
            for m in required:
                print(f"  [[container.mounts]] name = {toml_value(m['name'])}, path = {toml_value(m['path'])}"
                      f"{', readonly = true' if m['readonly'] else ''}, source = <a folder on your host>",
                      file=sys.stderr)
    Config(values, None)  # validate once more before writing
    atomic_write(path, config_to_toml(values), 0o644)
    print(f"wrote {path}")
    return 0


def tilde_path(p: Path) -> str:
    try:
        return "~/" + str(p.relative_to(home_dir()))
    except ValueError:
        return str(p)


def adopt_requirements(values: dict[str, Any]) -> list[dict[str, Any]]:
    """Take the project's REQUIRES_FILE (if its folder has one) as defaults for `values`.
    Returns the mounts it requires, which still need a host source."""
    path = Path(resolve(values)["project.host_path"]) / REQUIRES_FILE
    want = load_requirements(path)
    if want is None:
        return []
    print(f"  using {path} as the defaults for the project's container-side settings")
    required = want.pop("container.mounts", [])
    values.update(want)
    return required


def ask_mount_sources(required: list[dict[str, Any]]) -> list[dict[str, Any]]:
    print("  The project needs these host folders mounted in the container. Give the folder on this host:")
    mounts = []
    for m in required:
        while True:
            try:
                src = input(f"  {m['name']} -> {m['path']}{' (read-only)' if m['readonly'] else ''}: ").strip()
            except EOFError:
                src = ""
            if src.startswith(("/", "~")):
                break
            print("  ! an absolute path or ~/... is required")
        mounts.append({"name": m["name"], "source": src, "path": m["path"], "readonly": m["readonly"]})
    return mounts


def parse_answer(f: Field, ans: str) -> Any:
    if f.kind == "str":
        return ans
    if f.kind == "int":
        return int(ans)
    if f.kind == "bool":
        if ans.lower() in ("y", "yes", "true", "1"):
            return True
        if ans.lower() in ("n", "no", "false", "0"):
            return False
        raise ValueError("answer yes or no")
    items = [x.strip() for x in ans.split(",") if x.strip()]
    if f.kind == "strlist":
        return items
    if f.kind == "intlist":
        return [int(x) for x in items]
    raise ValueError(f"{f.key} can't be set interactively")


def cmd_config(args: argparse.Namespace, interactive: bool) -> int:
    if args.action == "explain":
        keys = [args.key] if args.key else [f.key for f in SCHEMA]
        for k in keys:
            if k not in FIELDS:
                hint = difflib.get_close_matches(k, FIELDS, n=1)
                raise ConfigError(f"unknown key {k}" + (f" (did you mean {hint[0]}?)" if hint else ""))
            f = FIELDS[k]
            print(f"{f.key}  ({f.kind})")
            print(textwrap.fill(f.help, 88, initial_indent="    ", subsequent_indent="    "))
            if f.choices:
                print(f"    choices: {', '.join(f.choices)}")
            print(f"    default: {toml_value(f.default) if f.kind not in ('strmap', 'mounts') else '(see example file)'}")
            print()
        return 0
    cfg = load_config(Path(args.config).expanduser())
    if args.action == "check":
        print(f"{cfg.source}: OK (dev URL https://{cfg.dev_host}, container {cfg['container.name']})")
        return 0
    print(config_to_toml(cfg.v), end="")
    return 0


def selected_phases(ctx: Ctx, args: argparse.Namespace) -> list[Phase]:
    enabled = [p for p in PHASES if p.enabled(ctx.cfg)]
    ids = [p.id for p in enabled]
    for opt in ("to", "only", "redo"):
        val = getattr(args, opt, None)
        if val and val not in ids:
            raise ConfigError(f"--{opt} {val}: not an enabled phase ({', '.join(ids)})")
    if getattr(args, "only", None):
        i = ids.index(args.only)
        missing = [p.id for p in enabled[:i] if ctx.state.status(p.id) != "done"]
        if missing:
            raise DevstackError(f"--only {args.only}: earlier phases not done: {', '.join(missing)}")
        return [enabled[i]]
    target = ids.index(args.to) if getattr(args, "to", None) else len(ids) - 1
    if getattr(args, "redo", None):
        target = max(target, max((i for i, p in enumerate(enabled) if ctx.state.status(p.id) == "done"), default=0))
    return [p for p in enabled[: target + 1]
            if ctx.state.status(p.id) != "done" or (getattr(args, "redo", None) and ids.index(p.id) >= ids.index(args.redo))]


def host_writes(ctx: Ctx, phases: list[Phase]) -> list[str]:
    c, ids = ctx.cfg, {p.id for p in phases}
    out = [f"{ctx.state_dir} (state, journal, backups, local CA)"]
    if c["logging.target"] in ("file", "both"):
        out.append(f"{c['logging.file']} (log, mode 0600)")
    if "base" in ids:
        out += [f"{ctx.project} (project folder; scaffold files are only added, never overwritten)",
                f"{c['ssh.key_path']} + .pub (new ssh key), {c['ssh.known_hosts_file']}",
                f"{c['ssh.config_file']} (one marked block for 'Host {c['ssh.host_alias']}')"]
    if "proxy" in ids:
        out += [f"{c['dns.dnsmasq_file']} (sudo; restarts {c['dns.dnsmasq_service']})",
                f"{c['tls.host_ca_file']} (sudo; system trust store, root CA limited to {', '.join(ca_names(c))})"]
        if c["tls.browser_trust"] != "no":
            out.append(f"{c['tls.nss_db']} (browser trust, if certutil and the db exist)")
    if "base" in ids and c["network.acl"]:
        out.append(f"incus network ACL {c['network.acl_name']} (attached to the container's NIC)")
    if "isolation" in ids and c["app.data"] == "volume":
        out.append(f"incus volume {c['container.storage_pool']}/{c['app.data_volume']} (app data); "
                   f"archives go to {c['app.data_backup_dir']}")
    if "postgres" in ids:
        out.append(f"incus volume {c['container.storage_pool']}/{c['postgres.volume']}; "
                   f"dumps go to {c['postgres.backup_dir']}")
    if c["sbom.enabled"]:
        out.append(f"{c['sbom.dir']}/*.cdx.json in the project (generated inventory, committed)")
        out.append(f"{c['sbom.db_dir']} (grype and its vulnerability database, ~1 GB, "
                   "only once you run `sbom scan`)")
    return out


def print_plan(ctx: Ctx, phases: list[Phase], pending: list[str] = ()) -> None:
    c = ctx.cfg
    print(f"\nstack {c['stack.name']}  ->  https://{c.dev_host}   (container {ctx.name}, config {c.source})")
    print("\n  Review first: devstack.toml acts like a script.")
    print(f"    image: {c['container.image']}   profiles: {', '.join(c['container.profiles'])}")
    shared = [f"{ctx.project} -> {ctx.cproject} (read-write)"]
    shared += [f"{ctx.project / r} -> {ctx.cproject}/{r} (read-only)" for r in [".git", *readonly_extra(c)]]
    shared += [f"{m['source']} -> {m['path']} ({'read-only' if m.get('readonly') else 'read-write'})"
               for m in c["container.mounts"]]
    if c["app.data"] == "host":
        shared.append(f"{c['app.data_source']} -> /var/lib/{c['isolation.app_user']} (app data, read-write)")
    print("    host folders shared with the container:")
    for line in shared:
        print(f"      {line}")
    print("    host paths written or changed:")
    for line in host_writes(ctx, phases):
        print(f"      {line}")
    print()
    for p in PHASES:
        status = ctx.state.status(p.id) if p.enabled(c) else "disabled"
        mark = "run " if p in phases else "    "
        print(f"  {mark}{p.id:<10} {status:<12} {p.title}")
    for p in phases:
        print(f"\n  {p.id}: {p.title}  [{p.layer}]")
        if p.snapshot and c["snapshots.mode"] == "per-phase":
            print(f"    - snapshot {ctx.name}/{c['snapshots.prefix']}{p.id} (undo point)")
        for line in p.describe(ctx):
            print(f"    - {line}")
    if pending:
        print("\n  updates to the existing container (outside the phases)")
        for line in pending:
            print(f"    - {line}")
    print()


def cmd_preflight(ctx: Ctx) -> int:
    rep = preflight(ctx, [p for p in PHASES if p.enabled(ctx.cfg)])
    report_preflight(rep)
    if rep.errors:
        raise (NeedsInput if rep.sudo_needs_input and len(rep.errors) == 1 else PreflightError)(
            f"preflight found {len(rep.errors)} problem(s)")
    log.info("preflight OK")
    return 0


def up_pending(ctx: Ctx, phases: list[Phase]) -> list[str]:
    """What up changes on the existing container besides running phases."""
    out = [] if any(p.id == "base" for p in phases) else pending_base(ctx)
    if not any(p.id in CADDY_PHASES for p in phases):
        out += [f"rewrite {f} (devstack or caddy.* settings changed); validate, reload Caddy" for f in pending_caddy(ctx)]
    if not any(p.id == "proxy" for p in phases) and pending_dns(ctx):
        out.append(f"rewrite {ctx.cfg['dns.dnsmasq_file']} (host names changed, e.g. a dev server); restart "
                   f"{ctx.cfg['dns.dnsmasq_service']} (sudo)")
    if not any(p.id == "isolation" for p in phases) and sync_script_stale(ctx):
        out.append(f"rewrite {SYNC_PATH} (devstack changed it; same verbs a fresh isolation phase installs)")
    return out


def cmd_plan(ctx: Ctx, args: argparse.Namespace) -> int:
    phases = selected_phases(ctx, args)
    print_plan(ctx, phases, up_pending(ctx, phases))
    rep = preflight(ctx, phases)
    report_preflight(rep)
    return 0


def cmd_up(ctx: Ctx, args: argparse.Namespace) -> int:
    with Lock(ctx):
        phases = selected_phases(ctx, args)
        pending = up_pending(ctx, phases)
        if not phases and not pending:
            log.info("nothing to do: all selected phases are done (use --redo PHASE to re-apply)")
            return 0
        print_plan(ctx, phases, pending)
        rep = preflight(ctx, phases)
        if rep.missing_pkgs and not handle_missing_packages(ctx, rep).errors:
            rep = preflight(ctx, phases)
        report_preflight(rep)
        if rep.errors:
            raise (NeedsInput if rep.sudo_needs_input and len(rep.errors) == 1 else PreflightError)(
                f"preflight found {len(rep.errors)} problem(s); nothing was changed")
        if args.dry_run:
            log.info("--dry-run: stopping before any change")
            return 0
        if not confirm_risks(ctx, rep.risks):
            log.info("aborted: nothing was changed")
            return 0
        if ctx.interactive and not ctx.confirm("Apply these changes?", default=True):
            return 0
        if ctx.interactive and (phases or pending):
            ctx.r.run(["sudo", "-v"], tty=True)

        if args.redo:
            redo = [p for p in active_phases(ctx) if PHASES.index(p) >= PHASES.index(PHASE_BY_ID[args.redo])]
            log.info("--redo %s: undoing %s first", args.redo, ", ".join(p.id for p in redo))
            undo_phases(ctx, redo, UndoOpts())

        if not any(p.id == "base" for p in phases):
            add_pending_mounts(ctx)
        if not any(p.id in CADDY_PHASES for p in phases):
            refresh_caddy(ctx)
        if not any(p.id == "proxy" for p in phases):
            refresh_dns(ctx)
        if not any(p.id == "isolation" for p in phases):
            refresh_sync(ctx)
        for i, phase in enumerate(phases, 1):
            run_phase(ctx, phase, i, len(phases))
            if phase.id == "base":
                write_requirements(ctx)
        if ctx.state.status("base") == "done":
            write_requirements(ctx)  # picks up config changes made since base ran

        if not phases:
            return 0
        if ctx.cfg["sbom.enabled"] and ctx.cfg["sbom.generate_on_up"] and ctx.state.status("base") == "done":
            # Every phase has passed by now, so a scan problem must not fail `up` and leave the
            # caller with a non-zero exit and nothing rolled back. The sbom check gate catches drift.
            try:
                generate_sboms(ctx)
            except DevstackError as e:
                log.warning("SBOM not regenerated (%s); run `./devstack sbom generate`", e)
        if ctx.cfg["snapshots.cleanup"] == "auto":
            prune_snapshots(ctx)
        summary(ctx)
    return 0


def write_requirements(ctx: Ctx) -> None:
    ctx.phase = "base"  # journaled under base, like the project folder itself
    ctx.project_file(REQUIRES_FILE, requirements_to_toml(requirements(ctx.cfg.v)), managed=True)


# --- browse: a Chromium that reaches only the dev domain ---
#
# The incus ACL keeps the container off the host and the LAN, but a browser showing the container's pages
# runs their scripts on the host's network: they could reach 127.0.0.1 services and LAN devices. The dev
# browser sends everything but the dev domain to a proxy that isn't there (so it fails closed), takes
# loopback out of Chromium's implicit proxy bypass, and keeps WebRTC off non-proxied UDP. It runs with its
# own HOME, which holds its NSS db: only it trusts the dev CA. Checked with Chromium 154: the system trust
# store is not used, the dead proxy has no direct fallback, and without <-loopback> 127.0.0.1 is reachable.

BROWSER_BINARIES = ("chromium", "chromium-browser", "google-chrome-stable", "google-chrome")
DEAD_PROXY = ("127.0.0.1", 9)  # nothing may listen here: checked before every launch
BROWSER_ENV_KEEP = {"XDG_RUNTIME_DIR", "XDG_SESSION_TYPE", "XDG_CURRENT_DESKTOP", "XDG_SESSION_DESKTOP"}


def dev_domains(c: Config) -> list[str]:
    """What the dev browser may reach, as Chromium proxy-bypass patterns."""
    base = [f"*.{c['dns.tld']}"] if c["dns.tld"] else [c["site.hostname"], f"*.{c['site.hostname']}"]
    return base + sorted(set(c["dns.extra_names"]))


def in_dev_domains(c: Config, host: str) -> bool:
    return any(host.endswith(p[1:]) if p.startswith("*.") else host == p for p in dev_domains(c))


def browser_home(ctx: Ctx) -> Path:
    return ctx.state_dir / "browser"


def browser_target(ctx: Ctx, target: str | None) -> str:
    c = ctx.cfg
    if not target:
        return f"https://{c.dev_host}/"
    if target in c["caddy.dev_servers"]:
        return f"https://{target}.{c.dev_host}/"
    url = target if "://" in target else f"https://{target}"
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname or not in_dev_domains(c, parts.hostname):
        names = ", ".join(sorted(c["caddy.dev_servers"])) or "none configured"
        raise ConfigError(f"{target}: the dev browser only reaches {', '.join(dev_domains(c))} "
                          f"(or a caddy.dev_servers name: {names})")
    return url


def browser_argv(ctx: Ctx, binary: str, url: str, app: bool) -> list[str]:
    """A normal window by default: Chromium draws its own frame there. An --app window asks the window
    manager for its title bar, and one that draws none (a borderless or tiling KWin setup) leaves it
    without a way to move or close it."""
    c = ctx.cfg
    return [
        binary,
        f"--user-data-dir={browser_home(ctx) / 'profile'}",
        f"--proxy-server=http://{DEAD_PROXY[0]}:{DEAD_PROXY[1]}",
        f"--proxy-bypass-list={';'.join([*dev_domains(c), '<-loopback>'])}",
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        "--no-first-run", "--no-default-browser-check", "--disable-default-apps",
        "--disable-sync", "--disable-extensions", "--disable-background-networking", "--disable-component-update",
        "--password-store=basic",
        f"--class=devstack-{c['stack.name']}",
        f"--app={url}" if app else url,
    ]


def browser_env(home: Path) -> dict[str, str]:
    """The desktop session's variables, with HOME (and so the NSS db) the dev browser's own. XDG base dirs
    are dropped so nothing lands in your real config or cache."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("XDG_") or k in BROWSER_ENV_KEEP}
    env["HOME"] = str(home)
    return env


def ensure_browser_trust(ctx: Ctx, ca: Path) -> None:
    """The dev CA's root in the dev browser's own NSS db, and nowhere else; replaced if the root changed."""
    db, nick = browser_home(ctx) / ".pki" / "nssdb", ctx.cfg["tls.nss_nickname"]
    if not (db / "cert9.db").exists():
        db.mkdir(mode=0o700, parents=True, exist_ok=True)
        ctx.r.run(["certutil", "-N", "-d", f"sql:{db}", "--empty-password"])
    have = ctx.r.run(["certutil", "-L", "-d", f"sql:{db}", "-n", nick, "-a"], check=False).stdout or ""
    if re.sub(r"\s+", "", have) == re.sub(r"\s+", "", ca.read_text()):
        return
    ctx.r.run(["certutil", "-D", "-d", f"sql:{db}", "-n", nick], check=False)
    ctx.r.run(["certutil", "-A", "-d", f"sql:{db}", "-t", "C,,", "-n", nick, "-i", ca])
    log.info("dev browser trusts the devstack root CA (in its own NSS db, %s)", db)


def dead_proxy_free() -> bool:
    with socket.socket() as sock:
        sock.settimeout(0.5)
        return sock.connect_ex(DEAD_PROXY) != 0


def launch_detached(argv: list[str], env: dict[str, str], log_path: Path) -> None:
    log.debug("$ %s", shlex.join(argv))
    fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "ab") as fh:
        subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL, stdout=fh, stderr=subprocess.STDOUT,
                         start_new_session=True)


def cmd_browse(ctx: Ctx, args: argparse.Namespace) -> int:
    c = ctx.cfg
    ca = ctx.state_dir / "ca" / "root.crt"
    if ctx.state.status("proxy") != "done" or not ca.exists():
        raise DevstackError("there is no dev site yet: run `devstack up` (through phase proxy) first")
    binary = c["browser.binary"] or next((b for b in BROWSER_BINARIES if shutil.which(b)), "")
    if not binary or not shutil.which(binary):
        raise DevstackError(f"no Chromium found ({c['browser.binary'] or ', '.join(BROWSER_BINARIES)}): "
                            "apt install chromium, or set browser.binary")
    if not shutil.which("certutil"):
        raise DevstackError("certutil is missing (sudo apt install libnss3-tools): the dev browser needs it "
                            "to trust the dev CA")
    if not dead_proxy_free():
        raise DevstackError(f"something listens on {DEAD_PROXY[0]}:{DEAD_PROXY[1]}, the dead-end proxy that keeps "
                            "the dev browser off everything but the dev domain: stop it first")
    url = browser_target(ctx, args.target)
    home = browser_home(ctx)
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(home, 0o700)
    ensure_browser_trust(ctx, ca)
    launch_detached(browser_argv(ctx, binary, url, args.app), browser_env(home), home / "chromium.log")
    log.info("dev browser: %s (reaches only %s; profile in %s)", url, ", ".join(dev_domains(c)), home)
    return 0


def summary(ctx: Ctx) -> None:
    c = ctx.cfg
    log.info("")
    log.info("done. Next:")
    log.info("  ssh %s                         # shell in the container", c["ssh.host_alias"])
    log.info("  VSCode: Remote-SSH -> %s -> open %s", c["ssh.host_alias"], ctx.cproject)
    if ctx.state.status("proxy") == "done":
        log.info("  ./devstack browse               # https://%s/ in a browser confined to the dev domain",
                 c.dev_host)
    if ctx.state.status("isolation") == "done":
        log.info("  inside: sudo devstack-sync status | restart app | reload caddy   (root: incus exec %s -- bash)",
                 ctx.name)
    if c["sbom.enabled"]:
        log.info("  ./devstack sbom show | scan     # dependency inventory in %s/, scanned by grype", c["sbom.dir"])
    log.info("  ./devstack leaks scan           # secrets in git history and uncommitted files, before you push")
    log.info("  ./devstack status | undo | snapshot list | db backup | data backup")


def cmd_status(ctx: Ctx) -> int:
    c = ctx.cfg
    inst = ctx.instance() if shutil.which("incus") else None
    print(f"stack {c['stack.name']} (config {c.source}, state {ctx.state_dir})")
    print(f"  container {ctx.name}: {inst['status'] if inst else 'absent'}   IPv4 {ctx.state.fact('ipv4', '-')}")
    print(f"  dev URL   https://{c.dev_host}/")
    print("  phases:")
    for p in PHASES:
        print(f"    {p.id:<10} {ctx.state.status(p.id) if p.enabled(c) else 'disabled':<12} {p.title}")
    if c["sbom.enabled"]:
        gen = ctx.state.fact("sbom_generated_at")
        stale = sbom_stale_inputs(ctx)
        where = f"{c['sbom.dir']}/"
        if not gen:
            print(f"  sbom      {where:<28} not generated yet")
        elif stale:
            print(f"  sbom      {where:<28} generated {gen}, STALE ({', '.join(stale)} changed)")
        else:
            print(f"  sbom      {where:<28} generated {gen} by syft {ctx.state.fact('sbom_syft_version', '?')}")
    owned = [e for e in ctx.journal.entries if e["status"] in OWNED]
    print(f"  journal: {len(ctx.journal.entries)} entries, {len(owned)} still owned")
    for e in owned:
        if e["kind"] in ("incus_volume", "incus_acl", "host_pkg", "host_tool", "incus_snapshot"):
            print(f"    {e['kind']:<15} {e['status']:<8} {e['args']}")
    return 0


def prune_snapshots(ctx: Ctx) -> int:
    n = 0
    for e in ctx.journal.entries:
        if e["kind"] == "incus_snapshot" and e["status"] == "applied" and ctx.state.status(e["phase"]) == "done":
            a = e["args"]
            if ctx.instance(a["instance"]) is not None and a["snapshot"] in ctx.snapshot_names(a["instance"]):
                ctx.r.run(["incus", "snapshot", "delete", a["instance"], a["snapshot"]])
            ctx.journal.mark(e, "pruned")
            log.info("pruned snapshot %s/%s (phase %s can now only be undone with undo --all)",
                     a["instance"], a["snapshot"], e["phase"])
            n += 1
    if not n:
        log.info("no phase snapshots to prune")
    return n


def cmd_snapshot(ctx: Ctx, args: argparse.Namespace) -> int:
    c = ctx.cfg
    if args.action == "list":
        data = ctx.iq(f"/1.0/instances/{ctx.name}/snapshots?recursion=1") or []
        mine = {e["args"]["snapshot"]: e for e in ctx.journal.entries
                if e["kind"] == "incus_snapshot" and e["status"] in ACTIVE}
        if not data:
            print("no snapshots")
        for s in data:
            e = mine.get(s["name"])
            role = (f"undo point for phase '{e['phase']}'" if e else
                    "checkpoint (devstack checkpoint)" if s["name"].startswith(CHECKPOINT_PREFIX) else
                    "manual (not managed by devstack)")
            print(f"  {s['name']:<32} {s.get('created_at', '')[:19]}  {role}")
        print("\nrollback: ./devstack undo [--to PHASE]   cleanup: ./devstack snapshot prune")
        return 0
    with Lock(ctx):
        if args.action == "create":
            if args.name.startswith((c["snapshots.prefix"], CHECKPOINT_PREFIX)):
                raise ConfigError(f"manual snapshot names must not start with {c['snapshots.prefix']} or "
                                  f"{CHECKPOINT_PREFIX}")
            ctx.r.run(["incus", "snapshot", "create", ctx.name, args.name], stream=True)
            log.info("created %s/%s (restore: incus snapshot restore %s %s)", ctx.name, args.name, ctx.name, args.name)
            return 0
        if not ctx.confirm("Delete the phase snapshots of all done phases? Those phases can then only be undone "
                           "with `undo --all`.", destructive=True):
            return 0
        prune_snapshots(ctx)
    return 0


def cmd_undo(ctx: Ctx, args: argparse.Namespace) -> int:
    with Lock(ctx):
        active = active_phases(ctx)
        whole = args.all or args.command == "destroy"
        if whole:
            targets = active
        elif args.to:
            if args.to not in PHASE_BY_ID:
                raise ConfigError(f"--to {args.to}: unknown phase")
            targets = [p for p in active if PHASES.index(p) > PHASES.index(PHASE_BY_ID[args.to])]
        else:
            targets = active[-1:]
        def leftover(e: dict) -> bool:
            return e["status"] in ACTIVE or (
                args.purge_data and e["kind"] == "incus_volume" and e["status"] == "kept")

        if not targets and not (whole and any(leftover(e) for e in ctx.journal.entries)):
            log.info("nothing to undo")
            return 0
        if args.purge_data and not whole:
            raise ConfigError("--purge-data only makes sense with undo --all / destroy")
        names = ", ".join(p.id for p in reversed(targets)) or "leftover journal entries"
        extra = (" AND DELETE the data volumes (Postgres, app data)" if args.purge_data
                 else " (the data volumes are kept)")
        if not ctx.confirm(f"Undo {names}{extra}?", destructive=True):
            return 0
        if ctx.interactive:
            ctx.r.run(["sudo", "-v"], tty=True)
        undo_phases(ctx, targets, UndoOpts(purge_data=args.purge_data, whole=whole))
        if whole:  # anything left: entries of earlier failed rollbacks, a kept volume when purging
            for e in reversed(ctx.journal.entries):
                if leftover(e):
                    ctx.phase = e["phase"]
                    ctx.journal.mark(e, UNDO[e["kind"]](ctx, e["args"], UndoOpts(args.purge_data, True)))
        log.info("undo finished: %s", names)
    return 0


# --- sbom: generate the CycloneDX inventory (syft, in the container) and scan it (grype, host) ---
#
# The split is deliberate. syft runs in the container because only there is the real dpkg database,
# the Node tarball and node_modules. grype runs on the host against the committed document, so the
# container never needs the ~1 GB vulnerability database and its restricted egress never has to
# reach a feed. The container is the artifact; the host is the auditor.


def sbom_path(ctx: Ctx, kind: str) -> Path:
    return ctx.project / ctx.cfg["sbom.dir"] / f"{kind}.cdx.json"


# The project files that most often leave the inventory stale: a declared apt package, and the npm
# lockfile. Both live on the host, so comparing their hashes is a container-free staleness *hint*.
# It is not a substitute for `sbom check`, which is the only thing that compares against the real
# container -- in particular it cannot see a package someone installed by hand with incus exec.
SBOM_INPUT_FILES = ("infra/apt-packages.txt", "pnpm-lock.yaml")


def sbom_input_hashes(ctx: Ctx) -> dict[str, str]:
    return {rel: (sha256_file(ctx.project / rel) if (ctx.project / rel).exists() else "")
            for rel in SBOM_INPUT_FILES}


def sbom_stale_inputs(ctx: Ctx) -> list[str]:
    """Which recorded inputs have changed since the inventory was last generated ([] if unknown)."""
    seen = ctx.state.fact("sbom_inputs") or {}
    if not seen:
        return []
    now = sbom_input_hashes(ctx)
    return [rel for rel, h in sorted(now.items()) if seen.get(rel, "") != h]


def sbom_kinds(which: str | None) -> tuple[str, ...]:
    return SBOM_KINDS if which in (None, "all") else (which,)


def host_arch() -> str:
    m = platform.machine().lower()
    if m in ("x86_64", "amd64"):
        return "amd64"
    if m in ("aarch64", "arm64"):
        return "arm64"
    raise PreflightError(f"no pinned grype/gitleaks build for this host's architecture ({m or 'unknown'})")


def sbom_scan_one(ctx: Ctx, kind: str) -> dict[str, Any]:
    """Run syft in the container for one document and bring the normalized result back."""
    c = ctx.cfg
    ctx.cexec(bash("install -d -m 0700 @@D@@", D=SBOM_DIR_CONTAINER))
    # A hung cataloger must fail loudly rather than wedge `up`.
    ctx.cexec(shlex.join(syft_argv(ctx, kind)), stream=True, timeout=900)
    local = ctx.state_dir / "tmp" / f"{kind}.cdx.json"
    try:
        ctx.cpull(f"{SBOM_DIR_CONTAINER}/{kind}.cdx.json", local)
        raw = json.loads(local.read_text())
    finally:
        local.unlink(missing_ok=True)
    doc = normalize_cdx(raw, kind=kind, stack=c["stack.name"],
                        source_version=c["container.image"] if kind == "container" else "")
    if kind == "app" and not doc["components"] and (ctx.project / "pnpm-lock.yaml").exists():
        raise DevstackError(
            "syft found no packages although pnpm-lock.yaml exists. Its lockfile parser may have "
            'changed: set sbom.app_source = "tree" to scan node_modules instead, and check whether '
            f"syft {SYFT_VERSION} still supports this lockfile version.")
    return doc


def sbom_text(ctx: Ctx, doc: dict[str, Any]) -> str:
    """Serialize, then refuse to go further if anything host-shaped survived."""
    text = cdx_bytes(doc)
    paths = [str(ctx.project), str(ctx.state_dir), str(home_dir())]
    paths += [str(m.get("source", "")) for m in ctx.cfg["container.mounts"]]
    assert_no_sbom_leaks(text, [p for p in paths if p and p != "/"],
                         names=[ctx.cfg["container.user"]])
    return text


def generate_sboms(ctx: Ctx, which: str | None = None) -> int:
    c = ctx.cfg
    ctx.phase = "base"  # journaled under base, next to infra/devstack-requires.toml
    for kind in sbom_kinds(which):
        doc = sbom_scan_one(ctx, kind)
        rel = f"{c['sbom.dir']}/{kind}.cdx.json"
        wrote = ctx.project_file(rel, sbom_text(ctx, doc), managed=True)
        log.info("  %s %s (%d components)", "wrote" if wrote else "unchanged", rel, len(doc["components"]))
    ctx.state.set_fact("sbom_syft_version", SYFT_VERSION)
    ctx.state.set_fact("sbom_generated_at", dt.datetime.now().isoformat(timespec="seconds"))
    if which in (None, "all"):  # a partial generate says nothing about the other document
        ctx.state.set_fact("sbom_inputs", sbom_input_hashes(ctx))
    return 0


def sbom_check(ctx: Ctx, which: str | None = None) -> int:
    """Regenerate and compare with what is committed. The machine gate: a dependency that changed
    without the inventory changing with it fails here instead of being noticed by nobody."""
    c = ctx.cfg
    drifted = []
    for kind in sbom_kinds(which):
        path, rel = sbom_path(ctx, kind), f"{c['sbom.dir']}/{kind}.cdx.json"
        fresh = sbom_text(ctx, sbom_scan_one(ctx, kind))
        if not path.exists():
            log.error("%s is missing; run `devstack sbom generate`", rel)
            drifted.append(kind)
            continue
        if path.read_text() == fresh:
            log.info("  %s is up to date", rel)
            continue
        drifted.append(kind)
        old, new = json.loads(path.read_text()), json.loads(fresh)
        before, after = dict((n, v) for n, v, _ in cdx_inventory(old)), dict(
            (n, v) for n, v, _ in cdx_inventory(new))
        for name in sorted(set(after) - set(before)):
            log.error("  + %s %s", name, after[name])
        for name in sorted(set(before) - set(after)):
            log.error("  - %s %s", name, before[name])
        for name in sorted(set(before) & set(after)):
            if before[name] != after[name]:
                log.error("  ~ %s %s -> %s", name, before[name], after[name])
        if before == after:  # metadata-only difference (a syft bump, usually)
            diff = list(difflib.unified_diff(path.read_text().splitlines(), fresh.splitlines(),
                                             rel, "regenerated", lineterm=""))[:40]
            log.error("  same packages, different document:\n    %s", "\n    ".join(diff))
    if drifted:
        raise GateError(f"{', '.join(drifted)}: the committed SBOM does not match the environment. "
                        "Run `devstack sbom generate` and commit the result.")
    if which in (None, "all"):
        ctx.state.set_fact("sbom_inputs", sbom_input_hashes(ctx))  # verified against the container
    return 0


def fetch_host_tool(ctx: Ctx, d: Path, tool: str, version: str, sha256: str, url: str) -> Path:
    """Download a pinned release tarball into d/bin, check its sha256 and keep only the one member
    named `tool`. No sudo, no apt: there is no Debian package, and the version has to match the pin
    that was verified."""
    ctx.phase = "host"
    ctx.ensure_dir(d, 0o700)
    ctx.ensure_dir(d / "bin", 0o700)
    binary = d / "bin" / f"{tool}-{version}"
    if binary.exists():
        return binary
    name = url.rsplit("/", 1)[1]
    tmp = d / name
    log.info("  downloading %s %s (%s)", tool, version, name)
    try:
        ctx.r.run(["curl", "-fsSL", "--max-time", "300", "-o", str(tmp), url])
        got = sha256_file(tmp)
        if got != sha256:
            raise DevstackError(f"{name} sha256 mismatch:\n  got      {got}\n  expected {sha256}\n"
                                "The download was not what this version of devstack pinned; nothing "
                                "was installed.")
        # Only the one member we want, by name: never extractall a downloaded archive.
        with tarfile.open(tmp, "r:gz") as tf:
            src = tf.extractfile(tool)
            if src is None:
                raise DevstackError(f"{name} has no '{tool}' entry")
            e = ctx.journal.add("host", "host_tool", path=str(binary))
            atomic_write(binary, src.read(), 0o700)  # atomic_write takes bytes too
            ctx.journal.mark(e, "applied")
    finally:
        tmp.unlink(missing_ok=True)
    log.info("  %s %s at %s", tool, version, binary)
    return binary


def ensure_grype(ctx: Ctx) -> Path:
    arch = host_arch()
    name = f"grype_{GRYPE_VERSION}_linux_{arch}.tar.gz"
    return fetch_host_tool(ctx, Path(ctx.cfg["sbom.db_dir"]), "grype", GRYPE_VERSION, GRYPE_SHA256[arch],
                           f"https://github.com/anchore/grype/releases/download/v{GRYPE_VERSION}/{name}")


# A finding whose fix.state is not "fixed" cannot be acted on: there is no package to upgrade to.
# Debian carries a lot of these ("not-fixed" = no fix yet, "wont-fix" = judged not worth one).
SBOM_FIXED = "fixed"


def gate_findings(report: dict[str, Any], fail_on: str, ignore: list[str],
                  *, only_fixed: bool = True) -> tuple[dict[str, int], dict[str, int], list[str]]:
    """Counts by severity, counts of those with a fix available, and the ids that trip the gate.

    Pure, so the gate is testable without grype. An unknown severity (a future grype adding one)
    counts but never trips the gate: a surprise string must not fail someone's build.

    only_fixed: count only findings with a fix available towards fail_on. On by default because a
    finding with no fix is not actionable -- measured on a 3214-package Debian system, *all* 554
    critical findings were not-fixed or wont-fix. Gating on those would make the gate permanently
    red, which teaches people to switch it off and is worse than having no gate. The full counts
    are still reported, so nothing is hidden; only what *fails the build* is narrowed."""
    skip = {i.strip().upper() for i in ignore}
    counts: dict[str, int] = {}
    fixable: dict[str, int] = {}
    tripped: set[str] = set()
    floor = SEVERITIES.index(fail_on) if fail_on in SEVERITIES else None
    for m in report.get("matches") or []:
        vuln = m.get("vulnerability") or {}
        vid = str(vuln.get("id", "")).strip()
        if not vid or vid.upper() in skip:
            continue
        sev = str(vuln.get("severity", "unknown")).lower()
        has_fix = str((vuln.get("fix") or {}).get("state", "")).lower() == SBOM_FIXED
        counts[sev] = counts.get(sev, 0) + 1
        if has_fix:
            fixable[sev] = fixable.get(sev, 0) + 1
        if floor is not None and sev in SEVERITIES and SEVERITIES.index(sev) >= floor \
                and (has_fix or not only_fixed):
            tripped.add(vid)
    return counts, fixable, sorted(tripped)


def sbom_scan(ctx: Ctx, args: argparse.Namespace) -> int:
    c = ctx.cfg
    fail_on = args.fail_on if args.fail_on is not None else c["sbom.fail_on"]
    if fail_on and fail_on not in SEVERITIES:
        raise ConfigError(f"--fail-on must be one of {', '.join(SEVERITIES)}")
    grype, db = ensure_grype(ctx), Path(c["sbom.db_dir"]) / "db"
    if args.offline and not db.exists():
        raise DevstackError(f"no vulnerability database in {db} and --offline was given. Run "
                            "`devstack sbom scan` once with network access first.")
    reports = ctx.state_dir / "sbom-reports"
    ctx.ensure_dir(reports, 0o700)
    stamp = f"{dt.datetime.now():%Y%m%d-%H%M%S}"
    # Keep the ambient environment (a proxy, a CA bundle and TMPDIR all matter for the database
    # download) but drop any ambient GRYPE_* setting, which could quietly change what is reported.
    env = {k: v for k, v in os.environ.items() if not k.startswith("GRYPE_")}
    env["GRYPE_DB_CACHE_DIR"] = str(db)
    if args.offline:
        env["GRYPE_DB_AUTO_UPDATE"] = "false"
    total: dict[str, int] = {}
    tripped: dict[str, list[str]] = {}
    ecosystems: set[str] = set()
    for kind in sbom_kinds(args.which):
        path = sbom_path(ctx, kind)
        if not path.exists():
            raise DevstackError(f"{path} does not exist; run `devstack sbom generate` first")
        out = reports / f"{stamp}-{kind}.json"
        log.info("scanning %s with grype %s", path.name, GRYPE_VERSION)
        p = ctx.r.run([str(grype), f"sbom:{path}", "-o", "table", "-o", f"json={out}", "--by-cve"],
                      env=env, stream=True, check=False)
        # grype leaves a zero-byte report behind when it fails (a missing database, for one), so
        # "the file is there" is not enough: an empty or unparsable report must be a clean error
        # rather than a traceback, and must never be mistaken for "nothing found".
        if p.returncode != 0 or not out.exists() or out.stat().st_size == 0:
            out.unlink(missing_ok=True)
            hint = ("\nThere is no vulnerability database yet: run `devstack sbom scan` with network "
                    "access once." if "database does not exist" in p.stdout else "")
            raise DevstackError(f"grype failed on {kind} (exit {p.returncode}):\n{p.stdout[-2000:]}{hint}")
        os.chmod(out, 0o600)
        try:
            report = json.loads(out.read_text())
        except ValueError as e:
            raise DevstackError(f"grype's report for {kind} is not valid JSON ({e}); see {out}") from None
        counts, fixable, ids = gate_findings(report, fail_on, c["sbom.ignore"],
                                             only_fixed=c["sbom.only_fixed"])
        for sev, n in counts.items():
            total[sev] = total.get(sev, 0) + n
        if ids:
            tripped[kind] = ids
            hit = set(ids)
            ecosystems |= {str((m.get("artifact") or {}).get("type", "")) for m in report.get("matches") or []
                           if str((m.get("vulnerability") or {}).get("id", "")) in hit}
        built = ((report.get("descriptor") or {}).get("db") or {}).get("built")
        if built:
            log.info("  vulnerability database built %s", built)
        # Show the split: on Debian most findings have no fix, and a bare count would look alarming
        # while describing nothing anyone can act on.
        shown = ", ".join(f"{n} {sev} ({fixable.get(sev, 0)} fixable)"
                          for sev, n in sorted(counts.items(), key=lambda kv: -kv[1]))
        log.info("  %s: %s", kind, shown or "nothing found")
        if sum(counts.values()) and not sum(fixable.values()):
            log.info("    none of these has a fix available: no package upgrade would change it")
    log.info("report(s) in %s (newest %d kept, not committed: a scan is point in time)",
             reports, SBOM_REPORT_KEEP)
    for old in sorted(reports.glob("*.json"), reverse=True)[SBOM_REPORT_KEEP * len(sbom_kinds(args.which)):]:
        old.unlink(missing_ok=True)
    if c["sbom.ignore"]:
        log.info("ignored by sbom.ignore: %s", ", ".join(c["sbom.ignore"]))
    if tripped:
        what = "fixable " if c["sbom.only_fixed"] else ""
        # Say what to actually run. The two halves of the inventory are fixed in different places:
        # deb packages from the host, npm packages by the project deliberately rewriting its lockfile.
        hints = []
        if "deb" in ecosystems:
            hints.append("`devstack upgrade` (or rebuild: `destroy` then `up`, for a fresh base image)")
        if "npm" in ecosystems:
            hints.append(f"`pnpm update <pkg>` in {ctx.cproject}, then `devstack sbom generate`")
        raise GateError(f"sbom.fail_on = {fail_on}: " + "; ".join(
            f"{kind}: {len(ids)} {what}finding(s) at or above {fail_on} "
            f"({', '.join(ids[:8])}{', ...' if len(ids) > 8 else ''})"
            for kind, ids in tripped.items())
            + ".\n  Fix: " + "; ".join(hints or ["upgrade the affected packages"])
            + "\n  Or record an accepted id in sbom.ignore, with the reason in the project README.")
    return 0


def sbom_show(ctx: Ctx, which: str | None = None) -> int:
    c = ctx.cfg
    for kind in sbom_kinds(which):
        path = sbom_path(ctx, kind)
        if not path.exists():
            raise DevstackError(f"{path} does not exist; run `devstack sbom generate` first")
        doc = json.loads(path.read_text())
        inv = cdx_inventory(doc)
        tools = ((doc.get("metadata") or {}).get("tools") or {}).get("components") or []
        by = ", ".join(f"{t.get('name')} {t.get('version')}" for t in tools)
        print(f"{c['sbom.dir']}/{kind}.cdx.json  CycloneDX {doc.get('specVersion')}, "
              f"{len(inv)} components, generated by {by}")
        eco: dict[str, int] = {}
        for _n, _v, purl in inv:
            key = purl.split("/", 1)[0].removeprefix("pkg:") if purl.startswith("pkg:") else "(no purl)"
            eco[key] = eco.get(key, 0) + 1
        print("  " + ", ".join(f"{n} {k}" for k, n in sorted(eco.items())))
        for name, ver, purl in inv:
            print(f"    {name:<34} {ver:<26} {purl}")
        print()
    return 0


def cmd_sbom(ctx: Ctx, args: argparse.Namespace) -> int:
    c = ctx.cfg
    if not c["sbom.enabled"]:
        raise ConfigError("sbom.enabled = false: set it to true and run `up --redo base` to install syft")
    if args.action == "show":
        return sbom_show(ctx, args.which)
    if args.action == "scan":
        with Lock(ctx):
            return sbom_scan(ctx, args)
    with Lock(ctx):
        if ctx.state.status("base") != "done":
            raise DevstackError("the base phase is not done: run `devstack up --to base` first")
        if not ctx.instance_running():
            raise DevstackError(f"container {ctx.name} is not running")
        ensure_syft(ctx)
        return generate_sboms(ctx, args.which) if args.action == "generate" else sbom_check(ctx, args.which)


# Secret scanning: gitleaks on the host, over the project's history and its uncommitted files.
# Every input gitleaks would take from the project is replaced by one of devstack's, because the
# project is writable from the container: see DESIGN §8.8.
LEAKS_CONFIG = "# generated by devstack: gitleaks' default rules, nothing else\n[extend]\nuseDefault = true\n"
# gitleaks runs git itself, so git_run's `-c` flags can't be passed; GIT_CONFIG_COUNT is the env form.
LEAKS_GIT_CONFIG = (("core.fsmonitor", "false"), ("core.hooksPath", "/dev/null"))
ANSI_RX = re.compile(r"\x1b\[[0-9;]*m")
# gitleaks logs a failed git (or any other error) as ERR and still exits 0 with an empty report.
LEAKS_ERROR_RX = re.compile(r"^\S+\s+(ERR|FTL|PNC)\b", re.M)


def ensure_gitleaks(ctx: Ctx) -> Path:
    arch = host_arch()
    name = f"gitleaks_{GITLEAKS_VERSION}_linux_{GITLEAKS_ARCH[arch]}.tar.gz"
    return fetch_host_tool(ctx, Path(ctx.cfg["leaks.tool_dir"]), "gitleaks", GITLEAKS_VERSION,
                           GITLEAKS_SHA256[arch],
                           f"https://github.com/gitleaks/gitleaks/releases/download/v{GITLEAKS_VERSION}/{name}")


def gitleaks_env(ctx: Ctx) -> dict[str, str]:
    """git_env (a complete environment, so no ambient GITLEAKS_CONFIG / GITLEAKS_CONFIG_TOML gets
    through) plus the config git_run passes on its command line."""
    env = git_env(ctx)
    env["GIT_CONFIG_COUNT"] = str(len(LEAKS_GIT_CONFIG))
    for i, (k, v) in enumerate(LEAKS_GIT_CONFIG):
        env[f"GIT_CONFIG_KEY_{i}"], env[f"GIT_CONFIG_VALUE_{i}"] = k, v
    return env


def gitleaks_argv(binary: Path, mode: str, source: Path, report: Path, config: Path, ignore: Path) -> list[str]:
    """mode "git": the history of the repository GIT_DIR names (gitleaks_env); mode "dir": a folder.

    `source` is always an empty or devstack-filled folder, never the project: gitleaks reads
    <source>/.gitleaksignore whatever --gitleaks-ignore-path says, and ./.gitleaksignore too unless that
    flag is given, so both point at devstack's files. --config wins over <source>/.gitleaks.toml and the
    GITLEAKS_CONFIG* variables. --ignore-gitleaks-allow: an inline `gitleaks:allow` is container-written
    text like any other. --exit-code 0: a non-zero exit then only ever means the tool broke, and
    devstack decides on findings itself (leaks.ignore is matched in leaks_gate, not by gitleaks)."""
    return [str(binary), mode, "--no-banner", "--no-color", "--redact", "--exit-code", "0",
            "--ignore-gitleaks-allow", "--report-format", "json", "--report-path", str(report),
            "--config", str(config), "--gitleaks-ignore-path", str(ignore), "--log-level", "info", str(source)]


def read_project_file(root: Path, rel: str) -> tuple[bytes | None, str]:
    """Read a file the container can write, from the host, without being led anywhere: no symlinks
    (O_NOFOLLOW for the last component, realpath for the parents), nothing but a regular file
    (O_NONBLOCK so a FIFO can't block the open, fstat before reading) and nothing over LEAKS_MAX_FILE.
    Returns (content, "") or (None, why); why is "" for things with nothing to scan (deleted,
    symlinks, directories such as submodules)."""
    full = root / rel
    if not _within(Path(os.path.realpath(full.parent)), root):
        return None, "a parent folder leads outside the project"
    try:
        fd = os.open(full, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return None, ""
    except OSError as e:
        return None, "" if e.errno == errno.ELOOP else (e.strerror or str(e))
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if stat.S_ISDIR(st.st_mode):
            return None, ""
        if not stat.S_ISREG(st.st_mode):
            return None, "not a regular file"
        if st.st_size > LEAKS_MAX_FILE:
            return None, f"larger than {human_bytes(LEAKS_MAX_FILE)}"
        return f.read(LEAKS_MAX_FILE + 1), ""


def leaks_stage_tree(ctx: Ctx, dest: Path) -> tuple[int, list[str]]:
    """Copy what is about to be committed into dest, for `gitleaks dir`: working/<path> for every
    tracked or untracked-but-not-ignored file as it is now, staged/<path> for the index version of
    each staged change. Not `gitleaks git --pre-commit`/`--staged`: those scan a `git diff`, and a
    container-written .gitattributes saying `-diff` turns a change into "Binary files differ"
    (GIT_ATTR_SOURCE, the way around that, needs git 2.40). Ignored files (.env) stay out, as they
    stay out of git. Returns (files copied, "path (why)" for each one skipped)."""
    root = ctx.project.resolve()
    copied, skipped = 0, []

    def put(sub: str, rel: str, data: bytes) -> None:
        target = Path(os.path.normpath(dest / sub / rel))
        if not _within(target, dest / sub):  # git never lists such a path; refuse one anyway
            skipped.append(f"{rel} (not a plain relative path)")
            return
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    listed = nul_paths(git_run(ctx, "ls-files", "-z", "--cached", "--others", "--exclude-standard"))
    for rel in dict.fromkeys(listed):  # a conflicted path is listed once per stage
        data, why = read_project_file(root, rel)
        if data is None:
            if why:
                skipped.append(f"{rel} ({why})")
            continue
        put("working", rel, data)
        copied += 1
    staged = nul_paths(git_run(ctx, "diff", "--cached", "--name-only", "-z", "--no-renames",
                               "--diff-filter=d"))
    for rel in staged:
        try:
            data = git_run(ctx, "cat-file", "blob", f":{rel}")  # bytes as staged, no filters
        except CommandError:  # a conflicted path has stages 1-3, not 0: the working copy covers it
            continue
        if len(data) > LEAKS_MAX_FILE:
            skipped.append(f"{rel} (staged, larger than {human_bytes(LEAKS_MAX_FILE)})")
            continue
        put("staged", rel, data)
        copied += 1
    return copied, skipped


def leaks_findings(report: Any, strip: str = "") -> list[dict[str, Any]]:
    """One gitleaks JSON report -> what devstack prints and gates on. Secret and Match are never
    carried over: --redact already blanks them, and leaving them out here means a gitleaks change
    can't put a credential into devstack's output or log. `strip` removes the staging folder's prefix,
    so a fingerprint is stable from run to run: <commit>:<file>:<rule>:<line> from history (the same as
    gitleaks' own), working/<file>:<rule>:<line> or staged/<file>:<rule>:<line> otherwise."""
    if not isinstance(report, list):
        raise DevstackError(f"gitleaks report is not a list (got {type(report).__name__})")
    out = []
    for f in report:
        file = str(f.get("File") or "")
        if strip and file.startswith(strip):
            file = file[len(strip):]
        rule, line, commit = str(f.get("RuleID") or ""), int(f.get("StartLine") or 0), str(f.get("Commit") or "")
        out.append({"rule": rule, "file": file, "line": line, "commit": commit,
                    "date": str(f.get("Date") or "")[:10],
                    "fingerprint": f"{commit}:{file}:{rule}:{line}" if commit else f"{file}:{rule}:{line}"})
    return sorted(out, key=lambda x: (x["file"], x["line"], x["rule"], x["commit"]))


def leaks_gate(findings: list[dict[str, Any]], ignore: list[str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(counted, ignored). Matched here rather than by gitleaks, so leaks.ignore uses the fingerprints
    devstack prints and the decision is testable without the binary."""
    skip = set(ignore)
    return ([f for f in findings if f["fingerprint"] not in skip],
            [f for f in findings if f["fingerprint"] in skip])


def run_gitleaks(ctx: Ctx, argv: list[str], report: Path, what: str) -> tuple[Any, str]:
    p = ctx.r.run(argv, env=gitleaks_env(ctx), stream=True, check=False)
    out = ANSI_RX.sub("", p.stdout or "")
    errors = [m.group(0) for m in LEAKS_ERROR_RX.finditer(out)]
    if p.returncode != 0 or errors or not report.exists() or report.stat().st_size == 0:
        report.unlink(missing_ok=True)
        tail = "\n".join(ln for ln in out.splitlines()[-30:])
        raise DevstackError(f"gitleaks failed on {what} (exit {p.returncode}); an error is never read as "
                            f"'nothing found':\n{tail}")
    os.chmod(report, 0o600)
    try:
        return json.loads(report.read_text()), out
    except ValueError as e:
        raise DevstackError(f"gitleaks' report for {what} is not valid JSON ({e}); see {report}") from None


def leaks_scan(ctx: Ctx, args: argparse.Namespace) -> int:
    c = ctx.cfg
    history = c["leaks.history"] and not args.no_history
    try:
        git_run(ctx, "rev-parse", "--git-dir")
    except CommandError:
        raise DevstackError(f"{ctx.project} is not a git repository: there is nothing to scan yet") from None
    has_commits = bool(git_run(ctx, "rev-parse", "--verify", "-q", "HEAD", check=False).strip())
    gitleaks = ensure_gitleaks(ctx)
    work = ctx.state_dir / "leaks"
    reports = ctx.state_dir / "leaks-reports"
    ctx.ensure_dir(work, 0o700)
    ctx.ensure_dir(reports, 0o700)
    config, ignore = work / "gitleaks.toml", work / "empty.gitleaksignore"
    atomic_write(config, LEAKS_CONFIG, 0o600)
    atomic_write(ignore, "", 0o600)
    stamp = f"{dt.datetime.now():%Y%m%d-%H%M%S}"
    findings: list[dict[str, Any]] = []
    skipped: list[str] = []
    tmp = Path(tempfile.mkdtemp(prefix="scan-", dir=work))  # 0700; holds copies of project files
    try:
        if history and has_commits:
            src = tmp / "history"
            src.mkdir()
            out = reports / f"{stamp}-history.json"
            log.info("scanning git history with gitleaks %s", GITLEAKS_VERSION)
            report, text = run_gitleaks(ctx, gitleaks_argv(gitleaks, "git", src, out, config, ignore), out,
                                        "the git history")
            m = re.search(r"(\d+) commits scanned", text)
            if not m or int(m.group(1)) == 0:  # HEAD exists, so zero commits means git failed quietly
                raise DevstackError(f"gitleaks scanned no commits although {ctx.project} has some:\n{text[-2000:]}")
            got = leaks_findings(report)
            log.info("  %s commit(s), %d finding(s)", m.group(1), len(got))
            findings += got
        elif history:
            log.info("no commits yet: only the files themselves are scanned")
        src = tmp / "tree"
        src.mkdir()
        copied, skipped = leaks_stage_tree(ctx, src)
        out = reports / f"{stamp}-files.json"
        log.info("scanning %d current and staged file(s) with gitleaks %s", copied, GITLEAKS_VERSION)
        report, _ = run_gitleaks(ctx, gitleaks_argv(gitleaks, "dir", src, out, config, ignore), out,
                                 "the project's files")
        got = leaks_findings(report, strip=f"{src}/")
        log.info("  %d finding(s)", len(got))
        findings += got
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    for f in skipped:
        log.warning("not scanned: %s", f)
    for old in sorted(reports.glob("*.json"), reverse=True)[LEAKS_REPORT_KEEP * 2:]:
        old.unlink(missing_ok=True)
    counted, ignored = leaks_gate(findings, c["leaks.ignore"])
    for f in counted:
        where = (f"commit {f['commit'][:12]} ({f['date']})" if f["commit"] else
                 "staged" if f["file"].startswith("staged/") else "working tree")
        name = f["file"].split("/", 1)[1] if not f["commit"] else f["file"]
        log.info("  %-22s %s:%d  %s\n      fingerprint %s", f["rule"], name, f["line"], where, f["fingerprint"])
    log.info("report(s) in %s (redacted, newest %d kept, never committed)", reports, LEAKS_REPORT_KEEP)
    if ignored:
        log.info("ignored by leaks.ignore: %d finding(s)", len(ignored))
    if counted:
        raise GateError(
            f"{len(counted)} possible secret(s) in the project.\n"
            "  A real one: rotate it first -- once committed, and above all once pushed, treat it as "
            "leaked; rewriting history does not take it back. Then remove it from the file and keep it "
            "in an ignored file (.env) or the container's secrets folder.\n"
            "  A false positive: add its fingerprint to leaks.ignore in devstack.toml.")
    log.info("no secrets found")
    return 0


def cmd_leaks(ctx: Ctx, args: argparse.Namespace) -> int:
    with Lock(ctx):
        return leaks_scan(ctx, args)


def cmd_db(ctx: Ctx, args: argparse.Namespace) -> int:
    c = ctx.cfg
    if ctx.state.status("postgres") != "done":
        raise DevstackError("postgres phase is not done")
    if args.action == "backup":
        db_backup(ctx, args.file)
        return 0
    if args.action == "shell":
        user = c["container.user"]
        return ctx.r.run(["incus", "exec", "-t", ctx.name, "--", "runuser", "-u", user, "--", "env", f"HOME=/home/{user}",
                          "psql", "-h", "127.0.0.1", "-p", c["postgres.port"], "-U", c["postgres.role"], c["postgres.db"]],
                         tty=True, check=False).returncode
    src = Path(args.file).expanduser()
    if not src.is_file():
        raise ConfigError(f"{src} is not a file")
    if not ctx.confirm(f"Restore {src} into database {c['postgres.db']} as role {c['postgres.role']}? "
                       "Existing objects are dropped first.",
                       destructive=True):
        return 0
    with Lock(ctx):
        log.info("taking a safety backup first")
        db_backup(ctx, None)
        # As the app role (not the superuser), over 127.0.0.1: a dump cannot run superuser-only SQL.
        # The password comes from postgres.env inside the container (never argv); the dump is streamed
        # through stdin; --single-transaction means a failed restore leaves the database untouched.
        script = bash(PG_RESTORE, ENVFILE=f"{c['secrets.dir']}/{c['postgres.env_file']}")
        argv = ["incus", "exec", ctx.name, "--", "bash", "-euo", "pipefail", "-c", script]
        log.debug("$ %s < %s", short_cmd(argv), src)
        with open(src, "rb") as fh:
            p = subprocess.run(argv, stdin=fh, capture_output=True)
        if p.returncode != 0:
            manual = (f"incus exec {ctx.name} -- runuser -u postgres -- pg_restore --clean --if-exists "
                      f"--no-owner -p {c['postgres.port']} -d {c['postgres.db']} < {src}")
            raise DevstackError(
                f"pg_restore failed as role {c['postgres.role']} (nothing was changed):\n"
                f"{p.stderr.decode(errors='replace').strip()[-2000:]}\n"
                "Restores deliberately run without superuser rights, so dumps that create extensions or need "
                f"superuser SQL fail. If you trust this dump, restore it yourself as the superuser:\n  {manual}")
        log.info("restored %s into %s", src, c["postgres.db"])
    return 0


def cmd_data(ctx: Ctx, args: argparse.Namespace) -> int:
    c = ctx.cfg
    if ctx.state.status("isolation") != "done":
        raise DevstackError("isolation phase is not done")
    if app_data_dir(c) is None:
        raise DevstackError('app.data = "none": there is no app data')
    if args.action == "backup":
        data_backup(ctx, args.file)
        return 0
    src = Path(args.file).expanduser()
    if not src.is_file():
        raise ConfigError(f"{src} is not a file")
    if not ctx.confirm(f"Restore {src} into {app_data_dir(c)}? The app and runners stop meanwhile, and the "
                       "current app data is replaced (a safety backup is taken first).", destructive=True):
        return 0
    with Lock(ctx):
        log.info("taking a safety backup first")
        safety = data_backup(ctx, None)
        data_restore(ctx, src, f"The previous data is in {safety}: `devstack data restore {safety}` puts it back")
    return 0


def data_restore(ctx: Ctx, src: Path, hint: str = "") -> None:
    """Replace the app data with an archive, through the container (app and runners stopped meanwhile)."""
    c = ctx.cfg
    script = bash(DATA_RESTORE, DIR=app_data_dir(c), APP=c["isolation.app_user"], DATA=c["isolation.data_group"],
                  RUNNER=c["isolation.runner_user"], UNIT=f"{c['app.service_name']}.service",
                  SOCKETS=[f"{runner_unit(c, r)}.socket" for r in c["app.runners"]])
    argv = ["incus", "exec", ctx.name, "--", "bash", "-euo", "pipefail", "-c", script]
    log.debug("$ %s < %s", short_cmd(argv), src)
    with open(src, "rb") as fh:
        p = subprocess.run(argv, stdin=fh, capture_output=True)
    if p.returncode != 0:
        raise DevstackError(f"restore failed: {p.stderr.decode(errors='replace').strip()[-2000:]}\n{hint}".rstrip())
    log.info("restored %s into %s", src, app_data_dir(c))


# --- checkpoint: undo what came after provisioning (container, data volumes, project) ---
#
# Phase snapshots undo provisioning. A checkpoint undoes what came after it: an agent's changes, a bad
# install, test data. Its parts are taken with the container stopped, so they are from one moment:
#   - an incus snapshot of the container (checkpoint-<name>: outside the journal and snapshots.prefix, like
#     pre-upgrade-*, so undo and preflight leave it alone)
#   - incus snapshots of the data volumes (Postgres; app data in volume mode). App data in host mode is
#     archived through the container, since the host user can't read it.
#   - the project: a commit of the working tree (tracked and untracked files, .gitignore respected) on
#     refs/devstack/checkpoints/<name>, made with plumbing on a scratch index -- no hooks, no filters, no
#     global or system config; HEAD, branches and the index are untouched -- plus the index file, and a tar
#     of the small ignored files outside checkpoint.derived (.env, say). Derived folders (node_modules) are
#     rebuilt by checkpoint.restore_command.
# Restore requires the phases that were done then: otherwise the restored container and the journal disagree.

CHECKPOINT_PREFIX = "checkpoint-"
CHECKPOINT_REF = "refs/devstack/checkpoints/"
CHECKPOINT_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,40}")
GIT_IDENT = {"GIT_AUTHOR_NAME": "devstack", "GIT_AUTHOR_EMAIL": "devstack@localhost",
             "GIT_COMMITTER_NAME": "devstack", "GIT_COMMITTER_EMAIL": "devstack@localhost"}


def human_bytes(n: int | None) -> str:
    if n is None:
        return "?"
    for unit in ("B", "KiB", "MiB", "GiB"):
        if abs(n) < 1024 or unit == "GiB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024  # type: ignore[assignment]
    return "?"


def git_env(ctx: Ctx, index: Path | None = None) -> dict[str, str]:
    """git on the project from the host, hermetic: the repository pinned (no discovery), no system or
    global config (their filters, fsmonitor, hooksPath, excludes), HOME pointing nowhere of yours."""
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C", "HOME": str(ctx.state_dir),
           "GIT_DIR": str(ctx.project / ".git"), "GIT_WORK_TREE": str(ctx.project),
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0", **GIT_IDENT}
    if index is not None:
        env["GIT_INDEX_FILE"] = str(index)
    return env


def git_run(ctx: Ctx, *args: str, index: Path | None = None, input: bytes | None = None,
            check: bool = True) -> bytes:
    """Bytes in and out: file names and contents are not text."""
    argv = ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", *args]
    log.debug("$ %s", shlex.join(argv))
    p = subprocess.run(argv, input=input, capture_output=True, env=git_env(ctx, index))
    if check and p.returncode != 0:
        raise CommandError(argv, p.returncode, p.stderr.decode(errors="replace"))
    return p.stdout


def nul_paths(out: bytes) -> list[str]:
    return [os.fsdecode(x) for x in out.split(b"\0") if x]


def project_walk(root: Path, rel: str, skip: set[str]) -> list[str]:
    """Files and symlinks under root/rel, never following a symlink; .git and skip folders left out."""
    out = []
    for here, dirs, files in os.walk(root / rel):
        base = Path(here)
        keep = []
        for d in dirs:
            if (base / d).is_symlink():
                files.append(d)
            elif d != ".git" and d not in skip:
                keep.append(d)
        dirs[:] = keep
        out += [(base / f).relative_to(root).as_posix() for f in files]
    return sorted(out)


def capture_ignored(ctx: Ctx, tar_path: Path) -> dict[str, Any]:
    """Ignored files outside checkpoint.derived, up to checkpoint.capture_max_mb, into a tar."""
    c, root = ctx.cfg, ctx.project
    budget, derived = c["checkpoint.capture_max_mb"] * 1024 * 1024, set(c["checkpoint.derived"])
    files: list[str] = []
    uncaptured: list[list[str]] = []
    total = 0
    for entry in nul_paths(git_run(ctx, "ls-files", "-z", "-o", "-i", "--exclude-standard", "--directory")):
        rel = entry.rstrip("/")
        if PurePosixPath(rel).name in derived:
            uncaptured.append([entry, "derived: rebuilt by checkpoint.restore_command"])
            continue
        over = 0
        for p in (project_walk(root, rel, derived) if entry.endswith("/") else [rel]):
            try:
                st = (root / p).lstat()
            except OSError:
                continue
            if not (stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode)):
                continue
            size = st.st_size if stat.S_ISREG(st.st_mode) else 0
            if total + size > budget:
                over += 1
                continue
            total += size
            files.append(p)
        if over:
            uncaptured.append([entry, f"{over} file(s) over checkpoint.capture_max_mb"])
    fd = os.open(tar_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh, tarfile.open(fileobj=fh, mode="w") as tar:
        for p in files:
            try:
                tar.add(root / p, arcname=p, recursive=False)
            except OSError as e:
                uncaptured.append([p, f"unreadable ({e.strerror})"])
    return {"ignored_files": len(files), "ignored_bytes": total, "uncaptured": uncaptured}


def capture_project(ctx: Ctx, name: str, dest: Path) -> dict[str, Any]:
    """The working tree as a commit on refs/devstack/checkpoints/<name>, plus the index and ignored files."""
    root = ctx.project
    tracked: dict[str, tuple[str, str]] = {}
    for rec in git_run(ctx, "ls-files", "-z", "-s", "-c").split(b"\0"):
        if rec:
            info, path = rec.split(b"\t", 1)
            mode, sha, _stage = info.decode().split()
            tracked[os.fsdecode(path)] = (mode, sha)
    others = nul_paths(git_run(ctx, "ls-files", "-z", "-o", "--exclude-standard"))
    entries: list[tuple[str, str, str]] = []
    regular: list[tuple[str, str]] = []
    skipped: list[list[str]] = []
    for path in sorted(set(tracked) | set(others)):
        if path.endswith("/"):
            skipped.append([path, "a git repository nested in the project"])
            continue
        if tracked.get(path, ("", ""))[0] == "160000":
            entries.append((*tracked[path], path))  # a submodule: its commit, not its files
            continue
        try:
            st = (root / path).lstat()
        except FileNotFoundError:
            continue  # deleted in the working tree
        if "\n" in path:
            skipped.append([path, "newline in the name"])
        elif stat.S_ISLNK(st.st_mode):
            target = os.fsencode(os.readlink(root / path))
            entries.append(("120000", git_run(ctx, "hash-object", "-w", "--stdin", input=target).decode().strip(), path))
        elif stat.S_ISREG(st.st_mode):
            regular.append((path, "100755" if st.st_mode & 0o111 else "100644"))
        else:
            skipped.append([path, "not a file"])
    if regular:  # raw bytes: --no-filters ignores .gitattributes, which the container can write
        out = git_run(ctx, "hash-object", "-w", "--no-filters", "--stdin-paths",
                      input=b"".join(os.fsencode(str(root / p)) + b"\n" for p, _ in regular))
        entries += [(mode, sha, path) for (path, mode), sha in zip(regular, out.decode().split())]
    index = dest / "tree.index"
    git_run(ctx, "update-index", "-z", "--index-info", index=index,
            input=b"".join(f"{m} {s}\t".encode() + os.fsencode(p) + b"\0" for m, s, p in entries))
    tree = git_run(ctx, "write-tree", index=index).decode().strip()
    index.unlink(missing_ok=True)
    head = git_run(ctx, "rev-parse", "-q", "--verify", "HEAD^{commit}", check=False).decode().strip()
    branch = git_run(ctx, "symbolic-ref", "-q", "--short", "HEAD", check=False).decode().strip()
    commit = git_run(ctx, "commit-tree", tree, *(["-p", head] if head else []),
                     "-m", f"devstack checkpoint {name}").decode().strip()
    git_run(ctx, "update-ref", CHECKPOINT_REF + name, commit)
    if (root / ".git" / "index").is_file():
        shutil.copyfile(root / ".git" / "index", dest / "index")
        os.chmod(dest / "index", 0o600)
    return {"commit": commit, "head": head, "branch": branch, "files": len(entries), "skipped": skipped,
            **capture_ignored(ctx, dest / "ignored.tar")}


def safe_parent(root: Path, rel: str) -> Path | None:
    """The folder rel goes into, made of real folders inside root. A symlink or file in the way (made since
    the checkpoint, maybe by the container) is removed, so nothing is ever written outside the project."""
    parts = PurePosixPath(rel).parts
    if not parts or rel.startswith("/") or ".." in parts or parts[0] == ".git":
        return None
    cur = root
    for part in parts[:-1]:
        cur = cur / part
        try:
            st = cur.lstat()
        except FileNotFoundError:
            cur.mkdir()
            continue
        if not stat.S_ISDIR(st.st_mode):
            cur.unlink()
            cur.mkdir()
    return cur


def remove_path(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink()


def write_project_file(root: Path, rel: str, data: bytes, mode: str) -> bool:
    """Put one file (or symlink, mode 120000) back; False when it is already identical."""
    parent = safe_parent(root, rel)
    if parent is None:
        return False
    path = parent / PurePosixPath(rel).name
    try:
        st: os.stat_result | None = path.lstat()
    except FileNotFoundError:
        st = None
    if mode == "120000":
        target = os.fsdecode(data)
        if st is not None and stat.S_ISLNK(st.st_mode) and os.readlink(path) == target:
            return False
        if st is not None:
            remove_path(path)
        os.symlink(target, path)
        return True
    executable = mode == "100755"
    if (st is not None and stat.S_ISREG(st.st_mode) and st.st_size == len(data)
            and bool(st.st_mode & 0o111) == executable and path.read_bytes() == data):
        return False
    if st is not None and not stat.S_ISREG(st.st_mode):
        remove_path(path)
    tmp = parent / f".{path.name}.devstack-restore"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    os.chmod(tmp, 0o755 if executable else 0o644)
    os.replace(tmp, path)
    return True


def remove_project_file(root: Path, rel: str) -> bool:
    """Delete a file made since the checkpoint; never through a symlinked folder."""
    parts = PurePosixPath(rel).parts
    if not parts or rel.startswith("/") or ".." in parts or parts[0] == ".git":
        return False
    cur = root
    for part in parts[:-1]:
        cur = cur / part
        if cur.is_symlink() or not cur.is_dir():
            return False
    path = cur / parts[-1]
    if path.is_symlink() or path.is_file():
        path.unlink()
        while cur != root and not any(cur.iterdir()):
            cur.rmdir()
            cur = cur.parent
        return True
    return False


def cat_blobs(ctx: Ctx, shas: list[str], chunk: int = 200):
    """(sha, content) for each blob, a chunk at a time."""
    for i in range(0, len(shas), chunk):
        out = git_run(ctx, "cat-file", "--batch", input="".join(s + "\n" for s in shas[i:i + chunk]).encode())
        pos = 0
        while pos < len(out):
            nl = out.index(b"\n", pos)
            sha, _kind, size = out[pos:nl].decode().split()
            start = nl + 1
            yield sha, out[start:start + int(size)]
            pos = start + int(size) + 1


def restore_project(ctx: Ctx, meta: dict[str, Any], ckdir: Path) -> dict[str, Any]:
    root, commit = ctx.project, meta["project"]["commit"]
    current = set(nul_paths(git_run(ctx, "ls-files", "-z", "-c", "-o", "--exclude-standard")))
    want: dict[str, tuple[str, str]] = {}
    for rec in git_run(ctx, "ls-tree", "-r", "-z", "--full-tree", commit).split(b"\0"):
        if rec:
            info, path = rec.split(b"\t", 1)
            mode, _kind, sha = info.decode().split()
            want[os.fsdecode(path)] = (mode, sha)
    blobs = {p: v for p, v in want.items() if v[0] != "160000"}
    by_sha: dict[str, list[str]] = {}
    for p, (_, sha) in blobs.items():
        by_sha.setdefault(sha, []).append(p)
    written = 0
    for sha, data in cat_blobs(ctx, sorted(by_sha)):
        for p in by_sha[sha]:
            written += write_project_file(root, p, data, blobs[p][0])
    removed = sum(remove_project_file(root, p) for p in sorted(current - set(want), reverse=True)
                  if not p.endswith("/"))
    ignored = 0
    tar_path = ckdir / "ignored.tar"
    if tar_path.is_file():
        with tarfile.open(tar_path) as tar:
            for m in tar.getmembers():
                if m.isfile():
                    fh = tar.extractfile(m)
                    data = fh.read() if fh else b""
                    ignored += write_project_file(root, m.name, data, "100755" if m.mode & 0o111 else "100644")
                elif m.issym():
                    ignored += write_project_file(root, m.name, os.fsencode(m.linkname), "120000")
    head = git_run(ctx, "rev-parse", "-q", "--verify", "HEAD^{commit}", check=False).decode().strip()
    index_back = head == meta["project"]["head"] and (ckdir / "index").is_file()
    if index_back:  # same commit as then: the staged changes of then come back too
        tmp = root / ".git" / "index.devstack-restore"
        shutil.copyfile(ckdir / "index", tmp)
        os.replace(tmp, root / ".git" / "index")
    return {"written": written, "removed": removed, "ignored": ignored, "head": head, "index": index_back}


def checkpoint_metas(ctx: Ctx) -> list[dict[str, Any]]:
    d = ctx.state_dir / "checkpoints"
    out = []
    for f in (d.glob("*/meta.json") if d.is_dir() else []):
        try:
            out.append(json.loads(f.read_text()))
        except (OSError, ValueError):
            log.warning("unreadable checkpoint metadata: %s", f)
    return sorted(out, key=lambda m: m["created"])


def checkpoint_volumes(ctx: Ctx) -> list[str]:
    c = ctx.cfg
    vols = []
    if c["postgres.enabled"] and ctx.volume(c["postgres.volume"]) is not None:
        vols.append(c["postgres.volume"])
    if c["app.data"] == "volume" and ctx.volume(c["app.data_volume"]) is not None:
        vols.append(c["app.data_volume"])
    return vols


def pool_space(ctx: Ctx) -> tuple[int | None, int | None]:
    """(used, free) bytes of the container's storage pool."""
    r = (ctx.iq(f"/1.0/storage-pools/{ctx.cfg['container.storage_pool']}/resources") or {}).get("space", {})
    used, total = r.get("used"), r.get("total")
    return used, (total - used if used is not None and total else None)


def volume_snapshot_exists(ctx: Ctx, vol: str, snap: str) -> bool:
    pool = ctx.cfg["container.storage_pool"]
    return ctx.iq(f"/1.0/storage-pools/{pool}/volumes/custom/{vol}/snapshots/{snap}") is not None


def checkpoint_missing(ctx: Ctx, meta: dict[str, Any]) -> list[str]:
    snap = CHECKPOINT_PREFIX + meta["name"]
    missing = []
    if ctx.instance() is None or snap not in ctx.snapshot_names():
        missing.append("container snapshot")
    missing += [f"volume snapshot {v}" for v in meta["volumes"] if not volume_snapshot_exists(ctx, v, snap)]
    if git_run(ctx, "cat-file", "-e", meta["project"]["commit"], check=False) != b"" or \
            not git_run(ctx, "rev-parse", "-q", "--verify", CHECKPOINT_REF + meta["name"], check=False).strip():
        missing.append("project commit")
    return missing


def delete_checkpoint(ctx: Ctx, meta: dict[str, Any]) -> None:
    name, pool = meta["name"], ctx.cfg["container.storage_pool"]
    snap = CHECKPOINT_PREFIX + name
    if ctx.instance() is not None and snap in ctx.snapshot_names():
        ctx.r.run(["incus", "snapshot", "delete", ctx.name, snap])
    for v in meta.get("volumes", []):
        if volume_snapshot_exists(ctx, v, snap):
            ctx.r.run(["incus", "storage", "volume", "snapshot", "delete", pool, v, snap])
    git_run(ctx, "update-ref", "-d", CHECKPOINT_REF + name, check=False)
    shutil.rmtree(ctx.state_dir / "checkpoints" / name, ignore_errors=True)
    log.info("deleted checkpoint %s", name)


def describe_checkpoint(m: dict[str, Any]) -> str:
    age = dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(m["created"])
    hours = age.total_seconds() / 3600
    when = f"{age.total_seconds() / 60:.0f} min ago" if hours < 1 else (
        f"{hours:.1f} h ago" if hours < 48 else f"{hours / 24:.0f} days ago")
    p = m["project"]
    at = f"{p['branch'] or 'detached'}@{p['head'][:8] or 'no commits'}"
    return f"{m['name']:<20} {m['created'][:16].replace('T', ' ')}  {when:<12} {human_bytes(m.get('bytes')):>10}  {at}"


def checkpoint_create(ctx: Ctx, name: str | None) -> int:
    c = ctx.cfg
    phases = [p.id for p in active_phases(ctx)]
    if not phases or any(ctx.state.status(p) != "done" for p in phases) or ctx.instance() is None:
        raise DevstackError("a checkpoint needs a provisioned stack with no failed or half-run phase: "
                            "run `devstack up` first")
    if git_dir_problem(ctx.project) or not (ctx.project / ".git").is_dir():
        raise DevstackError(f"{ctx.project} is not a git repository: run `devstack up` (it requires git)")
    name = name or dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    if not CHECKPOINT_NAME.fullmatch(name):
        raise ConfigError(f"checkpoint name {name!r}: lowercase letters, digits and '-', at most 41 characters")
    existing = checkpoint_metas(ctx)
    if any(m["name"] == name for m in existing):
        raise ConfigError(f"checkpoint {name} exists already (`devstack checkpoint delete {name}` first)")
    drop = existing[:max(0, len(existing) + 1 - c["checkpoint.keep"])]
    vols, pool = checkpoint_volumes(ctx), c["container.storage_pool"]
    host_data = c["app.data"] == "host" and ctx.state.status("isolation") == "done"
    log.info("checkpoint %s of %s captures:", name, ctx.name)
    log.info("  the container            incus snapshot %s%s", CHECKPOINT_PREFIX, name)
    for v in vols:
        log.info("  volume %-17s incus volume snapshot", v)
    if host_data:
        log.info("  app data (host folder)   archived through the container: %s", c["app.data_source"])
    log.info("  the project              tracked and untracked files as a commit (%s%s); ignored files up to "
             "%d MB, except %s, which `%s` rebuilds on restore", CHECKPOINT_REF, name,
             c["checkpoint.capture_max_mb"], ", ".join(c["checkpoint.derived"]) or "nothing",
             c["checkpoint.restore_command"] or "(no checkpoint.restore_command)")
    log.info("  %s stops meanwhile (ssh and VSCode sessions drop) and starts again", ctx.name)
    used, free = pool_space(ctx)
    estimate = next((m.get("bytes") for m in reversed(existing) if m.get("bytes")), None)
    log.info("  storage pool %s: %s free; the last checkpoint took %s", pool, human_bytes(free), human_bytes(estimate))
    if estimate and free is not None and free < estimate * 1.2:
        raise DevstackError(f"not enough space in storage pool {pool} for another checkpoint (about "
                            f"{human_bytes(estimate)}, {human_bytes(free)} free). The new one is made before the old "
                            "one is deleted, so delete one first: devstack checkpoint delete NAME")
    if existing:
        log.info("existing checkpoints:")
        for m in existing:
            log.info("  %s%s", describe_checkpoint(m), "   <- deleted after this one is made" if m in drop else "")
    if drop:
        if not ctx.confirm(f"Create checkpoint {name}, then delete {', '.join(m['name'] for m in drop)} "
                           f"(checkpoint.keep = {c['checkpoint.keep']})?", destructive=True):
            return 0
    elif existing:
        log.warning("%d checkpoint(s) kept, using %s of %s (checkpoint.keep = %d); `devstack checkpoint delete "
                    "NAME` frees the space", len(existing), human_bytes(sum(m.get("bytes") or 0 for m in existing)),
                    pool, c["checkpoint.keep"])
    with Lock(ctx):
        ckdir = ctx.state_dir / "checkpoints" / name
        ckdir.mkdir(mode=0o700, parents=True)
        os.chmod(ckdir.parent, 0o700)
        snap = CHECKPOINT_PREFIX + name
        made: dict[str, Any] = {"snapshot": False, "volumes": [], "ref": False}
        running = ctx.instance_running()
        try:
            if host_data:
                if not running:
                    ctx.r.run(["incus", "start", ctx.name])
                    ctx.wait_ipv4()
                data_backup(ctx, str(ckdir / "appdata.tar.gz"))
            if ctx.instance_running():
                log.info("stopping %s", ctx.name)
                ctx.stop_instance()
            project = capture_project(ctx, name, ckdir)
            made["ref"] = True
            ctx.r.run(["incus", "snapshot", "create", ctx.name, snap], stream=True)
            made["snapshot"] = True
            for v in vols:
                ctx.r.run(["incus", "storage", "volume", "snapshot", "create", pool, v, snap], stream=True)
                made["volumes"].append(v)
        except BaseException:
            log.error("checkpoint %s failed; removing what was made of it", name)
            delete_checkpoint(ctx, {"name": name, "volumes": made["volumes"]})
            raise
        finally:
            if running and not ctx.instance_running():
                ctx.r.run(["incus", "start", ctx.name])
                ctx.wait_ipv4()
        used_after, _ = pool_space(ctx)
        extra = sum(f.stat().st_size for f in ckdir.iterdir())
        meta = {"name": name, "created": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                "phases": phases, "volumes": vols, "app_data_archive": host_data, "project": project,
                "bytes": (used_after - used + extra) if used is not None and used_after is not None else None}
        atomic_write(ckdir / "meta.json", json.dumps(meta, indent=2) + "\n", 0o600)
        for m in drop:
            delete_checkpoint(ctx, m)
    log.info("checkpoint %s: %d project files, %d ignored file(s) (%s), about %s in all",
             name, project["files"], project["ignored_files"], human_bytes(project["ignored_bytes"]),
             human_bytes(meta["bytes"]))
    for path, why in (project["skipped"] + project["uncaptured"])[:15]:
        log.info("  not captured: %s (%s)", path, why)
    return 0


def checkpoint_restore(ctx: Ctx, name: str) -> int:
    c = ctx.cfg
    meta = next((m for m in checkpoint_metas(ctx) if m["name"] == name), None)
    if meta is None:
        raise ConfigError(f"no checkpoint {name} (devstack checkpoint list)")
    phases = [p.id for p in active_phases(ctx)]
    if phases != meta["phases"] or any(ctx.state.status(p) != "done" for p in phases):
        raise DevstackError(f"checkpoint {name} was taken with phases {', '.join(meta['phases'])} done; now "
                            f"{', '.join(phases) or 'none'} (not all done, or different). Restoring it would leave "
                            "the container and devstack's journal disagreeing: bring the phases back first")
    if missing := checkpoint_missing(ctx, meta):
        raise DevstackError(f"checkpoint {name} is incomplete ({', '.join(missing)} gone); "
                            f"`devstack checkpoint delete {name}` removes the rest")
    commit, snap, pool = meta["project"]["commit"], CHECKPOINT_PREFIX + name, c["container.storage_pool"]
    changes = git_run(ctx, "diff", "--shortstat", commit, check=False).decode().strip() or "no tracked changes"
    log.info("checkpoint %s", describe_checkpoint(meta))
    if not ctx.confirm(f"Restore checkpoint {name}? This replaces the container, "
                       f"{'the volumes ' + ', '.join(meta['volumes']) + ', ' if meta['volumes'] else ''}"
                       f"{'the app data, ' if meta.get('app_data_archive') else ''}and the project's files "
                       f"(since then: {changes}, plus untracked files). Commits made since then are kept.",
                       destructive=True):
        return 0
    with Lock(ctx):
        if ctx.instance_running():
            log.info("stopping %s", ctx.name)
            ctx.stop_instance()
        ctx.r.run(["incus", "snapshot", "restore", ctx.name, snap], stream=True)
        for v in meta["volumes"]:
            ctx.r.run(["incus", "storage", "volume", "snapshot", "restore", pool, v, snap], stream=True)
        result = restore_project(ctx, meta, ctx.state_dir / "checkpoints" / name)
        ctx.r.run(["incus", "start", ctx.name])
        ctx.wait_ipv4()
        if meta.get("app_data_archive"):
            data_restore(ctx, ctx.state_dir / "checkpoints" / name / "appdata.tar.gz")
    log.info("restored checkpoint %s: container%s; project: %d file(s) written, %d removed, %d ignored file(s) put back",
             name, f", {', '.join(meta['volumes'])}" if meta["volumes"] else "", result["written"], result["removed"],
             result["ignored"])
    if cmd := c["checkpoint.restore_command"]:
        log.info("rebuilding derived files: %s", cmd)
        p = ctx.cexec(f"export COREPACK_ENABLE_DOWNLOAD_PROMPT=0\ncd {shlex.quote(ctx.cproject)}\n{cmd}",
                      user=c["container.user"], stream=True, check=False, timeout=1800)
        if p.returncode != 0:
            log.warning("checkpoint.restore_command failed (exit %d): run it yourself in the container", p.returncode)
    then, now = meta["project"]["head"], result["head"]
    if then != now:
        log.warning("git: HEAD moved since the checkpoint (%s then, %s now). The files are as they were then; "
                    "the commits made since are kept, and `git status` shows the difference.", then[:8] or "none",
                    now[:8] or "none")
        if then:
            log.warning("  see them:    git log --oneline %s..%s", then[:12], now[:12] or "HEAD")
            log.warning("  drop them:   git reset %s   (moves the branch back; the files stay as restored)",
                        then[:12])
    elif not result["index"]:
        log.info("git: same commit as then; `git status` shows the restored changes")
    return 0


def cmd_checkpoint(ctx: Ctx, args: argparse.Namespace) -> int:
    if args.action == "create":
        return checkpoint_create(ctx, args.name)
    if args.action == "list":
        metas = checkpoint_metas(ctx)
        if not metas:
            print("no checkpoints")
        for m in metas:
            missing = checkpoint_missing(ctx, m)
            stale = m["phases"] != [p.id for p in active_phases(ctx)]
            note = f"incomplete: {', '.join(missing)} gone" if missing else ("phases changed since" if stale else "")
            print(f"  {describe_checkpoint(m)}" + (f"   ({note})" if note else ""))
        used = sum(m.get("bytes") or 0 for m in metas)
        if metas:
            print(f"\n{len(metas)} checkpoint(s), about {human_bytes(used)} (checkpoint.keep = {ctx.cfg['checkpoint.keep']})")
        print("restore: ./devstack checkpoint restore NAME   delete: ./devstack checkpoint delete NAME")
        return 0
    meta = next((m for m in checkpoint_metas(ctx) if m["name"] == args.name), None)
    if args.action == "restore":
        return checkpoint_restore(ctx, args.name)
    if meta is None:
        raise ConfigError(f"no checkpoint {args.name} (devstack checkpoint list)")
    if not ctx.confirm(f"Delete checkpoint {args.name}?", destructive=True):
        return 0
    with Lock(ctx):
        delete_checkpoint(ctx, meta)
    return 0




def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-c", "--config", default=argparse.SUPPRESS, help="config file (default ./devstack.toml)")
    common.add_argument("-n", "--non-interactive", action="store_true", default=argparse.SUPPRESS,
                        help="never prompt; anything missing or unknown is an error")
    common.add_argument("-y", "--yes", action="store_true", default=argparse.SUPPRESS,
                        help="pre-approve destructive confirmations")
    common.add_argument("--log-target", choices=("stderr", "file", "both", "journald"), default=argparse.SUPPRESS)
    common.add_argument("--log-file", default=argparse.SUPPRESS)
    common.add_argument("--log-level", choices=tuple(LEVELS), default=argparse.SUPPRESS)

    ap = argparse.ArgumentParser(prog="devstack", parents=[common],
                                 description="Build the generic dev + local app environment (see index.html).")
    ap.add_argument("--version", action="version", version=f"devstack {VERSION}")
    sub = ap.add_subparsers(dest="command", required=True, metavar="COMMAND")

    p = sub.add_parser("init", parents=[common], help="write a commented devstack.toml")
    p.add_argument("--force", action="store_true", help="overwrite an existing file")
    p.add_argument("--project", metavar="PATH", help="project folder; its infra/devstack-requires.toml "
                   "(if any) supplies the defaults")
    p = sub.add_parser("config", parents=[common], help="show | explain [KEY] | check")
    p.add_argument("action", choices=("show", "explain", "check"))
    p.add_argument("key", nargs="?")
    sub.add_parser("preflight", parents=[common], help="check config + environment, change nothing")
    for name in ("plan", "up"):
        p = sub.add_parser(name, parents=[common], help="show the steps" if name == "plan" else "apply phases")
        g = p.add_mutually_exclusive_group()
        g.add_argument("--to", metavar="PHASE")
        g.add_argument("--only", metavar="PHASE")
        g.add_argument("--redo", metavar="PHASE")
        if name == "up":
            p.add_argument("--dry-run", action="store_true", help="plan + preflight, then stop")
    sub.add_parser("status", parents=[common], help="phase states and owned resources")
    for name in ("undo", "destroy"):
        p = sub.add_parser(name, parents=[common], help="undo the last phase" if name == "undo" else "undo everything")
        if name == "undo":
            g = p.add_mutually_exclusive_group()
            g.add_argument("--to", metavar="PHASE", help="undo every phase after PHASE")
            g.add_argument("--all", action="store_true", help="undo everything (same as destroy)")
        p.add_argument("--purge-data", action="store_true", help="also delete the Postgres data volume")
    p = sub.add_parser("snapshot", parents=[common], help="list | create NAME | prune")
    p.add_argument("action", choices=("list", "create", "prune"))
    p.add_argument("name", nargs="?")
    p = sub.add_parser("db", parents=[common], help="backup [FILE] | restore FILE | shell")
    p.add_argument("action", choices=("backup", "restore", "shell"))
    p.add_argument("file", nargs="?")
    p = sub.add_parser("data", parents=[common], help="backup [FILE] | restore FILE (the app data folder)")
    p.add_argument("action", choices=("backup", "restore"))
    p.add_argument("file", nargs="?")
    p = sub.add_parser("upgrade", parents=[common],
                       help="patch the container's Debian packages (from the host)")
    p.add_argument("--dry-run", action="store_true", help="show what would upgrade, change nothing")
    p.add_argument("--no-snapshot", action="store_true", help="skip the pre-upgrade snapshot")
    p = sub.add_parser("checkpoint", parents=[common],
                       help="create [NAME] | list | restore NAME | delete NAME (container + data + project)")
    p.add_argument("action", choices=("create", "list", "restore", "delete"))
    p.add_argument("name", nargs="?")
    p = sub.add_parser("browse", parents=[common],
                       help="open the dev site in a Chromium that reaches only the dev domain")
    p.add_argument("target", nargs="?", help="a caddy.dev_servers name, or a URL under the dev domain")
    p.add_argument("--app", action="store_true",
                   help="an app window (no tabs or address bar); needs a window manager that draws title bars")
    p = sub.add_parser("sbom", parents=[common],
                       help="generate | check | scan | show [container|app] (CycloneDX inventory + grype)")
    p.add_argument("action", choices=("generate", "check", "scan", "show"))
    p.add_argument("which", nargs="?", choices=("container", "app", "all"))
    p.add_argument("--fail-on", choices=("", *SEVERITIES), default=argparse.SUPPRESS,
                   help="scan only: override sbom.fail_on ('' = report only)")
    p.add_argument("--offline", action="store_true", default=argparse.SUPPRESS,
                   help="scan only: never update the vulnerability database")
    p = sub.add_parser("leaks", parents=[common],
                       help="scan (secrets in git history and uncommitted files, by gitleaks on the host)")
    p.add_argument("action", choices=("scan",))
    p.add_argument("--no-history", action="store_true", default=argparse.SUPPRESS,
                   help="only the files as they are now and what is staged, not every commit")
    return ap


def main(argv: list[str] | None = None) -> int:
    setup_logging()
    args = build_parser().parse_args(argv)
    for k, d in (("config", "devstack.toml"), ("non_interactive", False), ("yes", False), ("log_target", None),
                 ("log_file", None), ("log_level", None), ("to", None), ("only", None), ("redo", None),
                 ("dry_run", False), ("all", False), ("purge_data", False), ("key", None), ("name", None),
                 ("file", None), ("which", None), ("fail_on", None), ("offline", False),
                 ("no_snapshot", False), ("no_history", False)):
        if not hasattr(args, k):
            setattr(args, k, d)
    interactive = not args.non_interactive and sys.stdin.isatty()
    try:
        if args.command == "checkpoint" and args.action in ("restore", "delete") and not args.name:
            raise ConfigError(f"checkpoint {args.action} needs a NAME (devstack checkpoint list)")
        if args.command == "snapshot" and args.action == "create" and not args.name:
            raise ConfigError("snapshot create needs a NAME")
        if args.command in ("db", "data") and args.action == "restore" and not args.file:
            raise ConfigError(f"{args.command} restore needs a FILE")
        if args.command == "config" and args.action != "explain" and args.key:
            raise ConfigError(f"config {args.action} takes no KEY")
        if args.command == "sbom" and args.action != "scan" and (args.fail_on is not None or args.offline):
            raise ConfigError("--fail-on and --offline only apply to `sbom scan`")
        if args.command == "init":
            return cmd_init(args, interactive)
        if args.command == "config":
            return cmd_config(args, interactive)
        ctx = make_ctx(args, interactive)
        if args.command == "preflight":
            return cmd_preflight(ctx)
        if args.command == "plan":
            return cmd_plan(ctx, args)
        if args.command == "up":
            return cmd_up(ctx, args)
        if args.command == "status":
            return cmd_status(ctx)
        if args.command == "browse":
            return cmd_browse(ctx, args)
        if args.command == "checkpoint":
            return cmd_checkpoint(ctx, args)
        if args.command in ("undo", "destroy"):
            return cmd_undo(ctx, args)
        if args.command == "snapshot":
            return cmd_snapshot(ctx, args)
        if args.command == "db":
            return cmd_db(ctx, args)
        if args.command == "data":
            return cmd_data(ctx, args)
        if args.command == "upgrade":
            return cmd_upgrade(ctx, args)
        if args.command == "sbom":
            return cmd_sbom(ctx, args)
        if args.command == "leaks":
            return cmd_leaks(ctx, args)
        raise ConfigError(f"unknown command {args.command}")
    except DevstackError as e:
        log.error("%s", e)
        return e.exit_code
    except KeyboardInterrupt:
        log.error("interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
