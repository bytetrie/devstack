# devstack

> **Note from the owner:**
> 
> This project was mostly created using Claude, but is based around my own
> exploration of automating stack boilerplate and running a linux container for
> development. How secure it truly is, is not yet determined. This is an
> experiment and study in using tools to make something I can trust somewhat, more
> than just running bare agents and code on my machine, by adding a layer in
> between.
> 
> It started mostly as a script to automate some set up and evolved as I
> researched more tools and configuration to make it work "nice" (for my
> purposes). If you come across this tool and find ways to make it better and want
> to contribute, I welcome you to do so.
> 
> That being said, for now this project is to help automate some dev steps but
> would be best treated as a reference rather than a professsional tool.
> 
> For example, the set up script alone is over 7000 lines of unreviewed generated
> code that, until I find time to really read, is just being "trusted" as is.


`devstack` builds one hardened **incus system container** (Debian 13) on a
Debian-family Linux host. The container is both

- a **dev box**: VSCode Remote-SSH in, the project folder shared from the host,
  and
- a **local copy of production**: Caddy (local TLS) in front of a hardened
  systemd Node app, with Postgres on a persistent volume.

VSCode, extensions and coding agents run as your container user, which keeps the
internet and the database but has no general root (`sudo` only runs the fixed
`devstack-sync` command). The app and runner jobs run as their own system users,
and nftables limits what each may reach. An incus network ACL, enforced on the
host, keeps the whole container off your host and LAN. See "Security and trust"
in `index.html`.

One `devstack.toml` describes everything. `devstack up` applies six idempotent,
undoable **phases**: `base`, `postgres`, `app`, `proxy`, `standards`,
`isolation`. It is a stdlib-only Python (>= 3.11) CLI; no pip.

## Quick start

```sh
./devstack init                 # walk through every setting, writes devstack.toml
./devstack preflight            # check config + host, change nothing
./devstack plan                 # review image, profiles, shared folders, every host path written
./devstack up --to base         # first run: stop after the container exists, inspect
./devstack up                   # the rest
./devstack browse               # the app, in a Chromium that reaches only the dev domain
./devstack checkpoint create    # container + data volumes + project, restorable in one step
./devstack undo                 # undo the last phase (./devstack destroy: everything)
./devstack sbom show | scan     # dependency inventory, and known vulnerabilities in it
./devstack leaks scan           # secrets in git history and uncommitted files, before you push
```

Then `./devstack browse` opens `https://app.example.com.devbox/` in a Chromium
confined to the dev domain, with its own trust in the dev CA (needs
`sudo apt install libnss3-tools`). Pages the container serves are untrusted: in
your everyday browser their scripts could reach your host's loopback services
and your LAN. The host must already resolve through dnsmasq; `index.html`
explains the one-time setup. Read `index.html` (the user manual) before the
first run.

## Read a devstack.toml before you run it

A config decides which host folders are mounted into the container, which incus
profiles and image are used, and which host files are written, so a
`devstack.toml` from someone else is like a script. `plan` lists all of it, and
mounts of `/`, your home folder, `~/.ssh`, `~/.gnupg`, `/etc`, `/root` or `/var`
need a typed `yes` (or `--yes`), as do settings that widen access: full sudo, an
unrestricted app profile, LAN exceptions in the ACL, and new or changed runners.

## Your config stays private; the project gets its requirements

Your `devstack.toml` holds host details (paths, ssh, DNS, mount sources) and is
not copied into the project. `up` writes
`<project>/infra/devstack-requires.toml` instead: only the container-side
settings (image, Node, Postgres, app, Caddy, firewall, whether the project needs
the GPU) and the mounts the project expects, by name and container path. Commit
it. Someone cloning the project runs `./devstack init --project <folder>` to get
a config with those defaults; it asks for each mount's host folder. That file is
read with an allowlist, so a repo can't use it to set anything on the host.

## Security model (short)

The container is where untrusted code runs; nothing inside it is restricted.
What crosses to the host is limited:

| Channel              | Protection                                                                                                                                                                                                                                                                             |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Browser → app        | Caddy answers requests from other sites (foreign `Origin`, `Sec-Fetch-Site` cross-site/same-site) with 403 by default; no CORS headers (`caddy.same_origin`)                                                                                                                           |
| Browser trust        | Root CA made and kept on the host, name-constrained to `*.<dns.tld>`; the container only gets an intermediate; only the dev browser trusts it                                                                                                                                          |
| Dev browser          | `devstack browse`: Chromium with its own profile, reaching only the dev domain (dead-end proxy, loopback not exempt, no non-proxied WebRTC UDP)                                                                                                                                        |
| DNS                  | `dns.tld` may not be a real TLD (bundled IANA list)                                                                                                                                                                                                                                    |
| ssh / Remote-SSH     | key-only, per-stack key, host key pinned, X11/agent forwarding off                                                                                                                                                                                                                     |
| Project folder       | read-write by design; treat its contents as untrusted on the host (no tools that run workspace code: direnv, npm scripts, editors without workspace trust); all of `.git` is read-only in the container (git is required and runs on the host), and `project.readonly_paths` adds more |
| Downloads            | Caddy/PGDG key fingerprints, the Node keyring (pinned commit + sha256) and the syft/grype/gitleaks release tarballs (pinned sha256) checked in code                                                                                                                                    |
| Dependency inventory | Generated inside the container, then normalized to strip file locations and absolute paths before it is committed; the scanner and its database stay on the host                                                                                                                       |
| Secret scan          | gitleaks on the host, with devstack's config only: the project's `.gitleaks.toml`, `.gitleaksignore`, `.gitattributes` and inline `gitleaks:allow` are container-written and ignored                                                                                                   |
| `db restore`         | runs as the app role, single transaction                                                                                                                                                                                                                                               |
| Undo                 | only touches paths the current config would produce                                                                                                                                                                                                                                    |

`incus-admin` group membership is root-equivalent on the host. Details:
`index.html` (Security and trust), `SECURITY.md`, `DESIGN.md`.

## Files

| Path                    | Role                                                                                 |
| ----------------------- | ------------------------------------------------------------------------------------ |
| `devstack`              | bash launcher; picks a Python >= 3.11 and execs `devstack.py`                        |
| `devstack.py`           | the whole tool: schema/config, logging, runner, journal, undo, phases, CLI           |
| `devstack.example.toml` | generated from the schema (`./devstack init -n -c devstack.example.toml --force`)    |
| `templates/project/`    | scaffold copied into the user's project (server.ts, static/, error/, README.md, ...) |
| `templates/system/`     | files rendered into the container (sshd drop-in, app unit, pg_hba, pg conf)          |
| `data/iana-tlds.txt`    | snapshot of delegated TLDs, used to validate `dns.tld`                               |
| `tests/`                | unit tests for the pure-Python parts                                                 |
| `DESIGN.md`             | maintainer/agent design doc (authoritative on behaviour)                             |
| `index.html`            | end-user manual                                                                      |

Templates hold content, `devstack.py` holds logic. Template placeholders are
`@@UPPER_SNAKE@@` (rendering fails on an unreplaced one); config placeholders
are `{section.key}`.

## Development

```sh
bash -n devstack && python3 -m py_compile devstack.py
python3 -m unittest discover -s tests      # needs Python >= 3.11; the CA tests also need openssl
./devstack config check -c devstack.example.toml
```

## Dependency inventory and vulnerabilities

Every project devstack scaffolds carries a machine-readable
[CycloneDX](https://cyclonedx.org/) inventory, committed with the code:

| File                            | What it covers                                                                |
| ------------------------------- | ----------------------------------------------------------------------------- |
| `<sbom.dir>/container.cdx.json` | everything installed in the container: Debian packages, Node, Caddy, Postgres |
| `<sbom.dir>/app.cdx.json`       | the project's npm packages, from `pnpm-lock.yaml`                             |

Both are produced by [syft](https://github.com/anchore/syft) **inside the
container** -- only there is the real dpkg database, the Node install and
`node_modules`. [grype](https://github.com/anchore/grype) runs **on the host**
against those files, so the container never needs the ~1 GB vulnerability
database and its restricted egress never has to reach a feed. The container is
the artifact; the host is the auditor.

```sh
./devstack sbom generate   # syft in the container -> normalize -> write the two files
./devstack sbom check      # regenerate and diff: non-zero (exit 5) if they drifted
./devstack sbom scan       # grype against what is committed; --fail-on gates on severity
./devstack sbom show       # read the committed files, no container needed
```

`up` refreshes them at the end (a failure there is a warning, never a failed
phase). The documents are normalized -- no timestamps, no run-to-run ids, purls
and properties sorted, syft's file-location and `package-id` noise removed -- so
the committed bytes are a function of the dependency set alone and a diff always
means a real change. What normalization must _not_ touch is everything grype
matches on (the purl's `arch`/`distro`/`upstream` qualifiers, each component's
CPE, and the `operating-system` component carrying the distro); stripping those
would leave a scan that finds nothing and a gate that is green for no reason, so
a unit test asserts they survive.

`sbom scan` gates on **fixable** findings only (`sbom.only_fixed`). Debian
carries a lot of vulnerabilities with no fix available -- on a 3214-package
system, all 554 critical findings were `not-fixed` or `wont-fix` -- and failing
a build on something no upgrade can change just teaches people to turn the gate
off. Everything is still reported, with the fixable subset shown beside each
count.

When a scan does report something fixable, it names the command. Debian packages
are patched from the host, which keeps the container user's rights unchanged:

```sh
./devstack upgrade --dry-run   # what would upgrade
./devstack upgrade             # snapshot, apt upgrade, regenerate the SBOM
./devstack destroy && ./devstack up   # or rebuild: fresh base image, data volumes kept
```

npm packages are the project's own call: `pnpm update <pkg>` in the container,
then `sbom generate`, committing the lockfile and `app.cdx.json` together. A
rebuild deliberately does _not_ move them -- that is what the lockfile is for.

`sbom check` needs a container, so it belongs on a developer machine or a
self-hosted runner. A plain CI job can still scan the committed files, which is
the point of committing them:

```sh
grype sbom:infra/sbom/container.cdx.json --fail-on high
```

## Project checks

A project devstack scaffolds from scratch starts with its checks in place.
Existing projects are left alone.

| File                      | What it does                                                                                                                                                                                                                                                                                                     |
| ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `eslint.config.js`        | typescript-eslint `strict-type-checked` (type-aware), plus no `any`, no narrowing casts without a reason, no unhandled promises, `eslint-plugin-security` (Node), `eslint-plugin-no-unsanitized` (browser), no `eval`/`new Function`, `child_process` in one wrapper module, `eslint-disable` only with a reason |
| `tsconfig.json`           | `strict`, `noUncheckedIndexedAccess`; `pnpm typecheck` runs `tsc --noEmit`                                                                                                                                                                                                                                       |
| `pnpm-workspace.yaml`     | `minimumReleaseAge` 7 days, `blockExoticSubdeps`, `trustPolicy: no-downgrade`, `strictDepBuilds` (pnpm 10.26+; `node.pnpm_version` is pinned)                                                                                                                                                                    |
| `scripts/lint-changed.sh` | `pnpm lint:changed`: lint what changed since the last commit, in the container                                                                                                                                                                                                                                   |

TypeScript is held at 6.0, because typescript-eslint doesn't support 7 yet.
There are no git hooks; DESIGN.md §8.2 says why. devstack doesn't write CI
files. In whatever CI the project uses, the blocking check is
`corepack enable && pnpm install --frozen-lockfile && pnpm check`.

## Secret scanning

Coding agents write into a folder that is committed, and only `.gitignore` keeps
a `.env` or a key file out of git. `leaks scan` checks what actually went in, or
is about to:

```sh
./devstack leaks scan                # every commit, plus the current and staged files
./devstack leaks scan --no-history   # only what is about to be committed
```

[gitleaks](https://github.com/gitleaks/gitleaks) runs **on the host**, like
grype, and needs no container. It scans the git history and a copy of every
tracked or untracked-but-not-ignored file, plus the staged version of each
staged change. Ignored files (`.env`) are skipped, just as git skips them. Exit
5 means a finding; the output names the rule, the file, the line and a
fingerprint, never the secret (the reports in the state dir are redacted too).

Everything gitleaks would normally take from the project is replaced, because
the container can write all of it: devstack passes its own config and an empty
ignore file, scans from a folder of its own, turns off inline `gitleaks:allow`,
and reads the working tree as files (a `.gitattributes` with `-diff` would hide
changes from a `git diff`). A false positive goes in `leaks.ignore` in your
`devstack.toml`. A real secret gets rotated: once committed, and above all once
pushed, it has leaked.

It is a command, not a git hook, for the reasons in DESIGN.md §8.7: run it
before pushing.

## Trust roots

Every third-party download is pinned in `devstack.py` and checked before use, so
a swapped artifact fails the build instead of being trusted:

| What                    | Pinned value                                                                                                                                                         | Source                                                                                                                                               |
| ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| Caddy apt signing key   | fingerprint `65760C51EDEA2017CEA2CA15155B6D79CA56EA34`                                                                                                               | `https://dl.cloudsmith.io/public/caddy/stable/gpg.key`, checked with `gpg --show-keys` before dearmoring                                             |
| PGDG apt signing key    | fingerprint `B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8`                                                                                                               | `https://www.postgresql.org/media/keys/ACCC4CF8.asc`, checked before it becomes the `signed-by=` file                                                |
| Node.js release keyring | commit `481637f813e912c4aa3622d7964ab426c97b8e8d`, sha256 `610b8d249da3d5733f5a128def2dd0294dbbf5b5713e6ca2529db8db419dee00`                                         | [nodejs/release-keys](https://github.com/nodejs/release-keys) at that commit (not `HEAD`), hash checked, then used by `gpgv` on `SHASUMS256.txt.asc` |
| syft (container)        | `1.54.0`, sha256 amd64 `54a87372498168b2d033e876fd41fa4e8035b872699e525a57046e1f2f09c860`, arm64 `ee6d4566373a05b344bc6b5f1706f14419bf9338ba39ff686e247deefe9b8818`  | GitHub release tarball, `sha256sum -c` before install                                                                                                |
| grype (host)            | `0.120.0`, sha256 amd64 `a5a1218dce63acdac152a6b3b5bb366e7267e36f4069848cf455543b3fa5700e`, arm64 `bc0e52b1a0de37e2ff021c4924d689dce7dcff2e7d74b39aea16c0453e69be18` | GitHub release tarball, hash checked, then one named member extracted                                                                                |
| gitleaks (host)         | `8.30.1`, sha256 x64 `551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb`, arm64 `e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080`    | GitHub release tarball (`gitleaks_<ver>_linux_x64` / `_arm64`), hash checked, then one named member extracted                                        |

Changing a trust root means updating the constant in `devstack.py` **and** its
row above: `python3 -m unittest` fails if a pin appears in no doc, so the two
cannot drift apart. A pinned sha256 is deliberately preferred over cosign
verification for syft, grype and gitleaks -- it is a far smaller trust root than
a Fulcio/Rekor root plus another binary.

## License

No license file has been chosen yet.
