# devstack — design doc

Status: v2 (2026-10-04). Key decisions: python stdlib tool, always-dnsmasq DNS,
project at `/srv/<name>` in the container, debian/13 default image, snapshot
cleanup manual by default. v2: the OS enforces what services and the login user
may do (fixed service users + nftables egress profiles, limited sudo, incus
network ACL); see §1.3. Audience: agents and humans who need to run, extend
or debug the `devstack` setup tool in this folder.

## 1. Purpose

`devstack` builds, in one repeatable command, a **generic environment for a
full-stack web app**: a hardened incus container on a Linux host that is at the
same time

- a **local dev environment** (VSCode Remote-SSH into the container, project
  folder shared with the host), and
- a **local containerized app environment** (Caddy with local TLS, a hardened
  systemd app service, Postgres with persistent data) that mirrors how the app
  will run in production.

### 1.1 Background: the layered approach

The environment is built in layers, each adding one concern on top of the
previous one:

1. **Contain** — dev work (npm packages, build tools, the app itself) runs in an
   incus container, so user-level but potentially untrusted code can't reach the
   host's files or processes. The editor runs on the host and connects in over
   ssh; the project folder is shared so host tools see the same files.
2. **Serve** — a tiny zero-dependency server proves the container can run an app
   that reads files and answers requests. It's a smoke test, not the app.
3. **Proxy** — a reverse proxy (Caddy) sits in front of the app, so the browser
   reaches it at its real intended domain plus a dev suffix
   (`app.example.com.webstack` for a future `app.example.com`), over HTTPS with
   a locally trusted CA, with no port numbers. Caddy serves static files
   directly and forwards `/api/*` to the app.
4. **Standards** (client-side safety and speed) — precompressed static files,
   response compression, and security headers including a Content Security
   Policy.
5. **Isolation** (server-side safety) — the app listens on 127.0.0.1 only (the
   top rule: never 0.0.0.0), a firewall backs that up, the app only accepts
   requests carrying a secret token that only Caddy adds, and the app runs as a
   heavily restricted systemd service under a fixed system user whose outbound
   traffic is limited by an nftables egress profile (loopback only by default).
   Tools that need the internet run as socket-activated runners with their own
   user and profile. The login user gets no general root, and Caddy's admin API
   is off TCP. Nothing the login user can edit runs as root.
6. **Data** — Postgres, local-only with password auth, and its data kept outside
   the container so it survives rebuilds.

### 1.2 Phases

| # | Phase id    | Layer     | Result                                                                                    |
| - | ----------- | --------- | ----------------------------------------------------------------------------------------- |
| 1 | `base`      | contain   | container, project mount (+ read-only git hooks/config), host ACL, user (limited sudo), ssh-only access, pinned IP, Node + pnpm |
| 2 | `app`       | serve     | minimal zero-dep TypeScript smoke-test app scaffolded in the project                      |
| 3 | `proxy`     | proxy     | Caddy + local CA, host DNS for the dev TLD, host trusts the CA                            |
| 4 | `standards` | standards | precompressed static files, `encode`, security headers / CSP                              |
| 5 | `isolation` | isolation | ufw, service users, nftables egress profiles, app data volume, runners, `devstack-sync`, Caddy admin socket + internal token, hardened systemd unit, header hiding |
| 6 | `postgres`  | data      | Postgres on a **persistent incus volume**, local-only, scram auth, app role + db + test db, backups |

The tool is the **repro recipe**: the project's git repo (with its
`infra/devstack-requires.toml`) + this folder + a personal `devstack.toml` made
with `init --project` is enough to rebuild the whole environment on another
machine. Data
moves with `devstack db backup` / `devstack db restore` and
`devstack data backup` / `devstack data restore`.

### 1.3 Trust zones

| Zone | Who | What protects everything else |
| --- | --- | --- |
| Host + LAN | the developer | incus network ACL on the container's NIC, enforced on the host (§8.1) |
| Container as the login user | developer, VSCode, extensions, terminals, coding agents | `container.sudo = "limited"` (§8.5); the container is disposable |
| Services | the app, runner jobs | fixed system user + nftables egress profile + systemd hardening (§8.5) |

The login user and its agents share one uid and can't be told apart, so the rule
is not about *who* acts: **code that runs as root is never code the login user
can edit, and security-relevant changes are applied from the host** (`devstack
up`). Root for the developer is `incus exec <container> -- bash`.

What the login user and agents **can** do: edit and run any project code, use
the internet, use the database as the app role, read logs (`systemd-journal`)
and app data, run `sudo devstack-sync`, and change a project-owned Caddyfile.
What they **can't**: become root, write app data directly, change firewall rules
or units, reach the host or LAN, give a service more network access, or use
Caddy's admin API.

Limits, stated so nobody reads more into the isolation than it gives:
- The login user can send the real database and the app data out (it has both,
  and the internet). Deliberate: they develop against that database.
- An app that can hand a runner any URL reaches the internet through it.
- A project-owned Caddyfile can make Caddy serve anything the caddy user can
  read, including the intermediate CA key (name-constrained to the dev domain).
- Profiles constrain *services*. They are not a sandbox for the login user.

### 1.4 Why v2: what v1 got wrong (found on a v1 container, 2026-10-03/04)

v1 relied on settings and comments that the OS didn't enforce. Goal of v2:
only what is expected reaches out of the container or into its services, **and
the OS enforces it**; the same unit and rule files work on a VPS; no extra
long-running services.

| v1 | What was found |
| --- | --- |
| `IPAddressDeny=any` + `IPAddressAllow=localhost` on the app unit | **Not enforced, no warning.** Unprivileged incus containers can't attach the cgroup BPF program, so systemd starts the unit without the filter: a unit with it reached `1.1.1.1:443`. netfilter owner matching (`meta skuid`) does work there, hence nftables profiles. |
| `DynamicUser=yes` | The uid changes, so no firewall rule or file owner can target the app, and the app had no writable path at all. Hence fixed system users. |
| Passwordless sudo for the login user | Every agent and extension was root. Hence `container.sudo = "limited"`. |
| Container → host / LAN | Nothing stopped it (only closed ports did). Hence the incus ACL. |
| Caddy admin API on `127.0.0.1:2019`, no auth | Any local process could replace Caddy's config. Hence the root/caddy-only unix socket. |
| Comments: "Network: loopback only", "loopback-only network" | Agents read them as "the container has no outbound access", which was never true. **Rule since: never describe a protection the OS doesn't enforce, and say who it applies to.** |

### 1.5 Decisions (made; reopen only with new facts)

| Question | Decision | Why |
| --- | --- | --- |
| Per-service network control | Fixed system users + nftables `skuid` profiles | systemd's IP filter doesn't work in the container; netfilter does, and works the same on a VPS |
| Outbound-capable tools | Socket-activated runners: one short-lived job per connection, no daemon, no secrets | Nothing to keep running; each job is limited and disposable |
| Domain allow-lists / egress proxy | Not now | Can't be enforced at the netfilter layer; "public internet only" doesn't need it. A future egress-proxy profile would (§12) |
| Agents installing apt packages | Allowed via `devstack-sync packages`: Debian repos only, list in git (`infra/apt-packages.txt`) | Signed packages; every change is a reviewable line; new repos and services still need the host |
| Login user's access to app data | Read-only | Least privilege; writes go through the app, which keeps its invariants (rows ↔ files) |
| App data storage | incus custom volume by default; host folder optional | Survives rebuilds; a host folder holds files owned by the shifted service uid, unreadable for the host user |
| Caddyfile | Stays project-editable; global options (admin socket) are devstack's | Routes and CSP change with the app and are in git; the real hole was the unauthenticated admin port |
| Test database | Always provisioned (`<db>_test`) unless disabled | Every TypeScript + Postgres project needs one that tests may wipe |
| Login user's database access | Full, as the app role | They develop against it. Accepted as the largest remaining way for data to leave (§1.3) |
| Upgrade path | Rebuild the container; in-place upgrade best-effort only | The owner rebuilds anyway; volumes and project files survive a rebuild |
| Secret scanning | gitleaks on the host, `devstack leaks scan` (§8.8) | One static binary, pinnable like grype; covers the real gap (agents write into a committed folder) |
| Trivy | No | Does what syft + grype already do, without their normalization or fixable-only gate; its Dockerfile/K8s/Terraform checks have nothing to check here; its secret rules are weaker than gitleaks'; its release pipeline was compromised in 2026 |
| Lint and type checks | ESLint (typescript-eslint strict-type-checked, security, no-unsanitized) + `tsc`, scaffolded into new projects (§8.2); in the container and CI, not a git hook | Stands in for a SAST tool; a hook would be host-executed project code |
| CI | Agnostic: devstack gives commands and exit codes, never a workflow file for a project | Which forge and runner a project uses is its own choice; `sbom scan`/`check` (exit 5) and `pnpm check` drop into any of them. devstack's own `.github/workflows/ci.yml` is for devstack, not a template |
| Semgrep (SAST) | Not now | pip-distributed (no single binary to pin), `--config auto` fetches rules and sends metrics, registry rules have their own license. Revisit as Opengrep (standalone binaries) with a vendored rule set, opt-in |


## 2. Files in this folder

```
run/setup/
  DESIGN.md                this document
  index.html               human guide (what each phase does, how to run/undo, security and trust)
  data/iana-tlds.txt       snapshot of IANA's delegated TLDs (dns.tld must not be one)
  tests/                   unittest suite for the pure-Python parts (no incus/sudo/network)
  devstack                 bash launcher: finds python >= 3.11, execs devstack.py
  devstack.py              the tool (python stdlib only, no pip)
  devstack.example.toml    every config key, default and explanation
  templates/               files rendered into the project / container
    project/               scaffold: server.ts, static/, error/, package.json, README.md,
                           AGENTS.md (what the container enforces, for coding agents) ...
    system/                sshd drop-in, app unit, runner socket + service, egress.nft +
                           devstack-egress.service, devstack-sync, pg_hba, pg conf ...
```

Rule for agents: **templates hold file content, devstack.py holds logic.**
Placeholders in templates are `@@UPPER_SNAKE@@` (chosen because `${}` and `{}`
collide with TypeScript and Caddyfile syntax). Rendering fails if any
placeholder is left unreplaced.

## 3. Runtime requirements and dependency policy

Assume nothing beyond: Debian-family host, bash, `sudo`.

- **Launcher** (`devstack`, bash) tries, in order: `$DEVSTACK_PYTHON`,
  `/usr/bin/python3`, `python3.13`, `python3.12`, `python3.11`, `python3`, and
  picks the first with version >= 3.11 (needed for `tomllib`). Reason:
  pyenv/conda shims often shadow the system python with an older one. If none is
  found it prints the apt command and exits 3. It never installs python on its
  own.
- **Host dependencies** are checked in preflight with a table: name, required by
  which phase, present?, how to install. Required: `incus` (+ user can talk to
  the daemon), `ssh`, `ssh-keygen`, `sudo`, `curl`, `getent`, `openssl` (local
  CA), `ip` (iproute2: the host's addresses for the network ACL); `dnsmasq` (must already be the host's resolver, see §9); `certutil`
  optional (browser trust). Missing required deps: interactive → offer to
  `apt install` them (shows the exact command); non-interactive → install only
  if `host.install_missing = true`, else exit 3. VSCode / Chromium are reported,
  never installed.
- **Host packages installed by devstack are never removed by undo** (removing
  incus would kill unrelated containers). They are listed by `devstack status`.
- **Container dependencies** are always installed by the phases (the container
  is disposable and snapshotted).
- The tool refuses to run as root (paths like `~` must be the developer's) and
  uses `sudo` per command for the few host-root actions. Non-interactive mode
  requires `sudo -n true` to succeed (cached creds or NOPASSWD), else exit 4.

## 4. Command line

```
./devstack [global options] <command> [command options]

  init                write a commented devstack.toml (interactive walk-through,
                      or all defaults with -n)
  config show         print the resolved config (placeholders expanded)
  config explain [KEY]print docs for every key (or one key)
  config check        validate config only (no environment access)
  preflight           validate config + environment + name conflicts, no changes
  plan                list every step that `up` would run, with targets
  up                  apply phases in order (idempotent, skips done phases)
      --to PHASE        stop after PHASE        --only PHASE   just that phase
      --redo PHASE      undo then re-apply PHASE (and everything after it)
      --dry-run         plan + preflight, then stop before any change
  status              phase states, journal summary, resources owned
  undo                undo the last applied phase
      --to PHASE        undo every phase after PHASE
      --all             undo everything (== destroy)
      --purge-data      also delete the data volumes (Postgres, app data; asks/needs --yes)
  destroy             alias for undo --all
  upgrade             patch the container's Debian packages (apt upgrade, from the host)
      --dry-run         show what would upgrade, change nothing
      --no-snapshot     skip the pre-upgrade snapshot
  sbom generate       syft (in the container) -> normalize -> write <sbom.dir>/*.cdx.json
  sbom check          regenerate and diff against the committed files (exit 5 on drift)
  sbom scan           grype (on the host) against the committed files
      --fail-on SEV     override sbom.fail_on (exit 5 at or above SEV)
      --offline         never update the vulnerability database
  sbom show           print the committed inventory (no container needed)
      sbom … [container|app]   default: both
  snapshot list       devstack + manual snapshots, size hint, which phase needs it
  snapshot create NAME  manual snapshot (outside the journal, never auto-deleted)
  snapshot prune      delete phase snapshots of done phases (asks/needs --yes;
                      those phases can then only be undone with undo --all)
  db backup [FILE]    pg_dump -Fc of the app db to host backup_dir
  db restore FILE     restore a dump into the app db (asks/needs --yes)
  db shell            psql as the app role inside the container
  data backup [FILE]  tar.gz of the app data folder to host app.data_backup_dir
  data restore FILE   replace the app data with an archive (asks/needs --yes)
  checkpoint create [NAME] | list | restore NAME | delete NAME
                      container + data volumes + project, together (§7.5)
  browse [TARGET]     Chromium confined to the dev domain (TARGET: a caddy.dev_servers
                      name or a URL under the dev domain; default the app)
      --app             app window (no tabs/address bar; the WM must draw its title bar)

global options:
  -c, --config PATH      default ./devstack.toml
  -n, --non-interactive  never prompt; anything unknown/missing → exit 4
  -y, --yes              pre-approve destructive confirmations
      --log-target T     stderr | file | both | journald  (overrides config)
      --log-file PATH    (overrides config)
      --log-level L      debug | info | warning | error
```

Unknown commands, options or extra arguments are an error (exit 2) in both
modes.

### Interactive vs non-interactive

Mode = non-interactive if `-n` is given **or** stdin is not a TTY.

| Situation                                          | interactive                              | non-interactive                                   |
| -------------------------------------------------- | ---------------------------------------- | ------------------------------------------------- |
| no config file                                     | offer to run `init`                      | exit 2 (run `devstack init -n` to write defaults) |
| unknown config key                                 | exit 2, "did you mean"                   | exit 2, "did you mean"                            |
| invalid value                                      | exit 2                                   | exit 2                                            |
| name conflict found in preflight                   | explain, exit 3                          | exit 3                                            |
| missing host dep                                   | offer install                            | install iff `host.install_missing`, else exit 3   |
| `ssh.key_passphrase = "prompt"`                    | ssh-keygen asks                          | exit 4                                            |
| `up`                                               | show plan, ask once                      | proceed                                           |
| `undo` / `destroy` / `db restore` / `data restore` / `--purge-data` | ask                                      | proceed only with `--yes`, else exit 4            |
| step fails                                         | ask: rollback phase / keep for debugging | follow `run.on_failure`                           |

`init` explains every key (section intro + key help + default) and lets the user
accept or override. It writes TOML with the help text as comments, so the config
file documents itself. `init -n` writes all defaults without asking.

Exit codes: 0 ok · 1 step failed · 2 usage/config · 3 preflight · 4 needs input
in non-interactive mode · 130 interrupted.

## 5. Configuration

- Format TOML, read with stdlib `tomllib`. Written by a small built-in writer
  (only scalars, arrays, tables, arrays of tables are needed).
- **Single source of truth: the `SCHEMA` table in devstack.py.** Each entry has
  key, type, default, help text, validator, and optional `choices`. `init`,
  `config explain`, validation and `devstack.example.toml` all derive from it.
  When adding a key, add it to SCHEMA only, then regenerate the example with
  `./devstack init -n -c devstack.example.toml --force` (pure config code,
  touches nothing else).
- **Unknown keys are errors** (with `difflib` suggestions). Missing keys take
  the default.
- Defaults may reference other keys with `{section.key}` placeholders and a few
  computed values (`{env.user}`, `{env.uid}`, `{env.home}`), so renaming
  `stack.name` renames everything derived from it. Resolution is recursive with
  cycle detection. User values may use placeholders too.
- `~` is expanded in every path key; paths must be absolute after expansion.

### Everything that names a file/resource is configurable

Anything that can collide with another stack, an existing setup on the host, or
be reused is a key, derived from `stack.name` by default:

| What                                                                                         | Key                             | Default                                                      |
| -------------------------------------------------------------------------------------------- | ------------------------------- | ------------------------------------------------------------ |
| stack name (root of all names)                                                               | `stack.name`                    | `webstack`                                                   |
| container                                                                                    | `container.name`                | `{stack.name}`                                               |
| dev TLD (all `*.tld` → container); must not be a delegated TLD unless `dns.allow_public_tld` | `dns.tld`                       | `{container.name}`                                           |
| app hostname (prod) / dev URL                                                                | `site.hostname`                 | `app.example.com` → `https://app.example.com.{dns.tld}`      |
| host project dir                                                                             | `project.host_path`             | `~/code/{stack.name}`                                        |
| project dir in container                                                                     | `project.container_path`        | `/srv/{stack.name}`                                          |
| ssh key                                                                                      | `ssh.key_path`                  | `~/.ssh/{container.name}_ed25519`                            |
| ssh host alias                                                                               | `ssh.host_alias`                | `{container.name}`                                           |
| per-stack known_hosts                                                                        | `ssh.known_hosts_file`          | `~/.ssh/known_hosts.d/devstack-{stack.name}`                 |
| dnsmasq drop-in                                                                              | `dns.dnsmasq_file`              | `/etc/dnsmasq.d/devstack-{stack.name}.conf`                  |
| host CA file                                                                                 | `tls.host_ca_file`              | `/usr/local/share/ca-certificates/devstack-{stack.name}.crt` |
| browser cert nickname                                                                        | `tls.nss_nickname`              | `devstack-{stack.name}`                                      |
| app systemd unit                                                                             | `app.service_name`              | `{stack.name}-app`                                           |
| secrets dir in container                                                                     | `secrets.dir`                   | `/etc/app-secrets`                                           |
| pg data volume                                                                               | `postgres.volume`               | `{stack.name}-pgdata`                                        |
| pg db / role                                                                                 | `postgres.db` / `postgres.role` | `{stack.name_sql}` / `{stack.name_sql}_app`                  |
| host state dir                                                                               | `host.state_dir`                | `~/.local/state/devstack/{stack.name}`                       |
| db backups                                                                                   | `postgres.backup_dir`           | `~/.local/share/devstack/{stack.name}/backups`               |
| logs                                                                                         | `logging.file`                  | `{host.state_dir}/devstack.log`                              |
| snapshot prefix                                                                              | `snapshots.prefix`              | `devstack-pre-`                                              |
| host network ACL                                                                             | `network.acl_name`              | `devstack-{stack.name}`                                      |
| app data volume                                                                              | `app.data_volume`               | `{stack.name}-appdata`                                       |
| login user (uid = host uid, so shared files line up)                                         | `container.user`, `container.uid`  | `dev`, `auto`                           |
| service users / groups (fixed ids from `isolation.system_uid_base`, default 510-513)         | `isolation.app_user`, `.runner_user`, `.data_group`, `.dev_group` | `{stack.name}-app`, `-runner`, `-data`, `-dev` |
| test database                                                                                | `postgres.test_db`              | `{postgres.db}_test`                                         |
| app data archives                                                                            | `app.data_backup_dir`           | `~/.local/share/devstack/{stack.name}/backups`               |

(`{stack.name_sql}` = stack name with `-` → `_`, valid as a SQL identifier.)

Fixed names in the container, derived from the stack: runner units
`<stack>-<runner>.socket` / `@.service` (ports from the config, checked for
clashes), the sudoers drop-in `/etc/sudoers.d/devstack-<stack>`,
`/usr/local/sbin/devstack-sync`, `/etc/devstack/egress.nft` (nftables table
`inet devstack_egress`) and `/etc/devstack/runners`.

Preflight checks every one of these for conflicts that devstack does not own
(container/volume exists, file exists, TLD already present in any
`address=/<tld>/` line in the dnsmasq dir, ssh alias already in `~/.ssh/config`,
...). "Owned" means recorded in this stack's journal, so re-running is fine and
conflicts with _other_ setups are caught.

The config itself stays with the user: it holds host details (paths, ssh,
DNS, mount sources) and is never copied into the project, which is usually a
public repo. Instead `up` writes `<project>/infra/devstack-requires.toml`
(managed, journaled under `base`): the container-side keys only (`PROJECT_KEYS`
in the code: project container path and read-only paths, image, `container.sudo`,
Node, site hostname, Caddy routes and headers, app incl. `profile`, `data` mode and
`[[app.runners]]`, firewall, secrets, Postgres in-container settings incl. the test
db, `gpu.enabled`) plus the required mounts as `name`/`path`/`readonly`, never `source`. Host
details stay out: `network.*` (LAN CIDRs), `caddy.admin`, volume names and host
folders, and the host-specific half of `[gpu]` (`gpu.pci`, `gpu.nvidia_runtime`). A project can therefore *request* a runner, a wider profile or the GPU, and the
"differs from what this stack last wrote" check below makes the developer approve
it on the host.

- `init --project PATH` reads it and uses it as defaults (in the interactive
  walk-through, also as soon as `project.host_path` is answered), and asks for a
  host folder per required mount.
- It may come from someone else's repo, so it is read with an allowlist: any
  other key, a mount `source`, or a `{section.key}`/`{env.*}` placeholder is
  an error. It cannot reveal or steer anything on the host.
- Preflight compares it with the config. If the file is exactly what this
  stack last wrote (journal sha256), `up` just rewrites it from the config.
  Otherwise (from the repo, or changed by a `git pull`) a required mount
  missing from the config is an error, and any other difference is a risk
  that needs `yes` / `--yes`, because `up` would overwrite it.

## 6. Logging

- Python `logging`, configured from `[logging]` and overridable by CLI flags.
- `logging.target`: `stderr` | `file` | `both` (default) | `journald` (stdlib
  `SysLogHandler('/dev/log')`, tag `devstack-<name>`, read with
  `journalctl -t devstack-<name>`).
- `logging.level` sets the console level (default `info`). The file always gets
  `debug`: every command run (argv, cwd, exit code, duration) and its output.
- **Secrets are never logged**: they are only passed through stdin or written to
  files, never on argv, and a redaction filter replaces any registered secret
  value with `***` as a second line of defence.
- Each run starts with a header: version, config path, mode, phase range,
  git-style short hash of the resolved config.

## 7. Undo model (the most important part)

Goal: **no half-finished state you can't get out of.** Two complementary
mechanisms:

### 7.1 Container internals → incus snapshots

Before each phase after `base`, `<snapshots.prefix><phase>` is snapshotted
(`snapshots.mode = "per-phase"`, default). Undoing a phase restores that
snapshot, which reverts packages, config files, users, services _and the
instance's device config_ without needing per-command inverse logic. Snapshots
of phases that have been undone are deleted.

- On the `dir` storage driver snapshots are full copies of the rootfs (a fresh
  Debian container is a few hundred MB, so 5 snapshots ≈ 1–3 GB).
- `snapshots.cleanup = "manual"` (default) keeps them until you run
  `devstack snapshot prune`; `"auto"` prunes them once `up` finishes with every
  requested phase verified. After pruning, the pruned phases can only be undone
  with `undo --all` (the data volume is still kept).
- `snapshots.mode = "off"` never takes them, with the same consequence.
- The `base` phase needs no snapshot: its undo deletes the container.
- Manual snapshots (`devstack snapshot create`) don't use the prefix, aren't in
  the journal and are only deleted with the container. Restoring one is a plain
  `incus restore` — the guide warns that this can make `state.json` disagree
  with the container, and that `up` re-verifies phases afterwards.
- Custom volumes (Postgres data) are **not** part of instance snapshots. That is
  deliberate: rolling the container back never rolls back your data.

### 7.2 Host and shared resources → journal

Everything outside the container rootfs is recorded in
`<state_dir>/journal.jsonl` **before** it is changed (write-ahead). Each entry:
`{seq, ts, phase, kind, args, status}`. `kind` is one of a fixed registry of
undo actions (no arbitrary shell strings in the journal):

| kind             | apply                                                                                                              | undo                                                                        |
| ---------------- | ------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------- |
| `host_file`      | write file (backup old one to `state_dir/backups/`)                                                                | restore backup or delete; optional `then_restart` unit                      |
| `marked_block`   | add `# >>> devstack:<name> >>>` block to a shared file (only `~/.ssh/config`)                                      | remove exactly that block                                                   |
| `project_file`   | create scaffold file (never overwrite), or rewrite a devstack-managed file (Caddyfile, unit copy) keeping a backup | delete or restore the backup **only if sha256 unchanged**, else keep + warn |
| `dir`            | create a folder (project, ~/.ssh/known_hosts.d, ...)                                                               | remove if empty                                                             |
| `project_tree`   | folder created by a tool (node_modules)                                                                            | `rm -rf` (only inside the project)                                          |
| `incus_config`   | set instance config (`nvidia.runtime`)                                                                             | unset                                                                       |
| `ssh_key`        | ssh-keygen                                                                                                         | delete key pair (only if devstack created it)                               |
| `incus_instance` | `incus init`                                                                                                       | backup db if possible, stop + delete instance (+ its snapshots)             |
| `incus_device`   | add / override device                                                                                              | remove device (idempotent)                                                  |
| `incus_snapshot` | snapshot                                                                                                           | stop, restore, start; then delete snapshot                                  |
| `incus_volume`   | create custom volume (Postgres data, app data)                                                                     | **kept** unless `--purge-data`                                              |
| `incus_acl`      | create the network ACL (+ attach it to the NIC with allow defaults)                                                | detach from the NIC, delete the ACL (only the configured name)              |
| `host_ca`        | install the host-made root CA + `update-ca-certificates`                                                           | remove + `update-ca-certificates --fresh`                                   |
| `nss_cert`       | `certutil -A`                                                                                                      | `certutil -D`                                                               |
| `host_pkg`       | apt install                                                                                                        | **not undone**, reported                                                    |

**Undo does not trust the journal's paths.** The journal is a plain file, so
before any `sudo rm` / `sudo install` / `rmtree` / key deletion the stored path
is compared with what the current config would produce (dnsmasq file,
known_hosts file, host CA file, ssh key, project subtree) or an allowed prefix
(`dns.dnsmasq_dir`, `/usr/local/share/ca-certificates`, the project, `~/.ssh`);
paths are `normpath`ed first (no `..` tricks) and backups must live in
`state_dir/backups`. A mismatch is skipped with a warning and the entry is
marked `kept` (`undo_path_ok`, `undo_backup_ok`).

Undo walks the journal in reverse (LIFO), so e.g. a dnsmasq restart recorded
after the file write is not needed separately — `host_file` carries
`then_restart`. Every undo action is idempotent (already gone = success), so an
interrupted undo can simply be re-run.

### 7.3 Failure handling

- A phase is a list of **steps**. Each step has `describe()` (for `plan`),
  `is_done()` (for idempotent re-runs) and `apply()`. A phase ends with
  **verify** checks (e.g. `curl` the dev URL, `ss` shows 127.0.0.1 only).
- Phase states in `state.json`:
  `pending → running → done | failed →
  rolled_back`.
- On any exception or Ctrl-C inside a phase: log the error with the failing
  command and its output; then `run.on_failure`:
  - `rollback` (default): undo this phase's journal entries (incl. snapshot
    restore) → `rolled_back`. Previous phases stay done.
  - `stop`: leave as `failed` for debugging; `devstack undo` later cleans it up.
    Interactive mode asks, with `rollback` preselected.
- A lock file (`fcntl.flock` on `state_dir/lock`) prevents two runs at once.
- `up --dry-run` (and `plan`) run preflight + `describe()` for each phase and
  write nothing.

### 7.4 What survives what

| Action                   | container   | project files                     | pg data volume              | db backups |
| ------------------------ | ----------- | --------------------------------- | --------------------------- | ---------- |
| `undo` (one phase)       | rolled back | scaffold removed only if unedited | kept                        | kept       |
| `undo --all` / `destroy` | deleted     | unedited scaffold removed         | **kept**                    | kept       |
| `destroy --purge-data`   | deleted     | unedited scaffold removed         | deleted (auto-backup first) | kept       |

The app data volume behaves exactly like the pg data volume (column 4), with
`devstack data backup` archives instead of dumps (automatic before undoing
`isolation` or destroying, `app.data_backup_before_undo`).

Re-running `up` after `destroy` re-attaches the existing volume and reuses the
data (see 8.6).

### 7.5 Checkpoints (undo after provisioning)

Phase snapshots undo provisioning; `devstack checkpoint` undoes what came after
(an agent's changes, a bad install, test data). Parts, taken with the container
stopped so they are from one moment:

| Part | Mechanism |
| --- | --- |
| Container | `incus snapshot create <inst> checkpoint-<name>`. Outside the journal and `snapshots.prefix` (like `pre-upgrade-*`), so undo, prune and preflight ignore it; `snapshot create` refuses the prefix |
| Postgres, app data (volume) | `incus storage volume snapshot create <pool> <vol> checkpoint-<name>` |
| App data (host folder) | `data backup` through the container (the host user can't read it); `data restore` after |
| Project, tracked + untracked | A commit on `refs/devstack/checkpoints/<name>` (parent: HEAD), built on a scratch index with `hash-object -w --no-filters`, `update-index --index-info`, `write-tree`, `commit-tree`, `update-ref`. HEAD, branches and the index untouched; the index file is copied |
| Project, ignored | Outside `checkpoint.derived` (basename, any depth), up to `checkpoint.capture_max_mb`, into a tar in the state dir (secrets such as `.env` stay out of `.git`); the rest is listed |

git runs hermetically (`git_run`): `GIT_DIR`/`GIT_WORK_TREE` pinned,
`GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_NOSYSTEM=1`, `HOME` = the state dir,
`-c core.fsmonitor=false -c core.hooksPath=/dev/null`, a fixed identity, bytes
in and out. Nothing the container wrote (`.gitattributes` filters, nested
repos) or the user's global config (fsmonitor, filters) runs on the host; a test
plants all three and checks, and fails with the protections removed.

Restore: the done phases must equal those at creation (else the container and
the journal disagree), every part must exist, and the user confirms. Stop;
restore the container and volume snapshots; restore the project; start; app
data; `checkpoint.restore_command` in the project as the container user. The
project restore writes the commit's blobs raw (`cat-file --batch`, no
filters), skips identical files (mtimes kept), removes non-ignored files made
since, and puts captured ignored files back. Every write goes through
`safe_parent`: a symlink or file where the checkpoint has a folder is replaced
by a real folder, so nothing is written outside the project; removal never
follows a symlinked folder. On the same HEAD the index comes back too;
otherwise commits made since are kept and the output shows `git log a..b` and
`git reset <then>`.

Create: `checkpoint.keep` (default 1) — list existing, make the new one first,
then delete the oldest beyond `keep` (confirmed; `--yes` in scripts). Size is
measured as the storage pool's used space before/after (works on `dir`, where
incus reports no usage), plus the tar and index; create refuses when the pool's
free space is under 1.2× the last checkpoint. A failure removes what was made
and restarts the container. Recovery, not containment: a checkpoint taken after
something malicious ran restores it too.

## 8. Phases in detail

Each bullet is a step; (H) = host, (C) = inside container, (P) = project dir.

### 8.0 Preflight (always, no changes)

Python version · not root · OS family · sudo works · incus reachable and version
· storage pool + network exist · nic device name of the profile (auto-detect,
`container.nic_device`) · host deps table · name conflicts (§5) · host uid (for
idmapped mount) · GPU prerequisites if `gpu.enabled`.

Preflight also reviews the config as if it were a script: **risks** need a typed `yes`
(interactive) or `--yes` (non-interactive, else exit 4) before `up` changes
anything: the project folder or a `container.mounts` source that is `/`,
`$HOME`, contains `$HOME`, or is/contains/sits inside `~/.ssh`, `~/.gnupg`,
`/etc`, `/root`, `/var` (the same for `app.data_source`); overwriting a project's
`infra/devstack-requires.toml` that differs from the config (§5);
`container.sudo = "full"`; `app.profile = "open"`; a non-empty
`network.allow_private`; and every new or changed runner (project code run as a
service with internet access; compared with the runners the last isolation run
applied). **Warnings**: profiles other than `default`, an image
not from `images:`, `dns.tld = ""` (overrides a real domain host-wide),
`network.acl = false`, a `project.readonly_paths`
entry that doesn't exist yet or is inside `.git`, a git repository nested in the
project, replace refs, grafts or alternates in `.git`, a read-only device that
differs from what the config produces. **Errors**: no `network_bridge_acl_devices` API
extension, a firewall driver other than nftables or a non-bridge network (with
`network.acl`), an ACL or app data volume of that name that this stack doesn't own,
and a project-owned Caddyfile that starts with a global options block. `plan` always
prints image, profiles, shared folders and every host path that would be
written.

### 8.1 `base`

1. (P) create `project.host_path` (journal `dir`). git is required: if the
   project has no `.git`, `git init` it on the host **before the container's first
   start**, so `.git` is read-only from the first boot, and set
   `core.useReplaceRefs = false` in its `.git/config` (`ensure_git_repo`; neither
   is undone, the repository is the user's). Preflight errors if git is missing
   on the host or `.git` is not a plain folder (a worktree or submodule pointer, a
   symlink): the read-only mount needs the real thing inside the project.
2. (H) `incus init <image> <name>` with `container.profiles`, optional
   `limits.cpu` / `limits.memory` (journal `incus_instance`).
3. (H) disk device `project`:
   `source=host_path path=container_path
   shift=true` (idmapped, so files keep
   host uid ownership). On top of it, all of `.git` is a read-only disk device
   `git`, always: the host runs git there, so hooks and `.git/config`
   (`core.fsmonitor`, `core.hooksPath`, `core.sshCommand` run on the host's next
   `git status`) are code it executes, and refs, `packed-refs`, `refs/replace/`,
   `info/grafts` and `objects/info/alternates` decide what `git log` and
   `git diff` show, so a reviewed commit could differ from the pushed one.
   `project.readonly_paths` entries become further read-only devices `ro-<hash
   of the path>` (`.git/...` entries are folded into `git` with a warning), mounted
   parents first. A path that doesn't exist yet is skipped and added by the next
   `up` once it does, with a warning to review it (it was writable until then).
   Verified with `findmnt` in the container. Cost: git in the container can only
   read; commits, branches and pushes happen on the host.
   Not covered: a repository nested in the project (`sub/.git`, or a submodule's
   `.git` file, which the container can point anywhere). The host's git uses its
   config when run in that folder, so preflight lists them (`nested_git`,
   `node_modules` skipped) and asks for them to be deleted.
4. (H) extra mounts from `[[container.mounts]]` (e.g. a shared data folder).
   Entries added to the config after `base` is done are added by the next `up`
   (shown as "mounts" in the plan, journaled under `base`). Changed or removed
   entries are not applied to the existing device; preflight warns about changes.
5. (H) optional GPU: `gpu` device + `nvidia.runtime=true` (needs
   `nvidia-container-toolkit` on host; off by default).
6. (H) start; pin IPv4: use `container.ipv4` if set, else read the DHCP address,
   then `incus config device override <name> <nic> ipv4.address=<ip>` and
   restart. IP saved to `state.json`.
6a. (H) `network.acl`: create the incus network ACL `network.acl_name` (journal
   `incus_acl`) and attach it to the NIC with
   `security.acls.default.{ingress,egress}.action=allow` (once a NIC has any ACL,
   incus rejects unmatched traffic in both directions, which would cut ssh and
   HTTPS in). The ACL holds reject rules only: private ranges (`10/8`,
   `172.16/12`, `192.168/16`, `100.64/10`, `169.254/16`, `224/4`, `fc00::/7`) and
   the host's own global addresses (`ip -j addr`), minus the bridge gateway and
   `network.allow_private`; TCP/UDP to `fe80::/10` (ICMPv6 stays for NDP); and
   TCP/UDP to the gateway on every port except DNS (53) and DHCP (67, 547).
   incus orders rules by action (drop, reject, allow), so exceptions are carved
   out of the ranges (`subtract_networks`) rather than written as allow rules.
   Re-running refreshes the rules; an existing container whose NIC lacks the ACL
   gets it on the next `up` (like late mounts).
7. (C) wait for network + `apt update`; install
   `openssh-server sudo curl
   ca-certificates gnupg gpgv xz-utils iproute2 procps`.
8. (C) create user `container.user` (default `dev`) with **uid = host uid**
   (needed so the shared folder ownership lines up), in `systemd-journal`
   (service logs without sudo). The name is deliberately generic and the uid is
   the only thing tied to the host: a host-derived name buys nothing (the ssh
   config block carries `User`, so nobody types it) and leaks into files the
   project commits -- the scaffolded `README.md` names the account, and a
   container scan can see `/home/<user>`. It is still settable for anyone who
   wants their login name, which is why the SBOM leak guard checks for it. Sudo per `container.sudo`: `limited` (default) = not in
   `sudo`, one drop-in `/etc/sudoers.d/devstack-<stack>` allowing only
   `/usr/local/sbin/devstack-sync` (validated with `visudo -c` before install);
   `full` = `sudo` group + `NOPASSWD:ALL` (a risk); `none`. Applied again in
   isolation (`SUDO_APPLY`, idempotent), which also strips an older container's
   user of `sudo` on `up --redo isolation`.
9. (C) sshd drop-in `/etc/ssh/sshd_config.d/10-devstack.conf`:
   `PasswordAuthentication no`, `PermitRootLogin no`,
   `PubkeyAuthentication
   yes`, `AllowUsers <user>`, `X11Forwarding no`,
   `AllowAgentForwarding no` (TCP forwarding stays on: Remote-SSH needs it);
   reload sshd.
10. (H) ssh key at `ssh.key_path` (journal `ssh_key`), push `.pub` to the
    container's `authorized_keys` via `incus exec` (trusted channel).
11. (H) known_hosts: read the container's host key **via `incus exec`** (so no
    trust-on-first-use) into the per-stack `ssh.known_hosts_file`.
12. (H) `~/.ssh/config` marked block: `Host <alias>` with `HostName <ip>`,
    `User`, `IdentityFile`, `IdentitiesOnly yes`, `HostKeyAlias <alias>`,
    `UserKnownHostsFile <per-stack file>`, `StrictHostKeyChecking yes`.
13. (C) Node `node.version`: download tarball + `SHASUMS256.txt.asc` + Node
    release keyring (from the pinned commit `NODE_KEYRING_COMMIT` of
    nodejs/release-keys, sha256 `NODE_KEYRING_SHA256` checked), `gpgv` verify,
    `sha256sum -c`, unpack to `/usr/local/node-v<ver>-linux-<arch>`, symlink
    binaries into `/usr/local/bin`,
    `corepack enable --install-directory /usr/local/bin`.
14. Verify: `ssh <alias> true` works with BatchMode; `node --version` matches;
    with `network.acl`, devstack opens a temporary listener on the host (all
    addresses, random port) and the container (as the login user) must fail to
    connect to it at the gateway and the host's other IPv4 addresses. Its own
    listener, because existing services may already be firewalled on the host,
    which would hide a missing ACL. Checked on incus 6.0.4: the NIC-level ACL
    covers traffic to the host (an ACL-less container reached the listener on
    the gateway; the ACL'd one was refused).

### 8.2 `app`

Scaffold into the project dir — **never overwrites**; existing files are skipped
and reported: `package.json` (`"type": "module"`, `packageManager` pinned by
corepack), `tsconfig.json`, `infra/apt-packages.txt` (format header only),
`scripts/sync-env.sh` (`sudo devstack-sync packages < infra/apt-packages.txt`,
then `pnpm install --frozen-lockfile`), `server.ts` (zero deps; binds `app.bind`:`app.port`,
default 127.0.0.1:8080; `/api/health`; token middleware is present but only
enforced when `INTERNAL_TOKEN` is set, so phase 2 runs before phase 5 exists;
with `NODE_ENV=production`, which the systemd unit sets, a missing token fails
closed: every request gets a bare 500), `static/{index.html,style.css,main.js}`,
`error/index.html`, `.gitignore`, and `README.md` (which carries the dependency
policy: why each piece is there and what was deliberately ruled out -- the
machine-readable inventory is generated into `<sbom.dir>/`, see §8.7). Then
(C) as the user: `corepack use pnpm@<node.pnpm_version>` and `pnpm add -D` of
`dev_packages()` if `package.json` was just created; for an existing project without `node_modules` (a clone, or a rebuild:
undo removes the `node_modules` devstack created), `pnpm install
--frozen-lockfile` (plain `install` without a lockfile). Verify:
`node --check`-style dry start of `server.ts` on the port, curl `/api/health`
from inside the container, stop.

**The project toolchain** (only with a new `package.json`: `SCAFFOLD_NEW_PROJECT_ONLY`).
A new project gets `pnpm-workspace.yaml`, `eslint.config.js` and
`scripts/lint-changed.sh`, and `package.json` gets `typecheck`, `lint`, `lint:changed`
and `check`. They are never added to an existing project: they assume
the devDependencies above, and a `pnpm-workspace.yaml` appearing under an existing
lockfile makes the next `pnpm install --frozen-lockfile` re-check every locked version
against its release-age and trust rules, which could fail a rebuild.

- `pnpm-workspace.yaml`: `minimumReleaseAge: 10080` (explicit, so strict: no fallback to
  a younger version), `blockExoticSubdeps`, `trustPolicy: no-downgrade`,
  `strictDepBuilds`; `allowBuilds` starts empty. Needs pnpm 10.26 (`PNPM_MIN`, checked on
  `node.pnpm_version`). The pnpm default is an exact version at least a week old, not
  `latest`: corepack's download of pnpm itself is not covered by `minimumReleaseAge`.
- `dev_packages()`: `TYPESCRIPT_SPEC` holds TypeScript at 6.0, because typescript-eslint 8
  supports `<6.1.0` and the plain `typescript` dist-tag is 7.x; `@types/node@<node major>`
  so the types match the runtime; the rest unpinned, left to `minimumReleaseAge`.
- `eslint.config.js`: typescript-eslint `strictTypeChecked` with `projectService`, plus
  `no-unsafe-type-assertion` (not in the preset: a narrowing cast then needs a disable
  comment, and `require-description` makes that comment carry the justification) and
  `consistent-type-assertions` with object/array literal assertions banned;
  `eslint-plugin-security` for Node files, `eslint-plugin-no-unsanitized` for `static/`;
  `no-eval`/`no-new-func`/`no-implied-eval`; `child_process` only in
  `src/lib/child-process.ts`. Security's preset warns rather than errors, so every lint
  script runs `--max-warnings 0`. The scaffolded `server.ts` is written to pass it.
- No git hook for "lint on commit", for §8.7's reasons: `scripts/lint-changed.sh` (lint
  what differs from `HEAD`, plus untracked files) runs in the container. It only reads
  `.git` (`git diff --name-only HEAD`, `git ls-files --others`), which works on the
  read-only mount: git skips the index refresh it can't write (verified with an
  unwritable `.git`). The container has no git binary unless the project lists `git` in
  `infra/apt-packages.txt`; without it the script lints everything.
- No CI file (§1.5, CI): the project README gives the blocking command,
  `pnpm install --frozen-lockfile && pnpm check`.

Note: from the start the server binds **127.0.0.1**, not 0.0.0.0 (the top
isolation rule, §1.1), so it can't be opened at `http://<container-ip>:8080`;
the inside-container curl checks it instead. Browser access comes with phase 3.

### 8.3 `proxy`

1. (C) Caddy apt repo (cloudsmith key → `/usr/share/keyrings`, its primary
   fingerprint checked against `CADDY_KEY_FPR` with `gpg --show-keys` before
   dearmoring), install `caddy`. No `libnss3-tools` in the container.
2. (H) **local CA on the host** (`ensure_host_ca`, `openssl`, EC P-256) in
   `state_dir/ca/` (dir 0700, keys 0600): a **root** whose X.509 name constraint
   only permits `.<dns.tld>` (or `site.hostname` when `dns.tld = ""`) plus
   `dns.extra_names`, and an **intermediate** signed by it (`pathlen:0`). The
   root is regenerated if missing, within 30 days of expiry, or if the permitted
   names changed (`names.json`); the intermediate is re-signed when missing or
   within 30 days of expiry. The root key never goes into the container.
3. (C) copy only `intermediate.crt` / `intermediate.key` to `/etc/caddy/pki/`
   (key `root:caddy` 0640). Drop cached leaf certs and restart Caddy.
4. (P) generate `infra/Caddyfile` (managed file, header says _generated — change
   devstack.toml or set `caddy.manage_caddyfile = false`_): snippets and site
   blocks only. Level "proxy": site block for the dev host (static root +
   `reverse_proxy /api/*`), `http://` catch-all → error page. Every site block
   starts with `import devstack_same_origin` (step 5), and the app's one gets
   `request_body { max_size … }` when `caddy.max_request_body` is set.
5. (C) `/etc/caddy/Caddyfile` (root-owned, devstack's in both modes): the global
   block — `local_certs`, `skip_install_trust` (don't add Caddy's own unused
   root to the container), `pki { ca local { intermediate { cert … key … } } }`,
   and from the isolation level on `admin <caddy.admin>` — then the snippet
   `(devstack_same_origin)` for `caddy.same_origin` (below), then
   `import <container_path>/infra/Caddyfile`. Caddy accepts a global block only
   as the first block, so a project file with its own fails to parse instead of
   overriding devstack's (it fails closed; Caddy re-reads the file on every
   restart, so a check in `devstack-sync` alone would not cover it). Validate
   **as the caddy user** (as root, a parse error of `import /etc/shadow` would
   print the file's first token), then `systemctl reload caddy` (always via
   systemd so the unit's environment applies). Caddy still creates its own root
   under `pki/authorities/local/`; it is never trusted or pulled.

   `devstack_same_origin`: `@foreign expression` matching `Sec-Fetch-Site` in
   `cross-site`/`same-site`, or an `Origin` that isn't `{scheme}://{hostport}`;
   `respond @foreign 403`. `allow-navigation` exempts `GET` +
   `Sec-Fetch-Mode: navigate` + `Sec-Fetch-Dest: document`; `off` leaves the
   snippet empty so imports still parse. In the root file so a fix reaches every
   project, including those with their own Caddyfile; it guards the app against
   other sites in the browser, not the host against the container (the dev user
   can rewrite the app anyway). A project file that defines a snippet of that
   name is refused (Caddy errors on redeclaration); one that never imports it
   gets a preflight warning. On an existing container whose phases are done,
   `up` rewrites the root file (and a managed project Caddyfile) when they
   differ from what the done phases would write now (`pending_caddy`), so a new
   snippet or a changed `caddy.same_origin` arrives without a phase rerun.
6. (H) install the host **root** as `tls.host_ca_file` +
   `update-ca-certificates` (journal `host_ca`). `tls.browser_trust` (default
   `no`) only covers the everyday browser's `~/.pki/nssdb`: `auto`/`yes` import
   there (journal `nss_cert`). By default only the dev browser trusts the root
   (§8.3.1), so dev pages are not trusted in the browser you use for everything.
7. (H) DNS: dnsmasq drop-in (see §9), journal `host_file` with
   `then_restart = dnsmasq`.
8. Verify: from host `curl --fail https://<dev host>/` and `/api/health` (system
   CA store, real DNS). Unless `caddy.same_origin = "off"` (or a project file
   without the import): a cross-site `fetch` gets 403 and a same-origin one
   doesn't.

Why: trusting a CA means trusting everything it signs. With Caddy's own CA the
signing key lived where untrusted code runs and the host trusted it for every
site. Now a key stolen from the container can only sign `*.<tld>` names, which
OpenSSL and Chromium enforce (`permitted subtree violation`). Checked with Caddy
2.11, OpenSSL 3.0 and Chromium; browsers that ignore name constraints are not
covered. Rebuilding the container no longer changes the CA.

### 8.3.1 `devstack browse` and dev servers

The ACL keeps the container off the host and LAN, but a browser on the host
running the container's pages is on the host's network: their scripts can reach
`127.0.0.1` services and LAN devices. `browse` starts Chromium with:

- `--proxy-server=http://127.0.0.1:9` and `--proxy-bypass-list=<dev domains>;<-loopback>`:
  only the dev domain (`*.<tld>`, or the hostname and its subdomains with an
  empty TLD, plus `dns.extra_names`) goes direct; everything else goes to a proxy
  that isn't there and fails (no direct fallback for a fixed proxy). `<-loopback>`
  removes Chromium's implicit loopback bypass. Refuses to start if something
  listens on port 9.
- `--force-webrtc-ip-handling-policy=disable_non_proxied_udp`.
- `HOME=<state_dir>/browser`: Chromium's NSS db is `$HOME/.pki/nssdb`, so the
  dev CA's root goes there (`certutil -N`, then `-A -t C,,`; replaced when the
  root changes) and nowhere else. XDG base dirs are dropped from the env.
  `--user-data-dir=<state_dir>/browser/profile`.
- A normal window (`--app` on request), no extensions, sync, background
  networking, component updates or default apps; `--password-store=basic`.
  Normal by default because Chromium draws a normal window's frame itself, while
  an app window asks the window manager for a title bar: on a KWin set up
  without decorations (every window frame 0) it got none, so it couldn't be
  moved or closed. `custom_chrome_frame` doesn't change that for app windows.

Checked with Chromium 154 (headless, same flags): with the root only in that
HOME's db the dev site loads, while an empty db or another HOME fails even
though the system store trusts the root (Chromium ignores it); the public
internet, `127.0.0.1`/`localhost` services and the LAN gateway fail; without
`<-loopback>` a host loopback service loads. Not covered: a compromise of
Chromium's network process. Stronger, not done: a separate OS user whose egress
nftables limits (`meta skuid`) — the hard part is a GUI without a shared X11.

`caddy.dev_servers` (`name = "port"`, a project requirement): a site block per
entry **in the root file** (so projects that own their Caddyfile get them too),
before the project import: `import devstack_same_origin`, `/api/*` to the app
(with the internal token from the isolation level on), everything else to
`localhost:<port>` with `header_up Host {upstream_hostport}` (dev servers'
host checks; Caddy's `localhost` reaches a server bound to `::1` only, as Node
does). Page and API share one origin, so the same-origin rule needs no
exception and nothing rewrites `Origin`. No security headers (a CSP breaks HMR).
Names are `<name>.<dev host>`: covered by the CA's name constraint and, with
`dns.wildcard`, by DNS; without it, `host-record` lines. When the drop-in
differs from what proxy would write now (a dev server added later), `up` rewrites
it and restarts dnsmasq (`pending_dns`, journaled under proxy) rather than
needing `--redo proxy`, which would also redo every later phase. Ports may not be the app's, Postgres' or a
runner's. A forwarded port (VSCode) lands on host loopback, which the dev browser
can't reach by design.

### 8.4 `standards`

1. (C) install `brotli`.
2. (P) `infra/compress-static.sh` (writes `.br` and `.gz` copies, skips
   already-compressed and binary formats); run it on `static/` and `error/`.
3. (P) re-render Caddyfile at level "standards": `encode zstd gzip`,
   `file_server { precompressed br gzip }`, `(error_page)` snippet +
   `handle_errors`, `header` block with CSP etc. from `caddy.headers` (config
   table, strict defaults). The error page's inline `<style>` hash is **computed
   by devstack** and added to `style-src`.
4. Verify: response has `Content-Security-Policy`, `content-encoding: br` for
   `index.html` with `Accept-Encoding: br`.

### 8.5 `isolation`

1. (C) apt: `nftables` (+ `ufw`). ufw: default deny in / allow out; allow
   `firewall.allow` (22, 80, 443); deny `firewall.deny`, the app port, 5432 and
   runner ports; enable. (incus exec stays available, so no lockout risk.)
2. (C) system users and groups with fixed ids from `isolation.system_uid_base`
   (default 510; mid-range like `postgres.system_uid`), so owners on persistent
   volumes and the egress profiles' uid matches never change:
   `<stack>-app` (uid base, primary group `<stack>-data`), `<stack>-runner`
   (uid/gid base+1, its own group, **not** in `<stack>-data`), groups
   `<stack>-data` (base+2) and `<stack>-dev` (base+3). The login user joins both
   groups. `nologin`, no home.
3. (C) `secrets.dir` (`root:<stack>-dev 0710`); `internal-token.env`
   (`INTERNAL_TOKEN=<64 hex>`, `root:<stack>-dev 0640`, so dev servers can call
   the API directly) — generated once, kept on re-runs. `postgres.env` stays
   root 0600.
4. (H/C) app data (`app.data`): `volume` = incus custom volume `app.data_volume`
   (journal `incus_volume`, kept on undo, `app.data_adopt` like
   `postgres.adopt_volume`), `host` = disk device from `app.data_source`
   (shift), `none` = nothing. Device `appdata` at `/var/lib/<stack>-app`:
   `<stack>-app:<stack>-data 2751` (o+x so runners can traverse to `incoming/`;
   the app's `UMask=0027` makes everything below `0640`/`2750`), and
   `incoming/` `<stack>-runner:<stack>-data 2770`. The login user reads app
   data, can't write it (writes go through the app); it can write `incoming/`,
   which is untrusted input anyway.
5. (C) egress profiles: `/etc/devstack/egress.nft` (template
   `system/egress.nft`), own table `inet devstack_egress` replaced atomically
   on each load (`table …` + `delete table …` + definition), loaded by the
   oneshot `devstack-egress.service`. Not Debian's `nftables.service`, whose
   `flush ruleset` would wipe ufw's rules (devstack disables it). Output chain:
   `ct state established,related accept` (replies on connections someone else
   opened, e.g. Caddy → app or a client → a runner socket created by pid 1),
   then `meta skuid <uid> jump <profile>` with numeric uids:

   | Profile (chain) | Allowed | Used by |
   | --- | --- | --- |
   | `local` (`local_only`) | loopback, **except port 53** (the resolver would forward queries out: a DNS tunnel) | the app, default |
   | `internet` (`local_internet`) | loopback + DNS to the configured nameservers + public internet (never private/host ranges) | the app with `app.profile = "internet"` |
   | `open` | no rule (a risk) | the app with `app.profile = "open"` |
   | runners (`internet_only`) | DNS to the nameservers in `/etc/resolv.conf`, then the public internet; no loopback, no private ranges | every runner job |

   Domain allow-lists are deliberately absent: they can't be enforced at this
   layer. A project that needs one later gets an egress-proxy profile of its own.
6. (C) caddy drop-in `/etc/systemd/system/caddy.service.d/10-devstack.conf`:
   `EnvironmentFile=<token>`, `RuntimeDirectory=caddy`, `RuntimeDirectoryMode=0700`
   (the admin socket's directory: caddy and root only).
7. (P/C) re-render the Caddyfile at level "isolation": `(common)` snippet
   removing `Server`/`Via`, `header_up X-Internal-Token {env.INTERNAL_TOKEN}`,
   the 500-masking `handle_response`, and `admin <caddy.admin>` in
   `/etc/caddy/Caddyfile`. Caddy is **restarted**, not reloaded: `caddy reload`
   would look for the new admin socket before it exists.
8. (C) app unit `/etc/systemd/system/<app.service_name>.service` from the
   template: `User=<stack>-app`, `Group=<stack>-data`, `StateDirectory=` (mode
   2751) unless `app.data = "none"`, `UMask=0027`, `ProtectSystem=strict`,
   `ProtectHome=yes`, `PrivateTmp`, no capabilities, `RestrictAddressFamilies`,
   syscall filter, `Requires=`/`After=devstack-egress.service` (no rules, no
   app). Because the project lives at `/srv/<name>` (not under /home),
   `ProtectHome=yes` works. A copy is kept at `infra/<unit>.service`.
   `enable --now`.
9. (C) runners (`[[app.runners]]`: name, command, port, memory_max = `1G`,
   runtime_max = `1h`, max_connections = 4): `<stack>-<name>.socket`
   (`ListenStream=127.0.0.1:<port>`, `Accept=yes`, `MaxConnections=`) and
   `<stack>-<name>@.service` (`User=<stack>-runner`, stdin/stdout = the
   connection, the app unit's hardening, `MemoryMax=`, `RuntimeMaxSec=`,
   `ReadWritePaths=<data>/incoming`, `InaccessiblePaths=-<project>/.git`, **no
   `EnvironmentFile=`**). One short-lived process per connection; no daemon.
   `command` is validated as plain words so it can't carry systemd specifiers,
   `$` or quoting into `ExecStart=`. Runners removed from the config are
   disabled and deleted (list in `/etc/devstack/runners`). The request protocol
   and how results are imported belong to the project.
10. (C) `/usr/local/sbin/devstack-sync` (template `system/devstack-sync`, bash,
    root 0755, outside the project) and the sudo policy (§8.1 step 8). Fixed
    subcommands, no other arguments:

    | Subcommand | Does |
    | --- | --- |
    | `packages` | reads names **from stdin** (root never opens a file the user controls), 64 KiB max, `#` comments; each must match `^[a-z0-9][a-z0-9+.-]*[a-z0-9+]$` (no trailing `-`: `apt-get install foo-` removes foo) and be an exact name in `apt-cache pkgnames` (no regex/glob fallback); installs the missing ones with `--no-install-recommends` under a `policy-rc.d` that forbids starting services, then masks every service/socket/timer/path unit shipped by a newly installed package and reports setuid/setgid files; logs to the journal (`devstack-sync`). Never removes. |
    | `check-packages` | the same validation, without root or changes |
    | `restart app` / `restart runners` | the devstack-managed units only |
    | `validate caddy` | validate as caddy, change nothing (root only for the CA key Caddy reads) |
    | `reload caddy` | validate as caddy, `systemctl reload caddy` |
    | `status` | unit states, egress rules, last syncs |

    Applied only from the host by `devstack up`: runners, profiles, app data,
    mounts, apt repos, sudo, ACL exceptions. When devstack changes the template,
    `up` reinstalls it on an existing container whose isolation phase is done
    (`refresh_sync`): the same script a fresh isolation run would install.
11. Verify: `systemd-analyze security` score logged; `ss -tlnp` shows the app
    only on 127.0.0.1; direct request without token → 500; through Caddy → 200;
    no `Server` header; `ufw status` as expected. As each service user: the app
    (`local`) reaches `127.0.0.1:443` but not `1.1.1.1:443` nor the resolver on
    53; the runner user doesn't reach `127.0.0.1:443` (reaching `1.1.1.1:443` is
    only a warning); nothing listens on `127.0.0.1:2019`; with limited sudo, the
    login user isn't in `sudo` and `sudo -l` lists only `devstack-sync`; the app
    can write its data folder, the login user can read but not write it, the
    runner user can't read it but can write `incoming/`.

### 8.6 `postgres`

1. (H) create custom volume `postgres.volume` on `container.storage_pool` if
   missing (journal `incus_volume`; never deleted without `--purge-data`);
   attach as disk device `pgdata` at `/var/lib/postgresql` (journal
   `incus_device`).
2. (C) pre-create `postgres` user/group with fixed `postgres.system_uid`
   (default 500; Debian allocates system ids downward from 999, so 99x collides
   with polkitd/caddy etc.) **before** installing, so a re-created container
   owns the preserved data files.
   `createcluster.conf: create_main_cluster = false`.
3. (C) PGDG repo the manual way (key downloaded, primary fingerprint checked
   against `PGDG_KEY_FPR`, then → `/usr/share/postgresql-common/pgdg/`,
   `deb [signed-by=…] https://apt.postgresql.org/pub/repos/apt <codename>-pgdg main`),
   install `postgresql-<version>`.
4. (C) cluster: if `/var/lib/postgresql/<v>/main/PG_VERSION` exists on the
   volume → check version matches (else exit 1: major upgrade is manual) and
   integrate it with `pg_createcluster <v> main` (reuses existing data dir);
   else create a fresh cluster.
5. (C) `conf.d/10-devstack.conf`: `listen_addresses = 'localhost'`,
   `password_encryption = scram-sha-256`; replace `pg_hba.conf` with: postgres
   via peer on the local socket, everyone else scram-sha-256 on socket and
   127.0.0.1/::1 only. ufw deny 5432 (already in phase 5 list).
6. (C) secret `postgres.env` (`DATABASE_URL=…`, `PG*` vars) generated once;
   role + db created if missing, password set (via psql stdin, `\gexec`, never
   argv). If the role already existed (reused volume) its password is reset to
   the new secret.
7. (C) optional `~/.pgpass` for the dev user (`postgres.write_pgpass`; app db and
   test db, written as the user). The
   test database `postgres.test_db` (default `<db>_test`, `""` = none): created
   if missing, owned by the app role, not backed up (disposable). The dev env
   file `~<user>/.config/devstack/<stack>.env` (0600, written **as the user**,
   so root never writes through a path the user controls) has `DATABASE_URL`
   and `TEST_DATABASE_URL` for dev tools (`node --env-file-if-exists=…`). The
   app unit still only gets `postgres.env`.
8. (C) add `EnvironmentFile=<secrets>/postgres.env` to the app unit, restart;
   `/api/health` reports db reachability.
9. Verify: `pg_isready`, login as app role over 127.0.0.1 (and into the test
   db), `ss` shows 5432 on loopback only, `/api/health` → `"db": true`.

Backups: `devstack db backup` streams `pg_dump -Fc` over `incus exec` to
`postgres.backup_dir/<db>-<timestamp>.dump`; automatic before undoing `postgres`
and before `destroy` (`postgres.backup_before_undo`).

Restore: `devstack db restore FILE` takes a safety backup, then streams the dump
through stdin to
`pg_restore --clean --if-exists --no-owner --single-transaction` run **as the
app role** over 127.0.0.1 (password from `postgres.env` sourced inside the
container, never argv). The app role owns the database, so cleaning works; dumps
that need superuser (extensions, `COPY … PROGRAM`) fail on purpose, roll back
completely, and the error prints the manual superuser command.

### 8.7 SBOM and vulnerability scanning (not a phase)

**The split.** `syft` is installed **in the container** (phase `base`, pinned
version + sha256, same pattern as the Node tarball): only there is the real dpkg
database, the Node install under `/usr/local`, and `node_modules` under the
project mount. `grype` is downloaded **on the host** into `sbom.db_dir` and runs
against the generated document (`grype sbom:<file>`). So the container never
needs the ~1 GB vulnerability database, and its nftables-restricted egress never
has to reach a feed. The container is the artifact; the host is the auditor.

**Two documents**, both CycloneDX JSON, both `project_file(managed=True)` under
`base` so backup/undo work like `infra/devstack-requires.toml`:

| File | Scan root | Covers |
|---|---|---|
| `<sbom.dir>/container.cdx.json` | `dir:/` in the container | deb packages, Node, Caddy, Postgres |
| `<sbom.dir>/app.cdx.json` | `dir:<project.container_path>` | npm packages from `pnpm-lock.yaml` |

**Why not a seventh phase.** It would have to run last (to see Caddy, Postgres
and `node_modules`), so `up --to postgres` would stop meaning "the whole stack"
and every `--to`/`--redo` reference in the docs would need rewording. It would
add a full container snapshot per `up` for a phase whose only container state is
one binary. And there would be nothing for `undo_phase` to do: the two project
files are already journaled by `project_file`, and the binary is covered by the
container's own snapshots. The honest cost of the chosen approach is that `base`
gains a GitHub download, which is why `sbom.enabled = false` skips it entirely,
is reflected in `base.describe()`, and is **not** in `PROJECT_KEYS` (a cloned
repo must not be able to add a download to someone else's `base`).

**Generation runs at the end of `up`** (`sbom.generate_on_up`), after every phase
has passed and been snapshot-pruned. A failure there is a `log.warning`, never a
failed `up`: exiting non-zero with nothing rolled back would be worse than a
warning plus the `sbom check` gate. `grype` never runs during `up` -- a feed
download or a brand-new CVE must not be able to block provisioning.

**The exclude list is computed** (`rootfs_excludes`), not a literal:
`/proc`, `/sys`, `/dev`, `/run` (kernel/volatile), `/tmp`, `/var/tmp`,
`/var/cache`, `/var/log` (scratch), `/home` and `/root` (**privacy**, see §10.1),
the project folder and every `container.mounts[].path` (host folders shared in;
their contents are not this container's inventory), `/var/lib/postgresql` and the
app's state directory (data, not packages).

**Normalization** (`normalize_cdx`) is what makes the committed file worth
committing. syft emits a random `serialNumber`, a fresh `metadata.timestamp`, and
bom-refs carrying a `package-id` content hash; raw, the file would churn on every
`up`. The normalizer drops those, drops `type: "file"` components (syft names them
by absolute path), filters properties through an **allowlist**, canonicalizes
bom-refs to the purl and rewrites the dependency graph to match, collapses
duplicates and sorts everything, then serializes with `sort_keys=True`. The
result is a pure function of the dependency set. `assert_no_sbom_leaks` is the
fail-closed backstop: it refuses to write a document containing a host path, the
container user's name, a mount source, or a `urn:uuid:`.

**The gate counts only findings with a fix available** (`sbom.only_fixed`, default on). This is not
a convenience: measured with grype on a 3214-package Debian system, there were 554 critical findings
and **not one** had a fix available -- every one was `not-fixed` (no fix yet) or `wont-fix` (Debian
judged it not worth one). Gating on those produces a permanently red gate, which is worse than no
gate because it teaches people to switch it off. The full counts are always printed, with the
fixable subset beside each (`554 critical (0 fixable)`) and an explicit line when nothing in a
document can be fixed, so narrowing the *gate* never hides anything from the *report*.

**Exit code 5** (`GateError`) is used by both `sbom check` (the committed
inventory no longer matches the container) and `sbom scan` (findings at or above
`sbom.fail_on`), so CI can tell "the gate says no" from "the tool broke" (1/2/3).
`grype --fail-on` is deliberately **not** used: grype exits 1 for both a tripped
gate and a tool error, so the report is parsed and `gate_findings` decides --
which also makes `sbom.ignore` free and the gate unit-testable without grype.

**Remediation is host-side** (`devstack upgrade`), and that is a trust decision, not an
ergonomic one. §1.3 says security-relevant changes are applied from the host; putting the apt
upgrade here means `devstack-sync` keeps its fixed verb set and **the login user gains no new
capability at all**, so §1.3's list of what it cannot do needs no amendment. (An in-container
`devstack-sync upgrade` was the alternative. It is defensible -- installing signed packages is
already delegated, and upgrading existing ones is a smaller action -- but it would have put
patching in the hands of the zone the isolation is meant to contain.) It is also where the
workflow already is: you run `sbom scan` on the host, so you remediate there.

Three guards, each protecting a policy a plain `apt-get upgrade` would weaken:

1. **`-o Dpkg::Options::=--force-confold`.** `/etc/caddy/Caddyfile` is a *caddy package conffile*
   and is where devstack puts `admin unix//run/caddy/admin.sock`. Without this, a caddy upgrade
   could restore the vendor file and put the admin API back on TCP:2019 -- exactly what §5 says a
   project must never be able to cause. It is the only package-owned file devstack writes (the
   sshd and caddy unit settings are drop-ins; the rest sit on paths no package owns), and the
   Postgres install already uses the same flag.
2. **A generated `policy-rc.d` allowing only units that are already active.** An upgrade *must*
   be able to restart what it patches, or the new binary sits on disk while the vulnerable process
   keeps running. But a service that exists and is stopped, or one that arrives with the upgrade,
   must stay down -- "a long-running root service needs the host's approval". Note this is the
   opposite of `devstack-sync packages`, which blocks every service start: there, nothing being
   installed was ever approved; here, what is running already was.
3. **A before/after diff of unit *files*, not of packages.** An already-installed package can gain
   a unit in a new version, so comparing package lists (as `devstack-sync packages` does) would
   miss it. Anything new is masked, and nothing is ever unmasked.

`upgrade` uses `apt-get upgrade`, never `full-upgrade`/`dist-upgrade`, so it can never remove a
package to satisfy another; what that holds back is reported, and the answer for those is a
rebuild. Before changing anything it takes a plain `pre-upgrade-<timestamp>` snapshot: manual
snapshot names are deliberately outside `snapshots.prefix`, so it is a revert point without
becoming an undo point or tripping preflight's "prefixed snapshot devstack did not take" check.

**Staying current.** `up` regenerates the inventory at the end, so anything applied through a
phase is current by construction. The gap is `scripts/sync-env.sh`, which changes the container's
packages from the inside, where nothing can reach incus or the project's git. Two cheap warnings
cover it: `sync-env.sh` says what to run on the host, and `generate` records the sha256 of the
project files that usually cause drift (`infra/apt-packages.txt`, `pnpm-lock.yaml`) so `preflight`
and `status` can report staleness with no container at all. Both are *hints*: they cannot see a
package installed by hand with `incus exec`. `sbom check` is the only exact answer, and belongs in
CI or a pre-push on a machine that has the stack.

**Not a git hook**, deliberately. `.git` is mounted read-only in the
container precisely because they are code the host executes (§8.1, and 10.1 below), so devstack
installing a hook there would add host-executed code to the directory it hardened against exactly
that. A hook is also weak for this job: it is not cloned, `--no-verify` skips it, regenerating
would need the container running at commit time, and a pre-commit hook that rewrites a tracked
file breaks partial staging.

**Caches.** `sbom.db_dir` (grype plus its database) and
`<state_dir>/sbom-reports/` (the newest `SBOM_REPORT_KEEP` grype reports, mode
0600) are caches in the class of `backups/`, `ca/` and `devstack.log`: not
journaled, never committed. The grype **binary** is journaled as `host_tool` with
`phase="host"`, so `destroy`'s leftover pass removes it while a per-phase `undo`
leaves it alone. A scan report is point in time and must never be committed.

### 8.8 Secret scanning (not a phase)

`devstack leaks scan` runs gitleaks **on the host**, like grype: it needs no container,
and a scanner inside the zone it audits could be tampered with by that zone. The
binary is pinned and downloaded by `fetch_host_tool`, the same path as grype, into
`leaks.tool_dir`, journaled as `host_tool`.

**Two scans.** (1) `gitleaks git` over the whole history (`leaks.history`; `--no-history`
skips it). The repository comes from `git_env`'s `GIT_DIR`/`GIT_WORK_TREE`, with
`core.fsmonitor`/`core.hooksPath` forced off through `GIT_CONFIG_COUNT`, since gitleaks
runs git itself. (2) `gitleaks dir` over a copy, in a 0700 temp folder under the state
dir, of `working/<path>` for every tracked or untracked-but-not-ignored file and
`staged/<path>` for the index version of every staged change (`leaks_stage_tree`).
Ignored files (`.env`) are not copied: the question is what is or is about to be in
git, and they would make every scan red. Files are read with `O_NOFOLLOW|O_NONBLOCK`,
a parent that resolves outside the project is skipped, only regular files are read,
and anything over `LEAKS_MAX_FILE` is reported as not scanned.

**Why not `gitleaks git --pre-commit`/`--staged`** for uncommitted work: they scan a
`git diff`, and a container-written `.gitattributes` with `-diff` turns a change into
"Binary files differ" (verified with gitleaks 8.30.1). `GIT_ATTR_SOURCE` would stop
that but needs git 2.40, and Debian 12 has 2.39. A folder scan has no attributes.
(History is not affected: verified the same way.)

**Every project input is replaced**, because the container can write all of them:

| gitleaks input | Replaced by |
|---|---|
| `<source>/.gitleaks.toml`, `GITLEAKS_CONFIG`, `GITLEAKS_CONFIG_TOML` | `--config` (devstack's: default rules only); `git_env` is a full environment, so no `GITLEAKS_*` gets through |
| `<source>/.gitleaksignore` (read **whatever** `--gitleaks-ignore-path` says) | `source` is a folder devstack made, never the project: empty for history, `working/` + `staged/` for files. Subfolders' ignore files are not read (verified) |
| `./.gitleaksignore` (the default `-i .` is the cwd, which may be the project) | `--gitleaks-ignore-path` at an empty file of devstack's |
| inline `gitleaks:allow` | `--ignore-gitleaks-allow` |

`leaks.ignore` is matched in Python (`leaks_gate`) against the fingerprints devstack
prints (`<commit>:<file>:<rule>:<line>`, or `working/…`/`staged/…` without a commit),
not handed to gitleaks, whose fingerprints for the folder scan would carry the temp path.
No `leaks.*` key is in `PROJECT_KEYS`.

**Fail closed.** `--exit-code 0`, so any non-zero exit is a tool error. gitleaks logs a
failed `git log` as `ERR` and still exits 0 with `[]` and "no leaks found" (verified
by deleting an object), so any `ERR`/`FTL` line is a failure, and a repository with a
`HEAD` must report more than zero commits scanned. Findings exit 5 (`GateError`), as
`sbom scan` does. Output and reports never carry `Secret`/`Match`: `--redact`, and
`leaks_findings` drops them. Reports are 0600 in `<state_dir>/leaks-reports/`, newest
`LEAKS_REPORT_KEEP` per kind; the temp copy is removed in a `finally`.

Not a git hook, for §8.7's reasons.

## 9. Host DNS (always dnsmasq)

The host is **assumed to already resolve through dnsmasq** (set up once by hand,
see §9.1, including any VPN workaround). devstack never touches
`/etc/resolv.conf`, NetworkManager or `/etc/hosts`. It only writes **one drop-in
file per stack** (`dns.dnsmasq_file`) and restarts dnsmasq, so provisioning or
removing a stack is one file add/delete:

```
# devstack:<name> — generated, removed by `devstack undo`
address=/<tld>/<ip>              # dns.wildcard = true: <tld> and every *.<tld>
host-record=<name>,<ip>          # one per dns.extra_names (exact names only)
```

- `dns.tld` (default `{container.name}`, e.g. `webstack`) lets you use the full
  intended domain (`app.example.com.webstack`) against the container.
- `dns.tld` must not end in a delegated TLD (`public_tld_problem`, checked in
  `validate()` against the bundled `data/iana-tlds.txt` snapshot):
  `address=/com/ip` would hijack every `.com` name on the host. `home.arpa` is
  allowed; `dns.allow_public_tld = true` is the explicit override. Prefer
  `internal`. Because the default derives from `stack.name`, a stack named `app`
  or `dev` is refused until `dns.tld` is set.
- `dns.tld = ""` is the single-domain case: the dev host is `site.hostname`
  itself and only exact `host-record` lines are written (handy for overriding a
  real domain locally; preflight warns that it overrides it for the whole host).
  `dns.wildcard` then applies to `site.hostname`.
- Preflight: dnsmasq service active, the drop-in dir exists and is loaded by
  dnsmasq, no other file in it already claims the TLD/names, warns on `*~`
  files.
- Verify: `getent hosts <dev host>` returns the container IP. If it doesn't, the
  host isn't actually resolving through dnsmasq: the phase fails (and rolls
  back) with a pointer to the guide's DNS section.

Known host quirk: Debian's dnsmasq loads every file in `/etc/dnsmasq.d` except
`.dpkg-*`, so editor backups like `mystack.conf~` are loaded too. Preflight
warns about `*~` files in the dnsmasq dir.

### 9.1 One-time manual setup (outline)

Not automated, because it changes how the whole host resolves names:

- `apt install dnsmasq`; note the current upstream DNS servers from
  `/etc/resolv.conf`.
- A base drop-in in `/etc/dnsmasq.d/`: `no-resolv`, `server=<upstream>` lines,
  `listen-address=127.0.0.1`, `bind-interfaces` (plus `domain=`/`local=` lines
  if the old resolv.conf had a `search` domain). Restart dnsmasq.
- Back up `/etc/resolv.conf` and set it to `nameserver 127.0.0.1`.
- Stop NetworkManager rewriting it: `[main] dns=none` in
  `/etc/NetworkManager/NetworkManager.conf`.
- A VPN client that manages DNS itself may still override resolv.conf. A
  workaround is to give dnsmasq a second listen address on `lo` (a oneshot
  systemd unit running `ip addr add <addr>/32 dev lo` before dnsmasq) and point
  the VPN's custom DNS setting at it.
- Check: reconnecting the network/VPN and rebooting keep resolv.conf at
  127.0.0.1, and a test `address=` entry resolves (see the guide's DNS section).

## 10. Extending (guidance for agents)

- New phase: add a `Phase` subclass with ordered steps + verify, register it in
  `PHASES` after its dependency, add its config section to `SCHEMA`, add a
  section to `index.html`, and a row to the table in §1.2.
- Any new host-side change needs a journal kind with an idempotent undo. If no
  safe undo exists, don't do it automatically — print instructions instead.
- Any new name/path that could collide → config key derived from `stack.name`
  - preflight conflict check.
- Never put secrets on argv or in logs; generate with `secrets.token_hex`.
- A new long-running service gets its own fixed system user (an id from
  `isolation.system_uid_base`) and an egress profile line in `egress.nft`, and
  `Requires=devstack-egress.service`. Nothing the login user can edit runs as
  root; root steps never open, follow or write a path the login user controls
  (feed data on stdin, run as the user, or run as the service user).
- Anything that widens what the login user or a service may do is a preflight
  risk, and `devstack-sync` never gains a way to apply it.
- Undo/destroy must work on containers built by an older devstack (a v1
  container has no app data, ACL or read-only git paths): check what the
  container actually has, not what the phase status implies.

### 10.1 Security details that look simplifiable but aren't

Each of these closes a hole found in review or testing; keep them when refactoring.

| Detail | What breaks without it |
| --- | --- |
| Package names must not end in `-`; each must be an exact name in `apt-cache pkgnames` | `apt-get install foo-` **removes** foo; an unknown name containing `.` is treated as a pattern and installs everything matching |
| `devstack-sync` reads the package list from stdin | As root it would follow a symlink in the project (`apt-packages.txt` → `/etc/shadow`) and echo lines in its errors |
| `policy-rc.d` during install, then mask the new packages' units | A listed package could add a long-running root service without the host's approval |
| `caddy validate` as the caddy user | As root, `import /etc/shadow` prints the file's first token in the parse error |
| Same-origin rule on by default, as a root-owned snippet every site block imports | Other sites' pages could call the app with the browser's cookies; one definition devstack can fix for every project, and Caddy refuses a project copy instead of shadowing it |
| `Sec-Fetch-Site: same-site` refused too | Names under the dev TLD are one browser "site" but may be different projects |
| `strict` refuses top-level navigations from other sites; `allow-navigation` is opt-in | Inside a confined dev browser nothing else is reachable anyway; OAuth/payment redirects are the case that needs it, and the project records that in its requirements |
| Checkpoints stop the container | Container, volumes and project from one moment; a running Postgres would leave a crash-consistent volume snapshot at best |
| Project checkpoint as a git commit on a hidden ref, ignored files as a tar | Reviewable as a diff, cheap (objects shared with history), branches untouched; secrets in ignored files stay out of `.git` |
| `checkpoint.keep = 1`, new one before the old one is deleted | Bounded space by default, and never a moment without one |
| A confined dev browser, not the everyday one; `tls.browser_trust` defaults to `no` | Container pages' scripts in the everyday browser reach host loopback and the LAN, past the ACL; a certificate error there is a useful reminder |
| Dev servers through Caddy on the dev domain, not forwarded ports | Forwarded ports are host loopback, which the dev browser must not reach; one origin for page and API also avoids an `Origin` rewrite that could launder other sites' requests |
| Global options only in `/etc/caddy/Caddyfile` | A project file could put the admin API back on TCP; a second global block fails to parse instead (fails closed, also on restart) |
| Isolation restarts Caddy, not reload | `caddy reload` would look for the new admin socket before it exists |
| ACL default actions set to `allow`, reject-only rules | Once a NIC has an ACL, incus rejects unmatched traffic both ways: ssh and HTTPS in would break |
| Gateway carved out of the reject ranges, then port-limited rejects | incus orders rules by action (drop, reject, allow), so an "allow DNS" rule can't beat a "reject 10/8" rule |
| All of `.git` read-only, not only hooks and config; git required, `git init` before the first start | `core.fsmonitor`/`core.hooksPath`/`core.sshCommand` run commands on the host's next `git status`; refs, replace refs, grafts and alternates change what the host's `git log`/`git diff` show; a path created later was writable from the container until then |
| Read-only devices named by path (`ro-<hash>`), not position | Numbered `ro1..roN`, removing an entry made the next one's device look present, so its path was silently never mounted |
| Read-only device changes on an existing container made with it stopped | Hot-adding `.git` while `.git/hooks` is mounted, then removing that, would unmount under the new mount; and no moment with `.git` writable |
| `core.useReplaceRefs = false` in the repo config | Replace refs planted before `.git` was read-only stay inert; the container can't change the setting |
| Runners not in `<stack>-data`; data folder `2751` | A compromised job (internet + untrusted files) could read and send out all app data |
| `local_only` rejects port 53 before accepting loopback | The local resolver forwards queries: a DNS tunnel out of a "no internet" app |
| Nameserver accepts before the private-range rejects | Without systemd-resolved the resolver is the bridge gateway, a private address |
| `ct state established,related accept` first | Replies on connections others opened (Caddy → app, client → runner) must never hit a profile |
| Numeric uids in `egress.nft`; `Requires=devstack-egress.service` | Loading never depends on name resolution; no rules, no service (fails closed) |
| Not Debian's `nftables.service` | `/etc/nftables.conf` starts with `flush ruleset`, which wipes ufw's rules too |
| Runner `command`: plain words only | `$`, `%`, quotes would be expanded or split by systemd's `ExecStart=` |
| The base ACL check opens its own host listener | Existing host services may already be firewalled, which hides a missing ACL |
| Root never writes into the login user's home (dev env file written as the user) | A symlinked `~/.config/devstack` would redirect a root write anywhere |
| The rootfs SBOM scan excludes `/home` and `/root`, and `type: "file"` components are dropped | `container.user` defaults to your **host** login name, and syft names a file component by its absolute path -- both would be published in a committed file |
| `upgrade` passes `--force-confold` | `/etc/caddy/Caddyfile` is a caddy conffile holding the admin unix socket; the vendor file would put the admin API back on TCP |
| `upgrade`'s `policy-rc.d` allows already-active units, unlike `devstack-sync packages` which blocks all | Blocking the restart of a package you just patched leaves the vulnerable process running; allowing an inactive or brand-new service to start would hand out a root daemon |
| SBOM property filtering is an allowlist, and the kept fields are asserted | A denylist leaks whatever the next syft version adds. But a *greedy* allowlist is just as bad: drop the purl's `arch`/`distro`/`upstream` qualifiers, the CPEs or the `operating-system` component and grype matches nothing and reports a clean bill of health -- a green gate that means nothing |

| `leaks scan` points gitleaks at a folder of devstack's, never the project | gitleaks reads `<source>/.gitleaksignore` even with `--gitleaks-ignore-path`; a container-written one silences any finding |
| Uncommitted files scanned as a folder copy, not `--pre-commit`/`--staged` | A container-written `.gitattributes` with `-diff` hides the change from `git diff` |
| gitleaks `ERR` lines are failures; zero commits scanned with a `HEAD` is a failure | gitleaks exits 0 and reports "no leaks found" when its git call fails |

- Keep the tool stdlib-only.
- Any new or changed dependency of the environment (apt package or repo, image,
  download, npm package) → `./devstack sbom check` must pass, which means
  regenerating `<sbom.dir>/*.cdx.json` and committing it in the same change.
- Any new or changed **trust root** (a key fingerprint, the Node keyring pin, the
  syft/grype/gitleaks version + sha256) → update the constant in `devstack.py` **and** its
  row in README.md's "Trust roots" table. A unit test fails if a pin's value
  appears in no doc, so they cannot drift apart.

## 11. Testing policy

Agents changing the tool don't run it against a real host; the owner of the host
does. Checks an agent may do: `python3 -m py_compile devstack.py`,
`bash -n devstack`, `python3 -m unittest discover -s tests` (Python >= 3.11:
config resolve/validate, `render()`, `bash()` quoting, journal + undo with a
fake `Runner`, undo path checks, the CA name constraints with real `openssl`,
rendered scripts through `bash -n`), `./devstack config check` and
`./devstack plan` (both read-only). CI (`.github/workflows/ci.yml`) runs the
same. First real run should be `preflight`, then `up --to base`, inspect, then
continue.

The SBOM work is almost entirely host-free and so is fully agent-testable: the
normalizer is a pure function (determinism, idempotence, that grype's matching
inputs survive, that file components and host paths do not), `gate_findings` is a
pure function, and the scan scope (`rootfs_excludes`, `app_excludes`,
`syft_argv`) is computed from config. Only `generate`/`check`/`scan` themselves
need a real container or the network.

The secret scan is the same: `gitleaks_argv`, `gitleaks_env`, `leaks_findings` and
`leaks_gate` are pure, and `leaks_stage_tree` runs against a real temp git repo
(staged vs working copies, ignored and symlinked files, a FIFO, a symlinked parent).
Only the gitleaks run itself needs the binary.

The one check that cannot run host-free is verifying a pin is still the real
artifact. That belongs in a scheduled, network-only CI job (`tests/verify_pins.py`
-- download each pinned tarball and compare sha256 to the constant), kept off
pull requests so a docs change is never blocked by GitHub rate limits. It still
needs no host, no root and no incus.

Checks that need no host or root, used for the v2 isolation and worth repeating
when `egress.nft` or the Caddy layout changes:
- **nftables rules**: render `egress_nft()` to a file and run `nft -c -f` in an
  unprivileged namespace (`unshare -rn`; `nft` can come from `apt-get download
  nftables libnftables1 …` + `dpkg-deb -x`, no install). For behaviour, use
  `unshare --map-auto --map-root-user --net`, bring up `lo`, add a dummy
  interface with a default route, load the rules, and connect as each uid with
  `setpriv --reuid=<uid>`: "refused" = our reject, "timeout" = let through into
  the dummy black hole.
- **Caddy layout**: render `caddy_global()` + `caddyfile()` with
  `project.container_path` pointing at a temp dir and run `caddy adapt` (any
  release binary): `admin.listen` must be the unix socket, and a project file
  with its own global block must exit 1.

Real-host checks for the owner after changing isolation (all passed on incus
6.0.4 / Debian 13, 2026-10-04):
- As the login user: internet and DNS work; `sudo -l` lists only
  `devstack-sync`; `infra/apt-packages.txt` + `scripts/sync-env.sh` installs a
  package; bad names (`jq-`, `lib.*`, `-o`) are refused; `postgres.env`,
  units, `egress.nft` and `devstack-sync` aren't readable/writable as
  applicable; `127.0.0.1:2019` is closed; `.git/config` and `.git/hooks` and
  the app data folder aren't writable; `https://<dev host>/` works with curl
  and Node.
- As the app user (`runuser -u <stack>-app`): Postgres and Caddy reachable;
  `1.1.1.1:443` and the resolver's port 53 blocked.
- Host ACL: start a listener on the host (`0.0.0.0`, any port) and connect
  from the container to the gateway and the host's LAN address. Compare with
  a container without the ACL to tell the ACL from the host's own firewall
  (an ACL reject is an immediate "connection refused").
- A project Caddyfile with a global block fails `sudo devstack-sync reload
  caddy` and the site keeps serving; a package with a service (e.g.
  `tinyproxy`) installs with the unit masked; `data backup`/`data restore`
  round-trips; `destroy` keeps the volumes unless `--purge-data`.
- A runner job (a probe script as `command`, connect with
  `exec 3<>/dev/tcp/127.0.0.1/<port>`): public internet and DNS only, no
  loopback/host/LAN, no secrets in its environment or readable, can't list app
  data or read `.git`, writes `incoming/` as `<stack>-runner:<stack>-data 0640`,
  and the app reads what it left.

## 12. Open items

- `devstack export`: `incus export` + `incus storage volume export` for moving a
  whole environment incl. data in one go.
- IPv6 pinning (needs `ipv6.dhcp.stateful` on the bridge).
- GPU: only passthrough is provided; drivers/toolkits inside the container are
  not installed.
- Network ACL on other incus versions: on 6.0.4 the NIC-level ACL also covers
  traffic to the host itself (verified). If a version doesn't, base's verify
  step fails; the fallback would be host nftables rules on the bridge
  interface, journaled the same way.
- Egress-proxy profile (domain allow-lists) for projects that need specific
  external APIs from the app.
- In-place upgrade of v1 containers: `up --redo isolation` applies the new
  isolation (users, profiles, sudo, Caddy admin socket); the ACL and the
  read-only `.git` reach an existing container through the pending-base step of
  `up` (which stops and restarts it for device changes, replaces `ro1..roN`, and
  points at what in the formerly writable `.git` to review). Not tested; rebuilding is the supported path (`destroy` of a v1
  container is tested and works).
