# Security policy

## Reporting a vulnerability

Please report security problems privately (a private security advisory on the
repository, or an email to the maintainer) instead of opening a public issue.
Include the devstack version (`./devstack --version`), what you did and what you
expected.

## What devstack protects, and what it does not

devstack keeps untrusted code inside an incus container. Inside it, the
developer's login user (and so VSCode, extensions and coding agents) keeps
internet access and the database, but nothing it can edit runs as root, and the
services it edits stay inside OS-enforced limits:

- The login user has no general sudo (`container.sudo = "limited"`): only the
  fixed `devstack-sync` command, which never opens a file the user controls as
  root, installs only exact Debian package names from the configured repos, and
  masks the services those packages ship.
- The app and runner jobs run as fixed system users with nftables egress
  profiles: by default the app reaches loopback only (no DNS), runners reach the
  public internet only (no loopback, no private ranges) and get no secrets.
  `container.services` each run a root-owned, sha256-pinned download as their
  own user, loopback only by default.
- A passed-through GPU is hidden from the login user, the app and runners
  (`gpu.login_user = false`, the default); only services with `gpu = true` get
  the device nodes.
- Caddy's admin API is a unix socket only caddy and root can use, and its global
  options are root-owned, so a project Caddyfile can't turn it back on.

It also limits what crosses from the container to the host:

- An incus network ACL, enforced on the host, rejects traffic from the container
  to the host (except DNS/DHCP) and to the LAN.
- All of `.git` is read-only inside the container, so container code can't plant
  commands the host's git runs (hooks, `core.fsmonitor`) or change what it shows
  (refs, replace refs, grafts). The host's git ignores replace refs
  (`core.useReplaceRefs = false`), and preflight warns about git repositories
  nested in the project, whose `.git` the container can still write.

- Caddy refuses requests that a browser marks as coming from another site (a
  foreign `Origin`, `Sec-Fetch-Site` cross-site or same-site) with a 403, by default
  and from a root-owned snippet, so other sites' pages can't call the app with your
  cookies (`caddy.same_origin`).
- `devstack browse` opens the container's pages in a Chromium that reaches only
  the dev domain (everything else goes to a dead-end proxy; loopback is not
  exempt; WebRTC can't use non-proxied UDP), with its own profile and its own trust
  in the dev CA. In your everyday browser those pages could reach your host's
  loopback services and your LAN, which the ACL can't stop. Chromium enforces this
  itself; a browser exploit that takes over its network process is not covered.
- The project folder is untrusted on the host: don't open it with tools that run
  workspace code (editors without workspace trust, direnv, npm/pnpm scripts, shell
  prompt plugins that switch Node versions). Review pushes as commits
  (`git log -p @{u}..HEAD`), not only as a working-tree diff.
- The local root CA that the host trusts is created on the host, its key never
  enters the container, and it is X.509 name-constrained to the dev domain.
- `db restore` runs as the app role, not as the Postgres superuser.
- Trust roots (Caddy and PostgreSQL apt keys, the Node.js release keyring) are
  pinned in code.
- `devstack leaks scan` runs gitleaks on the host with devstack's own config, ignore
  file and scan folder: the project's `.gitleaks.toml`, `.gitleaksignore`,
  `.gitattributes` and inline `gitleaks:allow` comments are written from the
  container and cannot silence a finding.
- Undo only touches paths the current config would produce.
- `devstack.toml` is reviewed like a script: risky host shares need a typed
  `yes` / `--yes`.

By design, two channels reach the host: ssh / VSCode Remote-SSH, and the project
folder, which is shared read-write (so treat its contents as untrusted when you
run them on the host). Membership of the `incus-admin` group is root-equivalent
on the host. See the "Security and trust" section of `index.html`.

Known and accepted: the login user (every agent) can read and write the real
database as the app role, read the app data and use the internet, so it can send
that data out; an app that can hand a runner arbitrary URLs can reach the
internet through it; anything in the container can call a service's loopback
API (an Ollama API can create models from uploaded files, so a parser bug there
runs code as that service, with its GPU); and a project-owned Caddyfile can serve anything the caddy
user can read, including the intermediate CA key (limited to the dev domain by
the root's name constraint).

## In scope

Bugs that let container code reach the host beyond the channels above, make the
host trust more than the dev domain, run attacker-controlled shell through
config values, or make undo modify files it does not own. Also: ways for the
login user to become root without `incus exec`, for the app, a runner or a
service to get past its egress profile or file permissions, or for anything but
a GPU service to open a hidden GPU.

## Out of scope

Anything that requires already having root on the host or membership of
`incus-admin`, anything that needs root in the container first, and the
accepted limits listed above.
