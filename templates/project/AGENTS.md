# Agent notes for @@STACK@@

Read this before writing code here. It records what the container actually enforces, so you don't
have to discover it by hitting it. `README.md` is the human orientation; this file is the contract.

`@@PROJECT@@` is this folder inside the container. The declared container-side configuration is in
`infra/devstack-requires.toml` — read it rather than guessing ports, users or runner names.

## You

You run as `@@USER@@`, the same account as the terminal, VSCode and its extensions. It has full
internet access but no general root: `sudo` runs only `devstack-sync`. The host and the LAN are
blocked by an incus ACL on the host, not by anything in here.

- **System packages**: add one name per line to `infra/apt-packages.txt`, then run
  `scripts/sync-env.sh`. `apt-get install` by hand is refused, and a hand-installed package is gone
  on the next rebuild. Any service a package ships is masked. After adding one, the SBOM has to be
  regenerated on the host (`./devstack sbom generate`) and `@@SBOM_DIR@@/` committed — say so rather
  than trying it.
- **Git**: all of `.git` is read-only, because the host runs git on it; commits happen on the host.
  Leave your work in the working tree and say what you changed. With git installed, reading works
  (`git log`, `git diff`, `git status`); anything that writes `.git` (commit, branch, stash, `git add`,
  switching branches) fails. Never create a repository inside the project (`git init`, a clone, a
  submodule): the host's git would run its config. Clone into `/tmp` instead.
- **Secrets**: never in a tracked file, not even in a test or an example. Credentials go in an
  ignored file (`.env`) or the container's secrets folder. Before pushing, the host runs
  `./devstack leaks scan` (gitleaks, with its own config) over the history and every file that isn't
  ignored; `gitleaks:allow` comments, `.gitleaksignore` and `.gitleaks.toml` here have no effect on it.
- **npm dependencies**: never add, remove or upgrade one (`pnpm add`, `pnpm update`, an edit to
  `package.json` or `pnpm-lock.yaml`) without saying so: name the package, the version and why. Each one
  is reviewed by a person, and so is every lockfile change. Don't touch `pnpm-workspace.yaml`'s
  settings or add to `allowBuilds` (which lets a package run its install script) without flagging it
  the same way. pnpm refuses versions less than 7 days old; pick an older one rather than working
  around it. Never `npm install` here.
- **Checks**: before handing work over, run `pnpm typecheck` and `pnpm lint:changed` (or `pnpm check`
  for everything), which is also what CI runs. They are not git hooks. Fix the cause rather
  than the warning:
  - no `any`, and no casts that narrow a type (`JSON.parse(x) as T`): validate external data instead.
    A cast you can justify gets `// eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion
    -- <why it is safe>`; never `{ ... } as T` (annotate the variable).
  - every promise is awaited, returned or explicitly handled; no async callbacks where a void one is
    expected.
  - no `eval`, `new Function` or string timers. Browser code doesn't assign HTML strings
    (`innerHTML`, `insertAdjacentHTML`, `document.write`): build elements or set `textContent`.
  - `child_process` only in `src/lib/child-process.ts`: execFile/spawn with an argument array, never
    `shell: true`. Create it there if you need it.
  - `eslint-disable` only for one rule, on one line, with `-- reason`; never edit `eslint.config.js`
    or `tsconfig.json` to loosen a rule without flagging it.
- **Calling the app**: use `https://@@DEV_HOST@@`, not `127.0.0.1:@@APP_PORT@@`. Without Caddy's
  internal token the app answers every request with a bare 500. Login shells get the dev CA through
  `NODE_EXTRA_CA_CERTS`; set it yourself for a process started another way.

## The app — `@@SERVICE@@`

Runs as `@@APP_USER@@` on `@@APP_BIND@@:@@APP_PORT@@`, egress profile `@@PROFILE@@`. Its one writable
path is `$STATE_DIRECTORY` (`/var/lib/@@APP_USER@@`). The project tree is read-only to it, so nothing
may be written beside the code at runtime. `sudo devstack-sync restart app` after an edit;
`journalctl -u @@SERVICE@@ -f` for logs, no sudo needed.

## Caddy — `infra/Caddyfile`

Every site block imports `devstack_same_origin`, defined root-owned in `/etc/caddy/Caddyfile`;
`caddy.same_origin` in `infra/devstack-requires.toml` decides what it does. By default only the
site's own pages may make requests to it: a request the browser marks as coming from another site (a
foreign `Origin`, or `Sec-Fetch-Site: cross-site` or `same-site`) gets a bare 403.

- `curl`, Node `fetch`, test runners and you all pass: they send neither header. A 403 that only the
  browser gets is this rule.
- Never add CORS headers, let another origin in, or remove the import: that is the user's decision.
  Say what needs it and why. Don't define `(devstack_same_origin)` here either: Caddy refuses a
  second definition and stops loading.
- A dev server (Vite, Storybook) is reached through Caddy, not a forwarded port: once the user lists
  it in `caddy.dev_servers` on the host, it is served at `https://<name>.@@DEV_HOST@@/` with `/api/*`
  going to the app, so page and API share one origin. Keep it on `localhost`; don't proxy `/api`
  yourself or rewrite `Origin`. If Vite's hot reload doesn't connect, set `server.hmr.clientPort = 443`.
- `sudo devstack-sync validate caddy` checks the config without applying it; `sudo devstack-sync
  reload caddy` validates, then applies. (`caddy validate` as you fails: it can't read Caddy's CA key.)

## Runners — the full contract

A runner is **not** a daemon. It is a socket-activated, per-connection job for tools that need the
internet or parse untrusted files, and it is the most tightly sandboxed thing in this stack. The
enforced version of all of this is the unit itself: `systemctl cat @@STACK@@-<name>@.service`.

**Shape**

- stdin and stdout *are* the TCP connection. Read the request from stdin, write the reply to stdout;
  stderr goes to the journal.
- One process per connection; the connection closing ends the job. No accept loop, no listener, no
  in-memory state between requests.
- `MemoryMax` (default `1G`) and `RuntimeMaxSec` (default `1h`) are hard caps. Exceeding either kills
  the job mid-request.
- The request and response format is the project's to define. Define it explicitly and validate input.

**Environment**

- It is exactly `NODE_ENV=production` and `INCOMING_DIR`. There is no `EnvironmentFile=`, so no
  `DATABASE_URL`, no `INTERNAL_TOKEN`, no secrets of any kind, and none to be read from a file either.
- Use `$INCOMING_DIR`. A runner unit has no `StateDirectory=`, so `$STATE_DIRECTORY` is unset here.

**Filesystem**

- `$INCOMING_DIR` is the only writable path: no logs, caches, lockfiles or build output anywhere else.
  The project tree is `ReadOnlyPaths`, `.git` is `InaccessiblePaths`, and `/tmp` is private per job.
- Write with generated names; never let a request choose the path.
- A runner is not in `@@DATA_GROUP@@`, so it cannot read the rest of the app's data — only traverse
  into `incoming/`. Everything it leaves there is untrusted input that the app must validate.

**Network**

- Public internet and DNS only. **No loopback**: a runner cannot reach the app, Caddy, Postgres or
  anything on `127.0.0.1`, so there is no callback channel. The only ways to return data are stdout
  and a file in `$INCOMING_DIR`. No host, no LAN, no private ranges.
- `RestrictAddressFamilies=AF_INET AF_INET6`: no unix sockets, for IPC or anything else.
- An app that may hand a runner any URL reaches the internet through it. That is accepted, not
  prevented — validate URLs on the app side if it matters.

**Kernel and process limits**

- `SystemCallFilter=@system-service` with `SystemCallErrorNumber=EPERM`: a syscall outside that set
  fails with `EPERM` rather than anything clearer.
- `CapabilityBoundingSet=` is empty, so no capabilities and no port below 1024.
- Do not add `MemoryDenyWriteExecute=yes` to a Node unit — V8's JIT needs W+X pages.

**Declaring and changing one**

- `command` must be plain words from `[A-Za-z0-9_./=:@+-]` separated by single spaces,
  project-relative. No shell, quotes, `$`, `%`, pipes or redirection: `node scripts/runner.ts` is
  valid, `sh -c "node scripts/runner.ts 2>&1"` is not. Anything more goes inside the script.
- The port is loopback-only and must not collide with the app, Postgres, 22, 80, 443, 2019 or another
  runner. It is denied in the firewall: runners stay internal.
- Adding a runner, or changing its name, port, command or limits, is a **host** operation: edit
  `devstack.toml`, then `./devstack up --redo isolation`, which asks for a typed `yes` because it runs
  project code as a service with internet access. Ask for it; do not write systemd units yourself.
- Changing a runner's **code** needs no host step: `sudo devstack-sync restart runners`, or just open
  a new connection. Logs: `journalctl -u '@@STACK@@-<name>@*' -f`.

**Testing one**

From inside the container, `printf '<request>' | nc 127.0.0.1 <port>`. Check the reply on stdout, that
the expected file appeared under `INCOMING_DIR`, and that nothing else was written. Confirm the
sandbox rather than assuming it: a loopback connection from inside the job must be refused.

## When you are done

Say which of these constraints the work relies on, and flag anything you worked around — especially a
wish for loopback, a secret, a writable project path or a shell. Those mean the work belongs in the
app, not in a runner.
