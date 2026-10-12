// Minimal zero-dependency smoke-test server, scaffolded by devstack.
// Replace freely: devstack never overwrites this file once it exists.
//
// - Binds to loopback only: Caddy is the only way in.
// - When INTERNAL_TOKEN is set (phase "isolation"), every request must carry the
//   X-Internal-Token header that Caddy adds; anything else gets a bare 500.
//   With NODE_ENV=production (the systemd unit) a missing token fails closed: every request
//   gets that 500. Without NODE_ENV=production (early phases, manual runs) the check is skipped.
// - /api/health reports whether Postgres is reachable when DATABASE_URL is set
//   (phase "postgres"), using a plain TCP check so no driver is needed.
// Node >= 23.6 runs .ts files directly (type stripping), so no build step.
// Written to pass the scaffolded eslint.config.js (typescript-eslint strict-type-checked) as is.

import { createServer } from "node:http";
import type { IncomingMessage, ServerResponse } from "node:http";
import { connect } from "node:net";
import { timingSafeEqual } from "node:crypto";

const HOST = process.env.APP_BIND ?? "@@APP_BIND@@";
const PORT = Number(process.env.APP_PORT ?? "@@APP_PORT@@");
const TOKEN = process.env.INTERNAL_TOKEN ?? "";
const DATABASE_URL = process.env.DATABASE_URL ?? "";
const PRODUCTION = process.env.NODE_ENV === "production";

if (PRODUCTION && !TOKEN) {
  console.error("INTERNAL_TOKEN is not set: refusing every request (fail closed)");
}

function tokenOk(header: string | string[] | undefined): boolean {
  if (!TOKEN) return !PRODUCTION; // open only before the isolation phase provides a token
  if (typeof header !== "string") return false;
  const given = Buffer.from(header);
  const expected = Buffer.from(TOKEN);
  return given.length === expected.length && timingSafeEqual(given, expected);
}

function dbReachable(): Promise<boolean | null> {
  if (!DATABASE_URL) return Promise.resolve(null);
  const url = new URL(DATABASE_URL);
  return new Promise((resolve) => {
    const socket = connect({ host: url.hostname, port: Number(url.port || 5432) });
    const done = (ok: boolean) => {
      socket.destroy();
      resolve(ok);
    };
    socket.setTimeout(1000, () => {
      done(false);
    });
    socket.once("connect", () => {
      done(true);
    });
    socket.once("error", () => {
      done(false);
    });
  });
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
  });
  res.end(JSON.stringify(body));
}

async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (!tokenOk(req.headers["x-internal-token"])) {
    res.writeHead(500);
    res.end();
    return;
  }
  const url = new URL(req.url ?? "/", "http://localhost");
  if (url.pathname === "/api/health") {
    sendJson(res, 200, { ok: true, db: await dbReachable(), time: new Date().toISOString() });
    return;
  }
  sendJson(res, 404, { error: "not found" });
}

const server = createServer((req, res) => {
  handle(req, res).catch((err: unknown) => {
    console.error(err);
    if (!res.headersSent) res.writeHead(500);
    res.end();
  });
});

server.listen(PORT, HOST, () => {
  console.log(`listening on http://${HOST.includes(":") ? `[${HOST}]` : HOST}:${String(PORT)}`);
});
