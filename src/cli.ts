#!/usr/bin/env node
import { VERSION } from "./version.js";
import { login, type LoginOptions } from "./login.js";
import { currentSession, logout } from "./session.js";
import { users } from "./users.js";

const HELP = `Identity CLI ${VERSION}

identityctl login [--issuer HTTPS_ORIGIN] [--api-url HTTPS_ORIGIN] [--client-id ID]
                  [--no-browser] [--callback-port PORT] [--timeout SECONDS]
identityctl status | token | logout
identityctl users import TENANT_ID CANONICAL_JSON_FILE
identityctl users imports TENANT_ID [PAGE]
identityctl users import-results TENANT_ID JOB_ID [PAGE]
identityctl users cancel-import TENANT_ID JOB_ID
identityctl users export TENANT_ID IDEMPOTENCY_KEY
identityctl users exports TENANT_ID [PAGE]
identityctl users export-records TENANT_ID JOB_ID [PAGE]
identityctl users export-download TENANT_ID JOB_ID
identityctl users cancel-export TENANT_ID JOB_ID

Configure IDENTITYCTL_ISSUER, IDENTITYCTL_API_URL, IDENTITYCTL_CLIENT_ID,
IDENTITYCTL_SESSION_FILE, IDENTITYCTL_CALLBACK_PORT, IDENTITYCTL_LOGIN_TIMEOUT
and IDENTITYCTL_NO_BROWSER. Login uses the control tenant's public native client.
IDENTITY_ADMIN_ACCESS_TOKEN and IDENTITY_ADMIN_API_URL override login for users
commands. Credentials are never included in process arguments by this client.
`;

function loginOptions(args: string[]): LoginOptions {
  const values = new Map<string, string>();
  let noBrowser = process.env.IDENTITYCTL_NO_BROWSER === "true";
  const known = new Set(["--issuer", "--api-url", "--client-id", "--callback-port", "--timeout"]);
  for (let index = 0; index < args.length; index++) {
    const key = args[index]!;
    if (key === "--no-browser") { if (values.has(key)) throw new Error("Duplicate --no-browser option"); values.set(key, "true"); noBrowser = true; continue; }
    const value = args[++index];
    if (!known.has(key) || values.has(key) || !value || value.startsWith("--")) throw new Error("Invalid or duplicate login option; run identityctl --help");
    values.set(key, value);
  }
  const issuer = values.get("--issuer") ?? process.env.IDENTITYCTL_ISSUER;
  if (!issuer) throw new Error("Set IDENTITYCTL_ISSUER or provide login --issuer with the control tenant's origin");
  const apiUrl = values.get("--api-url") ?? process.env.IDENTITYCTL_API_URL;
  const clientId = values.get("--client-id") ?? process.env.IDENTITYCTL_CLIENT_ID;
  const callbackPort = values.get("--callback-port") ?? process.env.IDENTITYCTL_CALLBACK_PORT;
  const timeout = values.get("--timeout") ?? process.env.IDENTITYCTL_LOGIN_TIMEOUT;
  return { issuer, noBrowser, ...(apiUrl ? { apiUrl } : {}), ...(clientId ? { clientId } : {}),
    ...(callbackPort ? { callbackPort } : {}), ...(timeout ? { timeout } : {}) };
}

async function main(): Promise<void> {
  const [command, ...args] = process.argv.slice(2);
  if (["--version", "version"].includes(command ?? "") && !args.length) { console.log(VERSION); return; }
  if (["help", "--help", "-h"].includes(command ?? "") && !args.length) { process.stdout.write(HELP); return; }
  if (command === "login") { await login(loginOptions(args)); console.log("Identity CLI authenticated."); return; }
  if (command === "users") { await users(args); return; }
  if (["status", "token", "logout"].includes(command ?? "") && !args.length) {
    if (command === "logout") { await logout(); console.log("Identity CLI session revoked and removed."); return; }
    const session = await currentSession();
    if (command === "token") { console.log(session.accessToken); return; }
    console.log(JSON.stringify({ authenticated: true, issuer: session.issuer, apiUrl: session.apiUrl, clientId: session.clientId,
      accessTokenExpiresAt: session.accessTokenExpiresAt, scopes: session.scopes.split(" ").filter(Boolean) }));
    return;
  }
  throw new Error("Unknown command or arguments; run identityctl --help");
}

process.stdout.on("error", (error: NodeJS.ErrnoException) => { if (error.code === "EPIPE") process.exit(0); throw error; });
main().catch((error: unknown) => {
  const code = (error as NodeJS.ErrnoException)?.code;
  const message = code === "ENOENT" ? "Identity session or input file is missing; check the path or run identityctl login" :
    error instanceof Error ? error.message : "Identity command failed";
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});
