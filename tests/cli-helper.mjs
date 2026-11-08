import { spawn, execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { createServer } from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

export const cliCommand = process.env.IDENTITYCTL_TEST_EXECUTABLE ?? process.execPath;
export const cliPrefix = process.env.IDENTITYCTL_TEST_EXECUTABLE ? [] : [fileURLToPath(new URL("../dist/cli.js", import.meta.url))];
export const runFile = promisify(execFile);
export const tenantId = "11111111-1111-4111-8111-111111111111";
export const jobId = "22222222-2222-4222-8222-222222222222";
export function cleanEnv(path, extra = {}) {
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("IDENTITY")));
  return { ...env, IDENTITYCTL_SESSION_FILE: path, IDENTITYCTL_NO_BROWSER: "true", ...extra };
}
export async function fixture(t, handler) {
  const directory = await mkdtemp(join(tmpdir(), "identityctl-test-"));
  const path = join(directory, "session.json");
  const calls = [];
  const server = createServer(async (request, response) => {
    try {
      const chunks = [];
      for await (const bytes of request) chunks.push(bytes);
      const body = Buffer.concat(chunks).toString();
      calls.push({ method: request.method, url: request.url, headers: request.headers, body });
      await handler(request, response, body);
    } catch (error) { response.writeHead(500); response.end(); t.diagnostic(error); }
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); await rm(directory, { recursive: true, force: true }); });
  return { directory, path, origin, calls, env: cleanEnv(path) };
}
export function command(args, env) {
  return runFile(cliCommand, [...cliPrefix, ...args], { env, maxBuffer: 4 * 1024 * 1024 });
}
export async function beginLogin(t, env, extra = []) {
  const child = spawn(cliCommand, [...cliPrefix, "login", "--no-browser", ...extra], { env, stdio: ["ignore", "pipe", "pipe"] });
  let stdout = "", stderr = "";
  child.stdout.on("data", chunk => { stdout += chunk; });
  const result = new Promise((resolve, reject) => {
    child.on("error", reject);
    child.on("close", code => resolve({ code, stdout, stderr }));
  });
  const authorization = await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error("CLI did not announce authorization")), 10_000);
    child.stderr.on("data", chunk => {
      stderr += chunk;
      const value = /https?:\/\/[^\s]+\/oauth2\/authorize\?[^\s]+/.exec(stderr)?.[0];
      if (value) { clearTimeout(timeout); resolve(new URL(value)); }
    });
    child.once("close", () => { clearTimeout(timeout); reject(new Error("CLI ended before authorization")); });
  });
  t.after(() => { if (child.exitCode === null) child.kill(); });
  return { child, authorization, result };
}
export function callbackUrl(authorization, overrides = {}) {
  const callback = new URL(authorization.searchParams.get("redirect_uri"));
  callback.search = new URLSearchParams({ state: authorization.searchParams.get("state"), iss: authorization.origin,
    code: "one-use-authorization-code", ...overrides }).toString();
  return callback;
}
export function json(response, data, status = 200) {
  response.writeHead(status, { "Content-Type": "application/json" });
  response.end(JSON.stringify(data));
}
export function tokenResponse(overrides = {}) {
  return { access_token: "access.fixture.token", refresh_token: "refresh-fixture-token", token_type: "Bearer",
    expires_in: 3600, scope: "offline_access identity.admin.read identity.admin.users.import", ...overrides };
}
export function session(origin, overrides = {}) {
  return { schemaVersion: 1, issuer: origin, apiUrl: origin, clientId: "identityctl", accessToken: "access.fixture.token",
    refreshToken: "refresh-fixture-token", accessTokenExpiresAt: Math.floor(Date.now() / 1000) + 3600,
    scopes: "identity.admin.read identity.admin.users.import", ...overrides };
}
