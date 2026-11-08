import test from "node:test";
import metadata from "../package.json" with { type: "json" };
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { request as httpRequest } from "node:http";
import { chmod, lstat, readFile, writeFile, symlink } from "node:fs/promises";
import { join } from "node:path";
import { saveSession } from "../dist/session.js";
import { fixture, command, beginLogin, callbackUrl, json, tokenResponse, session, tenantId, jobId } from "./cli-helper.mjs";

test("version/help work without a session or runtime checkout", async t => {
  const f = await fixture(t, (_req, res) => json(res, {}));
  assert.equal((await command(["--version"], f.env)).stdout.trim(), metadata.version);
  assert.match((await command(["--help"], f.env)).stdout, /users export-download/);
  assert.equal(f.calls.length, 0);
});

test("PKCE login rejects wrong state, issuer, duplicate parameters and host before persisting a private session", async t => {
  let authorization;
  const f = await fixture(t, (req, res, body) => {
    assert.equal(req.url, "/oauth2/token");
    const form = new URLSearchParams(body);
    assert.equal(form.get("grant_type"), "authorization_code");
    assert.equal(form.get("client_id"), "identityctl");
    assert.equal(form.get("code"), "one-use-authorization-code");
    assert.equal(form.get("redirect_uri"), authorization.searchParams.get("redirect_uri"));
    assert.equal(createHash("sha256").update(form.get("code_verifier")).digest("base64url"), authorization.searchParams.get("code_challenge"));
    json(res, tokenResponse());
  });
  const login = await beginLogin(t, { ...f.env, IDENTITYCTL_ISSUER: f.origin });
  authorization = login.authorization;
  assert.equal(authorization.searchParams.get("resource"), f.origin + "/identity/admin");
  assert.equal(authorization.searchParams.get("code_challenge_method"), "S256");
  for (const overrides of [{ state: "wrong" }, { iss: "https://different.example" }]) {
    assert.equal((await fetch(callbackUrl(authorization, overrides))).status, 400);
  }
  const duplicate = callbackUrl(authorization);
  duplicate.searchParams.append("code", "duplicate");
  assert.equal((await fetch(duplicate)).status, 400);
  const wrongHost = await new Promise((resolve, reject) => {
    const req = httpRequest(callbackUrl(authorization), { headers: { Host: "other.example" } }, res => { res.resume(); resolve(res.statusCode); });
    req.on("error", reject); req.end();
  });
  assert.equal(wrongHost, 400);
  assert.equal(f.calls.length, 0);
  assert.equal((await fetch(callbackUrl(authorization))).status, 200);
  const result = await login.result;
  assert.equal(result.code, 0);
  assert.equal(f.calls.length, 1);
  const stored = JSON.parse(await readFile(f.path, "utf8"));
  assert.equal(stored.schemaVersion, 1);
  assert.equal(stored.issuer, f.origin);
  assert.equal(stored.clientId, "identityctl");
  assert.equal(stored.refreshToken, "refresh-fixture-token");
  if (process.platform !== "win32") assert.equal((await lstat(f.path)).mode & 0o777, 0o600);
  assert.equal(result.stdout.includes(stored.accessToken), false);
  assert.equal(result.stderr.includes(stored.refreshToken), false);
  const status = JSON.parse((await command(["status"], f.env)).stdout);
  assert.equal(status.authenticated, true);
  assert.equal("accessToken" in status, false);
  assert.equal("refreshToken" in status, false);
});

test("authorization refusal and timeout do not exchange codes or retain locks", async t => {
  const f = await fixture(t, (_req, res) => json(res, tokenResponse()));
  const login = await beginLogin(t, { ...f.env, IDENTITYCTL_ISSUER: f.origin });
  const rejected = callbackUrl(login.authorization, { error: "access_denied" });
  rejected.searchParams.delete("code");
  assert.equal((await fetch(rejected)).status, 400);
  const result = await login.result;
  assert.equal(result.code, 1);
  assert.match(result.stderr, /access_denied/);
  assert.equal(f.calls.length, 0);
  await assert.rejects(lstat(f.path), { code: "ENOENT" });
  await assert.rejects(lstat(f.path + ".lock"), { code: "ENOENT" });
  await assert.rejects(command(["login", "--issuer", f.origin, "--timeout", "1", "--no-browser"], f.env), error => /timed out/.test(error.stderr));
  await assert.rejects(lstat(f.path + ".lock"), { code: "ENOENT" });
});

test("refresh rotates atomically before the management request and token prints only the selected token", async t => {
  const f = await fixture(t, async (req, res, body) => {
    if (req.url === "/oauth2/token") {
      const form = new URLSearchParams(body);
      assert.equal(form.get("grant_type"), "refresh_token");
      assert.equal(form.get("refresh_token"), "refresh-fixture-token");
      json(res, tokenResponse({ access_token: "access.rotated.token", refresh_token: "rotated-refresh" }));
    } else {
      assert.equal(JSON.parse(await readFile(f.path, "utf8")).refreshToken, "rotated-refresh");
      assert.equal(req.headers.authorization, "Bearer access.rotated.token");
      json(res, { content: [], last: true });
    }
  });
  await saveSession(session(f.origin, { accessTokenExpiresAt: 1 }), f.path);
  const reply = await command(["users", "imports", tenantId], f.env);
  assert.equal(JSON.parse(reply.stdout).last, true);
  assert.equal(f.calls[1].url, `/identity/admin/tenants/${tenantId}/user-imports?page=0&size=100`);
  assert.equal((await command(["token"], f.env)).stdout, "access.rotated.token\n");
  assert.equal(f.calls.filter(call => call.url === "/oauth2/token").length, 1);
});

test("a session lock prevents concurrent rotating refresh use without contacting the server", async t => {
  const f = await fixture(t, (_req, res) => json(res, {}));
  await saveSession(session(f.origin, { accessTokenExpiresAt: 1 }), f.path);
  await writeFile(f.path + ".lock", '{"pid":1}', { mode: 0o600 });
  await assert.rejects(command(["token"], f.env), error => /Session is in use/.test(error.stderr));
  assert.equal(f.calls.length, 0);
  assert.equal(JSON.parse(await readFile(f.path, "utf8")).refreshToken, "refresh-fixture-token");
});

test("failed refresh is not retried and cannot call the management API", async t => {
  const f = await fixture(t, (_req, res) => json(res, { error: "invalid_grant", error_description: "refresh-fixture-token" }, 400));
  await saveSession(session(f.origin, { accessTokenExpiresAt: 1 }), f.path);
  await assert.rejects(command(["users", "imports", tenantId], f.env), error => {
    assert.match(error.stderr, /invalid_grant/);
    assert.equal(error.stderr.includes("refresh-fixture-token"), false);
    return true;
  });
  assert.equal(f.calls.length, 1);
  assert.equal(JSON.parse(await readFile(f.path, "utf8")).refreshToken, "refresh-fixture-token");
});

test("logout retains the session on revocation failure and removes it only after success", async t => {
  let fail = true;
  const f = await fixture(t, (req, res, body) => {
    assert.equal(req.url, "/oauth2/revoke");
    assert.equal(new URLSearchParams(body).get("token"), "refresh-fixture-token");
    if (fail) json(res, {}, 503); else { res.writeHead(200); res.end(); }
  });
  await saveSession(session(f.origin), f.path);
  await assert.rejects(command(["logout"], f.env));
  assert.equal(JSON.parse(await readFile(f.path, "utf8")).refreshToken, "refresh-fixture-token");
  fail = false;
  await command(["logout"], f.env);
  await assert.rejects(lstat(f.path), { code: "ENOENT" });
  assert.equal(f.calls.length, 2);
});

test("session origin/client drift and permissive POSIX permissions are rejected before requests", async t => {
  const f = await fixture(t, (_req, res) => json(res, {}));
  await saveSession(session(f.origin), f.path);
  for (const extra of [{ IDENTITYCTL_ISSUER: "https://other.example" }, { IDENTITYCTL_API_URL: "https://other.example" }, { IDENTITYCTL_CLIENT_ID: "other-client" }]) {
    await assert.rejects(command(["status"], { ...f.env, ...extra }), error => /does not match/.test(error.stderr));
  }
  if (process.platform !== "win32") {
    await chmod(f.path, 0o644);
    await assert.rejects(command(["status"], f.env), error => /private/.test(error.stderr));
  }
  assert.equal(f.calls.length, 0);
});

test("canonical imports and every job route retain bounded pagination and server contracts", async t => {
  const f = await fixture(t, (_req, res) => json(res, { content: [], last: true }));
  const env = { ...f.env, IDENTITY_ADMIN_API_URL: f.origin, IDENTITY_ADMIN_ACCESS_TOKEN: "automation-token" };
  const document = join(f.directory, "canonical.json");
  const data = { schemaVersion: 1, source: "customer", mode: "VALIDATE_ONLY", idempotencyKey: "validate-20261108", records: [{ externalId: "one" }] };
  await writeFile(document, JSON.stringify(data));
  const cases = [
    [["import", tenantId, document], "POST", "user-imports"],
    [["imports", tenantId, "2"], "GET", "user-imports?page=2&size=100"],
    [["import-results", tenantId, jobId, "3"], "GET", `user-imports/${jobId}/results?page=3&size=100`],
    [["cancel-import", tenantId, jobId], "DELETE", `user-imports/${jobId}`],
    [["export", tenantId, "export-key-20261108"], "POST", "user-exports"],
    [["exports", tenantId], "GET", "user-exports?page=0&size=100"],
    [["export-records", tenantId, jobId], "GET", `user-exports/${jobId}/records?page=0&size=100`],
    [["cancel-export", tenantId, jobId], "DELETE", `user-exports/${jobId}`],
  ];
  for (const [args, method, path] of cases) {
    await command(["users", ...args], env);
    const call = f.calls.at(-1);
    assert.equal(call.method, method);
    assert.equal(call.url, `/identity/admin/tenants/${tenantId}/${path}`);
    assert.equal(call.headers.authorization, "Bearer automation-token");
  }
  assert.deepEqual(JSON.parse(f.calls[0].body), data);
  assert.deepEqual(JSON.parse(f.calls[4].body), { schemaVersion: 1, idempotencyKey: "export-key-20261108" });
});

test("legacy arrays, malformed imports, overflow pages and unsafe file types never reach the API", async t => {
  const f = await fixture(t, (_req, res) => json(res, {}));
  const env = { ...f.env, IDENTITY_ADMIN_API_URL: f.origin, IDENTITY_ADMIN_ACCESS_TOKEN: "automation-token" };
  const path = join(f.directory, "source.json");
  for (const value of ["[]", "invalid-private-proof", "{}", " ".repeat(524289)]) {
    await writeFile(path, value);
    await assert.rejects(command(["users", "import", tenantId, path], env), error => !error.stderr.includes("invalid-private-proof"));
  }
  for (const args of [["imports", tenantId, "-1"], ["imports", tenantId, "2147483648"], ["export-records", tenantId, "bad-job"], ["imports", "bad-tenant"]]) {
    await assert.rejects(command(["users", ...args], env));
  }
  await assert.rejects(command(["users", "import", tenantId, f.directory], env));
  if (process.platform !== "win32") {
    const linked = join(f.directory, "linked.json");
    await symlink(path, linked);
    await assert.rejects(command(["users", "import", tenantId, linked], env));
  }
  assert.equal(f.calls.length, 0);
});

test("NDJSON downloads stream exactly and credentials never follow redirects", async t => {
  let redirect = false;
  let sinkRequests = 0;
  const sink = await fixture(t, (_req, res) => { sinkRequests++; json(res, {}); });
  const f = await fixture(t, (req, res) => {
    if (redirect) { res.writeHead(307, { Location: sink.origin + "/leak" }); res.end(); }
    else { assert.equal(req.headers.accept, "application/x-ndjson"); res.writeHead(200, { "Content-Type": "application/x-ndjson" }); res.write('{"externalId":"one"}\n'); res.end('{"externalId":"two"}\n'); }
  });
  await saveSession(session(f.origin), f.path);
  const result = await command(["users", "export-download", tenantId, jobId], f.env);
  assert.equal(result.stdout, '{"externalId":"one"}\n{"externalId":"two"}\n');
  redirect = true;
  await assert.rejects(command(["users", "imports", tenantId], f.env), error => !error.stderr.includes("access.fixture.token"));
  assert.equal(sinkRequests, 0);
});

test("invalid command options and origins fail without beginning authentication", async t => {
  const f = await fixture(t, (_req, res) => json(res, {}));
  for (const args of [["login", "--issuer", "http://remote.example", "--no-browser"], ["login", "--issuer", "https://user:secret@issuer.example"],
    ["login", "--issuer", f.origin, "--issuer", f.origin], ["login", "--issuer", f.origin, "--callback-port", "0"], ["status", "unexpected"]]) {
    await assert.rejects(command(args, f.env), error => !error.stderr.includes("user:secret"));
  }
  assert.equal(f.calls.length, 0);
});
