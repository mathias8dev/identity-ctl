import test from "node:test";
import assert from "node:assert/strict";
import { readFile, writeFile, lstat } from "node:fs/promises";
import { join } from "node:path";
import { saveSession } from "../dist/session.js";
import { fixture, command, json, session, tokenResponse, tenantId } from "./cli-helper.mjs";

test("generic API covers arbitrary authorized actions without a client-side permission catalog", async t => {
  const f = await fixture(t, (req, res, body) => {
    assert.equal(req.headers.authorization, "Bearer access.fixture.token");
    assert.equal(req.headers.cookie, undefined);
    if (req.method === "HEAD" || req.method === "DELETE") { res.writeHead(204); res.end(); }
    else json(res, { method: req.method, path: req.url, body: body ? JSON.parse(body) : null });
  });
  await saveSession(session(f.origin), f.path);
  const input = join(f.directory, "client.json");
  await writeFile(input, JSON.stringify({ clientId: "engagectl", applicationType: "NATIVE", tokenEndpointAuthMethod: "NONE" }));
  for (const method of ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]) {
    const path = `/identity/admin/tenants/${tenantId}/clients${method === "GET" ? "?page=0&size=10" : ""}`;
    const result = await command(["api", method, path, ...(["POST", "PUT", "PATCH"].includes(method) ? ["--input", input] : [])], f.env);
    if (result.stdout) {
      const data = JSON.parse(result.stdout);
      assert.equal(data.method, method); assert.equal(data.path, path);
      if (["POST", "PUT", "PATCH"].includes(method)) assert.equal(data.body.clientId, "engagectl");
    }
  }
  assert.equal(f.calls.length, 7);
});

test("expired API access is refreshed and atomically stored before executing a mutation", async t => {
  const f = await fixture(t, async (req, res, body) => {
    if (req.url === "/oauth2/token") {
      assert.equal(new URLSearchParams(body).get("grant_type"), "refresh_token");
      json(res, tokenResponse({ access_token: "access.rotated.token", refresh_token: "rotated-refresh" }));
    } else {
      assert.equal(req.headers.authorization, "Bearer access.rotated.token");
      assert.equal(JSON.parse(await readFile(f.path, "utf8")).refreshToken, "rotated-refresh");
      res.writeHead(204); res.end();
    }
  });
  await saveSession(session(f.origin, { accessTokenExpiresAt: 1 }), f.path);
  await command(["api", "DELETE", "/identity/admin/tenants/fixture"], f.env);
  assert.equal(f.calls.length, 2);
});

test("IdP permission denials remain authoritative, are not retried and never echo arbitrary response data", async t => {
  const f = await fixture(t, (_req, res) => json(res, { content: { errorCode: "IDENTITY_ADMINISTRATION_ACCESS_DENIED" }, message: "access.fixture.token must never be logged" }, 403));
  await saveSession(session(f.origin), f.path);
  await assert.rejects(command(["api", "POST", "/identity/admin/tenants"], f.env), error => {
    assert.match(error.stderr, /HTTP 403.*IDENTITY_ADMINISTRATION_ACCESS_DENIED/);
    assert.equal(error.stderr.includes("access.fixture.token"), false); return true;
  });
  assert.equal(f.calls.length, 1);
});

test("one-time secret and binary responses can be streamed to a new private file without overwrite", async t => {
  const bytes = Buffer.from([0, 255, 2, 10, 20]);
  const f = await fixture(t, (_req, res) => { res.writeHead(200, { "Content-Type": "application/octet-stream" }); res.end(bytes); });
  await saveSession(session(f.origin), f.path);
  const output = join(f.directory, "result.bin");
  const result = await command(["api", "GET", "/identity/admin/resource", "--output", output], f.env);
  assert.equal(result.stdout, ""); assert.deepEqual(await readFile(output), bytes);
  if (process.platform !== "win32") assert.equal((await lstat(output)).mode & 0o777, 0o600);
  await assert.rejects(command(["api", "POST", "/identity/admin/credentials", "--output", output], f.env));
  assert.equal(f.calls.length, 1, "Existing output must reject before issuing a secret or mutating the API");
});

test("custom headers and raw uploads work while credential, routing and cross-origin overrides fail before HTTP", async t => {
  const f = await fixture(t, (req, res, body) => { assert.equal(req.headers["x-custom"], "operator"); assert.equal(req.headers["content-type"], "image/svg+xml"); json(res, { body }); });
  await saveSession(session(f.origin), f.path);
  const input = join(f.directory, "image.svg"); await writeFile(input, "<svg/>");
  const headers = join(f.directory, "headers.json"); await writeFile(headers, '{"X-Custom":"operator"}');
  assert.equal(JSON.parse((await command(["api", "POST", "/identity/admin/branding/assets", "--input", input, "--headers", headers, "--content-type", "image/svg+xml"], f.env)).stdout).body, "<svg/>");
  for (const name of ["Authorization", "Cookie", "Host", "Forwarded", "X-Forwarded-Host"]) {
    await writeFile(headers, JSON.stringify({ [name]: "forbidden" }));
    await assert.rejects(command(["api", "GET", "/identity/admin/tenants", "--headers", headers], f.env));
  }
  for (const path of ["https://foreign.example/api", "//foreign.example/api", "/\\foreign.example/api", "/identity/admin#fragment"]) {
    await assert.rejects(command(["api", "GET", path], f.env));
  }
  assert.equal(f.calls.length, 1);
});

test("an explicitly supplied bearer uses the same transport without needing a stored session", async t => {
  const f = await fixture(t, (req, res) => { assert.equal(req.headers.authorization, "Bearer external.fixture.token"); json(res, { ok: true }); });
  const result = await command(["api", "GET", "/identity/admin/tenants"], { ...f.env, IDENTITY_ADMIN_API_URL: f.origin, IDENTITY_ADMIN_ACCESS_TOKEN: "external.fixture.token" });
  assert.equal(JSON.parse(result.stdout).ok, true);
});
