import test from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { symlink, readFile, lstat } from "node:fs/promises";
import { boundedBody } from "../dist/http.js";
import { saveSession } from "../dist/session.js";
import { fixture, command, beginLogin, callbackUrl, json, tokenResponse, session, tenantId } from "./cli-helper.mjs";

test("ordinary responses remain bounded without echoing their payload", async () => {
  await assert.rejects(boundedBody(new Response("sensitive-body"), 3), error => {
    assert.match(error.message, /exceeds/);
    assert.equal(error.message.includes("sensitive-body"), false);
    return true;
  });
});

test("login never overwrites an existing identity session", async t => {
  const f = await fixture(t, (_req, res) => json(res, {}));
  await saveSession(session(f.origin), f.path);
  const original = await readFile(f.path);
  await assert.rejects(command(["login", "--issuer", f.origin, "--no-browser"], f.env), error => /already exists/.test(error.stderr));
  assert.deepEqual(await readFile(f.path), original);
  assert.equal(f.calls.length, 0);
});

test("malformed token responses do not persist credentials or echo them", async t => {
  const f = await fixture(t, (_req, res) => json(res, tokenResponse({ token_type: "wrong-private-token-type" })));
  const login = await beginLogin(t, { ...f.env, IDENTITYCTL_ISSUER: f.origin });
  await fetch(callbackUrl(login.authorization));
  const result = await login.result;
  assert.equal(result.code, 1);
  assert.match(result.stderr, /invalid.*token response/);
  for (const secret of ["wrong-private-token-type", "access.fixture.token", "refresh-fixture-token"]) assert.equal(result.stderr.includes(secret), false);
  await assert.rejects(lstat(f.path), { code: "ENOENT" });
});

test("session symlinks cannot disclose or replace another file", { skip: process.platform === "win32" }, async t => {
  const f = await fixture(t, (_req, res) => json(res, {}));
  const real = join(f.directory, "real-session.json");
  await saveSession(session(f.origin), real);
  await symlink(real, f.path);
  await assert.rejects(command(["status"], f.env), error => /symlink/.test(error.stderr));
  assert.equal(JSON.parse(await readFile(real, "utf8")).accessToken, "access.fixture.token");
  assert.equal(f.calls.length, 0);
});

test("failed commands never echo raw remote response bodies", async t => {
  const f = await fixture(t, (_req, res) => json(res, { content: { message: "private-remote-proof" } }, 403));
  await assert.rejects(command(["users", "imports", tenantId], { ...f.env,
    IDENTITY_ADMIN_API_URL: f.origin, IDENTITY_ADMIN_ACCESS_TOKEN: "private-header-proof" }), error => {
    assert.match(error.stderr, /HTTP 403/);
    assert.equal(error.stderr.includes("private-remote-proof"), false);
    assert.equal(error.stderr.includes("private-header-proof"), false);
    return true;
  });
});
