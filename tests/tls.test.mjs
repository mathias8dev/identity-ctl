import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:https";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { command, cleanEnv, runFile, tenantId } from "./cli-helper.mjs";

test("the executable trusts enrolled system CAs and refuses an untrusted certificate", { skip: process.platform !== "linux" }, async t => {
  const directory = await mkdtemp(join(tmpdir(), "identityctl-tls-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const key = join(directory, "server.key"), cert = join(directory, "server.crt");
  const empty = join(directory, "empty");
  await mkdir(empty);
  const emptyBundle = join(empty, "empty.pem");
  await writeFile(emptyBundle, "");
  await runFile("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
    "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=127.0.0.1",
    "-addext", "subjectAltName=IP:127.0.0.1", "-addext", "basicConstraints=critical,CA:TRUE"]);
  let requests = 0;
  const server = createServer({ key: await readFile(key), cert: await readFile(cert) }, (_req, res) => {
    requests++; res.writeHead(200, { "Content-Type": "application/json" }); res.end('{"content":[],"last":true}');
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  t.after(() => { server.closeAllConnections(); return new Promise(resolve => server.close(resolve)); });
  const env = cleanEnv(join(directory, "session.json"), { SSL_CERT_FILE: cert, SSL_CERT_DIR: empty,
    IDENTITY_ADMIN_API_URL: `https://127.0.0.1:${server.address().port}`, IDENTITY_ADMIN_ACCESS_TOKEN: "private-tls-fixture" });
  delete env.NODE_EXTRA_CA_CERTS;
  delete env.NODE_TLS_REJECT_UNAUTHORIZED;
  assert.equal(JSON.parse((await command(["users", "imports", tenantId], env)).stdout).last, true);
  assert.equal(requests, 1);
  await assert.rejects(command(["users", "imports", tenantId], { ...env, SSL_CERT_FILE: emptyBundle }), error => {
    assert.match(error.stderr, /trusted CA/);
    assert.equal(error.stderr.includes("private-tls-fixture"), false);
    return true;
  });
  assert.equal(requests, 1);
});
