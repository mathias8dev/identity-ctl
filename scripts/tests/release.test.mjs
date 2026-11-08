import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { collectArtifacts, sha256, requirePublicationContext } from "../release.mjs";
import { TARGETS } from "../targets.mjs";
test("release requires all six exact-revision artifacts and rejects drift before publication", async t => {
  const directory = await mkdtemp(join(tmpdir(), "identityctl-manifest-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const revision = "a".repeat(40);
  const manifests = [];
  for (const { target } of TARGETS) {
    const file = `identityctl-0.1.0-${target}.${target.startsWith("windows-") ? "zip" : "tar.gz"}`;
    await writeFile(join(directory, file), `fixture:${target}`);
    const manifest = { version: "0.1.0", revision, target, file, nodeVersion: "24.16.0", sha256: await sha256(join(directory, file)) };
    manifests.push(manifest);
    await writeFile(join(directory, `manifest-${target}.json`), JSON.stringify(manifest));
  }
  assert.equal((await collectArtifacts(directory, "0.1.0", revision)).length, 6);
  await assert.rejects(collectArtifacts(directory, "0.1.0", "b".repeat(40)), /provenance/);
  await assert.rejects(collectArtifacts(directory, "../bad", revision), /SemVer/);
  await writeFile(join(directory, manifests[0].file), "tampered");
  await assert.rejects(collectArtifacts(directory, "0.1.0", revision), /checksum/);
  await writeFile(join(directory, manifests[0].file), `fixture:${manifests[0].target}`);
  await rm(join(directory, "manifest-linux-arm64.json"));
  await assert.rejects(collectArtifacts(directory, "0.1.0", revision), /ENOENT/);
});
test("publication requires an explicit dispatch from this repository's main", () => {
  const valid = { GITHUB_EVENT_NAME: "workflow_dispatch", GITHUB_REF: "refs/heads/main", GITHUB_REPOSITORY: "mathias8dev/identity-ctl" };
  for (const invalid of [{}, { ...valid, GITHUB_EVENT_NAME: "push" }, { ...valid, GITHUB_REF: "refs/heads/topic" },
    { ...valid, GITHUB_REPOSITORY: "other/identity-ctl" }]) {
    assert.throws(() => requirePublicationContext(invalid), /explicit workflow dispatch/);
  }
  assert.doesNotThrow(() => requirePublicationContext(valid));
});
