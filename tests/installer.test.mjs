import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { assertFreshWorker, deploymentUrl, installationName, privateWranglerConfig } from "../scripts/install-core.mjs";

test("fresh setup fails closed before secrets when a Worker exists or the check is uncertain", () => {
  assert.throws(() => assertFreshWorker({ code: 0, output: "[]" }), /existing Worker/);
  assert.throws(() => assertFreshWorker({ code: 1, output: "network timeout" }), /Could not safely determine/);
  assert.doesNotThrow(() => assertFreshWorker({ code: 1, output: "This Worker does not exist. [code: 10007]" }));
});

test("private config keeps the repository template unchanged and resolves source paths", async () => {
  const source = await readFile(new URL("../wrangler.jsonc", import.meta.url), "utf8");
  const local = JSON.parse(privateWranglerConfig(source, "vaultgram-examplebot-abcdef"));
  assert.equal(local.name, "vaultgram-examplebot-abcdef");
  assert.equal(local.main, "../src/index.ts");
  assert.equal(local.d1_databases[0].database_name, "vaultgram-examplebot-abcdef");
  assert.equal(local.d1_databases[0].migrations_dir, "../migrations");
  assert.equal(local.queues.producers[0].queue, "vaultgram-examplebot-abcdef-delete");
  assert.equal(local.queues.consumers[0].queue, "vaultgram-examplebot-abcdef-delete");
  assert.equal(JSON.parse(source).main, "src/index.ts");
  assert.equal(local.$schema, undefined);
});

test("bot usernames produce separate Cloudflare-safe installation names", () => {
  assert.equal(installationName("My_Bot", "abcdef"), "vaultgram-my-bot-abcdef");
  assert.notEqual(installationName("My_Bot", "abcdef"), installationName("My_Bot", "123456"));
  assert.throws(() => installationName("bot", "bad"));
});

test("installer accepts only an HTTPS deployment target", () => {
  assert.equal(deploymentUrl([
    JSON.stringify({ type: "wrangler-session" }),
    JSON.stringify({ type: "deploy", targets: ["https://vaultgram.example.workers.dev"] }),
  ]), "https://vaultgram.example.workers.dev");
  assert.throws(() => deploymentUrl([JSON.stringify({ type: "deploy", targets: ["http://unsafe.test"] })]), /no HTTPS Worker URL/);
});
