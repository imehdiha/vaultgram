import { applyD1Migrations } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { beforeAll } from "vitest";
beforeAll(async () => {
  const testEnv = env as typeof env & {
    TEST_MIGRATIONS: Parameters<typeof applyD1Migrations>[1];
  };
  await applyD1Migrations(testEnv.VAULTGRAM_DB, testEnv.TEST_MIGRATIONS);
});
