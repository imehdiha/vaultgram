import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-plugin";
import { configDefaults, defineConfig } from "vitest/config";
export default defineConfig({
  plugins: [
    cloudflareTest(async () => ({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        compatibilityDate:
          process.env.VAULTGRAM_TEST_COMPAT_DATE ?? "2026-09-27",
        bindings: { TEST_MIGRATIONS: await readD1Migrations("./migrations") },
      },
    })),
  ],
  test: {
    setupFiles: ["./tests/setup.ts"],
    exclude: [...configDefaults.exclude, "tests/installer.test.mjs"],
  },
});
