import { defineConfig } from "vitest/config";
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.toml" },
      miniflare: {
        compatibilityDate: "2025-05-31",
        bindings: {
          ADMIN_PASSWORD: "test-admin-password-123",
        },
      },
    }),
  ],
  test: {
    testTimeout: 30_000,
  },
});
