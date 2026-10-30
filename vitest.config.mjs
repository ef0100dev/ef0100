import { defineConfig } from "vitest/config";

// `pnpm coverage` fails if the files that decide what gets signed lose coverage. The CLI's terminal rendering is
// exercised through the built binary in CI and is left out of the count.
export default defineConfig({
  test: {
    coverage: {
      provider: "v8",
      include: ["src/**"],
      exclude: ["src/cli.ts", "src/cli/**"],
      reporter: ["text-summary", "text"],
      thresholds: {
        "src/guard/policy.ts": { statements: 95, branches: 90, functions: 95, lines: 98 },
        "src/guard/serve.ts": { statements: 90, branches: 80, lines: 95 },
        "src/evm/rlp.ts": { statements: 95, branches: 95, lines: 100 },
        "src/evm/fingerprint.ts": { lines: 100 },
      },
    },
  },
});
