import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const cli = new URL("../dist/cli.js", import.meta.url).pathname;

// The README shows the replay frame verbatim; it must never drift from what the CLI prints.
describe.skipIf(!existsSync(cli))("README", () => {
  it("shows exactly what `npx ef0100 replay` prints", () => {
    const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8");
    const block = readme.split("```\n$ npx ef0100 replay\n")[1]!.split("```")[0]!;
    const frame = execFileSync("node", [cli, "replay", "--speed", "0"], {
      encoding: "utf8",
      env: { ...process.env, NO_COLOR: "1" },
    });
    expect(block.trimEnd()).toBe(frame.trimEnd());
  });
});

describe.skipIf(!existsSync(cli))("guard test", () => {
  it("states the reasons the guard actually gave", () => {
    const out = JSON.parse(execFileSync("node", [cli, "guard", "test", "--json"], { encoding: "utf8" }));
    expect(out.rows.map((r: { reasons: Record<string, number> }) => r.reasons)).toEqual([
      { DELEGATE_NOT_ALLOWED: 50, NONCE_NOT_LIVE: 49 },
      { NO_PREIMAGE: 50 },
      { DELEGATE_NOT_ALLOWED: 9 },
      { ALLOWED: 1 },
    ]);
    expect(out.rows[0].why).toBe("delegate not allowed; 49 also off the live nonce");
  });
});

describe.skipIf(!existsSync(cli))("replay --flows", () => {
  it("prints the first hop with the decoded transfers and the blacklist times", () => {
    const out = execFileSync("node", [cli, "replay", "--flows"], {
      encoding: "utf8",
      env: { ...process.env, NO_COLOR: "1" },
    });
    expect(out).toContain("195,460 ETH → 0x8532…43D4");
    expect(out).toContain("120 B decoded");
    expect(out).toContain("blacklisted by Tether 21:01:35, Circle 21:04:59 UTC");
  });
});

describe.skipIf(!existsSync(cli))("README flows", () => {
  it("shows exactly what `npx ef0100 replay --flows` prints", () => {
    const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8");
    const block = readme.split("```\n$ npx ef0100 replay --flows\n")[1]!.split("```")[0]!;
    const out = execFileSync("node", [cli, "replay", "--flows"], {
      encoding: "utf8",
      env: { ...process.env, NO_COLOR: "1" },
    });
    expect(block.trim()).toBe(out.trim());
  });
});
