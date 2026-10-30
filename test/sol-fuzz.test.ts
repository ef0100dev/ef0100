import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { classifySigningInput } from "../src/guard/classify.ts";
import { checkSolanaTransaction } from "../src/sol/check.ts";
import { decodeSolanaTransaction } from "../src/sol/message.ts";

// The Solana side of fuzz.test.ts: damaged copies of the bundled mainnet transactions, seeded so a failure names its
// input. EF0100_FUZZ_RUNS raises the count.
const RUNS = Number(process.env.EF0100_FUZZ_RUNS ?? 2000);
const SEED = Number(process.env.EF0100_FUZZ_SEED ?? 0x7702);
const LIMIT = Math.max(10_000, RUNS * 4);

const cases = (
  JSON.parse(readFileSync(new URL("../fixtures/solana/cases.json", import.meta.url), "utf8")) as {
    cases: { base64: string }[];
  }
).cases.map((c) => Uint8Array.from(Buffer.from(c.base64, "base64")));

function rng(seed: number) {
  let x = seed >>> 0 || 1;
  return () => {
    x ^= x << 13;
    x >>>= 0;
    x ^= x >>> 17;
    x ^= x << 5;
    x >>>= 0;
    return x / 2 ** 32;
  };
}
const int = (r: () => number, n: number) => Math.floor(r() * n);
const bytes = (r: () => number, n: number) => Uint8Array.from({ length: n }, () => int(r, 256));

function mutate(r: () => number, src: Uint8Array): Uint8Array {
  const b = Uint8Array.from(src);
  const at = int(r, b.length);
  switch (int(r, 4)) {
    case 0:
      for (let i = 1 + int(r, 8); i > 0; i--) b[int(r, b.length)] ^= 1 << int(r, 8);
      return b;
    case 1:
      return b.slice(0, at);
    case 2:
      return Uint8Array.from([...b.slice(0, at), ...bytes(r, 1 + int(r, 16)), ...b.slice(at)]);
    default:
      b.set(bytes(r, Math.min(1 + int(r, 32), b.length - at)), at);
      return b;
  }
}

function isRefusal(e: unknown): boolean {
  return (
    (e instanceof RangeError || e instanceof TypeError) &&
    !/cannot read|is not a function|is not iterable|undefined|null|maximum call stack/i.test(e.message)
  );
}

describe(`Solana fuzz (seed ${SEED}, ${RUNS} runs)`, () => {
  it(
    "the transaction decoder returns or refuses on any damaged copy of a bundled transaction",
    () => {
      const r = rng(SEED + 10);
      for (let i = 0; i < RUNS; i++) {
        const input = mutate(r, cases[i % cases.length]!);
        try {
          decodeSolanaTransaction(input);
        } catch (e) {
          if (!isRefusal(e))
            throw new Error(`run ${i}: ${Buffer.from(input).toString("base64").slice(0, 60)}…: ${(e as Error).stack}`);
        }
      }
    },
    LIMIT,
  );

  it(
    "the pre-signing check returns a report or refuses, and never fails in its own code",
    () => {
      const r = rng(SEED + 11);
      let reports = 0;
      for (let i = 0; i < RUNS; i++) {
        const input = mutate(r, cases[i % cases.length]!);
        try {
          const rep = checkSolanaTransaction(input);
          expect(Array.isArray(rep.findings)).toBe(true);
          reports++;
        } catch (e) {
          if (!isRefusal(e))
            throw new Error(`run ${i}: ${Buffer.from(input).toString("base64").slice(0, 60)}…: ${(e as Error).stack}`);
        }
      }
      expect(reports).toBeGreaterThan(0);
    },
    LIMIT,
  );

  it(
    "classifying damaged message bytes for an ed25519 key never throws and never yields an EVM kind",
    () => {
      const r = rng(SEED + 12);
      for (let i = 0; i < RUNS; i++) {
        const input = mutate(r, cases[i % cases.length]!.slice(65));
        const k = classifySigningInput(input, { as: "preimage", curve: "ed25519" }).kind;
        expect(["solana-message", "solana-offchain-message", "unknown"]).toContain(k);
      }
    },
    LIMIT,
  );
});
