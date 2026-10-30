import { readFileSync } from "node:fs";
import { ed25519 } from "@noble/curves/ed25519.js";
import { base58 } from "@scure/base";
import { describe, expect, it } from "vitest";
import { checkSolanaTransaction } from "../src/sol/check.ts";
import { decodeSolanaTransaction } from "../src/sol/message.ts";
import { classifySigningInput } from "../src/guard/classify.ts";

interface Case {
  label: string;
  base64: string;
  preBalances: number[] | null;
}
const cases = (
  JSON.parse(readFileSync(new URL("../fixtures/solana/cases.json", import.meta.url), "utf8")) as { cases: Case[] }
).cases;
const raw = (prefix: string) => Buffer.from(cases.find((c) => c.label.startsWith(prefix))!.base64, "base64");
const pre = (prefix: string) => BigInt(cases.find((c) => c.label.startsWith(prefix))!.preBalances![0]!);
const HOT = "5tzFkiKscXHK5ZXCGbXZxdw7gTjjD1mBwuoFbhUvuAi9";
const exchange = { template: { nonceAuthority: HOT }, routineTransfers: true };
const codes = (r: { findings: { code: string }[] }) => r.findings.map((f) => f.code);

describe("Solana messages", () => {
  it("decodes every bundled transaction strictly, signatures and all", () => {
    for (const c of cases) {
      const tx = decodeSolanaTransaction(Buffer.from(c.base64, "base64"));
      expect(tx.signatures.length).toBe(tx.message.header.numRequiredSignatures);
      expect(classifySigningInput(tx.message.bytes, { as: "preimage", curve: "ed25519" }).kind).toBe("solana-message");
    }
  });
});

describe("the 2026-10-29 Solana leg, under the hot wallet's own template", () => {
  it("BLOCKs the theft transfer: no durable nonce from its pool, and 90.4% of the balance", () => {
    const r = checkSolanaTransaction(raw("Binance 2026-10-29 20:10:18Z"), {
      ...exchange,
      balance: { lamports: pre("Binance 2026-10-29 20:10:18Z") },
    });
    expect(r.verdict).toBe("BLOCK");
    expect(codes(r)).toEqual(expect.arrayContaining(["TEMPLATE_DRIFT", "BALANCE_FRACTION"]));
    expect(r.findings.find((f) => f.code === "BALANCE_FRACTION")!.message).toMatch(/90\.4%/);
  });

  it("lets a routine withdrawal batch through: OK, not REVIEW", () => {
    const r = checkSolanaTransaction(raw("Binance 2026-10-29 20:30:42Z"), {
      ...exchange,
      balance: { lamports: pre("Binance 2026-10-29 20:30:42Z") },
    });
    expect(r.verdict).toBe("OK");
    expect(r.durableNonce!.authority).toBe(HOT);
  });
});

describe("other Solana incidents", () => {
  it("Drift tx #1: update_admin inside a Squads vault message, bound to a durable nonce", () => {
    const r = checkSolanaTransaction(raw("Drift 2026-04-01 16:05:18Z"));
    expect(r.verdict).toBe("BLOCK");
    expect(r.findings.find((f) => f.code === "GOVERNANCE_AUTHORITY_TRANSFER")!.message).toMatch(
      /update_admin\(H7PiGqqUaanBovwKgEtreJbKmQe6dbq6VTrw6guy7ZgL\)/,
    );
    expect(codes(r)).toContain("DURABLE_NONCE_ON_PRIVILEGED_ACTION");
  });

  it("Drift tx #2: approve and execute in one durable-nonce transaction", () => {
    const r = checkSolanaTransaction(raw("Drift 2026-04-01 16:05:19Z"));
    expect(r.verdict).toBe("BLOCK");
    expect(codes(r)).toEqual(
      expect.arrayContaining(["APPROVE_AND_EXECUTE_SAME_TX", "DURABLE_NONCE_ON_PRIVILEGED_ACTION"]),
    );
  });

  it("SwissBorg/Kiln: eight Withdrawer authority changes behind a deactivate", () => {
    const r = checkSolanaTransaction(raw("SwissBorg/Kiln"));
    expect(r.verdict).toBe("BLOCK");
    expect(r.findings.filter((f) => f.code === "STAKE_AUTHORITY_CHANGE")).toHaveLength(8);
    expect(codes(r)).toContain("BULK_AUTHORITY_CHANGE");
  });

  it("owner-change phishing: an unknown program receives the victim's signature", () => {
    const r = checkSolanaTransaction(raw("Owner-change phishing"));
    expect(r.verdict).toBe("BLOCK");
    expect(codes(r)).toContain("UNKNOWN_PROGRAM_WITH_SIGNER");
  });
});

describe("Solana fixtures authenticate themselves", () => {
  it("every first signature verifies over the message with the fee payer's key", () => {
    for (const c of cases) {
      const raw = Buffer.from(c.base64, "base64");
      const tx = decodeSolanaTransaction(raw);
      const sig = base58.decode(tx.signatures[0]!);
      const payer = base58.decode(tx.message.staticKeys[0]!);
      expect(ed25519.verify(sig, tx.message.bytes, payer)).toBe(true);
    }
  });
});
