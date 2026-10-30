import { sha256 } from "@noble/hashes/sha2.js";
import { base58 } from "@scure/base";
import { describe, expect, it } from "vitest";
import { checkSolanaTransaction, PROGRAMS, type SolPolicy } from "../src/sol/check.ts";
import { decodeSolanaMessage } from "../src/sol/message.ts";

const pk = (n: number) => base58.encode(Uint8Array.from({ length: 32 }, (_, i) => (i === 0 ? n : 7)));
const ME = pk(1);
const ATTACKER = pk(2);
const NONCE = pk(3);
const OTHER = pk(4);

const le = (n: bigint, bytes: number) =>
  Uint8Array.from({ length: bytes }, (_, i) => Number((n >> BigInt(8 * i)) & 0xffn));
const cat = (...parts: (Uint8Array | number[])[]) => Uint8Array.from(parts.flatMap((p) => [...p]));
const shortvec = (n: number) => {
  const out: number[] = [];
  for (let v = n; ; v >>= 7) {
    if (v < 0x80) return [...out, v];
    out.push((v & 0x7f) | 0x80);
  }
};
const disc = (name: string) => sha256(new TextEncoder().encode(`global:${name}`)).subarray(0, 8);

interface Ix {
  program: string;
  accounts: string[];
  data: Uint8Array;
}

/** A legacy transaction: signers first (writable), then other writable keys, then read-only programs. */
function tx(signers: string[], ixs: Ix[], extraWritable: string[] = []): Uint8Array {
  const programs = [...new Set(ixs.map((i) => i.program))];
  const writable = [...new Set([...extraWritable, ...ixs.flatMap((i) => i.accounts)])].filter(
    (a) => !signers.includes(a) && !programs.includes(a),
  );
  const keys = [...signers, ...writable, ...programs];
  const at = (k: string) => keys.indexOf(k);
  const message = cat(
    [signers.length, 0, programs.length],
    shortvec(keys.length),
    ...keys.map((k) => base58.decode(k)),
    new Uint8Array(32).fill(9),
    shortvec(ixs.length),
    ...ixs.map((i) =>
      cat([at(i.program)], shortvec(i.accounts.length), i.accounts.map(at), shortvec(i.data.length), i.data),
    ),
  );
  return cat(shortvec(signers.length), new Uint8Array(64 * signers.length), message);
}

const check = (raw: Uint8Array, policy?: SolPolicy) => checkSolanaTransaction(raw, policy);
const codes = (r: ReturnType<typeof check>) => r.findings.map((f) => `${f.severity}:${f.code}`);

describe("token batch and unwrap", () => {
  it("decodes a Tokenkeg batch that approves and hands over the account", () => {
    const data = cat([0xff], [3, 9, 4], le(2n ** 64n - 1n, 8), [2, 35, 6, 2, 1], base58.decode(ATTACKER));
    const r = check(tx([ME], [{ program: PROGRAMS.token, accounts: [OTHER, ATTACKER, ME, OTHER, ME], data }]));
    expect(r.verdict).toBe("BLOCK");
    expect(codes(r)).toEqual(expect.arrayContaining(["critical:TOKEN_APPROVE", "critical:TOKEN_SET_AUTHORITY"]));
  });

  it("blocks unwrapping a whole wrapped-SOL balance to someone else", () => {
    const r = check(
      tx([ME], [{ program: PROGRAMS.token, accounts: [OTHER, ATTACKER, ME], data: Uint8Array.of(45, 0) }]),
    );
    expect(codes(r)).toContain("critical:TOKEN_UNWRAP_LAMPORTS");
  });

  it("reads Token-2022 TransferCheckedWithFee as a transfer and an unknown tag as unread", () => {
    const fee = cat([26, 1], le(1_000n, 8), [6], le(0n, 8));
    const r = check(tx([ME], [{ program: PROGRAMS.token2022, accounts: [OTHER, NONCE, ATTACKER, ME], data: fee }]));
    expect(codes(r)).toContain("high:TOKEN_TRANSFER");
    const unknown = check(tx([ME], [{ program: PROGRAMS.token, accounts: [OTHER], data: Uint8Array.of(99) }]));
    expect(codes(unknown)).toContain("high:UNRECOGNIZED_INSTRUCTION");
  });
});

describe("System and Stake", () => {
  it("blocks the 90% drain routed through a seed-created stake account the attacker can withdraw", () => {
    const seed = new TextEncoder().encode("x");
    const create = cat(
      le(3n, 4),
      base58.decode(ME),
      le(BigInt(seed.length), 8),
      seed,
      le(965_455_100_000_000n, 8),
      le(200n, 8),
      base58.decode(PROGRAMS.stake),
    );
    const init = cat(le(0n, 4), base58.decode(ATTACKER), base58.decode(ATTACKER), new Uint8Array(48));
    const r = check(
      tx(
        [ME],
        [
          { program: PROGRAMS.system, accounts: [ME, OTHER, ME], data: create },
          { program: PROGRAMS.stake, accounts: [OTHER], data: init },
        ],
      ),
      { balance: { lamports: 1_068_373_107_280_343n } },
    );
    expect(r.verdict).toBe("BLOCK");
    expect(codes(r)).toEqual(
      expect.arrayContaining([
        "critical:ACCOUNT_OWNER_CHANGE",
        "critical:STAKE_AUTHORITY_CHANGE",
        "critical:BALANCE_FRACTION",
      ]),
    );
  });

  it("counts TransferWithSeed and CreateAccount toward the balance share", () => {
    const seed = new TextEncoder().encode("s");
    const tws = cat(le(11n, 4), le(500_000_000n, 8), le(BigInt(seed.length), 8), seed, base58.decode(PROGRAMS.system));
    const r = check(tx([ME], [{ program: PROGRAMS.system, accounts: [OTHER, ME, ATTACKER], data: tws }]), {
      balance: { lamports: 1_000_000_000n },
    });
    expect(codes(r)).toEqual(expect.arrayContaining(["high:SOL_TRANSFER", "critical:BALANCE_FRACTION"]));
  });
});

describe("durable nonce template", () => {
  const advance = Uint8Array.of(4, 0, 0, 0);
  it("does not take account 2 on trust: another signer on the nonce instruction breaks the template", () => {
    const r = check(
      tx([ME, ATTACKER], [{ program: PROGRAMS.system, accounts: [NONCE, OTHER, ME, ATTACKER], data: advance }]),
      { template: { nonceAuthority: ME } },
    );
    expect(codes(r)).toContain("critical:TEMPLATE_DRIFT");
  });

  it("passes the routine shape: the template authority alone signs the nonce instruction", () => {
    const r = check(tx([ME], [{ program: PROGRAMS.system, accounts: [NONCE, OTHER, ME], data: advance }]), {
      template: { nonceAuthority: ME },
    });
    expect(codes(r)).not.toContain("critical:TEMPLATE_DRIFT");
  });
});

describe("priority fee", () => {
  it("counts a priority fee that eats the balance", () => {
    const price = cat([3], le(10_000_000_000_000n, 8));
    const r = check(tx([ME], [{ program: PROGRAMS.computeBudget, accounts: [], data: price }]), {
      balance: { lamports: 20_000_000_000_000n },
    });
    expect(codes(r)).toEqual(expect.arrayContaining(["high:PRIORITY_FEE", "critical:BALANCE_FRACTION"]));
  });
});

describe("Squads v4", () => {
  const innerMessage = (program: string, data: Uint8Array) => {
    const keys = [OTHER, program];
    return cat(
      [1, 1, 0, keys.length],
      ...keys.map((k) => base58.decode(k)),
      [1, 1, 1, 0],
      le(BigInt(data.length), 2),
      data,
      [0],
    );
  };
  const updateAdmin = cat(disc("update_admin"), base58.decode(ATTACKER));

  it("reads a batch_add_transaction message with the vault rules", () => {
    const msg = innerMessage(ATTACKER, updateAdmin);
    const data = cat(disc("batch_add_transaction"), [0], le(BigInt(msg.length), 4), msg);
    const r = check(tx([ME], [{ program: PROGRAMS.squadsV4, accounts: [OTHER], data }]));
    expect(codes(r)).toContain("critical:GOVERNANCE_AUTHORITY_TRANSFER");
  });

  it("applies the System rules inside a vault message", () => {
    const transfer = cat(le(2n, 4), le(5_000_000_000n, 8));
    const msg = innerMessage(PROGRAMS.system, transfer);
    const data = cat(disc("vault_transaction_create"), [0, 0], le(BigInt(msg.length), 4), msg);
    const r = check(tx([ME], [{ program: PROGRAMS.squadsV4, accounts: [OTHER], data }]));
    expect(r.findings.some((f) => f.code === "SOL_TRANSFER" && f.instruction === "ix0.inner0")).toBe(true);
  });

  it("does not let a buffer path or an unknown instruction pass as info", () => {
    for (const name of [
      "transaction_buffer_create",
      "vault_transaction_create_from_buffer",
      "config_transaction_execute",
    ]) {
      const r = check(tx([ME], [{ program: PROGRAMS.squadsV4, accounts: [OTHER], data: cat(disc(name), [0]) }]));
      expect(r.verdict).not.toBe("OK");
    }
    const unknown = check(tx([ME], [{ program: PROGRAMS.squadsV4, accounts: [OTHER], data: new Uint8Array(9) }]));
    expect(codes(unknown)).toContain("high:UNRECOGNIZED_INSTRUCTION");
  });
});

describe("message decoding", () => {
  it("refuses a message that loads the same account twice", () => {
    const keys = [ME, ME, PROGRAMS.system];
    const message = cat(
      [1, 0, 1],
      shortvec(keys.length),
      ...keys.map((k) => base58.decode(k)),
      new Uint8Array(32),
      [0],
    );
    expect(() => decodeSolanaMessage(message)).toThrow(/twice/);
  });
});
