import { describe, expect, it } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import { bytesToHex, hexToBytes } from "../src/evm/bytes.ts";
import { authorizationPreimage, recoverAuthority } from "../src/evm/eip7702.ts";
import { RlpError, rlpDecode, rlpEncode, type RlpItem } from "../src/evm/rlp.ts";
import { decodeTransaction } from "../src/evm/tx.ts";
import { Guard, profiles } from "../src/guard/policy.ts";
import { BadRequest, decide } from "../src/guard/serve.ts";
import { rawFix } from "./helpers.ts";

// Seeded, so a failure names the exact input that caused it. EF0100_FUZZ_RUNS raises the count; the default keeps the
// suite under a few seconds.
const RUNS = Number(process.env.EF0100_FUZZ_RUNS ?? 2000);
const SEED = Number(process.env.EF0100_FUZZ_SEED ?? 0x7702);
// About a millisecond per run on a laptop for the slowest property; the limit grows with the count.
const LIMIT = Math.max(60_000, RUNS * 4);

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

/** Bit flips, truncation, insertion or an overwritten run: the shapes a damaged or hostile input takes. */
function mutate(r: () => number, src: Uint8Array): Uint8Array {
  const b = Uint8Array.from(src);
  const at = int(r, b.length);
  switch (int(r, 4)) {
    case 0:
      for (let i = 1 + int(r, 8); i > 0; i--) b[int(r, b.length)] ^= 1 << int(r, 8);
      return b;
    case 1:
      return b.slice(0, at);
    case 2: {
      const extra = bytes(r, 1 + int(r, 16));
      return Uint8Array.from([...b.slice(0, at), ...extra, ...b.slice(at)]);
    }
    default:
      b.set(bytes(r, Math.min(1 + int(r, 32), b.length - at)), at);
      return b;
  }
}

/** A decoder may refuse an input, with its own error; it must never fail on its own code. */
function isRefusal(e: unknown): boolean {
  if (e instanceof RlpError) return true;
  return e instanceof TypeError && !/cannot read|is not a function|is not iterable|undefined|null/i.test(e.message);
}

const ATTACK = "0xad99264d5532ae0dd04b2004eebda05f25657e70dacb764f7ac8d4ccd051298b";
const B14 = "0x28C6c06298d514Db089934071355E5743bf21d60";
const SWEEPER = "0x63e842B054Bd624a465454D533C33F573e9c6fAe";
const ZERO = "0x0000000000000000000000000000000000000000";

describe(`fuzz (seed ${SEED}, ${RUNS} runs)`, () => {
  it(
    "the RLP decoder returns or refuses on any damaged copy of the 4,916-byte transaction",
    () => {
      const r = rng(SEED);
      const raw = hexToBytes(rawFix(ATTACK));
      const typed = raw.slice(1);
      let refused = 0;
      for (let i = 0; i < RUNS; i++) {
        const input = mutate(r, typed);
        try {
          rlpDecode(input);
        } catch (e) {
          if (!isRefusal(e)) throw new Error(`run ${i}: ${bytesToHex(input).slice(0, 80)}…: ${(e as Error).stack}`);
          refused++;
        }
      }
      expect(refused).toBeGreaterThan(RUNS / 2);
    },
    LIMIT,
  );

  it(
    "the transaction decoder returns or refuses on any damaged copy, and never on its own code",
    () => {
      const r = rng(SEED + 1);
      const raw = hexToBytes(rawFix(ATTACK));
      for (let i = 0; i < RUNS; i++) {
        const input = mutate(r, raw);
        try {
          decodeTransaction(input);
        } catch (e) {
          if (!isRefusal(e)) throw new Error(`run ${i}: ${bytesToHex(input).slice(0, 80)}…: ${(e as Error).stack}`);
        }
      }
    },
    LIMIT,
  );

  it(
    "RLP encodes and decodes random nested items to the same bytes",
    () => {
      const r = rng(SEED + 2);
      const item = (depth: number): RlpItem =>
        depth > 0 && r() < 0.35
          ? Array.from({ length: int(r, 6) }, () => item(depth - 1))
          : bytes(r, r() < 0.3 ? int(r, 2) : int(r, 80));
      for (let i = 0; i < RUNS; i++) {
        const x = item(3);
        const enc = rlpEncode(x);
        expect(rlpEncode(rlpDecode(enc))).toEqual(enc);
      }
    },
    LIMIT,
  );

  it(
    "the hot-wallet guard never signs a damaged authorization for a delegate it does not allow, and never throws",
    () => {
      const r = rng(SEED + 3);
      const guard = new Guard(profiles.hotWallet);
      const pre = authorizationPreimage({ chainId: 1n, address: SWEEPER, nonce: 18914809n });
      let authorizations = 0;
      for (let i = 0; i < RUNS; i++) {
        const input = mutate(r, pre);
        const d = guard.check(input, { as: "preimage" }, { signer: B14, nonce: 18914809n, now: i });
        if (d.classified.kind === "eip7702-authorization") {
          authorizations++;
          if (d.allow)
            expect((d.classified as { authorization: { address: string } }).authorization.address).toBe(ZERO);
        }
      }
      expect(authorizations).toBeGreaterThan(0);
    },
    LIMIT,
  );

  it(
    "refuses every random 32-byte digest for lack of a preimage",
    () => {
      const r = rng(SEED + 4);
      const guard = new Guard(profiles.hotWallet);
      for (let i = 0; i < RUNS; i++) {
        const d = guard.check(bytes(r, 32), { as: "digest" }, { signer: B14, nonce: 1n });
        expect(d.allow).toBe(false);
        expect(d.reasons.map((x) => x.code)).toContain("NO_PREIMAGE");
      }
    },
    LIMIT,
  );

  it(
    "recovers the signer of random authorizations signed by viem",
    async () => {
      const r = rng(SEED + 5);
      const n = Math.max(50, Math.floor(RUNS / 10));
      for (let i = 0; i < n; i++) {
        const sk = bytesToHex(bytes(r, 32));
        let account;
        try {
          account = privateKeyToAccount(sk);
        } catch {
          continue;
        }
        const auth = { address: bytesToHex(bytes(r, 20)), chainId: int(r, 2 ** 31), nonce: int(r, 2 ** 48) };
        const sig = await account.signAuthorization(auth);
        const ours = recoverAuthority({
          chainId: BigInt(auth.chainId),
          address: auth.address,
          nonce: BigInt(auth.nonce),
          yParity: sig.yParity!,
          r: BigInt(sig.r),
          s: BigInt(sig.s),
        });
        expect(ours.ok && ours.authority.toLowerCase()).toBe(account.address.toLowerCase());
      }
    },
    LIMIT,
  );

  it(
    "guard serve answers any JSON body with a decision or a 400, and never allows a request without a preimage",
    () => {
      const r = rng(SEED + 9);
      const g = new Guard(profiles.hotWallet);
      const B14 = "0x28C6c06298d514Db089934071355E5743bf21d60";
      const clear = bytesToHex(
        authorizationPreimage({ chainId: 1n, address: "0x0000000000000000000000000000000000000000", nonce: 18914809n }),
      );
      const tuple15 = bytesToHex(
        authorizationPreimage({ chainId: 1n, address: "0x63e842B054Bd624a465454D533C33F573e9c6fAe", nonce: 18914809n }),
      );
      const real = [clear, tuple15, "0x", "18914809"];
      const hex = (n: number) => bytesToHex(bytes(r, n));
      const value = (depth = 0): unknown => {
        switch (int(r, 12)) {
          case 0:
            return null;
          case 1:
            return r() < 0.5;
          case 2:
            return int(r, 2) ? int(r, 2 ** 31) : -int(r, 1000) - 0.5;
          case 3:
            return hex(int(r, 80));
          case 4:
            return "0x" + "zz".repeat(int(r, 4));
          case 5:
            return real[int(r, real.length)];
          case 6:
            return String(int(r, 2 ** 31));
          case 7:
            return depth < 2 ? Array.from({ length: int(r, 3) }, () => value(depth + 1)) : [];
          case 8:
            return depth < 2 ? body(depth + 1) : {};
          case 9:
            return B14;
          case 10:
            return "0x" + int(r, 2 ** 31).toString(16);
          default:
            return "x".repeat(int(r, 40));
        }
      };
      const KEYS = ["preimage", "digest", "signer", "nonce", "ownCode", "selfSponsored", "curve", "extra"];
      const body = (depth = 0): Record<string, unknown> =>
        Object.fromEntries(KEYS.filter(() => r() < 0.5).map((k) => [k, value(depth)]));
      let decided = 0;
      let rejected = 0;
      for (let i = 0; i < RUNS; i++) {
        const b = int(r, 10) === 0 ? value() : body();
        let d: ReturnType<typeof decide> | undefined;
        try {
          d = decide(g, b);
          decided++;
        } catch (e) {
          expect(e, `run ${i}: ${JSON.stringify(b)?.slice(0, 200)}`).toBeInstanceOf(BadRequest);
          rejected++;
          continue;
        }
        if (d.allow) {
          const req = b as Record<string, unknown>;
          expect(typeof req.preimage, `run ${i}`).toBe("string");
          expect(typeof req.ownCode, `run ${i}`).toBe("string");
          if (req.ownCode !== "0x") expect(req.preimage, `run ${i}: own code present, only the clear`).toBe(clear);
        }
      }
      expect(decided).toBeGreaterThan(0);
      expect(rejected).toBeGreaterThan(0);
    },
    LIMIT,
  );
});
