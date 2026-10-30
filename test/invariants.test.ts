import { describe, expect, it } from "vitest";
import { bytesToHex } from "../src/evm/bytes.ts";
import { authorizationPreimage } from "../src/evm/eip7702.ts";
import { Guard, type GuardPolicy } from "../src/guard/policy.ts";

// Each guard rule checked against random authorizations, seeded so a failure names its input. EF0100_FUZZ_RUNS raises
// the count, as in fuzz.test.ts.
const RUNS = Number(process.env.EF0100_FUZZ_RUNS ?? 2000);
const SEED = Number(process.env.EF0100_FUZZ_SEED ?? 0x7702);
const LIMIT = Math.max(10_000, RUNS * 4);

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
const big = (r: () => number) => (BigInt(int(r, 2 ** 31)) << 32n) | BigInt(int(r, 2 ** 32));
const addr = (r: () => number) => bytesToHex(Uint8Array.from({ length: 20 }, () => int(r, 256)));

const SIGNER = "0x28C6c06298d514Db089934071355E5743bf21d60";
const OK = "0x63e842B054Bd624a465454D533C33F573e9c6fAe";
const ZERO = "0x0000000000000000000000000000000000000000";
const policy = (extra: NonNullable<GuardPolicy["authorizations"]> = {}): GuardPolicy => ({
  authorizations: { allowDelegates: [{ address: OK }], maxPerWindow: 1_000_000, ...extra },
});
const ask = (g: Guard, chainId: bigint, address: string, nonce: bigint, ctx: Record<string, unknown> = {}) =>
  g.check(authorizationPreimage({ chainId, address, nonce }), { as: "preimage" }, { signer: SIGNER, ...ctx });
const codes = (d: { reasons: { code: string }[] }) => d.reasons.map((x) => x.code);

describe(`guard invariants (seed ${SEED}, ${RUNS} runs)`, () => {
  it(
    "signs an allowed delegate at the live nonce (the control for every rule below)",
    () => {
      const r = rng(SEED);
      const g = new Guard(policy());
      for (let i = 0; i < RUNS; i++) {
        const live = big(r);
        const d = ask(g, BigInt(1 + int(r, 2 ** 31)), OK, live, { nonce: live, now: i });
        expect(d.allow, `run ${i}: ${codes(d)}`).toBe(true);
      }
    },
    LIMIT,
  );

  it(
    "never signs chain_id 0, the wildcard valid on every 7702 chain",
    () => {
      const r = rng(SEED + 1);
      const g = new Guard(policy());
      for (let i = 0; i < RUNS; i++) {
        const live = big(r);
        const d = ask(g, 0n, r() < 0.5 ? OK : addr(r), live, { nonce: live, now: i });
        expect(d.allow).toBe(false);
        expect(codes(d)).toContain("WILDCARD_CHAIN_ID");
      }
    },
    LIMIT,
  );

  it(
    "never signs a nonce other than the live one: a signed future nonce stays valid until the account reaches it",
    () => {
      const r = rng(SEED + 2);
      const g = new Guard(policy());
      for (let i = 0; i < RUNS; i++) {
        const live = big(r);
        let other = big(r);
        if (other === live) other += 1n;
        const d = ask(g, BigInt(1 + int(r, 2 ** 31)), OK, other, { nonce: live, now: i });
        expect(d.allow).toBe(false);
        expect(codes(d)).toContain("NONCE_NOT_LIVE");
      }
    },
    LIMIT,
  );

  it(
    "never signs a delegate that is not on the list",
    () => {
      const r = rng(SEED + 3);
      const g = new Guard(policy());
      for (let i = 0; i < RUNS; i++) {
        const live = big(r);
        const who = addr(r);
        if (who.toLowerCase() === OK.toLowerCase() || who === ZERO) continue;
        const d = ask(g, BigInt(1 + int(r, 2 ** 31)), who, live, { nonce: live, now: i });
        expect(d.allow).toBe(false);
        expect(codes(d)).toContain("DELEGATE_NOT_ALLOWED");
      }
    },
    LIMIT,
  );

  it(
    "never signs more than maxPerWindow delegations in any window, whatever the timing",
    () => {
      const r = rng(SEED + 4);
      const max = 3;
      const windowMs = 60_000;
      const g = new Guard(policy({ maxPerWindow: max, windowMs }));
      const signed: number[] = [];
      let now = 0;
      for (let i = 0; i < RUNS; i++) {
        now += int(r, 25_000);
        const live = big(r);
        const d = ask(g, BigInt(1 + i), OK, live, { nonce: live, now });
        if (d.allow) signed.push(now);
        else expect(codes(d)).toContain("RATE_LIMITED");
        expect(signed.filter((t) => t > now - windowMs).length).toBeLessThanOrEqual(max);
      }
      expect(signed.length).toBeGreaterThan(0);
    },
    LIMIT,
  );

  it(
    "once the key's own account has code, signs only the clear",
    () => {
      const r = rng(SEED + 5);
      const g = new Guard(policy());
      for (let i = 0; i < RUNS; i++) {
        const live = big(r);
        const ownCode = Uint8Array.from({ length: 1 + int(r, 64) }, () => int(r, 256));
        const chainId = BigInt(1 + int(r, 2 ** 31));
        const d = ask(g, chainId, OK, live, { nonce: live, now: i, ownCode });
        expect(d.allow).toBe(false);
        expect(codes(d)).toContain("OWN_CODE_PRESENT");
        const clear = ask(g, chainId, ZERO, live, { nonce: live, now: i, ownCode });
        expect(clear.allow, `run ${i}: ${codes(clear)}`).toBe(true);
      }
    },
    LIMIT,
  );
});
