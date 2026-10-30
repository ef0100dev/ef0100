import { describe, expect, it } from "vitest";
import { bytesToHex } from "../src/evm/bytes.ts";
import { authorizationPreimage } from "../src/evm/eip7702.ts";
import { Guard, type GuardPolicy } from "../src/guard/policy.ts";
import { OwnCodeUnconfirmed, agreedOwnCode, type OwnCodeAnswer } from "../src/evm/owncode.ts";
import { checkRecipient } from "../src/evm/recipient.ts";
import { scanAddresses } from "../src/evm/scan.ts";

// Each guard rule checked against random authorizations, seeded so a failure names its input. EF0100_FUZZ_RUNS raises
// the count, as in fuzz.test.ts.
const RUNS = Number(process.env.EF0100_FUZZ_RUNS ?? 2000);
const SEED = Number(process.env.EF0100_FUZZ_SEED ?? 0x7702);
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

  it(
    "own code from several endpoints: one that lags or lies can make the guard refuse, never make it sign",
    () => {
      const r = rng(SEED + 7);
      const g = new Guard({ ...policy(), requireOwnCode: true });
      const answer = (): Omit<OwnCodeAnswer, "endpoint"> => {
        const k = int(r, 10);
        if (k < 2) return { error: "HTTP 504" };
        if (k < 7) return { code: "0x" };
        if (k < 9) return { code: `0xef0100${addr(r).slice(2)}` as `0x${string}` };
        return { code: bytesToHex(Uint8Array.from({ length: 1 + int(r, 40) }, () => int(r, 256))) };
      };
      let signed = 0;
      let refused = 0;
      for (let i = 0; i < RUNS; i++) {
        const n = 1 + int(r, 5);
        const answers = Array.from({ length: n }, (_, j) => ({ endpoint: `https://e${j}.example`, ...answer() }));
        const quorum = 1 + int(r, n);
        const seen = answers.flatMap((a) => (a.code === undefined ? [] : [a.code]));
        let ownCode: `0x${string}` | undefined;
        try {
          ownCode = agreedOwnCode(answers, quorum);
          expect(new Set(seen), `run ${i}`).toEqual(new Set([ownCode]));
          expect(seen.length).toBeGreaterThanOrEqual(quorum);
        } catch (e) {
          expect(e, `run ${i}`).toBeInstanceOf(OwnCodeUnconfirmed);
          expect(new Set(seen).size !== 1 || seen.length < quorum, `run ${i}`).toBe(true);
        }
        const live = big(r);
        const d = ask(g, BigInt(1 + int(r, 2 ** 31)), OK, live, { nonce: live, now: i, ownCode });
        if (seen.some((c) => c !== "0x")) expect(d.allow, `run ${i}: ${codes(d)}`).toBe(false);
        else if (ownCode === undefined) expect(codes(d), `run ${i}`).toContain("CONTEXT_MISSING");
        else expect(d.allow, `run ${i}: ${codes(d)}`).toBe(true);
        if (d.allow) signed++;
        else refused++;
      }
      expect(signed).toBeGreaterThan(0);
      expect(refused).toBeGreaterThan(0);
    },
    LIMIT,
  );

  it(
    "--cross-check: if any endpoint sees a delegation, scan reports it and recipient holds",
    async () => {
      const r = rng(SEED + 8);
      const urls = ["https://e0.example", "https://e1.example", "https://e2.example", "https://e3.example"];
      let delegated = 0;
      let held = 0;
      for (let i = 0; i < RUNS; i++) {
        const n = 1 + int(r, 4);
        const code: (string | null)[] = Array.from({ length: n }, () => {
          const k = int(r, 10);
          if (k < 2) return null;
          if (k < 6) return "0x";
          if (k < 9) return `0xef0100${addr(r).slice(2)}`;
          return bytesToHex(Uint8Array.from({ length: 1 + int(r, 40) }, () => int(r, 256)));
        });
        const fetch = (async (url: string | URL, init?: RequestInit) => {
          const c = code[urls.indexOf(String(url))];
          if (c === null || c === undefined) return new Response("", { status: 503 });
          const calls = JSON.parse(String(init?.body)) as { id: number; method: string; params: unknown[] }[];
          const result = (x: (typeof calls)[number]) =>
            x.method === "eth_getTransactionCount"
              ? "0x1"
              : x.method === "eth_call"
                ? "0x" + "0".repeat(64)
                : String(x.params[0]).toLowerCase() === SIGNER.toLowerCase()
                  ? c
                  : "0x";
          return new Response(JSON.stringify(calls.map((x) => ({ jsonrpc: "2.0", id: x.id, result: result(x) }))));
        }) as typeof globalThis.fetch;
        const chain = {
          id: 1,
          key: "ethereum",
          name: "Ethereum",
          rpc: urls.slice(0, n),
          explorer: "https://x.example",
        };
        const answered = code.filter((c): c is string => c !== null);
        const designators = answered.filter((c) => c.startsWith("0xef0100") && c.length === 48);
        const scan = await scanAddresses([SIGNER], { chains: [chain], fetch, crossCheck: true });
        const row = scan.rows[0]!;
        if (!answered.length) {
          expect(row.state, `run ${i}`).toBe("error");
          continue;
        }
        if (designators.length) {
          expect(row.state, `run ${i}`).toBe("delegated");
          expect(designators.map((d) => `0x${d.slice(8)}`)).toContain(row.delegate!.toLowerCase());
          delegated++;
        } else expect(row.state, `run ${i}`).toBe(answered.some((c) => c !== "0x") ? "contract" : "eoa");
        expect(row.disagreement !== undefined, `run ${i}`).toBe(new Set(answered).size > 1);
        const rec = await checkRecipient(SIGNER, { chain, fetch, crossCheck: true });
        if (answered.some((c) => c !== "0x")) {
          expect(rec.allow, `run ${i}: ${rec.reasons.map((x) => x.code)}`).toBe(false);
          held++;
        } else expect(rec.allow, `run ${i}`).toBe(true);
        if (new Set(answered).size > 1)
          expect(
            rec.reasons.map((x) => x.code),
            `run ${i}`,
          ).toContain("ENDPOINTS_DISAGREE");
      }
      expect(delegated).toBeGreaterThan(0);
      expect(held).toBeGreaterThan(0);
    },
    LIMIT,
  );
});
