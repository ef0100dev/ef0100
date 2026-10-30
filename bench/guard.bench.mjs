// The cost of the guard and the decoders on this machine: median and p99 per call over 20,000 calls, after warm-up.
// Run after `pnpm build`: node bench/guard.bench.mjs
import { readFileSync } from "node:fs";
import { performance } from "node:perf_hooks";
import {
  Guard,
  authorizationDigest,
  authorizationPreimage,
  decodeTransaction,
  hexToBytes,
  profiles,
  recoverAuthority,
} from "../dist/index.js";

const ATTACK = "0xad99264d5532ae0dd04b2004eebda05f25657e70dacb764f7ac8d4ccd051298b";
const raw = hexToBytes(
  readFileSync(new URL(`../fixtures/2026-10-29/raw/${ATTACK}.rlp.hex`, import.meta.url), "utf8").trim(),
);
const auth = { chainId: 1n, address: "0x63e842B054Bd624a465454D533C33F573e9c6fAe", nonce: 18914809n };
const pre = authorizationPreimage(auth);
const digest = authorizationDigest(auth);
const guard = new Guard(profiles.hotWallet);
const ctx = { signer: "0x28C6c06298d514Db089934071355E5743bf21d60", nonce: 18914809n };
const tuple15 = decodeTransaction(raw).authorizationList[15];

const N = Number(process.env.EF0100_BENCH_N ?? 20000);
function measure(name, fn) {
  for (let i = 0; i < 2000; i++) fn();
  const t = new Float64Array(N);
  for (let i = 0; i < N; i++) {
    const a = performance.now();
    fn();
    t[i] = performance.now() - a;
  }
  t.sort();
  const us = (ms) => (ms * 1000).toFixed(1);
  console.log(
    `${name.padEnd(52)} median ${us(t[N >> 1]).padStart(8)} µs   p99 ${us(t[Math.floor(N * 0.99)]).padStart(8)} µs`,
  );
}

console.log(
  `node ${process.version} · ${process.platform}/${process.arch} · ${N.toLocaleString("en-US")} calls each\n`,
);
measure("guard.check: tuple #15 preimage (refused)", () => guard.check(pre, { as: "preimage" }, ctx));
measure("guard.check: bare 32-byte digest (refused)", () => guard.check(digest, { as: "digest" }, ctx));
measure("guard.checkDigest: digest + preimage (refused)", () => guard.checkDigest(digest, pre, ctx));
measure("decodeTransaction: the 4,916-byte type-4 tx", () => decodeTransaction(raw));
measure("recoverAuthority: one tuple (secp256k1 recovery)", () => recoverAuthority(tuple15));
