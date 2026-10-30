import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { bytesToHex, hexToBytes, keccak256 } from "../src/evm/bytes.ts";
import { fingerprintCode } from "../src/evm/fingerprint.ts";
import { DELEGATES, lookupCodehash } from "../src/evm/registry.ts";
import { loadIncident } from "../src/incident.ts";
import { rawFiles, rawFix, readFix } from "./helpers.ts";

describe("bundled raw transactions", () => {
  it("every file hashes to its own name", () => {
    const files = rawFiles();
    expect(files.length).toBeGreaterThanOrEqual(7);
    for (const f of files) {
      const hash = f.replace(".rlp.hex", "");
      expect(bytesToHex(keccak256(hexToBytes(rawFix(hash))))).toBe(hash);
    }
  });

  it("events.json agrees with the ledger on every call's block and time", () => {
    const ev = JSON.parse(readFix("evm/events.json"));
    const rows = readFix("evm/drain_ledger.csv")
      .trim()
      .split("\n")
      .slice(1)
      .map((l) => l.split(","));
    const byTx = new Map(rows.map((r) => [r[0], { block: Number(r[1]), utc: r[2]!.slice(0, 19) + "Z" }]));
    for (const c of ev.calls) {
      const l = byTx.get(c.tx);
      if (!l) continue;
      expect({ tx: c.tx, block: c.block, utc: c.utc }).toEqual({ tx: c.tx, ...l });
    }
  });
});

describe("the incident, recomputed", () => {
  const inc = loadIncident();

  it("matches the on-chain record", () => {
    expect(inc.delegation.result.applied.map((o) => o.index)).toEqual([15]);
    expect(inc.timing).toEqual({ secondsToFirstSweep: 204, blocksToFirstSweep: 17, delegatedSeconds: 13_776 });
    expect(inc.calls).toHaveLength(12);
    expect(inc.calls.filter((c) => c.kind === "poll")).toHaveLength(5);
    expect(inc.refills.map((r) => r.sweptAfterSeconds)).toEqual([72, 60]);
  });

  it("totals what left through the delegation", () => {
    expect(inc.totals.eth).toBe("172624.404561620147322012");
    expect(inc.totals.usdt).toBe("1819724910.565362");
    expect(inc.totals.usdc).toBe("823000000");
    expect(inc.totals.sweptTokenContracts).toBe(184);
    expect(inc.calls[0]!.eth).toBe("167464.247856558836135296");
    expect(inc.calls[0]!.usdt).toBe("1615409498.97324");
  });

  it("recognizes the clearing transaction", () => {
    expect(inc.clear.result.applied[0]!.effect).toBe("clear");
    expect(inc.clear.result.after.get(inc.authority)!.delegate).toBeNull();
  });
});

describe("delegate fingerprints", () => {
  const v2 = fingerprintCode(readFix("evm/sweeper_v2_runtime.hex").trim());
  const v1 = fingerprintCode(readFix("evm/sweeper_v1_runtime.hex").trim());

  it("reads the sweeper's shape from its bytecode", () => {
    expect(v2.size).toBe(1674);
    expect(v2.codehash).toBe("0x7de93915e2660a045483ed0a02aef8c882d62179d69702e21cd4c97a92870e5d");
    const sel = v2.selectors.map((s) => s.selector);
    expect(sel).toEqual(expect.arrayContaining(["0x8a179be4", "0x043ff9d2", "0xb61d27f6", "0x70a08231", "0xa9059cbb"]));
    expect(v2.hardcodedAddresses).toContain("0x7C8601d4645b93cea45F71e118A729332e6B5CA0");
    expect(v2.traits).toEqual(expect.arrayContaining(["SWEEPS_TOKENS", "CHECKS_CALLER", "RESERVES_ONE_ETHER"]));
    expect(v2.sweeperLike).toBe(true);
  });

  it("finds execute(address,uint256,bytes) only in its shifted PUSH4 form", () => {
    expect(readFix("evm/sweeper_v2_runtime.hex").includes("b61d27f6")).toBe(false);
    expect(v2.selectors.some((s) => s.selector === "0xb61d27f6")).toBe(true);
  });

  it("tells v1 from v2: v1 has no callExecute", () => {
    expect(v1.selectors.map((s) => s.selector)).not.toContain("0x043ff9d2");
    expect(v1.sweeperLike).toBe(true);
    expect(lookupCodehash(v1.codehash)?.label).toMatch(/v1/);
  });

  it("every registry codehash belongs to a bundled bytecode or is absent", () => {
    const crime = fingerprintCode(
      readFileSync(new URL("../fixtures/registry/crimeenjoyor_runtime.hex", import.meta.url), "utf8").trim(),
    );
    for (const d of DELEGATES.filter((e) => e.codehash))
      expect([v1.codehash, v2.codehash, crime.codehash]).toContain(d.codehash);
  });
});

describe("the wallet, block by block", () => {
  const w = JSON.parse(readFix("evm/wallet_blocks.json")) as {
    rows: [number, number, number][];
    delegated: [number, number];
  };
  const at = new Map(w.rows.map((r) => [r[0], r]));

  it("agrees with the code and nonce timeline read from archive nodes", () => {
    const tl = JSON.parse(readFix("evm/code_nonce_timeline.json")).points as {
      block: number | string;
      nonce_after_block?: number;
    }[];
    for (const p of tl)
      if (typeof p.block === "number" && p.nonce_after_block) expect(at.get(p.block)![2]).toBe(p.nonce_after_block);
  });

  it("every own nonce follows the last, except the two an authorization consumed", () => {
    let skips = 0;
    for (let i = 1; i < w.rows.length; i++) {
      const [block, txs, after] = w.rows[i]!;
      const before = w.rows[i - 1]![2];
      expect(after - before).toBe(txs + (block === 26300753 || block === 26301896 ? 1 : 0));
      if (block === 26300753 || block === 26301896) skips++;
    }
    expect(skips).toBe(2);
  });

  it("shows the throughput change: at most 8 per block before, 1 while delegated, 28 after", () => {
    const max = (a: number, b: number) => Math.max(...w.rows.filter((r) => r[0] >= a && r[0] <= b).map((r) => r[1]));
    expect(max(26300485, 26300752)).toBe(8);
    expect(max(26300754, 26301895)).toBe(1);
    expect(max(26301897, 26302570)).toBe(28);
  });

  it("decodes every onward transfer from its bundled bytes and sums what reached each collector", () => {
    const o = loadIncident().onward;
    expect(o.transfers.map((t) => [t.eth, t.to.toLowerCase(), t.bytes])).toEqual([
      ["195460", "0x8532fa14acaf483729c449b8458aeddb900543d4", 120],
      ["2000", "0x8532fa14acaf483729c449b8458aeddb900543d4", 120],
      ["17260", "0x03b0ee5d82990cff1bda48651ac3e436d1a020ea", 113],
    ]);
    const into = (c: string, from: string) =>
      o.inflows.find((r) => r.collector === c && r.from.toLowerCase().startsWith(from.toLowerCase()))!;
    expect(into("R1", "0x28c6").eth).toBe("169534.002601469787170247");
    expect(into("R1", "0x28c6").usdt).toBe("1819724910.565362");
    expect(into("R1", "0xdfd5")).toMatchObject({ via: "signed transfers", eth: "28005.6", usdt: "55739800.5" });
    expect(into("R1", "0xee7a").usdc).toBe("823000000");
    expect(into("R2", "0x28c6").eth).toBe("3090.401960150360151765");
    const wei = (v: string) => BigInt(v.split(".")[0]!) * 10n ** 18n + BigInt((v.split(".")[1] ?? "").padEnd(18, "0"));
    const viaDelegation = o.inflows.filter((r) => r.via === "delegation").reduce((s, r) => s + wei(r.eth), 0n);
    expect(viaDelegation).toBe(wei(loadIncident().totals.eth));
  });

  it("sums own transactions from the same nonce-checked rows", () => {
    const t = loadIncident().throughput;
    const nonceAfter = (b: number) => w.rows.find((r) => r[0] === b)![2];
    const firstRow = w.rows[0]!;
    expect(t.before.txs).toBe(nonceAfter(26300752) - (firstRow[2] - firstRow[1]));
    expect(t.during.txs).toBe(nonceAfter(26301895) - nonceAfter(26300753));
    expect(t.after.txs).toBe(nonceAfter(t.after.to) - nonceAfter(26301896));
    expect([t.before.txs, t.during.txs, t.after.txs]).toEqual([554, 93, 291]);
    expect([t.before.maxPerBlock, t.during.maxPerBlock, t.after.maxPerBlock]).toEqual([8, 1, 28]);
    expect(t.during.blocks).toBe(1142);
  });
});
