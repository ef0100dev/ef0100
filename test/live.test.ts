import { describe, expect, it } from "vitest";
import { CHAINS, withRpcOverrides } from "../src/evm/chains.ts";
import { delegationCode } from "../src/evm/eip7702.ts";
import { inspectTransaction } from "../src/evm/inspect.ts";
import { redactRpc } from "../src/evm/rpc.ts";
import { scanAddresses } from "../src/evm/scan.ts";
import { mockRpc, rawFix, readFix } from "./helpers.ts";

const ATTACK = "0xad99264d5532ae0dd04b2004eebda05f25657e70dacb764f7ac8d4ccd051298b";
const B14 = "0x28C6c06298d514Db089934071355E5743bf21d60";
const SWEEPER = "0x63e842B054Bd624a465454D533C33F573e9c6fAe";
const eth = CHAINS.filter((c) => c.key === "ethereum");

describe("decode against a live-shaped RPC", () => {
  const block = JSON.parse(readFix("evm/block_26300753.json"));

  it("rebuilds the authority's nonce from the previous block plus its own earlier tx in the same block", async () => {
    const { fetch, calls } = mockRpc((method, params) => {
      switch (method) {
        case "eth_getRawTransactionByHash":
          return rawFix(ATTACK);
        case "eth_getTransactionByHash":
          return { hash: ATTACK, blockNumber: "0x1915151", transactionIndex: "0x8a", type: "0x4" };
        case "eth_getTransactionCount":
          expect(params).toEqual([B14, "0x1915150"]);
          return "0x1209df8";
        case "eth_getCode":
          return "0x";
        case "eth_getBalance":
          return "0x0";
        case "eth_getBlockByNumber":
          return block;
      }
      throw new Error(`unexpected ${method}`);
    });
    const res = await inspectTransaction(ATTACK, { chain: eth[0], fetch, watch: [B14] });
    expect(res.mined).toEqual({ block: 26_300_753n, index: 138 });
    expect(res.state.get(B14.toLowerCase())!.nonce).toBe(18_914_809n);
    expect(res.result!.applied.map((o) => o.index)).toEqual([15]);
    expect(res.findings.map((f) => f.code)).toContain("NONCE_SPRAY");
    expect(calls.some((c) => c.method === "eth_getBlockByNumber")).toBe(true);
  });

  it("still reports static findings when no endpoint serves history", async () => {
    const { fetch } = mockRpc((method) => {
      if (method === "eth_getRawTransactionByHash") return rawFix(ATTACK);
      if (method === "eth_getTransactionByHash")
        return { hash: ATTACK, blockNumber: "0x1915151", transactionIndex: "0x8a" };
      throw new Error("archive requests require a token");
    });
    const res = await inspectTransaction(ATTACK, { chain: eth[0], fetch });
    expect(res.result).toBeUndefined();
    expect(res.findings.map((f) => f.code)).toContain("NONCE_SPRAY");
    expect(res.notes.join(" ")).toMatch(/not simulated/);
  });
});

describe("scan", () => {
  const two = CHAINS.filter((c) => c.key === "ethereum" || c.key === "base");

  it("exit 2 for the sweeper, with the registry label and the delegate's code read", async () => {
    const { fetch } = mockRpc((method, params) => {
      const [addr] = params as string[];
      if (method === "eth_getTransactionCount") return "0x1209e10";
      if (method === "eth_getCode")
        return addr!.toLowerCase() === B14.toLowerCase()
          ? delegationCode(SWEEPER)
          : readFix("evm/sweeper_v2_runtime.hex").trim();
      throw new Error(method);
    });
    const res = await scanAddresses([B14], { chains: eth, fetch });
    expect(res.exitCode).toBe(2);
    expect(res.rows[0]).toMatchObject({ state: "delegated", delegate: SWEEPER });
    expect(res.rows[0]!.entry!.verdict).toBe("malicious");
    expect(res.rows[0]!.delegateCode!.sweeperLike).toBe(true);
  });

  it("exit 0 when clean, 69 when a chain does not answer, and --allow ignores a chosen delegate", async () => {
    const clean = mockRpc((m) => (m === "eth_getCode" ? "0x" : "0x5"));
    expect((await scanAddresses([B14], { chains: two, fetch: clean.fetch })).exitCode).toBe(0);
    const down = mockRpc(() => {
      throw new Error("down");
    });
    expect((await scanAddresses([B14], { chains: two, fetch: down.fetch })).exitCode).toBe(69);
    const chosen = mockRpc((m, p) =>
      m === "eth_getCode"
        ? (p as string[])[0]!.toLowerCase() === B14.toLowerCase()
          ? delegationCode("0x4Cd241E8d1510e30b2076397afc7508Ae59C66c9")
          : "0x60"
        : "0x1",
    );
    expect((await scanAddresses([B14], { chains: eth, fetch: chosen.fetch })).exitCode).toBe(1);
    expect(
      (
        await scanAddresses([B14], {
          chains: eth,
          fetch: chosen.fetch,
          allow: ["0x4Cd241E8d1510e30b2076397afc7508Ae59C66c9"],
        })
      ).exitCode,
    ).toBe(0);
  });
});

describe("your own RPC", () => {
  it("goes first, from EF0100_RPC_<CHAIN> or an override, and never prints its key", () => {
    const url = "https://eth-mainnet.g.alchemy.com/v2/abcdefghijklmnopqrstuvwxyz012345";
    const chains = withRpcOverrides(CHAINS, { EF0100_RPC_ETHEREUM: url });
    expect(chains[0]!.rpc[0]).toBe(url);
    expect(chains[0]!.archive![0]).toBe(url);
    expect(withRpcOverrides(CHAINS, {}, { base: url }).find((c) => c.key === "base")!.rpc[0]).toBe(url);
    expect(redactRpc(url)).toBe("https://eth-mainnet.g.alchemy.com");
    expect(redactRpc("https://rpc.example/?key=secret")).toBe("https://rpc.example");
  });
});
