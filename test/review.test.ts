import { readFileSync } from "node:fs";
import { base58 } from "@scure/base";
import { describe, expect, it } from "vitest";
import { bytesToHex, concatBytes, hexToBytes, keccak256 } from "../src/evm/bytes.ts";
import { CHAINS } from "../src/evm/chains.ts";
import { analyzeAuthorizationList } from "../src/evm/authlist.ts";
import { delegationCode } from "../src/evm/eip7702.ts";
import { fingerprintCode } from "../src/evm/fingerprint.ts";
import { inspectTransaction } from "../src/evm/inspect.ts";
import { checkRecipient } from "../src/evm/recipient.ts";
import { lookupCodehash } from "../src/evm/registry.ts";
import { rlpEncode } from "../src/evm/rlp.ts";
import { cleanText, redactRpc } from "../src/evm/rpc.ts";
import { scanAddresses } from "../src/evm/scan.ts";
import { decodeTransaction } from "../src/evm/tx.ts";
import { getSolanaTransaction } from "../src/sol/rpc.ts";
import { mockRpc, rawFix, readFix } from "./helpers.ts";

const ATTACK = "0xad99264d5532ae0dd04b2004eebda05f25657e70dacb764f7ac8d4ccd051298b";
const B14 = "0x28C6c06298d514Db089934071355E5743bf21d60";
const R1 = "0x5227f603C1eE34CE3C06eFe6477003BDfCCB2f8c";
const chain = (key: string) => CHAINS.find((c) => c.key === key)!;
const attack = decodeTransaction(rawFix(ATTACK));

describe("recipient reads each chain's own blacklists and never reports an unread one as clean", () => {
  it("flags R1 on Avalanche through Tether's isBlocked, and says what it did not read on BNB Chain", async () => {
    const { fetch, calls } = mockRpc((method, params) => {
      if (method === "eth_getCode") return "0x";
      const { data } = (params as [{ data: string }])[0];
      return data.startsWith("0xfbac3951") ? `0x${"0".repeat(63)}1` : `0x${"0".repeat(64)}`;
    });
    const avax = await checkRecipient(R1, { chain: chain("avalanche"), fetch });
    expect(avax.allow).toBe(false);
    expect(avax.reasons.map((r) => r.code)).toEqual(["USDT_BLACKLISTED"]);
    expect(avax.blacklists).toEqual({ usdt: true, usdc: false });
    expect(calls.some((c) => JSON.stringify(c.params).includes("0xfbac3951"))).toBe(true);
    const bsc = await checkRecipient(R1, { chain: chain("bsc"), fetch });
    expect(bsc.allow).toBe(true);
    expect(bsc.blacklists).toEqual({ usdt: null, usdc: null });
  });

  it("treats a blacklist call that fails as unread", async () => {
    const { fetch } = mockRpc((method) => {
      if (method === "eth_getCode") return "0x";
      throw new Error("execution reverted");
    });
    const r = await checkRecipient(R1, { chain: chain("ethereum"), fetch });
    expect(r.blacklists).toEqual({ usdt: null, usdc: null });
  });
});

describe("fingerprints survive odd bytecode", () => {
  it("stops at a PUSH20 that runs past the end instead of throwing", () => {
    const code = concatBytes(hexToBytes("0x6080604052"), Uint8Array.of(0x73), new Uint8Array(9));
    expect(() => fingerprintCode(code)).not.toThrow();
  });

  it("does not read ASCII text as an address, and does not call an ERC-20 token sweeper-like", () => {
    const text = new TextEncoder().encode("ERC20: insufficient!");
    const token = concatBytes(
      ...["0x18160ddd", "0x70a08231", "0xa9059cbb"].map((s) => concatBytes(Uint8Array.of(0x63), hexToBytes(s))),
      Uint8Array.of(0x73),
      text,
      Uint8Array.of(0x33),
    );
    const f = fingerprintCode(token);
    expect(f.hardcodedAddresses).toEqual([]);
    expect(f.traits).toContain("ERC20_TOKEN");
    expect(f.sweeperLike).toBe(false);
  });

  it("knows CrimeEnjoyor by its codehash", () => {
    const code = readFileSync(new URL("../fixtures/registry/crimeenjoyor_runtime.hex", import.meta.url), "utf8").trim();
    expect(lookupCodehash(fingerprintCode(code).codehash)?.verdict).toBe("malicious");
  });
});

describe("scan keeps going when one chain or one delegate misbehaves", () => {
  it("turns a malformed answer into error rows for that chain only", async () => {
    const { fetch } = mockRpc((method, params) => {
      if (method === "eth_getTransactionCount") return "not-a-number";
      if (method === "eth_getCode") return "0x";
      throw new Error(String(params));
    });
    const res = await scanAddresses([B14], { chains: [chain("ethereum")], fetch });
    expect(res.rows[0]!.state).toBe("error");
    expect(res.exitCode).toBe(69);
  });

  it("matches a sweeper's codehash even when a second delegate's code cannot be walked", async () => {
    const odd = `0x6080${"73"}${"00".repeat(5)}`;
    const v2 = readFix("evm/sweeper_v2_runtime.hex").trim();
    const OTHER = "0x00000000000000000000000000000000000Ca11B";
    const { fetch } = mockRpc((method, params) => {
      const [addr] = params as string[];
      if (method === "eth_getTransactionCount") return "0x1";
      if (addr!.toLowerCase() === B14.toLowerCase())
        return delegationCode("0x63e842B054Bd624a465454D533C33F573e9c6fAe");
      if (addr!.toLowerCase() === OTHER.toLowerCase())
        return delegationCode("0x000000005c84f8fd50b21cac312528a64437030e");
      if (addr!.toLowerCase() === "0x63e842b054bd624a465454d533c33f573e9c6fae") return v2;
      return odd;
    });
    const res = await scanAddresses([B14, OTHER], { chains: [chain("ethereum")], fetch });
    expect(res.exitCode).toBe(2);
  });
});

describe("decode", () => {
  it("looks raw bytes up by their hash and replays a mined transaction against the state it ran on", async () => {
    const block = JSON.parse(readFix("evm/block_26300753.json"));
    const { fetch, calls } = mockRpc((method) => {
      if (method === "eth_getTransactionByHash")
        return { hash: ATTACK, blockNumber: "0x1915151", transactionIndex: "0x8a", type: "0x4" };
      if (method === "eth_getTransactionCount") return "0x1209df8";
      if (method === "eth_getCode") return "0x";
      if (method === "eth_getBalance") return "0x1";
      if (method === "eth_getBlockByNumber") return block;
      throw new Error(method);
    });
    const res = await inspectTransaction(rawFix(ATTACK), { chain: chain("ethereum"), fetch });
    expect(calls.some((c) => c.method === "eth_getTransactionByHash")).toBe(true);
    expect(res.mined).toEqual({ block: 26_300_753n, index: 138 });
    expect(res.result!.applied.map((o) => o.index)).toEqual([15]);
    expect(res.notes.join(" ")).not.toMatch(/not mined/);
  });

  it("refuses to read a transaction's state from a chain the caller chose when it names another", async () => {
    const { fetch } = mockRpc(() => null);
    await expect(
      inspectTransaction(rawFix(ATTACK), { chain: chain("base"), chainLocked: true, fetch }),
    ).rejects.toThrow(/chain id 1/);
  });

  it("decodes a blob transaction in its network form to the canonical hash, and refuses one without a destination", () => {
    const body = [
      hexToBytes("0x01"),
      new Uint8Array(0),
      hexToBytes("0x01"),
      hexToBytes("0x02"),
      hexToBytes("0x5208"),
      hexToBytes(`0x${"11".repeat(20)}`),
      new Uint8Array(0),
      new Uint8Array(0),
      [],
      hexToBytes("0x01"),
      [hexToBytes(`0x01${"00".repeat(31)}`)],
      new Uint8Array(0),
      hexToBytes(`0x${"22".repeat(32)}`),
      hexToBytes(`0x${"33".repeat(32)}`),
    ];
    const canonical = concatBytes(Uint8Array.of(3), rlpEncode(body));
    const wrapped = concatBytes(Uint8Array.of(3), rlpEncode([body, [], [], []]));
    expect(decodeTransaction(wrapped).hash).toBe(bytesToHex(keccak256(canonical)));
    const noTo = [...body];
    noTo[5] = new Uint8Array(0);
    expect(() => decodeTransaction(concatBytes(Uint8Array.of(3), rlpEncode(noTo)))).toThrow(/destination/);
  });
});

describe("nonce spray", () => {
  const sprayOf = (indexes: number[]) => {
    const tx = { ...attack, authorizationList: indexes.map((i) => attack.authorizationList[i]!) };
    return analyzeAuthorizationList(tx).find((f) => f.code === "NONCE_SPRAY");
  };

  it("stays critical when the run has a gap or a repeated tuple", () => {
    const all = [...Array(50).keys()];
    expect(sprayOf(all)?.severity).toBe("critical");
    expect(sprayOf(all.filter((i) => i !== 20))?.severity).toBe("critical");
    expect(sprayOf([...all, 15])?.severity).toBe("critical");
  });

  it("describes what each order does", () => {
    expect(sprayOf([0, 1, 2])!.message).toMatch(/descending order, so at most one applies/);
    expect(sprayOf([2, 1, 0])!.message).toMatch(/ascending order, so every tuple from the live nonce upward applies/);
  });
});

describe("endpoints never leak keys or terminal escapes", () => {
  it("prints the host only and strips control characters from what an endpoint returns", () => {
    expect(redactRpc("https://user:pass@rpc.example/v2/short-key?x=1")).toBe("https://rpc.example");
    expect(cleanText("bad \u001b]52;c;cHduZWQ=\u0007 at https://rpc.example/v2/k")).toBe(
      "bad ?]52;c;cHduZWQ=? at https://rpc.example",
    );
  });

  it("refuses a Solana transaction that is not the one the signature names", async () => {
    const cases = JSON.parse(readFileSync(new URL("../fixtures/solana/cases.json", import.meta.url), "utf8")).cases as {
      base64: string;
    }[];
    const first = Buffer.from(cases[0]!.base64, "base64");
    const sigOfFirst = base58.encode(first.subarray(1, 65));
    const { fetch } = mockRpc(() => ({
      slot: 1,
      blockTime: null,
      transaction: [cases[1]!.base64, "base64"],
      meta: null,
    }));
    await expect(getSolanaTransaction(sigOfFirst, ["https://sol.example"], { fetch })).rejects.toThrow(
      /different transaction/,
    );
  });
});
