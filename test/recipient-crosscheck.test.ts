import { describe, expect, it } from "vitest";
import type { Chain } from "../src/evm/chains.ts";
import { checkRecipient } from "../src/evm/recipient.ts";
import { rpcBatchAll } from "../src/evm/rpc.ts";

const TO = "0x28C6c06298d514Db089934071355E5743bf21d60";
const DELEGATED = "0xef010063e842b054bd624a465454d533c33f573e9c6fae";
const A = "https://a.example/v2/SECRETKEY";
const B = "https://b.example/rpc";
const C = "https://c.example/rpc";
const eth: Chain = { id: 1, key: "ethereum", name: "Ethereum", rpc: [A, B, C], explorer: "https://eth.blockscout.com" };
const word = (b: boolean) => "0x" + (b ? "1" : "0").padStart(64, "0");

/** Per endpoint: the recipient's code (null: down) and whether its blacklist calls say true. */
function endpoints(code: Record<string, string | null>, blacklisted: Record<string, boolean> = {}) {
  const fetch = (async (url: string | URL, init?: RequestInit) => {
    const c = code[String(url)];
    if (c === null || c === undefined) return new Response("", { status: 503 });
    const calls = JSON.parse(String(init?.body)) as { id: number; method: string }[];
    return new Response(
      JSON.stringify(
        calls.map((x) => ({
          jsonrpc: "2.0",
          id: x.id,
          result: x.method === "eth_getCode" ? c : word(blacklisted[String(url)] ?? false),
        })),
      ),
    );
  }) as typeof globalThis.fetch;
  return fetch;
}

describe("recipient --cross-check", () => {
  it("by default sends when the first endpoint says no code", async () => {
    const r = await checkRecipient(TO, { chain: eth, fetch: endpoints({ [A]: "0x", [B]: DELEGATED, [C]: DELEGATED }) });
    expect(r.allow).toBe(true);
  });

  it("holds when any endpoint sees a delegation, and says the endpoints disagree", async () => {
    const r = await checkRecipient(TO, {
      chain: eth,
      crossCheck: true,
      fetch: endpoints({ [A]: "0x", [B]: DELEGATED, [C]: "0x" }),
    });
    expect(r.allow).toBe(false);
    expect(r.delegate?.toLowerCase()).toBe("0x63e842b054bd624a465454d533c33f573e9c6fae");
    expect(r.reasons.map((x) => x.code)).toEqual(["DELEGATED_TO_MALICIOUS", "ENDPOINTS_DISAGREE"]);
    expect(r.reasons[1]!.message).toContain("https://b.example 0xef010063e8…");
    expect(r.reasons[1]!.message).not.toContain("SECRETKEY");
  });

  it("holds on a disagreement even when the delegate is one you allowed", async () => {
    const r = await checkRecipient(TO, {
      chain: eth,
      crossCheck: true,
      allowDelegates: ["0x63e842B054Bd624a465454D533C33F573e9c6fAe"],
      fetch: endpoints({ [A]: "0x", [B]: DELEGATED, [C]: DELEGATED }),
    });
    expect(r.reasons.map((x) => x.code)).toContain("ENDPOINTS_DISAGREE");
    expect(r.allow).toBe(false);
  });

  it("sends when every endpoint that answered agrees, and counts a blacklist hit from any of them", async () => {
    const ok = await checkRecipient(TO, {
      chain: eth,
      crossCheck: true,
      fetch: endpoints({ [A]: null, [B]: "0x", [C]: "0x" }),
    });
    expect(ok.allow).toBe(true);
    expect(ok.blacklists).toEqual({ usdt: false, usdc: false });
    const listed = await checkRecipient(TO, {
      chain: eth,
      crossCheck: true,
      fetch: endpoints({ [A]: "0x", [B]: "0x", [C]: "0x" }, { [C]: true }),
    });
    expect(listed.reasons.map((x) => x.code)).toEqual(["USDT_BLACKLISTED", "USDC_BLACKLISTED"]);
  });

  it("fails when no endpoint answers, and names hosts only", async () => {
    await expect(checkRecipient(TO, { chain: eth, crossCheck: true, fetch: endpoints({}) })).rejects.toThrow(
      /every endpoint failed/,
    );
    await expect(
      rpcBatchAll([A], [{ method: "eth_chainId", params: [] }], { fetch: endpoints({}) }),
    ).rejects.not.toThrow(/SECRETKEY/);
  });
});
