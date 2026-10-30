import { describe, expect, it } from "vitest";
import type { Chain } from "../src/evm/chains.ts";
import { scanAddresses } from "../src/evm/scan.ts";

const B14 = "0x28C6c06298d514Db089934071355E5743bf21d60";
const DELEGATE = "0x63e842b054bd624a465454d533c33f573e9c6fae";
const DELEGATED = `0xef0100${DELEGATE.slice(2)}`;
const A = "https://a.example/v2/SECRETKEY";
const B = "https://b.example/rpc";
const C = "https://c.example/rpc";
const eth: Chain[] = [
  { id: 1, key: "ethereum", name: "Ethereum", rpc: [A, B, C], explorer: "https://eth.blockscout.com" },
];

/** Each endpoint's eth_getCode answer for B14 (null: the endpoint is down); delegate code is empty everywhere. */
function endpoints(code: Record<string, string | null>) {
  const asked: string[] = [];
  const fetch = (async (url: string | URL, init?: RequestInit) => {
    asked.push(String(url));
    const answer = code[String(url)];
    if (answer === null || answer === undefined) return new Response("", { status: 503 });
    const calls = JSON.parse(String(init?.body)) as { id: number; method: string; params: string[] }[];
    const out = calls.map((c) => ({
      jsonrpc: "2.0",
      id: c.id,
      result:
        c.method === "eth_getTransactionCount"
          ? "0x1209df9"
          : c.params[0]!.toLowerCase() === B14.toLowerCase()
            ? answer
            : "0x",
    }));
    return new Response(JSON.stringify(out));
  }) as typeof globalThis.fetch;
  return { fetch, asked };
}

describe("scan --cross-check", () => {
  it("by default trusts the first endpoint that answers", async () => {
    const { fetch, asked } = endpoints({ [A]: "0x", [B]: DELEGATED, [C]: DELEGATED });
    const r = await scanAddresses([B14], { chains: eth, fetch });
    expect(r.rows[0]!.state).toBe("eoa");
    expect(r.exitCode).toBe(0);
    expect(asked).toEqual([A]);
  });

  it("with crossCheck, one endpoint that sees the delegation is enough, and the row says who said what", async () => {
    const { fetch } = endpoints({ [A]: "0x", [B]: DELEGATED, [C]: "0x" });
    const r = await scanAddresses([B14], { chains: eth, fetch, crossCheck: true });
    expect(r.rows[0]).toMatchObject({ state: "delegated", nonce: 18914809n });
    expect(r.rows[0]!.delegate!.toLowerCase()).toBe(DELEGATE);
    expect(r.rows[0]!.disagreement).toEqual([
      { endpoint: "https://a.example", code: "0x" },
      { endpoint: "https://b.example", code: DELEGATED },
      { endpoint: "https://c.example", code: "0x" },
    ]);
    expect(r.rows[0]!.entry?.verdict).toBe("malicious");
    expect(r.exitCode).toBe(2);
  });

  it("adds nothing when the endpoints agree, and rides out the ones that are down", async () => {
    const same = await scanAddresses([B14], {
      chains: eth,
      fetch: endpoints({ [A]: "0x", [B]: "0x", [C]: "0x" }).fetch,
      crossCheck: true,
    });
    expect(same.rows[0]).toMatchObject({ state: "eoa" });
    expect(same.rows[0]!.disagreement).toBeUndefined();
    const down = await scanAddresses([B14], {
      chains: eth,
      fetch: endpoints({ [A]: null, [B]: DELEGATED, [C]: null }).fetch,
      crossCheck: true,
    });
    expect(down.rows[0]!.state).toBe("delegated");
    expect(down.rows[0]!.disagreement).toBeUndefined();
  });

  it("reports contract code one endpoint sees over another's 0x", async () => {
    const r = await scanAddresses([B14], {
      chains: eth,
      fetch: endpoints({ [A]: "0x", [B]: "0x6080", [C]: "0x" }).fetch,
      crossCheck: true,
    });
    expect(r.rows[0]!.state).toBe("contract");
    expect(r.rows[0]!.disagreement).toHaveLength(3);
  });

  it("skips an endpoint's malformed answer and errors only when none answered", async () => {
    const odd = await scanAddresses([B14], {
      chains: eth,
      fetch: endpoints({ [A]: "nonsense", [B]: DELEGATED, [C]: DELEGATED }).fetch,
      crossCheck: true,
    });
    expect(odd.rows[0]!.state).toBe("delegated");
    const none = await scanAddresses([B14], { chains: eth, fetch: endpoints({}).fetch, crossCheck: true });
    expect(none.rows[0]!.state).toBe("error");
    expect(none.exitCode).toBe(69);
  });
});
