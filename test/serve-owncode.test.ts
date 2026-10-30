import { request } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bytesToHex } from "../src/evm/bytes.ts";
import { authorizationPreimage } from "../src/evm/eip7702.ts";
import { Guard, profiles } from "../src/guard/policy.ts";
import { createGuardServer } from "../src/guard/serve.ts";

const B14 = "0x28C6c06298d514Db089934071355E5743bf21d60";
const DELEGATED = "0xef010063e842b054bd624a465454d533c33f573e9c6fae";
const auth = { chainId: 1n, address: "0x63e842B054Bd624a465454D533C33F573e9c6fAe", nonce: 18914809n };
const pre = bytesToHex(authorizationPreimage(auth));
const clear = bytesToHex(authorizationPreimage({ ...auth, address: "0x0000000000000000000000000000000000000000" }));
const A = "https://a.example/v2/SECRETKEY";
const B = "https://b.example/rpc";
const C = "https://c.example/rpc";

/** Endpoint answers by URL, changeable between tests; every eth_getCode call is counted. */
const state: { answers: Record<string, string | null>; calls: string[] } = { answers: {}, calls: [] };
const fetch = (async (url: string | URL, init?: RequestInit) => {
  state.calls.push(String(url));
  const code = state.answers[String(url)];
  if (code === null || code === undefined) return new Response("", { status: 503 });
  const [call] = JSON.parse(String(init?.body)) as { id: number; params: unknown[] }[];
  expect(call!.params[0]).toBe(B14);
  return new Response(JSON.stringify([{ jsonrpc: "2.0", id: call!.id, result: code }]));
}) as typeof globalThis.fetch;

const server = createGuardServer(new Guard(profiles.hotWallet), {
  version: "test",
  ownCode: { urls: [A, B, C], quorum: 2, fetch },
});
let port = 0;
beforeAll(
  () =>
    new Promise<void>((r) =>
      server.listen(0, "127.0.0.1", () => ((port = (server.address() as AddressInfo).port), r())),
    ),
);
afterAll(() => new Promise<void>((r) => server.close(() => r())));

async function check(body: Record<string, unknown>, answers: Record<string, string | null>) {
  state.answers = answers;
  state.calls = [];
  const text = JSON.stringify(body);
  return new Promise<{ status: number; json: Record<string, unknown> }>((resolve, reject) => {
    const req = request(
      {
        host: "127.0.0.1",
        port,
        method: "POST",
        path: "/check",
        headers: { host: `127.0.0.1:${port}`, "content-type": "application/json" },
      },
      (res) => {
        let t = "";
        res.on("data", (c) => (t += c));
        res.on("end", () => resolve({ status: res.statusCode!, json: JSON.parse(t) }));
      },
    );
    req.on("error", reject);
    req.end(text);
  });
}
const reasons = (r: { json: Record<string, unknown> }) => (r.json.reasons as { code: string }[]).map((x) => x.code);
const all = (code: string | null) => ({ [A]: code, [B]: code, [C]: code });

describe("guard serve with its own endpoints", () => {
  it("reads the signer's own code itself and signs the clear when every endpoint says 0x", async () => {
    const r = await check({ preimage: clear, signer: B14, nonce: "0x1209df9" }, all("0x"));
    expect(r.json.allow).toBe(true);
    expect(state.calls).toHaveLength(3);
    expect(r.json.ownCodeAnswers).toEqual([
      { endpoint: "https://a.example", code: "0x" },
      { endpoint: "https://b.example", code: "0x" },
      { endpoint: "https://c.example", code: "0x" },
    ]);
  });

  it("applies the own-code rule when the endpoints agree on a delegation", async () => {
    const r = await check({ preimage: pre, signer: B14, nonce: "18914809" }, all(DELEGATED));
    expect(r.json.allow).toBe(false);
    expect(reasons(r)[0]).toBe("OWN_CODE_PRESENT");
  });

  it("refuses with CONTEXT_MISSING when the endpoints disagree, even the clear", async () => {
    const r = await check(
      { preimage: clear, signer: B14, nonce: "0x1209df9" },
      { [A]: "0x", [B]: DELEGATED, [C]: DELEGATED },
    );
    expect(r.json.allow).toBe(false);
    expect(reasons(r)).toContain("CONTEXT_MISSING");
  });

  it("rides out one endpoint down under quorum 2, not two", async () => {
    const one = await check({ preimage: clear, signer: B14, nonce: "0x1209df9" }, { [A]: null, [B]: "0x", [C]: "0x" });
    expect(one.json.allow).toBe(true);
    const two = await check({ preimage: clear, signer: B14, nonce: "0x1209df9" }, { [A]: null, [B]: null, [C]: "0x" });
    expect(reasons(two)).toContain("CONTEXT_MISSING");
  });

  it("counts the request's own ownCode as one more answer, so a caller can't talk the endpoints down", async () => {
    const lie = await check({ preimage: pre, signer: B14, nonce: "18914809", ownCode: "0x" }, all(DELEGATED));
    expect(reasons(lie)).toContain("CONTEXT_MISSING");
    expect((lie.json.ownCodeAnswers as { endpoint: string }[]).at(-1)).toEqual({ endpoint: "request", code: "0x" });
    const same = await check({ preimage: clear, signer: B14, nonce: "0x1209df9", ownCode: "0x" }, all("0x"));
    expect(same.json.allow).toBe(true);
  });

  it("without a signer it asks no endpoint and refuses", async () => {
    const r = await check({ preimage: clear, nonce: "0x1209df9", ownCode: "0x" }, all("0x"));
    expect(state.calls).toEqual([]);
    expect(r.json.allow).toBe(false);
    expect(reasons(r)).toContain("CONTEXT_MISSING");
  });

  it("answers a malformed request with 400 before asking any endpoint", async () => {
    for (const body of [
      { preimage: "0x123", signer: B14 },
      { signer: B14 },
      { preimage: clear, signer: B14, nonce: -1 },
      { preimage: clear, signer: B14, ownCode: "zz" },
    ]) {
      const r = await check(body, all("0x"));
      expect(r.status).toBe(400);
      expect(state.calls).toEqual([]);
    }
  });

  it("refuses a configuration it could never satisfy", () => {
    const g = new Guard(profiles.hotWallet);
    expect(() => createGuardServer(g, { ownCode: { urls: [] } })).toThrow(TypeError);
    expect(() => createGuardServer(g, { ownCode: { urls: [A], quorum: 2 } })).toThrow(TypeError);
    expect(() => createGuardServer(g, { ownCode: { urls: [A, B], quorum: 0 } })).toThrow(TypeError);
  });
});
