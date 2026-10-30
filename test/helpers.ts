import { readFileSync, readdirSync } from "node:fs";

export const FIX = new URL("../fixtures/2026-10-29/", import.meta.url);
export const readFix = (p: string) => readFileSync(new URL(p, FIX), "utf8");
export const rawFix = (hash: string) => readFix(`raw/${hash}.rlp.hex`).trim();
export const rawFiles = () => readdirSync(new URL("raw/", FIX)).filter((f) => f.endsWith(".rlp.hex"));

type Handler = (method: string, params: unknown[]) => unknown;

/** A fetch that answers JSON-RPC batches from a handler, and records every call it saw. */
export function mockRpc(handler: Handler) {
  const calls: { url: string; method: string; params: unknown[] }[] = [];
  const f = (async (url: string | URL, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body)) as { id: number; method: string; params: unknown[] }[];
    const out = body.map((c) => {
      calls.push({ url: String(url), method: c.method, params: c.params });
      try {
        return { jsonrpc: "2.0", id: c.id, result: handler(c.method, c.params) };
      } catch (e) {
        return { jsonrpc: "2.0", id: c.id, error: { code: -32000, message: (e as Error).message } };
      }
    });
    return new Response(JSON.stringify(out), { status: 200, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  return { fetch: f, calls };
}
