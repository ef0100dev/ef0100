import { request } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bytesToHex } from "../src/evm/bytes.ts";
import { authorizationDigest, authorizationPreimage } from "../src/evm/eip7702.ts";
import { Guard, profiles } from "../src/guard/policy.ts";
import { createGuardServer, MAX_BODY } from "../src/guard/serve.ts";

const B14 = "0x28C6c06298d514Db089934071355E5743bf21d60";
const auth = { chainId: 1n, address: "0x63e842B054Bd624a465454D533C33F573e9c6fAe", nonce: 18914809n };
const pre = bytesToHex(authorizationPreimage(auth));
const digest = bytesToHex(authorizationDigest(auth));
const clear = bytesToHex(authorizationPreimage({ ...auth, address: "0x0000000000000000000000000000000000000000" }));

const server = createGuardServer(new Guard(profiles.hotWallet), { version: "test" });
let port = 0;
beforeAll(
  () =>
    new Promise<void>((r) =>
      server.listen(0, "127.0.0.1", () => ((port = (server.address() as AddressInfo).port), r())),
    ),
);
afterAll(() => new Promise<void>((r) => server.close(() => r())));

function call(opts: { method?: string; path?: string; body?: string; headers?: Record<string, string> }) {
  return new Promise<{ status: number; json: Record<string, unknown> }>((resolve, reject) => {
    const req = request(
      {
        host: "127.0.0.1",
        port,
        method: opts.method ?? "POST",
        path: opts.path ?? "/check",
        headers: { host: `127.0.0.1:${port}`, "content-type": "application/json", ...opts.headers },
      },
      (res) => {
        let text = "";
        res.on("data", (c) => (text += c));
        res.on("end", () => resolve({ status: res.statusCode!, json: JSON.parse(text) }));
      },
    );
    req.on("error", reject);
    req.end(opts.body);
  });
}

describe("guard serve", () => {
  it("refuses tuple #15 with the reasons the library gives", async () => {
    const r = await call({ body: JSON.stringify({ preimage: pre, signer: B14, nonce: "18914809" }) });
    expect(r.status).toBe(200);
    expect(r.json.allow).toBe(false);
    expect(r.json.kind).toBe("eip7702-authorization");
    expect((r.json.reasons as { code: string }[]).map((x) => x.code)).toContain("DELEGATE_NOT_ALLOWED");
  });

  it("refuses a bare digest and checks a digest against its preimage", async () => {
    const bare = await call({ body: JSON.stringify({ digest, signer: B14, nonce: 18914809 }) });
    expect((bare.json.reasons as { code: string }[])[0]!.code).toBe("NO_PREIMAGE");
    const wrong = await call({ body: JSON.stringify({ digest, preimage: clear, signer: B14, nonce: 18914809 }) });
    expect((wrong.json.reasons as { code: string }[]).map((x) => x.code)).toContain("PREIMAGE_MISMATCH");
  });

  it("signs the wallet's own clear", async () => {
    const r = await call({ body: JSON.stringify({ preimage: clear, signer: B14, nonce: "0x1209df9", ownCode: "0x" }) });
    expect(r.json.allow).toBe(true);
  });

  it("refuses a request that does not say what the key's own code is, under the hot-wallet profile", async () => {
    const r = await call({ body: JSON.stringify({ preimage: clear, signer: B14, nonce: "0x1209df9" }) });
    expect(r.json.allow).toBe(false);
    expect((r.json.reasons as { code: string }[]).map((x) => x.code)).toContain("CONTEXT_MISSING");
  });

  it("refuses another Host and any browser Origin (DNS rebinding)", async () => {
    const body = JSON.stringify({ preimage: clear, signer: B14, nonce: 1 });
    expect((await call({ body, headers: { host: `evil.example:${port}` } })).status).toBe(403);
    expect((await call({ body, headers: { origin: "https://evil.example" } })).status).toBe(403);
  });

  it("answers malformed requests with 400, 404, 405 and 413, never with a decision", async () => {
    expect((await call({ body: "not json" })).status).toBe(400);
    expect((await call({ body: JSON.stringify({ preimage: "0x123" }) })).status).toBe(400);
    expect((await call({ body: JSON.stringify({ preimage: pre, nonce: -1 }) })).status).toBe(400);
    expect((await call({ body: JSON.stringify({}) })).status).toBe(400);
    expect((await call({ path: "/sign", body: "{}" })).status).toBe(404);
    expect((await call({ method: "GET" })).status).toBe(405);
    expect((await call({ body: "x".repeat(MAX_BODY + 1) })).status).toBe(413);
  });

  it("reports health", async () => {
    const r = await call({ method: "GET", path: "/health" });
    expect(r.json).toEqual({ ok: true, version: "test" });
  });
});
