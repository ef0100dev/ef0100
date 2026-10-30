import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { promisify } from "node:util";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const cli = new URL("../dist/cli.js", import.meta.url).pathname;
const run = promisify(execFile);
const B14 = "0x28C6c06298d514Db089934071355E5743bf21d60";
const DELEGATED = "0xef010063e842b054bd624a465454d533c33f573e9c6fae";

/** A JSON-RPC endpoint on 127.0.0.1 that answers every eth_getCode with `code`, or 503 when `code` is null. */
function endpoint(code: string | null): Promise<{ url: string; server: Server }> {
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      if (code === null) return res.writeHead(503).end();
      const calls = JSON.parse(body) as { id: number }[];
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(calls.map((c) => ({ jsonrpc: "2.0", id: c.id, result: code }))));
    });
  });
  return new Promise((ok) =>
    server.listen(0, "127.0.0.1", () =>
      ok({ url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, server }),
    ),
  );
}

async function owncode(...args: string[]) {
  try {
    const { stdout } = await run("node", [cli, "owncode", B14, "--json", ...args], { encoding: "utf8" });
    return { exit: 0, out: JSON.parse(stdout) };
  } catch (e) {
    const x = e as { code: number; stdout: string };
    return { exit: x.code, out: x.stdout ? JSON.parse(x.stdout) : null };
  }
}

describe.skipIf(!existsSync(cli))("ef0100 owncode", () => {
  const eps: Record<string, { url: string; server: Server }> = {};
  beforeAll(async () => {
    for (const [k, v] of [
      ["none1", "0x"],
      ["none2", "0x"],
      ["del1", DELEGATED],
      ["del2", DELEGATED],
      ["down", null],
    ] as const)
      eps[k] = await endpoint(v);
  });
  afterAll(() => Object.values(eps).forEach((e) => e.server.close()));
  const rpc = (...k: string[]) => k.flatMap((x) => ["--rpc", eps[x]!.url]);

  it("asks only the --rpc endpoints and exits 0 when they agree there is no code", async () => {
    const r = await owncode(...rpc("none1", "none2"));
    expect(r.exit).toBe(0);
    expect(r.out).toMatchObject({ confirmed: true, ownCode: "0x", quorum: 2 });
    expect(r.out.answers).toHaveLength(2);
  });

  it("exits 1 with the delegate when they agree on a designator", async () => {
    const r = await owncode(...rpc("del1", "del2"));
    expect(r.exit).toBe(1);
    expect(r.out).toMatchObject({
      confirmed: true,
      ownCode: DELEGATED,
      delegate: "0x63e842b054bd624a465454d533c33f573e9c6fae",
    });
  });

  it("exits 69 when one endpoint says no code and another sees a delegation", async () => {
    const r = await owncode(...rpc("none1", "del1", "del2"), "--quorum", "1");
    expect(r.exit).toBe(69);
    expect(r.out).toMatchObject({ confirmed: false, ownCode: null, reason: "disagree" });
  });

  it("tolerates an endpoint that is down only while the quorum still answers", async () => {
    expect((await owncode(...rpc("down", "del1", "del2"))).exit).toBe(1);
    const r = await owncode(...rpc("down", "del1", "del2"), "--quorum", "3");
    expect(r.exit).toBe(69);
    expect(r.out.reason).toBe("too few answers");
  });

  it("rejects a quorum larger than the endpoints asked", async () => {
    expect((await owncode(...rpc("none1"), "--quorum", "2")).exit).toBe(64);
  });
});
