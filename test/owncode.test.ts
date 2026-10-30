import { describe, expect, it } from "vitest";
import type { Hex } from "../src/evm/bytes.ts";
import { authorizationPreimage } from "../src/evm/eip7702.ts";
import { OwnCodeUnconfirmed, agreedOwnCode, ownCodeAnswers, readOwnCode } from "../src/evm/owncode.ts";
import { Guard, profiles } from "../src/guard/policy.ts";

const B14 = "0x28C6c06298d514Db089934071355E5743bf21d60";
const DELEGATED = "0xef010063e842b054bd624a465454d533c33f573e9c6fae";
const clear = { chainId: 1n, address: "0x0000000000000000000000000000000000000000", nonce: 18914809n };

type Answer = string | Error;

/** One fetch for several endpoints: each URL answers eth_getCode with its own value, or fails. */
function endpoints(answers: Record<string, Answer>) {
  const seen: string[] = [];
  const f = (async (url: string | URL, init?: RequestInit) => {
    const u = String(url);
    seen.push(u);
    const a = answers[u];
    if (a instanceof Error) throw a;
    const [call] = JSON.parse(String(init?.body)) as { id: number; method: string; params: unknown[] }[];
    expect(call!.method).toBe("eth_getCode");
    return new Response(JSON.stringify([{ jsonrpc: "2.0", id: call!.id, result: a }]), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;
  return { fetch: f, seen };
}

const A = "https://a.example/v2/SECRETKEY";
const B = "https://b.example/rpc";
const C = "https://c.example/rpc";

describe("readOwnCode", () => {
  it("returns the code when every endpoint returns the same bytes, case aside", async () => {
    const { fetch, seen } = endpoints({
      [A]: DELEGATED,
      [B]: DELEGATED.toUpperCase().replace("0X", "0x"),
      [C]: DELEGATED,
    });
    await expect(readOwnCode(B14, [A, B, C], { fetch })).resolves.toBe(DELEGATED);
    expect(seen.sort()).toEqual([A, B, C].sort());
  });

  it("returns 0x when every endpoint says there is no code", async () => {
    const { fetch } = endpoints({ [A]: "0x", [B]: "0x" });
    await expect(readOwnCode(B14, [A, B], { fetch })).resolves.toBe("0x");
  });

  it("throws when one endpoint says 0x and the others see a delegation, and the guard then refuses", async () => {
    const { fetch } = endpoints({ [A]: "0x", [B]: DELEGATED, [C]: DELEGATED });
    let ownCode: Hex | undefined;
    await expect(
      readOwnCode(B14, [A, B, C], { fetch }).then((c) => {
        ownCode = c;
      }),
    ).rejects.toBeInstanceOf(OwnCodeUnconfirmed);
    expect(ownCode).toBeUndefined();
    const v = new Guard(profiles.hotWallet).check(
      authorizationPreimage(clear),
      { as: "preimage" },
      { signer: B14, nonce: 18914809n, ownCode },
    );
    expect(v.allow).toBe(false);
    expect(v.reasons.map((r) => r.code)).toContain("CONTEXT_MISSING");
  });

  it("with a quorum, tolerates endpoints that don't answer, never ones that disagree", async () => {
    const down = endpoints({ [A]: new Error("connect ECONNREFUSED"), [B]: DELEGATED, [C]: DELEGATED });
    await expect(readOwnCode(B14, [A, B, C], { fetch: down.fetch, quorum: 2 })).resolves.toBe(DELEGATED);
    const lagging = endpoints({ [A]: DELEGATED, [B]: "0x", [C]: "0x" });
    const e = (await readOwnCode(B14, [A, B, C], { fetch: lagging.fetch, quorum: 1 }).catch(
      (x: unknown) => x,
    )) as OwnCodeUnconfirmed;
    expect(e).toBeInstanceOf(OwnCodeUnconfirmed);
    expect(e.message).toContain("endpoints disagree");
    expect(e.answers.map((a) => a.code)).toEqual([DELEGATED, "0x", "0x"]);
  });

  it("an endpoint that is down or answers garbage counts as no answer", async () => {
    const { fetch } = endpoints({ [A]: new Error("connect ECONNREFUSED"), [B]: "0x", [C]: "not hex" });
    await expect(readOwnCode(B14, [A, B, C], { fetch })).rejects.toBeInstanceOf(OwnCodeUnconfirmed);
    await expect(readOwnCode(B14, [A, B, C], { fetch, quorum: 1 })).resolves.toBe("0x");
  });

  it("names each endpoint by host only, never its path or key", async () => {
    const { fetch } = endpoints({ [A]: "0x", [B]: DELEGATED });
    const e = (await readOwnCode(B14, [A, B], { fetch }).catch((x: unknown) => x)) as Error;
    expect(e).toBeInstanceOf(OwnCodeUnconfirmed);
    expect(e.message).toContain("https://a.example");
    expect(e.message).toContain("https://b.example: 0xef010063…");
    expect(e.message).not.toContain("SECRETKEY");
  });

  it("asks at the block it is given", async () => {
    const params: unknown[][] = [];
    const fetch = (async (_u: string | URL, init?: RequestInit) => {
      const [call] = JSON.parse(String(init?.body)) as { id: number; params: unknown[] }[];
      params.push(call!.params);
      return new Response(JSON.stringify([{ jsonrpc: "2.0", id: call!.id, result: "0x" }]));
    }) as typeof globalThis.fetch;
    await readOwnCode(B14, [B], { fetch, block: "0x1209b19" });
    expect(params).toEqual([[B14, "0x1209b19"]]);
  });

  it("rejects bad input before any request", async () => {
    const { fetch, seen } = endpoints({});
    await expect(readOwnCode("0x1234", [A], { fetch })).rejects.toThrow(TypeError);
    await expect(readOwnCode(B14, [], { fetch })).rejects.toThrow(TypeError);
    await expect(readOwnCode(B14, [A, B], { fetch, quorum: 3 })).rejects.toThrow(TypeError);
    await expect(readOwnCode(B14, [A, B], { fetch, quorum: 0 })).rejects.toThrow(TypeError);
    await expect(readOwnCode(B14, [A, B], { fetch, quorum: 1.5 })).rejects.toThrow(TypeError);
    expect(seen).toEqual([]);
  });
});

describe("ownCodeAnswers and agreedOwnCode", () => {
  it("returns every endpoint's answer, named by host only", async () => {
    const { fetch } = endpoints({ [A]: "0x", [B]: new Error("HTTP 504") });
    expect(await ownCodeAnswers(B14, [A, B], { fetch })).toEqual([
      { endpoint: "https://a.example", code: "0x" },
      { endpoint: "https://b.example", error: "HTTP 504" },
    ]);
  });

  it("says how many answered when too few did", () => {
    expect(() =>
      agreedOwnCode([
        { endpoint: "a", code: "0x" },
        { endpoint: "b", error: "down" },
      ]),
    ).toThrow("1 of 2 answered, 2 needed");
    expect(
      agreedOwnCode(
        [
          { endpoint: "a", code: "0x" },
          { endpoint: "b", error: "down" },
        ],
        1,
      ),
    ).toBe("0x");
  });

  it("rejects a quorum that is not a whole number of at least 1", () => {
    for (const q of [0, -1, 1.5, NaN])
      expect(() => agreedOwnCode([{ endpoint: "a", code: "0x" }], q)).toThrow(TypeError);
  });
});
