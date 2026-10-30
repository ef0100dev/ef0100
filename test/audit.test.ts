import { describe, expect, it } from "vitest";
import { bytesToHex, keccak256 } from "../src/evm/bytes.ts";
import { authorizationDigest, authorizationPreimage } from "../src/evm/eip7702.ts";
import { Guard, profiles, type DecisionRecord } from "../src/guard/policy.ts";

const B14 = "0x28C6c06298d514Db089934071355E5743bf21d60";
const auth = { chainId: 1n, address: "0x63e842B054Bd624a465454D533C33F573e9c6fAe", nonce: 18914809n };
const clear = { ...auth, address: "0x0000000000000000000000000000000000000000" };

describe("audit trail", () => {
  it("records each decision once: kind, verdict, reason codes, signer, the digest of what was judged, the time", () => {
    const log: DecisionRecord[] = [];
    const g = new Guard(profiles.hotWallet, { onDecision: (r) => log.push(r) });
    const pre = authorizationPreimage(auth);
    g.check(
      pre,
      { as: "preimage" },
      { signer: B14, nonce: 18914809n, ownCode: "0x", now: Date.parse("2026-10-29T20:20:59Z") },
    );
    expect(log).toEqual([
      {
        at: "2026-10-29T20:20:59.000Z",
        kind: "eip7702-authorization",
        allow: false,
        reasons: ["DELEGATE_NOT_ALLOWED"],
        signer: B14,
        digest: bytesToHex(authorizationDigest(auth)),
      },
    ]);
    expect(log[0]!.digest).toBe(bytesToHex(keccak256(pre)));
  });

  it("records allowed decisions too, and a bare digest as itself", () => {
    const log: DecisionRecord[] = [];
    const g = new Guard(profiles.hotWallet, { onDecision: (r) => log.push(r) });
    g.check(authorizationPreimage(clear), { as: "preimage" }, { signer: B14, nonce: 18914809n, ownCode: "0x" });
    const d = authorizationDigest(auth);
    g.check(d, { as: "digest" }, { signer: B14, ownCode: "0x" });
    expect(log.map((r) => [r.allow, r.reasons[0]])).toEqual([
      [true, "ALLOWED"],
      [false, "NO_PREIMAGE"],
    ]);
    expect(log[1]!.digest).toBe(bytesToHex(d));
  });

  it("records a preimage that does not match its digest", () => {
    const log: DecisionRecord[] = [];
    const g = new Guard(profiles.hotWallet, { onDecision: (r) => log.push(r) });
    g.checkDigest(authorizationDigest(auth), authorizationPreimage(clear), { signer: B14, ownCode: "0x" });
    expect(log[0]!.reasons).toEqual(["PREIMAGE_MISMATCH"]);
  });

  it("never lets a failing logger change the decision", () => {
    const g = new Guard(profiles.hotWallet, {
      onDecision: () => {
        throw new Error("disk full");
      },
    });
    const d = g.check(
      authorizationPreimage(auth),
      { as: "preimage" },
      { signer: B14, nonce: 18914809n, ownCode: "0x" },
    );
    expect(d.allow).toBe(false);
    const ok = g.check(
      authorizationPreimage(clear),
      { as: "preimage" },
      { signer: B14, nonce: 18914809n, ownCode: "0x" },
    );
    expect(ok.allow).toBe(true);
  });
});
