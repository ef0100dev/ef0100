import { describe, expect, it } from "vitest";
import { parseTransaction, type Hex } from "viem";
import { hashAuthorization, recoverAuthorizationAddress } from "viem/utils";
import { privateKeyToAccount } from "viem/accounts";
import { bytesToHex, hexToBytes } from "../src/evm/bytes.ts";
import { authorizationDigest, recoverAuthority } from "../src/evm/eip7702.ts";
import { signDigest } from "../src/evm/secp256k1.ts";
import { decodeTransaction } from "../src/evm/tx.ts";
import { rawFiles, rawFix } from "./helpers.ts";

// An independent implementation (viem) must agree with ours on every bundled byte.
describe("cross-check against viem", () => {
  it("decodes every bundled type-4 transaction to the same fields", () => {
    for (const f of rawFiles()) {
      const raw = rawFix(f.replace(".rlp.hex", "")) as Hex;
      const ours = decodeTransaction(raw);
      const theirs = parseTransaction(raw);
      expect(BigInt(theirs.nonce!)).toBe(ours.nonce);
      expect(theirs.to?.toLowerCase()).toBe(ours.to?.toLowerCase());
      if (ours.type !== 4) continue;
      expect(theirs.authorizationList).toHaveLength(ours.authorizationList.length);
      ours.authorizationList.forEach((a, i) => {
        const t = theirs.authorizationList![i]!;
        expect(BigInt(t.nonce)).toBe(a.nonce);
        expect(t.address.toLowerCase()).toBe(a.address.toLowerCase());
        expect(bytesToHex(authorizationDigest(a))).toBe(
          hashAuthorization({ address: t.address, chainId: t.chainId, nonce: t.nonce }),
        );
      });
    }
  });

  it("recovers the same authority for all 50 attack tuples", async () => {
    const tx = decodeTransaction(rawFix("0xad99264d5532ae0dd04b2004eebda05f25657e70dacb764f7ac8d4ccd051298b"));
    for (const a of tx.authorizationList) {
      const theirs = await recoverAuthorizationAddress({
        authorization: {
          address: a.address as Hex,
          chainId: Number(a.chainId),
          nonce: Number(a.nonce),
          yParity: a.yParity,
          r: `0x${a.r.toString(16).padStart(64, "0")}`,
          s: `0x${a.s.toString(16).padStart(64, "0")}`,
        },
      });
      const ours = recoverAuthority(a);
      expect(ours.ok && ours.authority).toBe(theirs);
    }
  });

  it("viem's signAuthorization and a raw signature over the digest are the same bytes", async () => {
    const sk = "0x4242424242424242424242424242424242424242424242424242424242424242";
    const account = privateKeyToAccount(sk);
    const auth = { address: "0x63e842B054Bd624a465454D533C33F573e9c6fAe" as Hex, chainId: 1, nonce: 18914809 };
    const viaViem = await account.signAuthorization(auth);
    const viaViemRaw = await account.sign({ hash: hashAuthorization(auth) });
    const ours = signDigest(
      authorizationDigest({ ...auth, chainId: 1n, nonce: 18914809n }),
      Buffer.from(sk.slice(2), "hex"),
    );
    expect(BigInt(viaViem.r)).toBe(ours.r);
    expect(BigInt(viaViem.s)).toBe(ours.s);
    expect(viaViem.yParity).toBe(ours.yParity);
    expect(viaViemRaw.slice(0, 130)).toBe(
      `0x${ours.r.toString(16).padStart(64, "0")}${ours.s.toString(16).padStart(64, "0")}`,
    );
  });
});

describe("oracle output is reproducible", () => {
  it("anvil #0 signing digest #15 gives the published r and s", async () => {
    const sk = Buffer.from("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80", "hex");
    const sig = signDigest(hexToBytes("0xac384c3e6b0b119b06b4f409343faffa32a7410c91e9f049684e59513d2674ac"), sk);
    const r = sig.r.toString(16).padStart(64, "0");
    const s = sig.s.toString(16).padStart(64, "0");
    expect(r.startsWith("d4f27aad") && r.endsWith("321d")).toBe(true);
    expect(s.startsWith("47eb8ca2") && s.endsWith("516d")).toBe(true);
    const viaViem = await privateKeyToAccount(`0x${sk.toString("hex")}`).signAuthorization({
      address: "0x63e842B054Bd624a465454D533C33F573e9c6fAe",
      chainId: 1,
      nonce: 18914809,
    });
    expect(viaViem.r).toBe(`0x${r}`);
  });
});
