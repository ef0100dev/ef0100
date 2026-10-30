import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { bytesToHex, hexToBytes, keccak256 } from "../src/evm/bytes.ts";
import { rlpDecode, rlpEncode, RlpError } from "../src/evm/rlp.ts";
import {
  authorizationDigest,
  authorizationPreimage,
  delegationCode,
  parseDelegation,
  recoverAuthority,
} from "../src/evm/eip7702.ts";
import { decodeTransaction } from "../src/evm/tx.ts";
import { analyzeAuthorizationList, processAuthorizationList } from "../src/evm/authlist.ts";

const raw = (hash: string) =>
  readFileSync(new URL(`../fixtures/2026-10-29/raw/${hash}.rlp.hex`, import.meta.url), "utf8").trim();
const golden = JSON.parse(readFileSync(new URL("../fixtures/2026-10-29/evm/golden.json", import.meta.url), "utf8"));

const ATTACK = "0xad99264d5532ae0dd04b2004eebda05f25657e70dacb764f7ac8d4ccd051298b";
const CLEAR = "0xafbf94c92a8d749988411669fa14d4f8866d9b4420b4ebd299f28e958dac7209";
const B14 = "0x28C6c06298d514Db089934071355E5743bf21d60";
const SWEEPER = "0x63e842B054Bd624a465454D533C33F573e9c6fAe";
const OPERATOR = "0x7C8601d4645b93cea45F71e118A729332e6B5CA0";

describe("rlp", () => {
  it("round-trips and rejects non-canonical forms", () => {
    const item = [hexToBytes("0x01"), [hexToBytes("0x"), hexToBytes("0x8000")], new Uint8Array(60).fill(7)];
    expect(rlpDecode(rlpEncode(item))).toEqual(item);
    expect(() => rlpDecode(hexToBytes("0x8101"))).toThrow(RlpError);
    expect(() => rlpDecode(hexToBytes("0xb80101"))).toThrow(RlpError);
    expect(() => rlpDecode(hexToBytes("0x0102"))).toThrow(RlpError);
  });
});

describe("the 2026-10-29 delegation transaction", () => {
  const tx = decodeTransaction(raw(ATTACK));

  it("decodes the raw bytes and hashes to the transaction hash", () => {
    expect(hexToBytes(tx.raw).length).toBe(4916);
    expect(tx.hash).toBe(ATTACK);
    expect(tx.type).toBe(4);
    expect(tx.chainId).toBe(1n);
    expect(tx.nonce).toBe(10n);
    expect(tx.from).toBe(OPERATOR);
    expect(tx.to).toBe(B14);
    expect(tx.data).toBe("0x");
    expect(tx.gasLimit).toBe(1_550_000n);
    expect(tx.authorizationList).toHaveLength(50);
  });

  it("every one of the 50 tuples recovers to Binance 14", () => {
    tx.authorizationList.forEach((a, i) => {
      expect(a.chainId).toBe(1n);
      expect(a.address).toBe(SWEEPER);
      expect(a.nonce).toBe(18_914_824n - BigInt(i));
      expect(recoverAuthority(a)).toEqual({ ok: true, authority: B14 });
      expect(a.r.toString(16)).toBe(golden.attack_tx.authorizations[i].r.slice(2).replace(/^0+/, ""));
    });
  });

  it("tuple #15 has the documented preimage and digest", () => {
    const a = tx.authorizationList[15]!;
    expect(bytesToHex(authorizationPreimage(a))).toBe("0x05db019463e842b054bd624a465454d533c33f573e9c6fae8401209df9");
    expect(bytesToHex(authorizationDigest(a))).toBe(
      "0xac384c3e6b0b119b06b4f409343faffa32a7410c91e9f049684e59513d2674ac",
    );
  });

  it("with Binance 14 at nonce 18,914,809, exactly #15 applies", () => {
    const res = processAuthorizationList(tx, {
      chainId: 1n,
      state: (a) => (a.toLowerCase() === B14.toLowerCase() ? { nonce: 18_914_809n, code: "0x" } : undefined),
    });
    expect(res.applied.map((o) => o.index)).toEqual([15]);
    res.outcomes.forEach((o) => {
      if (o.index < 15) expect(o.status).toBe("nonce-ahead");
      if (o.index > 15) expect(o.status).toBe("nonce-used");
    });
    const after = res.after.get(B14)!;
    expect(after.nonce).toBe(18_914_810n);
    expect(after.code).toBe(delegationCode(SWEEPER).toLowerCase());
    expect(after.delegate).toBe(SWEEPER);
    expect(21_000n + res.gas.authorizationCost - res.gas.refund + 62n).toBe(1_258_562n);
  });

  it("flags the spray, the malicious delegate and the third-party sponsor", () => {
    const f = analyzeAuthorizationList(tx, { watch: [B14] });
    const codes = f.map((x) => x.code);
    expect(codes).toContain("NONCE_SPRAY");
    expect(codes).toContain("KNOWN_MALICIOUS_DELEGATE");
    expect(codes).toContain("WATCHED_AUTHORITY");
    expect(codes).toContain("THIRD_PARTY_SPONSOR");
    expect(f.find((x) => x.code === "NONCE_SPRAY")!.message).toMatch(
      /18914775\.\.18914824: listed in descending order/,
    );
  });
});

describe("the clearing transaction", () => {
  const tx = decodeTransaction(raw(CLEAR));
  it("is self-sponsored and authorizes 0x0 at tx nonce + 1", () => {
    expect(tx.hash).toBe(CLEAR);
    expect(tx.from).toBe(B14);
    expect(tx.to).toBe(B14);
    expect(tx.nonce).toBe(18_914_903n);
    expect(tx.authorizationList).toHaveLength(1);
    expect(tx.authorizationList[0]!.nonce).toBe(18_914_904n);
    const res = processAuthorizationList(tx, {
      chainId: 1n,
      state: () => ({ nonce: 18_914_903n, code: delegationCode(SWEEPER) }),
    });
    expect(res.applied).toHaveLength(1);
    expect(res.applied[0]!.effect).toBe("clear");
    expect(res.after.get(B14)).toEqual({ nonce: 18_914_905n, code: "0x", delegate: null });
    expect(analyzeAuthorizationList(tx).map((x) => x.code)).toEqual(["CLEARS_DELEGATION"]);
  });
});

describe("delegation designator", () => {
  it("parses 0xef0100 ‖ address and nothing else", () => {
    expect(parseDelegation("0xef010063e842b054bd624a465454d533c33f573e9c6fae")).toBe(SWEEPER);
    expect(parseDelegation("0x")).toBeNull();
    expect(parseDelegation("0xef010063e842b054bd624a465454d533c33f573e9c6f")).toBeNull();
    expect(parseDelegation("0x6080604052")).toBeNull();
    expect(bytesToHex(keccak256(hexToBytes(delegationCode(SWEEPER))))).toMatch(/^0x[0-9a-f]{64}$/);
  });
});
