import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { bytesToHex, concatBytes, hexToBytes, keccak256 } from "../src/evm/bytes.ts";
import { authorizationDigest, authorizationPreimage, delegationCode, recoverAuthority } from "../src/evm/eip7702.ts";
import { judgeRecipient } from "../src/evm/recipient.ts";
import { rlpEncode, rlpInt } from "../src/evm/rlp.ts";
import { decodeTransaction, setCodeTxPreimage } from "../src/evm/tx.ts";
import { addressOfSecretKey, signDigest } from "../src/evm/secp256k1.ts";
import { clearDelegationTx, planClearDelegation } from "../src/evm/remediate.ts";
import { classifySigningInput } from "../src/guard/classify.ts";
import { Guard, GuardRefusal, profiles } from "../src/guard/policy.ts";

const raw = (hash: string) =>
  readFileSync(new URL(`../fixtures/2026-10-29/raw/${hash}.rlp.hex`, import.meta.url), "utf8").trim();
const ATTACK = decodeTransaction(raw("0xad99264d5532ae0dd04b2004eebda05f25657e70dacb764f7ac8d4ccd051298b"));
const CLEAR = decodeTransaction(raw("0xafbf94c92a8d749988411669fa14d4f8866d9b4420b4ebd299f28e958dac7209"));
const B14 = "0x28C6c06298d514Db089934071355E5743bf21d60";

describe("classify", () => {
  it("names every signing domain from its first bytes", () => {
    const auth = ATTACK.authorizationList[15]!;
    expect(classifySigningInput(authorizationPreimage(auth), { as: "preimage" }).kind).toBe("eip7702-authorization");
    expect(classifySigningInput(authorizationDigest(auth), { as: "digest" }).kind).toBe("raw-digest");
    expect(
      classifySigningInput(concatBytes(Uint8Array.of(0x19, 0x01), new Uint8Array(64)), { as: "preimage" }).kind,
    ).toBe("eip712");
    const msg = new TextEncoder().encode("\x19Ethereum Signed Message:\n5hello");
    expect(classifySigningInput(msg, { as: "preimage" })).toMatchObject({ kind: "personal-message", text: "hello" });
    expect(
      classifySigningInput(concatBytes(Uint8Array.of(0x19, 0x00), new Uint8Array(21)), { as: "preimage" }).kind,
    ).toBe("eip191-data");
    expect(classifySigningInput(hexToBytes(CLEAR.signingHash), { as: "preimage" }).kind).toBe("unknown");
  });

  it("reads a set-code transaction's preimage, authorization list included", () => {
    const plan = planClearDelegation({
      chainId: 1n,
      authority: B14,
      nonce: CLEAR.nonce,
      maxFeePerGas: CLEAR.maxFeePerGas!,
      maxPriorityFeePerGas: CLEAR.maxPriorityFeePerGas!,
    });
    const built = clearDelegationTx(plan, CLEAR.authorizationList[0]!);
    const c = classifySigningInput(built.preimage, { as: "preimage" });
    expect(c).toMatchObject({ kind: "set-code-tx", chainId: 1n, nonce: 18_914_903n, to: B14 });
  });
});

describe("the guard against the 50 authorizations", () => {
  it("refuses every one of them, with reasons, when it sits in the signing path", () => {
    const guard = new Guard();
    let now = 1_000_000;
    const decisions = ATTACK.authorizationList.map((a) =>
      guard.check(authorizationPreimage(a), { as: "preimage" }, { signer: B14, nonce: 18_914_809n, now: now++ }),
    );
    expect(decisions.every((d) => !d.allow)).toBe(true);
    decisions.forEach((d, i) => {
      const codes = d.reasons.map((r) => r.code);
      expect(codes).toContain("DELEGATE_NOT_ALLOWED");
      if (i !== 15) expect(codes).toContain("NONCE_NOT_LIVE");
    });
  });

  it("refuses the same 50 as bare digests without decoding anything", () => {
    const guard = new Guard({
      authorizations: { allowDelegates: [{ address: ATTACK.authorizationList[0]!.address }] },
    });
    for (const a of ATTACK.authorizationList) {
      const d = guard.check(authorizationDigest(a), { as: "digest" }, { signer: B14 });
      expect(d.allow).toBe(false);
      expect(d.reasons[0]!.code).toBe("NO_PREIMAGE");
    }
  });

  it("rate-limits a burst even when the delegate is allowed", () => {
    const guard = new Guard({
      authorizations: { allowDelegates: [{ address: ATTACK.authorizationList[0]!.address }] },
    });
    const ok = guard.check(
      authorizationPreimage(ATTACK.authorizationList[15]!),
      { as: "preimage" },
      { signer: B14, nonce: ATTACK.authorizationList[15]!.nonce, now: 0 },
    );
    expect(ok.allow).toBe(true);
    const again = guard.check(
      authorizationPreimage(ATTACK.authorizationList[14]!),
      { as: "preimage" },
      { signer: B14, nonce: ATTACK.authorizationList[14]!.nonce, now: 10 },
    );
    expect(again.reasons.map((r) => r.code)).toEqual(["RATE_LIMITED"]);
  });

  it("lets Binance 14's own clearing transaction through", () => {
    const plan = planClearDelegation({
      chainId: 1n,
      authority: B14,
      nonce: CLEAR.nonce,
      maxFeePerGas: CLEAR.maxFeePerGas!,
      maxPriorityFeePerGas: CLEAR.maxPriorityFeePerGas!,
    });
    const guard = new Guard();
    const auth = guard.check(
      plan.authorizationPreimage,
      { as: "preimage" },
      { signer: B14, nonce: CLEAR.nonce, selfSponsored: true },
    );
    expect(auth.allow).toBe(true);
    const tx = clearDelegationTx(plan, CLEAR.authorizationList[0]!);
    const d = guard.check(tx.preimage, { as: "preimage" }, { signer: B14 });
    expect(d.allow).toBe(true);
  });

  it("refuses to relay someone else's delegation: the attack's own unsigned transaction", () => {
    const unsigned = setCodeTxPreimage({
      chainId: ATTACK.chainId!,
      nonce: ATTACK.nonce,
      maxPriorityFeePerGas: ATTACK.maxPriorityFeePerGas!,
      maxFeePerGas: ATTACK.maxFeePerGas!,
      gasLimit: ATTACK.gasLimit,
      to: ATTACK.to!,
      value: ATTACK.value,
      data: ATTACK.data,
      accessList: ATTACK.accessList,
      authorizationList: ATTACK.authorizationList,
    });
    expect(bytesToHex(keccak256(unsigned))).toBe(ATTACK.signingHash);
    const d = new Guard().check(unsigned, { as: "preimage" }, { signer: ATTACK.from! });
    expect(d.reasons.map((r) => r.code)).toEqual(["TOO_MANY_TUPLES"]);
    const wide = new Guard({ authorizations: { maxTuples: 64 } }).check(
      unsigned,
      { as: "preimage" },
      { signer: ATTACK.from! },
    );
    expect(wide.allow).toBe(false);
    const sponsored = wide.reasons.filter((r) => r.code === "SPONSORS_OTHER_AUTHORITY");
    expect(sponsored).toHaveLength(50);
  });

  it("wrap() throws a GuardRefusal before the key is ever called", async () => {
    let called = 0;
    const sign = new Guard().wrap(() => ++called, { as: "digest" });
    await expect(sign(authorizationDigest(ATTACK.authorizationList[15]!), { signer: B14 })).rejects.toBeInstanceOf(
      GuardRefusal,
    );
    expect(called).toBe(0);
  });
});

describe("a raw-digest signer is an authorization oracle", () => {
  it("signing the 32-byte digest yields a valid EIP-7702 authorization", () => {
    const sk = new Uint8Array(32).fill(0x42);
    const me = addressOfSecretKey(sk);
    const auth = { chainId: 1n, address: "0x63e842B054Bd624a465454D533C33F573e9c6fAe", nonce: 7n };
    const sig = signDigest(authorizationDigest(auth), sk);
    expect(recoverAuthority({ ...auth, ...sig })).toEqual({ ok: true, authority: me });
  });
});

describe("clear-delegation builder", () => {
  it("reproduces 0xafbf… byte for byte from its own signatures", () => {
    const plan = planClearDelegation({
      chainId: 1n,
      authority: B14,
      nonce: 18_914_903n,
      maxFeePerGas: 30_000_000_000n,
      maxPriorityFeePerGas: 1_000_000_000n,
    });
    expect(plan.authorization.nonce).toBe(18_914_904n);
    const a = CLEAR.authorizationList[0]!;
    expect(recoverAuthority(a)).toEqual({ ok: true, authority: B14 });
    const built = clearDelegationTx(plan, a);
    expect(built.signingHash).toBe(CLEAR.signingHash);
    expect(built.serialize(CLEAR)).toBe(CLEAR.raw);
  });
});

describe("checkDigest: a raw-digest signer with the preimage alongside", () => {
  it("judges the preimage once keccak matches, and refuses a mismatch", () => {
    const a = ATTACK.authorizationList[15]!;
    const g = new Guard();
    const d = g.checkDigest(authorizationDigest(a), authorizationPreimage(a), { signer: B14 });
    expect(d.classified.kind).toBe("eip7702-authorization");
    expect(d.reasons.map((r) => r.code)).toContain("DELEGATE_NOT_ALLOWED");
    const wrong = g.checkDigest(authorizationDigest(a), authorizationPreimage(ATTACK.authorizationList[14]!), {
      signer: B14,
    });
    expect(wrong.reasons.map((r) => r.code)).toEqual(["PREIMAGE_MISMATCH"]);
    expect(g.checkDigest(authorizationDigest(a), undefined).reasons[0]!.code).toBe("NO_PREIMAGE");
  });
});

describe("refill guard", () => {
  it("refuses both refills that were swept on 2026-10-29", () => {
    const delegated = delegationCode("0x63e842B054Bd624a465454D533C33F573e9c6fAe");
    const usdtRefill = judgeRecipient({ code: delegated });
    expect(usdtRefill.allow).toBe(false);
    expect(usdtRefill.reasons[0]!.code).toBe("DELEGATED_TO_MALICIOUS");
    const ethRefill = judgeRecipient({ code: delegated, usdtBlacklisted: true });
    expect(ethRefill.reasons.map((r) => r.code)).toEqual(["DELEGATED_TO_MALICIOUS", "USDT_BLACKLISTED"]);
  });

  it("allows a plain EOA, and a delegate you chose", () => {
    expect(judgeRecipient({ code: "0x" }).allow).toBe(true);
    const mine = delegationCode("0x4Cd241E8d1510e30b2076397afc7508Ae59C66c9");
    expect(judgeRecipient({ code: mine }).allow).toBe(false);
    expect(
      judgeRecipient({ code: mine }, { allowDelegates: ["0x4Cd241E8d1510e30b2076397afc7508Ae59C66c9"] }).allow,
    ).toBe(true);
    expect(judgeRecipient({ code: "0x6080" }).reasons[0]!.code).toBe("HAS_CODE");
  });
});

describe("OWN_CODE_PRESENT: once the key's own account has code", () => {
  const sweeperCode = delegationCode("0x63e842B054Bd624a465454D533C33F573e9c6fAe");
  // An unsigned EIP-1559 USDT transfer from the hot wallet: 0x02 ‖ rlp([chain, nonce, tip, maxFee, gas, to, value, data, accessList]).
  const routine = concatBytes(
    Uint8Array.of(2),
    rlpEncode([
      rlpInt(1n),
      rlpInt(18_914_810n),
      rlpInt(1_000_000_000n),
      rlpInt(170_000_000_000n),
      rlpInt(100_000n),
      hexToBytes("0xdAC17F958D2ee523a2206206994597C13D831ec7"),
      rlpInt(0n),
      hexToBytes(
        "0xa9059cbb000000000000000000000000f977814e90da44bfa03b6295a0616a897441acec00000000000000000000000000000000000000000000000000000000000f4240",
      ),
      [],
    ]),
  );

  it("refuses a routine transfer it would otherwise sign", () => {
    const g = new Guard();
    expect(g.check(routine, { as: "preimage" }, { signer: B14 }).allow).toBe(true);
    const d = new Guard().check(routine, { as: "preimage" }, { signer: B14, ownCode: sweeperCode });
    expect(d.allow).toBe(false);
    expect(d.reasons[0]!.code).toBe("OWN_CODE_PRESENT");
  });

  it("still signs the clear, and a break-glass transfer to a listed cold address", () => {
    const clear = CLEAR.authorizationList[0]!;
    const d = new Guard().check(
      authorizationPreimage(clear),
      { as: "preimage" },
      { signer: B14, ownCode: sweeperCode, nonce: CLEAR.nonce, selfSponsored: true },
    );
    expect(d.allow).toBe(true);
    const cold = new Guard({
      ...profiles.hotWallet,
      breakGlass: ["0xF977814e90dA44bFA03b6295A0616a897441aceC"],
      breakGlassTokens: ["0xdAC17F958D2ee523a2206206994597C13D831ec7"],
    });
    expect(cold.check(routine, { as: "preimage" }, { signer: B14, ownCode: sweeperCode }).allow).toBe(true);
  });

  it("does not treat a listed token contract as a destination: the recipient inside the calldata decides", () => {
    const tokenOnly = new Guard({ ...profiles.hotWallet, breakGlass: ["0xdAC17F958D2ee523a2206206994597C13D831ec7"] });
    expect(tokenOnly.check(routine, { as: "preimage" }, { signer: B14, ownCode: sweeperCode }).allow).toBe(false);
    const elsewhere = new Guard({
      ...profiles.hotWallet,
      breakGlass: ["0x000000000000000000000000000000000000dEaD"],
      breakGlassTokens: ["0xdAC17F958D2ee523a2206206994597C13D831ec7"],
    });
    expect(elsewhere.check(routine, { as: "preimage" }, { signer: B14, ownCode: sweeperCode }).allow).toBe(false);
  });

  it("refuses a clear that carries a payload: value or calldata riding on the self-clear", () => {
    const clear = CLEAR.authorizationList[0]!;
    const body = (to: string, value: bigint, data: `0x${string}`) =>
      setCodeTxPreimage({
        chainId: 1n,
        nonce: CLEAR.nonce,
        maxPriorityFeePerGas: CLEAR.maxPriorityFeePerGas!,
        maxFeePerGas: CLEAR.maxFeePerGas!,
        gasLimit: 120_000n,
        to,
        value,
        data,
        accessList: [],
        authorizationList: [clear],
      });
    const ctx = { signer: B14, ownCode: sweeperCode };
    expect(new Guard().check(body(B14, 0n, "0x"), { as: "preimage" }, ctx).allow).toBe(true);
    const drain = new Guard().check(
      body("0x000000000000000000000000000000000000dEaD", 172_624n * 10n ** 18n, "0x"),
      { as: "preimage" },
      ctx,
    );
    expect(drain.reasons[0]!.code).toBe("OWN_CODE_PRESENT");
    const usdt = new Guard().check(
      body(
        "0xdAC17F958D2ee523a2206206994597C13D831ec7",
        0n,
        `0xa9059cbb${"0".repeat(24)}000000000000000000000000000000000000dead${"f".repeat(64)}`,
      ),
      { as: "preimage" },
      ctx,
    );
    expect(usdt.allow).toBe(false);
  });
});

describe("guard context and parsing", () => {
  const tuple15 = ATTACK.authorizationList[15]!;

  it("refuses an authorization without the key it binds or the key's live nonce", () => {
    const pre = authorizationPreimage(tuple15);
    expect(new Guard().check(pre, { as: "preimage" }).reasons.map((r) => r.code)).toEqual(["CONTEXT_MISSING"]);
    const noNonce = new Guard({ authorizations: { allowDelegates: [{ address: tuple15.address }] } }).check(
      pre,
      { as: "preimage" },
      { signer: B14 },
    );
    expect(noNonce.reasons.map((r) => r.code)).toEqual(["CONTEXT_MISSING"]);
  });

  it("does not let a timestamp from the future clear the rate limit", () => {
    const g = new Guard({ authorizations: { allowDelegates: [{ address: tuple15.address }], maxPerWindow: 1 } });
    const at = (t: number, a = tuple15) =>
      g.check(authorizationPreimage(a), { as: "preimage" }, { signer: B14, nonce: a.nonce, now: t });
    expect(at(1_000_000).allow).toBe(true);
    expect(at(0, ATTACK.authorizationList[14]!).allow).toBe(true);
  });

  it("reads a personal message that starts with digits", () => {
    const msg = new TextEncoder().encode("\x19Ethereum Signed Message:\n152024 was a year");
    expect(classifySigningInput(msg, { as: "preimage" })).toMatchObject({
      kind: "personal-message",
      text: "2024 was a year",
    });
  });

  it("refuses a 32-byte input that only parses as a transaction, and an unprotected legacy transaction", () => {
    const tiny = rlpEncode([
      rlpInt(1n),
      rlpInt(1n),
      rlpInt(21_000n),
      new Uint8Array(20).fill(7),
      rlpInt(1n),
      new Uint8Array(0),
    ]);
    const padded = rlpEncode([
      rlpInt(1n),
      rlpInt(1n),
      rlpInt(21_000n),
      new Uint8Array(20).fill(7),
      rlpInt(1n),
      new Uint8Array(32 - tiny.length),
    ]);
    expect(padded.length).toBe(32);
    expect(classifySigningInput(padded, { as: "preimage" }).kind).toBe("unknown");
    expect(new Guard().check(tiny, { as: "preimage" }, { signer: B14 }).reasons.map((r) => r.code)).toEqual([
      "NO_CHAIN_ID",
    ]);
  });

  it("refuses an empty authorization list and caps how many tuples it recovers", () => {
    const tx = (list: typeof ATTACK.authorizationList) =>
      setCodeTxPreimage({
        chainId: 1n,
        nonce: 1n,
        maxPriorityFeePerGas: 1n,
        maxFeePerGas: 2n,
        gasLimit: 100_000n,
        to: B14,
        value: 0n,
        data: "0x",
        accessList: [],
        authorizationList: list,
      });
    expect(classifySigningInput(tx([]), { as: "preimage" }).kind).toBe("unknown");
    expect(
      new Guard()
        .check(tx(ATTACK.authorizationList.slice(0, 17)), { as: "preimage" }, { signer: B14 })
        .reasons.map((r) => r.code),
    ).toEqual(["TOO_MANY_TUPLES"]);
  });

  it("signs exactly the bytes it judged, even if the caller's buffer changes afterwards", async () => {
    const msg = new TextEncoder().encode("\x19Ethereum Signed Message:\n5hello");
    const sign = new Guard(profiles.user).wrap(
      async (b) => {
        await Promise.resolve();
        return bytesToHex(b);
      },
      { as: "preimage" },
    );
    const pending = sign(msg, { signer: B14 });
    msg[msg.length - 1] = 0x21;
    expect(await pending).toBe(bytesToHex(new TextEncoder().encode("\x19Ethereum Signed Message:\n5hello")));
  });

  it("keeps a user's wallet usable while it is delegated to a delegate the profile allows", () => {
    const wallet = delegationCode("0x63c0c19a282a1B52b07dD5a65b58948A07DAE32B");
    const transfer = concatBytes(
      Uint8Array.of(2),
      rlpEncode([
        rlpInt(1n),
        rlpInt(7n),
        rlpInt(1n),
        rlpInt(2n),
        rlpInt(21_000n),
        new Uint8Array(20).fill(9),
        rlpInt(1n),
        new Uint8Array(0),
        [],
      ]),
    );
    expect(new Guard(profiles.user).check(transfer, { as: "preimage" }, { signer: B14, ownCode: wallet }).allow).toBe(
      true,
    );
    expect(
      new Guard(profiles.hotWallet).check(transfer, { as: "preimage" }, { signer: B14, ownCode: wallet }).allow,
    ).toBe(false);
  });
});
