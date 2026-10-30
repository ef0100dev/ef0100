import { describe, expect, it } from "vitest";
import { concatBytes, hexToBytes, keccak256, bytesToHex } from "../src/evm/bytes.ts";
import { authorizationDigest, authorizationPreimage, delegationCode } from "../src/evm/eip7702.ts";
import { rlpEncode, rlpInt } from "../src/evm/rlp.ts";
import { addressOfSecretKey, signDigest } from "../src/evm/secp256k1.ts";
import { setCodeTxPreimage } from "../src/evm/tx.ts";
import { Guard, profiles, type GuardPolicy } from "../src/guard/policy.ts";

// The guard's less travelled rules, each with the case that must pass next to the case that must not.

const SK = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
const SIGNER = addressOfSecretKey(SK);
const OK = "0x63c0c19a282a1B52b07dD5a65b58948A07DAE32B";
const COLD = "0xF977814e90dA44bFA03b6295A0616a897441aceC";
const ZERO = "0x0000000000000000000000000000000000000000";
const codes = (d: { reasons: { code: string }[] }) => d.reasons.map((r) => r.code);
const auth = (address: string, chainId = 1n, nonce = 7n) => authorizationPreimage({ chainId, address, nonce });
const typedTx = (to: string | null, data = "0x", value = 0n) =>
  concatBytes(
    Uint8Array.of(2),
    rlpEncode([
      rlpInt(1n),
      rlpInt(7n),
      rlpInt(1_000_000_000n),
      rlpInt(30_000_000_000n),
      rlpInt(60_000n),
      to ? hexToBytes(to) : new Uint8Array(),
      rlpInt(value),
      hexToBytes(data),
      [],
    ]),
  );
const signed = (address: string, nonce: bigint) => {
  const a = { chainId: 1n, address, nonce };
  return { ...a, ...signDigest(authorizationDigest(a), SK) };
};
const base = (extra: NonNullable<GuardPolicy["authorizations"]>): GuardPolicy => ({
  authorizations: { allowDelegates: [{ address: OK }], maxPerWindow: 1000, ...extra },
});

describe("guard: delegate pinning", () => {
  const H = bytesToHex(keccak256(hexToBytes("0x6000")));
  const g = new Guard(base({ allowDelegates: [{ address: OK, codehash: H }] }));

  it("refuses an allowed delegate whose codehash is unknown or different, signs it when the codehash matches", () => {
    expect(codes(g.check(auth(OK), { as: "preimage" }, { signer: SIGNER, nonce: 7n }))).toContain(
      "DELEGATE_CODEHASH_MISMATCH",
    );
    const other = g.check(
      auth(OK),
      { as: "preimage" },
      { signer: SIGNER, nonce: 7n, codehashes: { [OK.toLowerCase()]: `0x${"ab".repeat(32)}` } },
    );
    expect(other.reasons[0]!.message).toMatch(/does not match/);
    const same = g.check(
      auth(OK),
      { as: "preimage" },
      { signer: SIGNER, nonce: 7n, codehashes: { [OK.toLowerCase()]: H } },
    );
    expect(same.allow).toBe(true);
  });

  it("refuses an allowed delegate on a chain it is not allowed on", () => {
    const g2 = new Guard(base({ allowDelegates: [{ address: OK, chains: [8453] }] }));
    expect(codes(g2.check(auth(OK, 1n), { as: "preimage" }, { signer: SIGNER, nonce: 7n }))).toContain(
      "DELEGATE_CHAIN_NOT_ALLOWED",
    );
    expect(g2.check(auth(OK, 8453n), { as: "preimage" }, { signer: SIGNER, nonce: 7n }).allow).toBe(true);
  });

  it("refuses a clear when the policy turns clearing off", () => {
    const g3 = new Guard(base({ allowClear: false }));
    expect(codes(g3.check(auth(ZERO), { as: "preimage" }, { signer: SIGNER, nonce: 7n }))).toContain(
      "CLEAR_NOT_ALLOWED",
    );
  });
});

describe("guard: a key whose own account has code", () => {
  const ownCode = hexToBytes(delegationCode(OK));

  it("treats its own allowed delegation as normal only when the policy says so, and only with a matching codehash", () => {
    const tx = typedTx("0x1111111111111111111111111111111111111111");
    expect(codes(new Guard(base({})).check(tx, { as: "preimage" }, { signer: SIGNER, ownCode }))).toContain(
      "OWN_CODE_PRESENT",
    );
    expect(
      new Guard(base({ trustAllowedDelegation: true })).check(tx, { as: "preimage" }, { signer: SIGNER, ownCode })
        .allow,
    ).toBe(true);
    const H = bytesToHex(keccak256(hexToBytes("0x6001")));
    const pinned = new Guard(base({ trustAllowedDelegation: true, allowDelegates: [{ address: OK, codehash: H }] }));
    expect(pinned.check(tx, { as: "preimage" }, { signer: SIGNER, ownCode }).allow).toBe(false);
    expect(
      pinned.check(tx, { as: "preimage" }, { signer: SIGNER, ownCode, codehashes: { [OK.toLowerCase()]: H } }).allow,
    ).toBe(true);
  });

  it("never trusts code that is not a delegation, or a delegation to an unlisted delegate", () => {
    const g = new Guard(base({ trustAllowedDelegation: true }));
    const tx = typedTx("0x1111111111111111111111111111111111111111");
    expect(g.check(tx, { as: "preimage" }, { signer: SIGNER, ownCode: hexToBytes("0x6080604052") }).allow).toBe(false);
    expect(g.check(tx, { as: "preimage" }, { signer: SIGNER, ownCode: hexToBytes(delegationCode(COLD)) }).allow).toBe(
      false,
    );
  });

  it("lets plain ETH go to a listed cold address, and nothing else", () => {
    const g = new Guard({ ...profiles.hotWallet, breakGlass: [COLD] });
    const ctx = { signer: SIGNER, ownCode };
    expect(g.check(typedTx(COLD, "0x", 10n ** 18n), { as: "preimage" }, ctx).allow).toBe(true);
    expect(
      g.check(typedTx("0x2222222222222222222222222222222222222222", "0x", 1n), { as: "preimage" }, ctx).allow,
    ).toBe(false);
    expect(g.check(typedTx(null, "0x6000"), { as: "preimage" }, ctx).allow).toBe(false);
    expect(g.check(typedTx(COLD, "0x", 1n), { as: "preimage" }, { ownCode }).allow).toBe(false);
  });

  it("refuses a token transfer to cold whose calldata is not exactly transfer(address,uint256)", () => {
    const USDT = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
    const g = new Guard({ ...profiles.hotWallet, breakGlass: [COLD], breakGlassTokens: [USDT] });
    const ok = `0xa9059cbb000000000000000000000000${COLD.slice(2).toLowerCase()}${"0".repeat(63)}1`;
    expect(g.check(typedTx(USDT, ok), { as: "preimage" }, { signer: SIGNER, ownCode }).allow).toBe(true);
    const dirtyHigh = `0xa9059cbb${"f".repeat(24)}${COLD.slice(2).toLowerCase()}${"0".repeat(63)}1`;
    expect(g.check(typedTx(USDT, dirtyHigh), { as: "preimage" }, { signer: SIGNER, ownCode }).allow).toBe(false);
    expect(g.check(typedTx(USDT, `${ok}00`), { as: "preimage" }, { signer: SIGNER, ownCode }).allow).toBe(false);
    const approve = `0x095ea7b3${ok.slice(10)}`;
    expect(g.check(typedTx(USDT, approve), { as: "preimage" }, { signer: SIGNER, ownCode }).allow).toBe(false);
  });
});

describe("guard: set-code transactions and kinds", () => {
  const body = (list: ReturnType<typeof signed>[]) =>
    setCodeTxPreimage({
      chainId: 1n,
      nonce: 7n,
      maxPriorityFeePerGas: 1n,
      maxFeePerGas: 2n,
      gasLimit: 100_000n,
      to: SIGNER,
      value: 0n,
      data: "0x",
      accessList: [],
      authorizationList: list,
    });

  it("refuses a set-code transaction carrying a tuple that does not recover", () => {
    const bad = { ...signed(OK, 8n), r: 0n };
    const d = new Guard(base({})).check(
      body([bad]),
      { as: "preimage" },
      { signer: SIGNER, nonce: 7n, selfSponsored: true },
    );
    expect(d.allow).toBe(false);
    expect(codes(d)).toContain("BAD_TUPLE_SIGNATURE");
  });

  it("refuses kinds outside allowKinds: set-code, legacy and EIP-712 under the hot-wallet profile", () => {
    const narrow = new Guard({ ...profiles.hotWallet, allowKinds: ["typed-tx"] });
    expect(
      codes(
        narrow.check(body([signed(ZERO, 8n)]), { as: "preimage" }, { signer: SIGNER, nonce: 7n, selfSponsored: true }),
      ),
    ).toContain("KIND_NOT_ALLOWED");
    const legacy = rlpEncode([
      rlpInt(7n),
      rlpInt(1n),
      rlpInt(21_000n),
      hexToBytes(COLD),
      rlpInt(1n),
      hexToBytes("0x1234"),
      rlpInt(1n),
      new Uint8Array(),
      new Uint8Array(),
    ]);
    expect(codes(narrow.check(legacy, { as: "preimage" }, { signer: SIGNER }))).toContain("KIND_NOT_ALLOWED");
    const permit = concatBytes(Uint8Array.of(0x19, 0x01), new Uint8Array(32).fill(1), new Uint8Array(32).fill(2));
    const hot = new Guard(profiles.hotWallet).check(permit, { as: "preimage" }, { signer: SIGNER });
    expect(hot.allow).toBe(false);
    expect(codes(hot)).toContain("KIND_NOT_ALLOWED");
  });

  it("refuses a 32-byte input that happens to parse as a transaction: a digest can be ground until it does", () => {
    const thirtyTwo = rlpEncode([
      rlpInt(7n),
      rlpInt(1n),
      rlpInt(21_000n),
      hexToBytes(COLD),
      rlpInt(1n),
      new Uint8Array(),
      rlpInt(1n),
      new Uint8Array(),
      new Uint8Array(),
    ]);
    expect(thirtyTwo.length).toBe(32);
    const d = new Guard(profiles.hotWallet).check(thirtyTwo, { as: "preimage" }, { signer: SIGNER });
    expect(d.allow).toBe(false);
    expect(codes(d)).toContain("UNKNOWN_INPUT");
  });

  it("keeps counting correctly past its memory of 10,000 authorizations", () => {
    const g = new Guard(base({ maxPerWindow: 1_000_000, windowMs: 1 }));
    for (let i = 0; i < 10_050; i++) {
      const d = g.check(auth(OK, BigInt(1 + i)), { as: "preimage" }, { signer: SIGNER, nonce: 7n, now: i * 10 });
      if (!d.allow) throw new Error(`run ${i}: ${codes(d)}`);
    }
  });
});
