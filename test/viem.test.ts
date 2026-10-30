import { describe, expect, it } from "vitest";
import { hashTypedData, keccak256, toHex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { delegationCode } from "../src/evm/eip7702.ts";
import { Guard, GuardRefusal, profiles } from "../src/guard/policy.ts";
import { guardAccount, typedDataPreimage } from "../src/integrations/viem.ts";

const SK = "0x4242424242424242424242424242424242424242424242424242424242424242";
const SWEEPER = "0x63e842B054Bd624a465454D533C33F573e9c6fAe";
const ALLOWED = "0x63c0c19a282a1B52b07dD5a65b58948A07DAE32B";
const tx = {
  chainId: 1,
  type: "eip1559" as const,
  nonce: 7,
  to: "0x1111111111111111111111111111111111111111" as const,
  value: 1n,
  gas: 21_000n,
  maxFeePerGas: 30_000_000_000n,
  maxPriorityFeePerGas: 1_000_000_000n,
};

describe("guardAccount (viem)", () => {
  const raw = privateKeyToAccount(SK);

  it("refuses an authorization to an unlisted delegate before the key is asked", async () => {
    const acct = guardAccount(raw, new Guard(profiles.hotWallet), () => ({ nonce: 7n, ownCode: "0x" }));
    await expect(acct.signAuthorization!({ chainId: 1, address: SWEEPER, nonce: 7 })).rejects.toThrow(GuardRefusal);
    await expect(acct.signAuthorization!({ chainId: 1, address: SWEEPER, nonce: 7 })).rejects.toThrow(
      /DELEGATE_NOT_ALLOWED/,
    );
  });

  it("signs an allowed delegation at the live nonce, with the same signature the bare account gives", async () => {
    const g = new Guard({ authorizations: { allowDelegates: [{ address: ALLOWED }] } });
    const acct = guardAccount(raw, g, () => ({ nonce: 7n, ownCode: "0x" }));
    const a = await acct.signAuthorization!({ chainId: 1, address: ALLOWED, nonce: 7 });
    const b = await raw.signAuthorization!({ chainId: 1, address: ALLOWED, nonce: 7 });
    expect(a.r).toBe(b.r);
    expect(a.s).toBe(b.s);
    await expect(acct.signAuthorization!({ chainId: 1, address: ALLOWED, nonce: 9 })).rejects.toThrow(/NONCE_NOT_LIVE/);
  });

  it("refuses a bare hash: the same 32 bytes could be an authorization", async () => {
    const acct = guardAccount(raw, new Guard(profiles.hotWallet), () => ({ ownCode: "0x" }));
    await expect(acct.sign!({ hash: keccak256(toHex("anything")) })).rejects.toThrow(/NO_PREIMAGE/);
  });

  it("judges a transaction by its serialized bytes, and refuses everything but the clear once the account has code", async () => {
    const clean = guardAccount(raw, new Guard(profiles.hotWallet), () => ({ ownCode: "0x" }));
    expect(await clean.signTransaction(tx)).toBe(await raw.signTransaction(tx));
    const taken = guardAccount(raw, new Guard(profiles.hotWallet), () => ({ ownCode: delegationCode(SWEEPER) }));
    await expect(taken.signTransaction(tx)).rejects.toThrow(/OWN_CODE_PRESENT/);
    const forgot = guardAccount(raw, new Guard(profiles.hotWallet));
    await expect(forgot.signTransaction(tx)).rejects.toThrow(/CONTEXT_MISSING/);
  });

  it("refuses personal messages and EIP-712 under the hot-wallet profile, and signs them under user", async () => {
    const td = {
      domain: { name: "Permit2", chainId: 1, verifyingContract: "0x000000000022D473030F116dDEE9F6B43aC78BA3" as const },
      types: { Note: [{ name: "text", type: "string" }] },
      primaryType: "Note" as const,
      message: { text: "hello" },
    };
    const hot = guardAccount(raw, new Guard(profiles.hotWallet), () => ({ ownCode: "0x" }));
    await expect(hot.signMessage({ message: "hello" })).rejects.toThrow(/KIND_NOT_ALLOWED/);
    await expect(hot.signTypedData(td)).rejects.toThrow(/KIND_NOT_ALLOWED/);
    const user = guardAccount(raw, new Guard(profiles.user), () => ({ ownCode: "0x" }));
    expect(await user.signMessage({ message: "hello" })).toBe(await raw.signMessage({ message: "hello" }));
    expect(await user.signTypedData(td)).toBe(await raw.signTypedData(td));
  });

  it("builds the EIP-712 preimage whose keccak256 is viem's hashTypedData", () => {
    const td = {
      domain: { name: "x", version: "1", chainId: 8453 },
      types: {
        Mail: [
          { name: "to", type: "address" },
          { name: "n", type: "uint256" },
        ],
      },
      primaryType: "Mail" as const,
      message: { to: ALLOWED, n: 5n },
    };
    expect(keccak256(typedDataPreimage(td))).toBe(hashTypedData(td));
  });
});
