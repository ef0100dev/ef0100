import { describe, expect, it } from "vitest";
import { FeeData, TypedDataEncoder, Wallet, keccak256 } from "ethers";
import { delegationCode } from "../src/evm/eip7702.ts";
import { Guard, GuardRefusal, profiles } from "../src/guard/policy.ts";
import { guardSigner, typedDataPreimageEthers } from "../src/integrations/ethers.ts";

const SK = "0x4242424242424242424242424242424242424242424242424242424242424242";
const SWEEPER = "0x63e842B054Bd624a465454D533C33F573e9c6fAe";
const ALLOWED = "0x63c0c19a282a1B52b07dD5a65b58948A07DAE32B";
const tx = {
  chainId: 1n,
  type: 2,
  nonce: 7,
  to: "0x1111111111111111111111111111111111111111",
  value: 1n,
  gasLimit: 21_000n,
  maxFeePerGas: 30_000_000_000n,
  maxPriorityFeePerGas: 1_000_000_000n,
};

describe("guardSigner (ethers v6)", () => {
  it("refuses an authorization to an unlisted delegate before the key is used", async () => {
    const w = guardSigner(new Wallet(SK), new Guard(profiles.hotWallet), () => ({ nonce: 7n, ownCode: "0x" }));
    await expect(w.authorize({ address: SWEEPER, chainId: 1n, nonce: 7n })).rejects.toThrow(GuardRefusal);
    await expect(w.authorize({ address: SWEEPER, chainId: 1n, nonce: 7n })).rejects.toThrow(/DELEGATE_NOT_ALLOWED/);
  });

  it("signs an allowed delegation at the live nonce exactly as the bare wallet does", async () => {
    const g = new Guard({ authorizations: { allowDelegates: [{ address: ALLOWED }] } });
    const w = guardSigner(new Wallet(SK), g, () => ({ nonce: 7n, ownCode: "0x" }));
    const a = await w.authorize({ address: ALLOWED, chainId: 1n, nonce: 7n });
    const b = await new Wallet(SK).authorize({ address: ALLOWED, chainId: 1n, nonce: 7n });
    expect(a.signature.serialized).toBe(b.signature.serialized);
    await expect(w.authorize({ address: ALLOWED, chainId: 1n, nonce: 8n })).rejects.toThrow(/NONCE_NOT_LIVE/);
  });

  it("judges a transaction by its unsigned serialization", async () => {
    const clean = guardSigner(new Wallet(SK), new Guard(profiles.hotWallet), () => ({ ownCode: "0x" }));
    expect(await clean.signTransaction(tx)).toBe(await new Wallet(SK).signTransaction(tx));
    const taken = guardSigner(new Wallet(SK), new Guard(profiles.hotWallet), () => ({
      ownCode: delegationCode(SWEEPER),
    }));
    await expect(taken.signTransaction(tx)).rejects.toThrow(/OWN_CODE_PRESENT/);
    const forgot = guardSigner(new Wallet(SK), new Guard(profiles.hotWallet));
    await expect(forgot.signTransaction(tx)).rejects.toThrow(/CONTEXT_MISSING/);
  });

  it("also guards what ethers signs from the inside: sendTransaction, and a connected copy", async () => {
    const sent: string[] = [];
    const provider = {
      getNetwork: async () => ({ chainId: 1n }),
      getTransactionCount: async () => 7,
      estimateGas: async () => 21_000n,
      getFeeData: async () => new FeeData(null, 30_000_000_000n, 1_000_000_000n),
      resolveName: async () => null,
      broadcastTransaction: async (raw: string) => {
        sent.push(raw);
        throw new Error("stop after broadcast");
      },
    };
    const taken = guardSigner(new Wallet(SK), new Guard(profiles.hotWallet), () => ({
      ownCode: delegationCode(SWEEPER),
    }));
    const connected = taken.connect(provider as never);
    await expect(connected.sendTransaction({ to: tx.to, value: 1n })).rejects.toThrow(/OWN_CODE_PRESENT/);
    expect(sent).toEqual([]);
    await expect(connected.signMessage("hi")).rejects.toThrow(GuardRefusal);
  });

  it("refuses personal messages and EIP-712 under hot-wallet, signs them unchanged under user", async () => {
    const domain = { name: "x", version: "1", chainId: 1 };
    const types = {
      Mail: [
        { name: "to", type: "address" },
        { name: "n", type: "uint256" },
      ],
    };
    const value = { to: ALLOWED, n: 5n };
    const hot = guardSigner(new Wallet(SK), new Guard(profiles.hotWallet), () => ({ ownCode: "0x" }));
    await expect(hot.signMessage("hello")).rejects.toThrow(/KIND_NOT_ALLOWED/);
    await expect(hot.signTypedData(domain, types, value)).rejects.toThrow(/KIND_NOT_ALLOWED/);
    const user = guardSigner(new Wallet(SK), new Guard(profiles.user), () => ({ ownCode: "0x" }));
    expect(await user.signMessage("hello")).toBe(await new Wallet(SK).signMessage("hello"));
    expect(await user.signTypedData(domain, types, value)).toBe(
      await new Wallet(SK).signTypedData(domain, types, value),
    );
    expect(keccak256(typedDataPreimageEthers(domain, types, value))).toBe(TypedDataEncoder.hash(domain, types, value));
  });
});
