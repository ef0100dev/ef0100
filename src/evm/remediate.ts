import { bytesToHex, keccak256, ZERO_ADDRESS, type Hex } from "./bytes.js";
import { authorizationDigest, authorizationPreimage, type Authorization, type SignedAuthorization } from "./eip7702.js";
import { serializeSetCodeTx, setCodeTxPreimage, type UnsignedSetCodeTx } from "./tx.js";

export interface ClearPlanInput {
  chainId: bigint;
  /** The delegated account. It sends the transaction to itself. */
  authority: string;
  /** The account's pending nonce: the transaction nonce. The authorization carries nonce + 1. */
  nonce: bigint;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
  /** 21,000 + 25,000 per tuple covers it; 50,000 leaves room for a delegate's receive(). */
  gasLimit?: bigint;
}

export interface ClearPlan {
  input: Required<ClearPlanInput>;
  authorization: Authorization;
  /** Step 1: the authority's key signs this preimage (or its keccak, the digest). */
  authorizationPreimage: Hex;
  authorizationDigest: Hex;
}

/**
 * Unsigned remediation for a delegated EOA: one self-sponsored type-4 transaction that authorizes address 0x0.
 * Self-sponsoring needs no third party and no other key, and the transaction nonce + 1 rule is built in.
 */
export function planClearDelegation(input: ClearPlanInput): ClearPlan {
  const full = { gasLimit: 50_000n, ...input };
  const authorization = { chainId: full.chainId, address: ZERO_ADDRESS, nonce: full.nonce + 1n };
  return {
    input: full,
    authorization,
    authorizationPreimage: bytesToHex(authorizationPreimage(authorization)),
    authorizationDigest: bytesToHex(authorizationDigest(authorization)),
  };
}

/** Step 2: with the signed authorization in hand, the transaction the same key signs next. */
export function clearDelegationTx(plan: ClearPlan, authSig: { yParity: number; r: bigint; s: bigint }) {
  const signed: SignedAuthorization = { ...plan.authorization, ...authSig };
  const tx: UnsignedSetCodeTx = {
    chainId: plan.input.chainId,
    nonce: plan.input.nonce,
    maxPriorityFeePerGas: plan.input.maxPriorityFeePerGas,
    maxFeePerGas: plan.input.maxFeePerGas,
    gasLimit: plan.input.gasLimit,
    to: plan.input.authority,
    value: 0n,
    data: "0x",
    accessList: [],
    authorizationList: [signed],
  };
  const preimage = setCodeTxPreimage(tx);
  return {
    tx,
    preimage: bytesToHex(preimage),
    signingHash: bytesToHex(keccak256(preimage)),
    /** Step 3: the broadcastable bytes once the transaction is signed. */
    serialize: (txSig: { yParity: number; r: bigint; s: bigint }) => serializeSetCodeTx(tx, txSig),
  };
}
