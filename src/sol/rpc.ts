import { ed25519 } from "@noble/curves/ed25519.js";
import { base58, base64 } from "@scure/base";
import { rpcBatchAny, type RpcOptions } from "../evm/rpc.js";
import { nonceAccountsFilter } from "./check.js";
import { decodeSolanaTransaction } from "./message.js";

/** Keyless endpoints. getProgramAccounts on the System program needs your own (EF0100_RPC_SOLANA). */
export const SOLANA_RPC = ["https://api.mainnet-beta.solana.com", "https://solana-rpc.publicnode.com"];

export function solanaEndpoints(
  env: Record<string, string | undefined> = typeof process === "undefined" ? {} : process.env,
  override?: string,
): string[] {
  return [override, env.EF0100_RPC_SOLANA].filter((u): u is string => !!u).concat(SOLANA_RPC);
}

export interface FetchedSolanaTx {
  raw: Uint8Array;
  slot: number;
  blockTime: number | null;
  /** Fee payer's balance before the transaction, in lamports. */
  feePayerPreBalance: bigint | null;
}

export async function getSolanaTransaction(
  signature: string,
  urls: string[],
  opts: RpcOptions = {},
): Promise<FetchedSolanaTx> {
  const [r] = (await rpcBatchAny(
    urls,
    [{ method: "getTransaction", params: [signature, { encoding: "base64", maxSupportedTransactionVersion: 0 }] }],
    opts,
  )) as [
    {
      slot: number;
      blockTime: number | null;
      transaction: [string, string];
      meta: { preBalances: number[] } | null;
    } | null,
  ];
  if (!r) throw new Error(`transaction ${signature} not found`);
  const raw = base64.decode(r.transaction[0]);
  // The endpoint is not trusted: the bytes must be the transaction that was asked for, signed by its signers.
  const tx = decodeSolanaTransaction(raw);
  if (tx.signatures[0] !== signature)
    throw new Error("the endpoint returned a different transaction than the signature names");
  tx.signatures.forEach((sig, i) => {
    if (!ed25519.verify(base58.decode(sig), tx.message.bytes, base58.decode(tx.message.staticKeys[i]!)))
      throw new Error(`signature ${i} does not verify over the returned message`);
  });
  return {
    raw,
    slot: r.slot,
    blockTime: r.blockTime,
    feePayerPreBalance: r.meta ? BigInt(r.meta.preBalances[0]!) : null,
  };
}

export interface NonceAccount {
  address: string;
  /** The stored durable nonce: the "blockhash" a pre-signed transaction must carry. */
  nonce: string;
  lamports: number;
}

/**
 * Every nonce account whose authority is `authority`. A transaction pre-signed against any of them stays valid until
 * that nonce is advanced, so this list is the set of signatures that do not expire.
 */
export async function listNonceAccounts(
  authority: string,
  urls: string[],
  opts: RpcOptions = {},
): Promise<NonceAccount[]> {
  const [res] = (await rpcBatchAny(
    urls,
    [
      {
        method: "getProgramAccounts",
        params: ["11111111111111111111111111111111", { encoding: "base64", filters: nonceAccountsFilter(authority) }],
      },
    ],
    opts,
  )) as [{ pubkey: string; account: { data: [string, string]; lamports: number } }[]];
  return res
    .map((a) => {
      const data = base64.decode(a.account.data[0]);
      return { address: a.pubkey, nonce: base58.encode(data.subarray(40, 72)), lamports: a.account.lamports };
    })
    .sort((x, y) => x.address.localeCompare(y.address));
}
