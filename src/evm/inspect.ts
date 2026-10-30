import { bytesToHex, hexToBytes, sameAddress, toBytes, type Hex } from "./bytes.js";
import { CHAINS, type Chain } from "./chains.js";
import { recoverAuthority, type SignedAuthorization } from "./eip7702.js";
import {
  analyzeAuthorizationList,
  processAuthorizationList,
  type AuthorityState,
  type Finding,
  type ProcessResult,
} from "./authlist.js";
import { decodeTransaction, serializeSetCodeTx, type DecodedTx } from "./tx.js";
import { RpcError, rpcBatchAny, toQuantity, type RpcOptions } from "./rpc.js";

export interface InspectOptions extends RpcOptions {
  /** Where to look a hash up, and the chain for a raw transaction that names none. Default Ethereum. */
  chain?: Chain;
  /** Chains to choose from by the transaction's own chain id, with any RPC overrides applied. Default CHAINS. */
  chains?: readonly Chain[];
  /** The caller chose the chain: a raw transaction for another chain is an error instead of a switch. */
  chainLocked?: boolean;
  watch?: string[];
}

export interface InspectResult {
  chain: Chain;
  tx: DecodedTx;
  /** Where the transaction sits, if it was mined. */
  mined?: { block: bigint; index: number };
  /** Authority state right before the transaction ran, and how it was obtained. */
  state: Map<string, AuthorityState & { source: string }>;
  result?: ProcessResult;
  findings: Finding[];
  notes: string[];
}

interface RpcTx {
  hash: Hex;
  type: Hex;
  from: string;
  nonce: Hex;
  blockNumber: Hex | null;
  transactionIndex: Hex | null;
  chainId?: Hex;
  to: string | null;
  value: Hex;
  input: Hex;
  gas: Hex;
  maxFeePerGas?: Hex;
  maxPriorityFeePerGas?: Hex;
  accessList?: { address: string; storageKeys: Hex[] }[];
  authorizationList?: { chainId: Hex; address: string; nonce: Hex; yParity: Hex; r: Hex; s: Hex }[];
  yParity?: Hex;
  v?: Hex;
  r: Hex;
  s: Hex;
}

const isHash = (s: string) => /^0x[0-9a-fA-F]{64}$/.test(s);

function authsFromRpc(list: NonNullable<RpcTx["authorizationList"]>): SignedAuthorization[] {
  return list.map((a) => ({
    chainId: BigInt(a.chainId),
    address: a.address,
    nonce: BigInt(a.nonce),
    yParity: Number(BigInt(a.yParity)),
    r: BigInt(a.r),
    s: BigInt(a.s),
  }));
}

/** Rebuilds a type-4 transaction's raw bytes from its JSON-RPC fields, for endpoints without eth_getRawTransactionByHash. */
function rawFromRpc(t: RpcTx): Hex {
  if (BigInt(t.type) !== 4n || !t.authorizationList || !t.to) throw new Error("raw transaction unavailable");
  return serializeSetCodeTx(
    {
      chainId: BigInt(t.chainId!),
      nonce: BigInt(t.nonce),
      maxPriorityFeePerGas: BigInt(t.maxPriorityFeePerGas!),
      maxFeePerGas: BigInt(t.maxFeePerGas!),
      gasLimit: BigInt(t.gas),
      to: t.to,
      value: BigInt(t.value),
      data: t.input,
      accessList: t.accessList ?? [],
      authorizationList: authsFromRpc(t.authorizationList),
    },
    { yParity: Number(BigInt(t.yParity ?? t.v!)), r: BigInt(t.r), s: BigInt(t.s) },
  );
}

/**
 * Decodes a transaction (by hash, or raw bytes) and, for type 4, replays its authorization list against the state each
 * authority had at that moment: the nonce at the end of the previous block, plus every earlier transaction in the
 * same block that touched it. That last part matters: on 2026-10-29 the victim's own transaction ran five positions
 * earlier in the same block and moved the nonce the attacker's tuple matched.
 */
export async function inspectTransaction(input: string, opts: InspectOptions = {}): Promise<InspectResult> {
  let chain = opts.chain ?? CHAINS[0]!;
  const notes: string[] = [];
  const byHash = isHash(input);
  let tx: DecodedTx;
  let meta: RpcTx | undefined;
  let lookup: "found" | "absent" | "failed" = "failed";
  if (byHash) {
    const [rawRes, txRes] = await Promise.allSettled([
      rpcBatchAny(chain.rpc, [{ method: "eth_getRawTransactionByHash", params: [input] }], opts),
      rpcBatchAny(
        [...chain.rpc, ...(chain.archive ?? [])],
        [{ method: "eth_getTransactionByHash", params: [input] }],
        opts,
      ),
    ]);
    if (rawRes.status === "rejected" && txRes.status === "rejected")
      throw new RpcError(`no endpoint answered for ${chain.name}`, chain.rpc[0] ?? "");
    meta = txRes.status === "fulfilled" ? ((txRes.value[0] as RpcTx | null) ?? undefined) : undefined;
    const raw = rawRes.status === "fulfilled" ? (rawRes.value[0] as Hex | null) : null;
    if (raw) tx = decodeTransaction(raw);
    else if (meta) tx = decodeTransaction(rawFromRpc(meta));
    else throw new Error(`transaction ${input} not found on ${chain.name}`);
    if (tx.hash.toLowerCase() !== input.toLowerCase())
      throw new Error("the endpoint returned bytes for a different hash");
    lookup = txRes.status === "fulfilled" ? (meta ? "found" : "absent") : "failed";
  } else {
    tx = decodeTransaction(hexToBytes(input));
  }

  // A typed or EIP-155 transaction names its chain; read state there, not wherever the defaults point.
  if (tx.chainId !== null && tx.chainId !== undefined && BigInt(chain.id) !== tx.chainId) {
    const named = (opts.chains ?? CHAINS).find((c) => BigInt(c.id) === tx.chainId);
    if (byHash || opts.chainLocked)
      throw new Error(`the transaction is for chain id ${tx.chainId}, not ${chain.name} (${chain.id})`);
    if (!named) throw new Error(`the transaction is for chain id ${tx.chainId}, which has no endpoints here`);
    chain = named;
    notes.push(`read from ${named.name}, the chain the transaction names`);
  }
  if (!byHash) {
    // The hash of raw bytes is known: look it up so a mined transaction replays against the state it ran on.
    try {
      const [m] = await rpcBatchAny(
        [...chain.rpc, ...(chain.archive ?? [])],
        [{ method: "eth_getTransactionByHash", params: [tx.hash] }],
        opts,
      );
      meta = (m as RpcTx | null) ?? undefined;
      lookup = meta ? "found" : "absent";
    } catch {
      lookup = "failed";
    }
  }

  const findings = tx.type === 4 ? analyzeAuthorizationList(tx, { watch: opts.watch }) : [];
  const state = new Map<string, AuthorityState & { source: string }>();
  if (tx.type !== 4) return { chain, tx, state, findings, notes: [...notes, "not a set-code transaction"] };

  const authorities = [
    ...new Set(
      tx.authorizationList
        .map((a) => recoverAuthority(a))
        .filter((r) => r.ok)
        .map((r) => (r as { authority: string }).authority),
    ),
  ];
  const mined =
    meta?.blockNumber && meta.transactionIndex
      ? { block: BigInt(meta.blockNumber), index: Number(BigInt(meta.transactionIndex)) }
      : undefined;
  const readState = async (tag: string, urls: string[], source: string) => {
    const reads = await rpcBatchAny(
      urls,
      authorities.flatMap((a) => [
        { method: "eth_getTransactionCount", params: [a, tag] },
        { method: "eth_getCode", params: [a, tag] },
        { method: "eth_getBalance", params: [a, tag] },
      ]),
      opts,
    );
    authorities.forEach((a, i) => {
      const nonce = BigInt(reads[i * 3] as string);
      const code = reads[i * 3 + 1] as Hex;
      const balance = BigInt(reads[i * 3 + 2] as string);
      state.set(a.toLowerCase(), {
        nonce,
        code,
        exists: nonce > 0n || balance > 0n || toBytes(code).length > 0,
        source,
      });
    });
  };

  try {
    if (mined) {
      await readState(
        toQuantity(mined.block - 1n),
        [...(chain.archive ?? []), ...chain.rpc],
        `end of block ${mined.block - 1n}`,
      );
      const hadCode = [...state.entries()].filter(([, st]) => st.code && toBytes(st.code).length > 0).map(([a]) => a);
      const [block] = (await rpcBatchAny(
        [...chain.rpc, ...(chain.archive ?? [])],
        [{ method: "eth_getBlockByNumber", params: [toQuantity(mined.block), true] }],
        opts,
      )) as [{ transactions: RpcTx[] }];
      const earlier = block.transactions.filter((t) => Number(BigInt(t.transactionIndex!)) < mined.index);
      const changedBy = new Set<number>();
      let codeInstalledAt = -1;
      earlier.forEach((t, k) => {
        const before = new Map([...state].map(([a, st]) => [a, `${st.nonce}:${bytesHex(st.code)}`]));
        for (const a of authorities) if (sameAddress(t.from, a)) state.get(a.toLowerCase())!.nonce += 1n;
        if (BigInt(t.type) === 4n && t.authorizationList) {
          const res = processAuthorizationList(
            { authorizationList: authsFromRpc(t.authorizationList), from: t.from, nonce: BigInt(t.nonce) },
            { chainId: BigInt(chain.id), state: (a) => state.get(a.toLowerCase()) },
          );
          for (const [a, after] of res.after) {
            const st = state.get(a.toLowerCase());
            if (!st) continue;
            st.nonce = after.nonce;
            st.code = after.code;
            if (toBytes(after.code).length > 0 && codeInstalledAt < 0) codeInstalledAt = k;
          }
        }
        for (const [a, st] of state) if (before.get(a) !== `${st.nonce}:${bytesHex(st.code)}`) changedBy.add(k);
      });
      for (const st of state.values())
        st.source += `, then ${earlier.length} earlier transaction(s) in block ${mined.block}`;
      if (changedBy.size)
        notes.push(`${changedBy.size} earlier transaction(s) in the same block changed an authority's state`);
      if (hadCode.length || (codeInstalledAt >= 0 && codeInstalledAt < earlier.length - 1))
        notes.push(
          "an authority had code while earlier transactions in this block ran; code can change its nonce (CREATE), so treat the simulation as approximate",
        );
    } else {
      await readState("latest", chain.rpc, "latest");
      notes.push(
        lookup === "absent"
          ? "not mined: replayed against the latest state"
          : meta
            ? "pending: replayed against the latest state"
            : "not looked up (no endpoint answered): replayed against the latest state",
      );
    }
  } catch (e) {
    notes.push(`authority state unavailable (${(e as Error).message}); tuples are not simulated`);
    return { chain, tx, mined, state, findings, notes };
  }

  const result = processAuthorizationList(tx, {
    chainId: BigInt(chain.id),
    state: (a) => state.get(a.toLowerCase()),
  });
  return { chain, tx, mined, state, result, findings, notes };
}

function bytesHex(code: Hex | Uint8Array | undefined): string {
  return code === undefined ? "0x" : typeof code === "string" ? code.toLowerCase() : bytesToHex(code);
}
