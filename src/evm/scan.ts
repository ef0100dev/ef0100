import { bytesToHex, isAddress, keccak256, toBytes, toChecksumAddress, type Hex } from "./bytes.js";
import { CHAINS, type Chain } from "./chains.js";
import { parseDelegation } from "./eip7702.js";
import { fingerprintCode, type CodeFingerprint } from "./fingerprint.js";
import { lookupCodehash, lookupDelegate, type DelegateEntry } from "./registry.js";
import { cleanText, rpcBatchAny, type RpcOptions } from "./rpc.js";

export type ScanState = "eoa" | "delegated" | "contract" | "error";

export interface ScanRow {
  chain: Pick<Chain, "id" | "key" | "name">;
  address: string;
  state: ScanState;
  nonce?: bigint;
  delegate?: string;
  /** Registry entry for the delegate, matched by address or by codehash. */
  entry?: DelegateEntry;
  delegateCode?: CodeFingerprint;
  error?: string;
}

export interface ScanResult {
  rows: ScanRow[];
  /** 0 nothing delegated, 1 delegated, 2 delegated to a malicious or sweeper-like delegate, 69 a chain did not answer. */
  exitCode: 0 | 1 | 2 | 69;
}

export interface ScanOptions extends RpcOptions {
  chains?: readonly Chain[];
  /** Delegates the caller put there on purpose: they do not raise the exit code. */
  allow?: string[];
}

/** eth_getCode and the nonce for every address on every chain, then the code of each delegate it finds. */
export async function scanAddresses(addresses: string[], opts: ScanOptions = {}): Promise<ScanResult> {
  for (const a of addresses) if (!isAddress(a)) throw new TypeError(`not an address: ${a}`);
  const list = addresses.map((a) => toChecksumAddress(a));
  const chains = opts.chains ?? CHAINS;
  // One chain's malformed answer becomes error rows for that chain; it never takes the other chains down with it.
  const rows = (
    await Promise.all(
      chains.map((c) =>
        scanChain(c, list, opts).catch((e: unknown) =>
          list.map((address) => ({
            chain: { id: c.id, key: c.key, name: c.name },
            address,
            state: "error" as const,
            error: cleanText((e as Error).message ?? String(e)),
          })),
        ),
      ),
    )
  ).flat();
  const allow = new Set((opts.allow ?? []).map((a) => a.toLowerCase()));
  let exitCode: ScanResult["exitCode"] = 0;
  for (const r of rows) {
    if (r.state !== "delegated" || allow.has(r.delegate!.toLowerCase())) continue;
    const bad = r.entry?.verdict === "malicious" || r.delegateCode?.sweeperLike;
    exitCode = Math.max(exitCode, bad ? 2 : 1) as ScanResult["exitCode"];
  }
  if (exitCode === 0 && rows.some((r) => r.state === "error")) exitCode = 69;
  return { rows, exitCode };
}

async function scanChain(chain: Chain, addresses: string[], opts: RpcOptions): Promise<ScanRow[]> {
  const meta = { id: chain.id, key: chain.key, name: chain.name };
  let results: unknown[];
  try {
    results = await rpcBatchAny(
      chain.rpc,
      addresses.flatMap((a) => [
        { method: "eth_getCode", params: [a, "latest"] },
        { method: "eth_getTransactionCount", params: [a, "latest"] },
      ]),
      opts,
    );
  } catch (e) {
    return addresses.map((address) => ({ chain: meta, address, state: "error" as const, error: (e as Error).message }));
  }
  const rows: ScanRow[] = addresses.map((address, i) => {
    try {
      const code = toBytes(results[i * 2] as string);
      const nonce = BigInt(results[i * 2 + 1] as string);
      const delegate = parseDelegation(code);
      if (delegate) return { chain: meta, address, state: "delegated", nonce, delegate };
      return { chain: meta, address, state: code.length ? "contract" : "eoa", nonce };
    } catch {
      return { chain: meta, address, state: "error", error: "the endpoint returned a malformed result" };
    }
  });
  const delegates = [...new Set(rows.filter((r) => r.delegate).map((r) => r.delegate!))];
  if (delegates.length) {
    try {
      const codes = await rpcBatchAny(
        chain.rpc,
        delegates.map((d) => ({ method: "eth_getCode", params: [d, "latest"] })),
        opts,
      );
      // One delegate's odd bytecode must not cost every other row its fingerprint or its codehash match.
      const byDelegate = new Map(
        delegates.map((d, i) => {
          const code = codes[i] as string;
          let fingerprint: ReturnType<typeof fingerprintCode> | undefined;
          try {
            fingerprint = fingerprintCode(code);
          } catch {
            fingerprint = undefined;
          }
          return [d, { fingerprint, codehash: codehashOf(code as Hex) }] as const;
        }),
      );
      for (const r of rows) {
        if (!r.delegate) continue;
        const got = byDelegate.get(r.delegate)!;
        r.delegateCode = got.fingerprint;
        r.entry = lookupDelegate(r.delegate) ?? lookupCodehash(got.codehash);
      }
    } catch {
      for (const r of rows) if (r.delegate) r.entry = lookupDelegate(r.delegate);
    }
  }
  return rows;
}

export function codehashOf(code: Hex | Uint8Array): Hex {
  return bytesToHex(keccak256(toBytes(code)));
}
