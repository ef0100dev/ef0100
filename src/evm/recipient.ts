import { bytesToHex, toBytes, type Hex } from "./bytes.js";
import { CHAINS, type Chain } from "./chains.js";
import { parseDelegation } from "./eip7702.js";
import { lookupDelegate } from "./registry.js";
import { rpcBatchAll, rpcBatchAny, type RpcCall, type RpcOptions } from "./rpc.js";
import { strongestCode } from "./scan.js";

export type RecipientReason =
  "DELEGATED" | "DELEGATED_TO_MALICIOUS" | "HAS_CODE" | "USDT_BLACKLISTED" | "USDC_BLACKLISTED" | "ENDPOINTS_DISAGREE";

export interface RecipientState {
  code: Hex | Uint8Array;
  /** true or false when the blacklist was read; null or absent when it was not (no table for the chain, or the call failed). */
  usdtBlacklisted?: boolean | null;
  usdcBlacklisted?: boolean | null;
  /** With crossCheck: what each endpoint returned for the code, when they differed. Any difference holds the transfer. */
  disagreement?: { endpoint: string; code: Hex }[];
}

export interface RecipientDecision {
  allow: boolean;
  delegate: string | null;
  reasons: { code: RecipientReason; message: string }[];
  /** Which stablecoin blacklists were actually read; an unread one is not evidence the address is clean. */
  blacklists: { usdt: boolean | null; usdc: boolean | null };
}

export interface RecipientPolicy {
  /** Delegates you put on your own wallets on purpose. Any other delegation blocks the transfer. */
  allowDelegates?: string[];
  /** Allow contract recipients (a cold-wallet multisig, a vault). Default false: refills go to EOAs. */
  allowContracts?: boolean;
}

/**
 * Should funds go to this address right now? While an EOA is delegated, whatever lands in it can be moved by the
 * delegate's code: on 2026-10-29 a 200M USDT refill was swept 72 s after it arrived, and a 2,961.99 ETH refill 60 s.
 */
export function judgeRecipient(state: RecipientState, policy: RecipientPolicy = {}): RecipientDecision {
  const code = toBytes(state.code);
  const delegate = parseDelegation(code);
  const reasons: RecipientDecision["reasons"] = [];
  if (delegate) {
    const allowed = (policy.allowDelegates ?? []).some((a) => a.toLowerCase() === delegate.toLowerCase());
    const entry = lookupDelegate(delegate);
    if (entry?.verdict === "malicious")
      reasons.push({ code: "DELEGATED_TO_MALICIOUS", message: `delegated to ${delegate}: ${entry.label}` });
    else if (!allowed)
      reasons.push({ code: "DELEGATED", message: `delegated to ${delegate}, which is not on your list` });
  } else if (code.length > 0 && !policy.allowContracts)
    reasons.push({ code: "HAS_CODE", message: "the recipient is a contract; refills go to EOAs unless allowed" });
  if (state.disagreement?.length)
    reasons.push({
      code: "ENDPOINTS_DISAGREE",
      message: `endpoints returned different code: ${state.disagreement.map((d) => `${d.endpoint} ${d.code.length > 12 ? `${d.code.slice(0, 12)}…` : d.code}`).join(", ")}`,
    });
  if (state.usdtBlacklisted) reasons.push({ code: "USDT_BLACKLISTED", message: "Tether has blacklisted this address" });
  if (state.usdcBlacklisted) reasons.push({ code: "USDC_BLACKLISTED", message: "Circle has blacklisted this address" });
  return {
    allow: reasons.length === 0,
    delegate,
    reasons,
    blacklists: { usdt: state.usdtBlacklisted ?? null, usdc: state.usdcBlacklisted ?? null },
  };
}

interface Blacklist {
  token: string;
  /** isBlackListed(address) on Ethereum USDT, isBlocked(address) on Tether's newer deployments, isBlacklisted(address) on USDC. */
  selector: Hex;
}

/** Stablecoin blacklists by chain id, each checked on chain against a known blacklisted address. */
export const BLACKLISTS: Record<number, { usdt?: Blacklist; usdc?: Blacklist }> = {
  1: {
    usdt: { token: "0xdAC17F958D2ee523a2206206994597C13D831ec7", selector: "0xe47d6060" },
    usdc: { token: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", selector: "0xfe575a87" },
  },
  43114: {
    usdt: { token: "0x9702230A8Ea53601f5cD2dc00fDBc13d4dF4A8c7", selector: "0xfbac3951" },
    usdc: { token: "0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E", selector: "0xfe575a87" },
  },
  137: {
    usdt: { token: "0xc2132D05D31c914a87C6611C10748AEb04B58e8F", selector: "0xfbac3951" },
    usdc: { token: "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359", selector: "0xfe575a87" },
  },
  42161: {
    usdt: { token: "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9", selector: "0xfbac3951" },
    usdc: { token: "0xaf88d065e77c8cC2239327C5EDb3A432268e5831", selector: "0xfe575a87" },
  },
  8453: { usdc: { token: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", selector: "0xfe575a87" } },
  10: { usdc: { token: "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85", selector: "0xfe575a87" } },
};

const word = (a: string) => a.slice(2).toLowerCase().padStart(64, "0");

/**
 * Reads the recipient's code and the chain's USDT and USDC blacklists, then applies judgeRecipient. A blacklist that
 * has no entry for the chain, or whose call fails, is reported as unread rather than as clean.
 */
export async function checkRecipient(
  address: string,
  opts: RecipientPolicy & RpcOptions & { chain?: Chain; crossCheck?: boolean } = {},
): Promise<RecipientDecision & { chain: string }> {
  const chain = opts.chain ?? CHAINS[0]!;
  const ask = async (calls: RpcCall[]) =>
    opts.crossCheck
      ? await rpcBatchAll(chain.rpc, calls, opts)
      : [{ endpoint: "", results: await rpcBatchAny(chain.rpc, calls, opts) }];
  const answers = await ask([{ method: "eth_getCode", params: [address, "latest"] }]);
  const seen = answers.flatMap((a) => {
    try {
      return [{ endpoint: a.endpoint, code: toBytes(a.results[0] as string) }];
    } catch {
      return [];
    }
  });
  if (!seen.length) throw new TypeError("no endpoint returned well-formed code for the recipient");
  const code = strongestCode(seen.map((x) => x.code));
  const differ = new Set(seen.map((x) => bytesToHex(x.code))).size > 1;
  const read = async (b: Blacklist | undefined): Promise<boolean | null> => {
    if (!b) return null;
    try {
      const got = (
        await ask([{ method: "eth_call", params: [{ to: b.token, data: b.selector + word(address) }, "latest"] }])
      )
        .map((a) => a.results[0] as Hex)
        .filter((r) => typeof r === "string" && /^0x[0-9a-fA-F]+$/.test(r) && r !== "0x")
        .map((r) => BigInt(r) !== 0n);
      return got.includes(true) ? true : got.length ? false : null;
    } catch {
      return null;
    }
  };
  const table = BLACKLISTS[chain.id] ?? {};
  const [usdt, usdc] = await Promise.all([read(table.usdt), read(table.usdc)]);
  return {
    chain: chain.name,
    ...judgeRecipient(
      {
        code,
        usdtBlacklisted: usdt,
        usdcBlacklisted: usdc,
        ...(differ ? { disagreement: seen.map((x) => ({ endpoint: x.endpoint, code: bytesToHex(x.code) })) } : {}),
      },
      opts,
    ),
  };
}
