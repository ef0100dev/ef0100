import { bytesToHex, sameAddress, toBytes, type Hex } from "./bytes.js";
import {
  delegationCode,
  isClearing,
  MAX_AUTH_NONCE,
  parseDelegation,
  PER_AUTH_BASE_COST,
  PER_EMPTY_ACCOUNT_COST,
  recoverAuthority,
  type SignedAuthorization,
} from "./eip7702.js";
import { DELEGATES, lookupDelegate, type DelegateEntry } from "./registry.js";

/** Why a tuple did or did not take effect, in the order EIP-7702 checks it. */
export type AuthStatus =
  | "applied"
  | "wrong-chain"
  | "nonce-overflow"
  | "bad-signature"
  | "authority-has-code"
  | "nonce-ahead"
  | "nonce-used"
  | "unknown-state";

export interface AuthorityState {
  nonce: bigint;
  /** Current code: "0x", a delegation designator, or contract code. Defaults to "0x". */
  code?: Hex | Uint8Array;
  /** Whether the account exists in state (decides the 12,500 gas refund). Defaults to nonce > 0 or code present. */
  exists?: boolean;
}

export interface AuthOutcome {
  index: number;
  chainId: bigint;
  delegate: string;
  nonce: bigint;
  authority: string | null;
  status: AuthStatus;
  /** The authority's nonce at the moment this tuple was processed. */
  authorityNonce?: bigint;
  effect?: "delegate" | "clear";
  refund?: boolean;
  signatureError?: string;
}

export interface AuthorityAfter {
  nonce: bigint;
  code: Hex;
  delegate: string | null;
}

export interface ProcessResult {
  outcomes: AuthOutcome[];
  applied: AuthOutcome[];
  after: Map<string, AuthorityAfter>;
  gas: { authorizationCost: bigint; refund: bigint };
}

export interface ProcessContext {
  /** Chain the transaction executes on. */
  chainId: bigint;
  /**
   * State of an authority immediately before this transaction executes (after earlier transactions in the block).
   * Return undefined when unknown; the tuple is then reported as "unknown-state" and not simulated.
   */
  state: (authority: string) => AuthorityState | undefined;
}

interface Working {
  nonce: bigint;
  code: Uint8Array;
  exists: boolean;
}

/**
 * Replays the authorization list exactly as clients process it: in order, after the sender's nonce was incremented,
 * skipping (never reverting on) every tuple that fails a check, with each applied tuple bumping the authority's nonce.
 */
export function processAuthorizationList(
  tx: { authorizationList: SignedAuthorization[]; from: string | null; nonce: bigint },
  ctx: ProcessContext,
): ProcessResult {
  const working = new Map<string, Working>();
  const load = (addr: string): Working | undefined => {
    const key = addr.toLowerCase();
    const cached = working.get(key);
    if (cached) return cached;
    const s = ctx.state(addr);
    if (!s) return undefined;
    const code = s.code === undefined ? new Uint8Array(0) : toBytes(s.code);
    const w = { nonce: s.nonce, code, exists: s.exists ?? (s.nonce > 0n || code.length > 0) };
    if (tx.from && sameAddress(addr, tx.from)) w.nonce = tx.nonce + 1n;
    working.set(key, w);
    return w;
  };
  if (tx.from) {
    const s = load(tx.from);
    if (!s) working.set(tx.from.toLowerCase(), { nonce: tx.nonce + 1n, code: new Uint8Array(0), exists: true });
  }

  const outcomes: AuthOutcome[] = [];
  let refund = 0n;
  tx.authorizationList.forEach((auth, index) => {
    const base = { index, chainId: auth.chainId, delegate: auth.address, nonce: auth.nonce };
    if (auth.chainId !== 0n && auth.chainId !== ctx.chainId) {
      outcomes.push({ ...base, authority: null, status: "wrong-chain" });
      return;
    }
    if (auth.nonce >= MAX_AUTH_NONCE) {
      outcomes.push({ ...base, authority: null, status: "nonce-overflow" });
      return;
    }
    const rec = recoverAuthority(auth);
    if (!rec.ok) {
      outcomes.push({ ...base, authority: null, status: "bad-signature", signatureError: rec.error });
      return;
    }
    const authority = rec.authority;
    const st = load(authority);
    if (!st) {
      outcomes.push({ ...base, authority, status: "unknown-state" });
      return;
    }
    if (st.code.length !== 0 && parseDelegation(st.code) === null) {
      outcomes.push({ ...base, authority, status: "authority-has-code", authorityNonce: st.nonce });
      return;
    }
    if (st.nonce !== auth.nonce) {
      outcomes.push({
        ...base,
        authority,
        status: auth.nonce > st.nonce ? "nonce-ahead" : "nonce-used",
        authorityNonce: st.nonce,
      });
      return;
    }
    const gotRefund = st.exists;
    if (gotRefund) refund += PER_EMPTY_ACCOUNT_COST - PER_AUTH_BASE_COST;
    const clear = isClearing(auth);
    outcomes.push({
      ...base,
      authority,
      status: "applied",
      authorityNonce: st.nonce,
      effect: clear ? "clear" : "delegate",
      refund: gotRefund,
    });
    st.code = clear ? new Uint8Array(0) : toBytes(delegationCode(auth.address));
    st.nonce += 1n;
    st.exists = true;
  });

  const after = new Map<string, AuthorityAfter>();
  for (const o of outcomes) {
    if (!o.authority) continue;
    const w = working.get(o.authority.toLowerCase());
    if (!w) continue;
    after.set(o.authority, { nonce: w.nonce, code: bytesToHex(w.code), delegate: parseDelegation(w.code) });
  }
  return {
    outcomes,
    applied: outcomes.filter((o) => o.status === "applied"),
    after,
    gas: { authorizationCost: PER_EMPTY_ACCOUNT_COST * BigInt(tx.authorizationList.length), refund },
  };
}

export type Severity = "info" | "warn" | "critical";

export type FindingCode =
  | "NONCE_SPRAY"
  | "REPEATED_AUTHORITY"
  | "WILDCARD_CHAIN_ID"
  | "KNOWN_MALICIOUS_DELEGATE"
  | "UNKNOWN_DELEGATE"
  | "WALLET_DELEGATE"
  | "WATCHED_AUTHORITY"
  | "THIRD_PARTY_SPONSOR"
  | "CLEARS_DELEGATION"
  | "BAD_SIGNATURE";

export interface Finding {
  code: FindingCode;
  severity: Severity;
  message: string;
  authority?: string;
  indexes?: number[];
}

export interface AnalyzeOptions {
  /** Addresses whose authorizations must raise a critical finding (hot wallets, treasuries). */
  watch?: string[];
  registry?: readonly DelegateEntry[];
}

/** Static findings over an authorization list. They do not need chain state; pair them with processAuthorizationList. */
export function analyzeAuthorizationList(
  tx: { authorizationList: SignedAuthorization[]; from: string | null },
  opts: AnalyzeOptions = {},
): Finding[] {
  const registry = opts.registry ?? DELEGATES;
  const watch = new Set((opts.watch ?? []).map((a) => a.toLowerCase()));
  const findings: Finding[] = [];
  const byAuthority = new Map<string, { authority: string; idx: number[]; nonces: bigint[] }>();
  const bad: number[] = [];

  tx.authorizationList.forEach((auth, i) => {
    const rec = recoverAuthority(auth);
    if (!rec.ok) {
      bad.push(i);
      return;
    }
    const key = rec.authority.toLowerCase();
    const g = byAuthority.get(key) ?? { authority: rec.authority, idx: [], nonces: [] };
    g.idx.push(i);
    g.nonces.push(auth.nonce);
    byAuthority.set(key, g);
  });
  if (bad.length)
    findings.push({
      code: "BAD_SIGNATURE",
      severity: "info",
      message: `${bad.length} tuple(s) do not recover to an authority and will be skipped`,
      indexes: bad,
    });

  for (const g of byAuthority.values()) {
    if (g.idx.length < 2) continue;
    const sorted = [...new Set(g.nonces)].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    if (sorted.length < 2) {
      findings.push({
        code: "REPEATED_AUTHORITY",
        severity: "warn",
        authority: g.authority,
        indexes: g.idx,
        message: `${g.idx.length} authorizations from ${g.authority} for the same nonce; the last valid one wins`,
      });
      continue;
    }
    // Several nonces from one authority is a spray whether or not the run has gaps or repeats: padding the range
    // must not lower the severity.
    const span = sorted.at(-1)! - sorted[0]! + 1n;
    const descending = g.nonces.every((n, i) => i === 0 || n < g.nonces[i - 1]!);
    const ascending = g.nonces.every((n, i) => i === 0 || n > g.nonces[i - 1]!);
    const sponsored = !!tx.from && !sameAddress(tx.from, g.authority);
    const unlisted = g.idx.some((i) => {
      const a = tx.authorizationList[i]!;
      return !isClearing(a) && lookupDelegate(a.address, registry)?.verdict !== "wallet";
    });
    findings.push({
      code: "NONCE_SPRAY",
      severity: sponsored || unlisted ? "critical" : "warn",
      authority: g.authority,
      indexes: g.idx,
      message:
        `${g.idx.length} authorizations from ${g.authority}, ${sorted.length} distinct nonces over ${sorted[0]}..${sorted.at(-1)}` +
        (sorted.length === Number(span) ? "" : ` (${sorted.length} of ${span})`) +
        (descending
          ? ": listed in descending order, so at most one applies and it uses one nonce"
          : ascending
            ? ": listed in ascending order, so every tuple from the live nonce upward applies, one nonce each, and the last applied delegate wins"
            : ": a tuple applies whenever its nonce equals the nonce the tuples before it left"),
    });
  }

  const delegateIdx = new Map<string, number[]>();
  tx.authorizationList.forEach((auth, i) => {
    if (auth.chainId === 0n)
      findings.push({
        code: "WILDCARD_CHAIN_ID",
        severity: isClearing(auth) ? "warn" : "critical",
        indexes: [i],
        message: `tuple ${i} has chain_id 0: valid on every EIP-7702 chain where the authority's nonce matches`,
      });
    if (isClearing(auth)) return;
    const k = auth.address.toLowerCase();
    delegateIdx.set(k, [...(delegateIdx.get(k) ?? []), i]);
  });
  for (const [k, idx] of delegateIdx) {
    const address = tx.authorizationList[idx[0]!]!.address;
    const entry = lookupDelegate(k, registry);
    if (entry?.verdict === "malicious")
      findings.push({
        code: "KNOWN_MALICIOUS_DELEGATE",
        severity: "critical",
        indexes: idx,
        message: `delegate ${address} is ${entry.label}`,
      });
    else if (entry?.verdict === "wallet")
      findings.push({
        code: "WALLET_DELEGATE",
        severity: "info",
        indexes: idx,
        message: `delegate ${address} is ${entry.label}`,
      });
    else
      findings.push({
        code: "UNKNOWN_DELEGATE",
        severity: "warn",
        indexes: idx,
        message: `delegate ${address} is not in the registry`,
      });
  }

  for (const g of byAuthority.values()) {
    const delegating = g.idx.filter((i) => !isClearing(tx.authorizationList[i]!));
    if (watch.has(g.authority.toLowerCase()) && delegating.length)
      findings.push({
        code: "WATCHED_AUTHORITY",
        severity: "critical",
        authority: g.authority,
        indexes: delegating,
        message: `watched wallet ${g.authority} signed ${delegating.length} delegating authorization(s)`,
      });
    if (tx.from && !sameAddress(tx.from, g.authority) && delegating.length)
      findings.push({
        code: "THIRD_PARTY_SPONSOR",
        severity: "info",
        authority: g.authority,
        indexes: delegating,
        message: `submitted by ${tx.from}, not by the authority`,
      });
    const clearing = g.idx.filter((i) => isClearing(tx.authorizationList[i]!));
    if (clearing.length)
      findings.push({
        code: "CLEARS_DELEGATION",
        severity: "info",
        authority: g.authority,
        indexes: clearing,
        message: `${g.authority} authorizes address 0x0: clears its delegation`,
      });
  }
  const rank: Record<Severity, number> = { critical: 0, warn: 1, info: 2 };
  return findings.sort((a, b) => rank[a.severity] - rank[b.severity]);
}
