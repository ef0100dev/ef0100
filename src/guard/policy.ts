import { bytesToHex, equalBytes, hexToBytes, keccak256, sameAddress, toBytes, type Hex } from "../evm/bytes.js";
import {
  authorizationDigest,
  isClearing,
  parseDelegation,
  recoverAuthority,
  type Authorization,
  type AuthorityResult,
} from "../evm/eip7702.js";
import { classifySigningInput, type Classified, type ClassifiedKind, type ClassifyOptions } from "./classify.js";

export interface AllowedDelegate {
  address: string;
  /** Chain ids this delegate may be used on. Defaults to every chain except the chain_id 0 wildcard. */
  chains?: number[] | "any";
  /** If set, the caller must supply the delegate's current codehash in the context and it must match. */
  codehash?: Hex;
}

export interface GuardPolicy {
  /** Kinds signed without further checks. Default: typed, set-code and legacy transactions, EIP-712, personal messages. */
  allowKinds?: ClassifiedKind[];
  /** Sign bare 32-byte digests. Default false: a digest can be an EIP-7702 authorization and nothing shows it. */
  allowRawDigest?: boolean;
  /**
   * Refuse any request that does not say what the key's own account code is (`ctx.ownCode`, `"0x"` for none). Without
   * it the own-code rule cannot fire, so a caller that forgets it silently loses that protection. On in `hotWallet`.
   */
  requireOwnCode?: boolean;
  /** Sign legacy transactions without a chain id (pre-EIP-155), which replay on every chain the key uses. Default false. */
  allowUnprotectedLegacy?: boolean;
  /**
   * Cold addresses for break-glass evacuation after the key's own account has code: a plain ETH transfer (no calldata)
   * to one of them, or `transfer(to, amount)` on a token in `breakGlassTokens` whose `to` is one of them.
   */
  breakGlass?: string[];
  /** Token contracts whose `transfer` to a `breakGlass` address may still be signed while the key's account has code. */
  breakGlassTokens?: string[];
  authorizations?: {
    /** Delegates this key may authorize. Default: none, so every delegating authorization is refused. */
    allowDelegates?: AllowedDelegate[];
    /** Authorizations to address 0x0 (clearing a delegation). Default true. */
    allowClear?: boolean;
    /** chain_id 0 authorizations, valid on every 7702 chain. Default false. */
    allowWildcardChain?: boolean;
    /** At most this many delegating authorizations per key per window; clears do not count. Default 1 per 60 s. */
    maxPerWindow?: number;
    windowMs?: number;
    /** Sign type-4 transactions that carry other accounts' authorizations (acting as a relayer). Default false. */
    allowSponsoring?: boolean;
    /** Refuse an authorization when the caller does not pass the key's live nonce. Default true. */
    requireNonce?: boolean;
    /** The longest authorization list the guard recovers (one ecrecover per tuple). Default 16. */
    maxTuples?: number;
    /**
     * Keep signing as usual while the key's own code is the designator of an allowed delegate (and its codehash matches
     * when one is pinned). Default false: any code on the key's account means it is compromised.
     */
    trustAllowedDelegation?: boolean;
  };
}

export interface GuardContext {
  /** Address of the key being asked to sign. Required for authorizations, rate limits and the own-code rule. */
  signer?: string;
  /** The key's pending nonce. Required for authorizations unless the policy turns `requireNonce` off. */
  nonce?: bigint;
  /**
   * The key will send the type-4 transaction itself, so its authorization must carry nonce + 1. Only set it from the
   * component that submits that transaction: an authorization for nonce + 1 that is never sent stays usable later.
   */
  selfSponsored?: boolean;
  /** Current codehash of each delegate address, keyed by lowercase address, when known. */
  codehashes?: Record<string, Hex>;
  /** Milliseconds; defaults to Date.now(). Times in the future do not count against the rate limit. */
  now?: number;
  /**
   * The key's own account code right now (eth_getCode). Non-empty means the key's account is delegated or is a
   * contract: from that moment the guard signs only the clear, plus break-glass transfers.
   */
  ownCode?: Hex | Uint8Array;
}

export type ReasonCode =
  | "NO_PREIMAGE"
  | "UNKNOWN_INPUT"
  | "KIND_NOT_ALLOWED"
  | "CONTEXT_MISSING"
  | "NO_CHAIN_ID"
  | "TOO_MANY_TUPLES"
  | "DELEGATE_NOT_ALLOWED"
  | "DELEGATE_CHAIN_NOT_ALLOWED"
  | "DELEGATE_CODEHASH_MISMATCH"
  | "WILDCARD_CHAIN_ID"
  | "CLEAR_NOT_ALLOWED"
  | "NONCE_NOT_LIVE"
  | "RATE_LIMITED"
  | "SPONSORS_OTHER_AUTHORITY"
  | "BAD_TUPLE_SIGNATURE"
  | "PREIMAGE_MISMATCH"
  | "OWN_CODE_PRESENT"
  | "ALLOWED";

export interface Reason {
  code: ReasonCode;
  message: string;
  /** Index in a set-code transaction's authorization list, when the reason is about one tuple. */
  tuple?: number;
}

export interface Decision {
  allow: boolean;
  classified: Classified;
  reasons: Reason[];
}

export class GuardRefusal extends Error {
  override name = "GuardRefusal";
  constructor(readonly decision: Decision) {
    super(`refused to sign ${decision.classified.kind}: ${decision.reasons.map((r) => r.code).join(", ")}`);
  }
}

const DEFAULT_KINDS: ClassifiedKind[] = ["typed-tx", "set-code-tx", "legacy-tx", "eip712", "personal-message"];
const TRANSFER = "a9059cbb";
const SEEN_LIMIT = 10_000;

/** Ready-made policies. Both refuse bare digests, chain_id 0, relayed tuples and unprotected legacy transactions. */
export const profiles = {
  /**
   * Exchange and treasury signers: transactions only (no EIP-712, which can carry a token permit, and no personal
   * messages), no delegation at all, only clearing one; one authorization per key per 10 minutes.
   */
  hotWallet: {
    allowKinds: ["typed-tx", "set-code-tx", "legacy-tx"],
    requireOwnCode: true,
    authorizations: { allowDelegates: [], allowClear: true, maxPerWindow: 1, windowMs: 600_000 },
  } satisfies GuardPolicy,
  /**
   * A person's own wallet: the two common wallet delegates are allowed, and being delegated to one of them is not
   * treated as compromise. Allowing a delegate is a decision, not a safety label: anyone who can sign for the key can
   * use the same delegate.
   */
  user: {
    authorizations: {
      allowDelegates: [
        { address: "0x4Cd241E8d1510e30b2076397afc7508Ae59C66c9" },
        { address: "0x63c0c19a282a1B52b07dD5a65b58948A07DAE32B" },
      ],
      allowClear: true,
      maxPerWindow: 3,
      windowMs: 600_000,
      trustAllowedDelegation: true,
    },
  } satisfies GuardPolicy,
} as const;

/**
 * A deny-by-default policy layer for whatever sits behind it (a KMS key, an HSM, a signing service). It decides from
 * the bytes it is asked to sign, plus the context the caller supplies about the key (signer, live nonce, own code).
 */
export class Guard {
  private readonly history = new Map<string, number[]>();
  /** Digests of authorizations this guard already allowed, so a transaction carrying one does not count it twice. */
  private readonly seen = new Set<string>();

  constructor(readonly policy: GuardPolicy = profiles.hotWallet) {}

  check(input: Uint8Array | string, opts: ClassifyOptions, ctx: GuardContext = {}): Decision {
    const classified = classifySigningInput(Uint8Array.from(toBytes(input)), opts);
    const reasons: Reason[] = [];
    const now = ctx.now ?? Date.now();
    const p = this.policy.authorizations ?? {};
    const kinds = this.policy.allowKinds ?? DEFAULT_KINDS;
    let recovered: AuthorityResult[] = [];
    switch (classified.kind) {
      case "raw-digest":
        if (!this.policy.allowRawDigest)
          reasons.push({
            code: "NO_PREIMAGE",
            message: "a bare 32-byte digest cannot be classified; it could be an EIP-7702 authorization",
          });
        break;
      case "unknown":
        reasons.push({ code: "UNKNOWN_INPUT", message: classified.reason });
        break;
      case "eip7702-authorization":
        if (!ctx.signer)
          reasons.push({
            code: "CONTEXT_MISSING",
            message: "an authorization needs ctx.signer, the key it would bind",
          });
        else reasons.push(...this.checkAuthorization(classified.authorization, ctx.nonce, ctx.selfSponsored, ctx, now));
        break;
      case "set-code-tx": {
        if (!kinds.includes("set-code-tx")) {
          reasons.push({ code: "KIND_NOT_ALLOWED", message: "set-code-tx is not in allowKinds" });
          break;
        }
        const max = p.maxTuples ?? 16;
        if (classified.authorizationList.length > max) {
          reasons.push({
            code: "TOO_MANY_TUPLES",
            message: `${classified.authorizationList.length} authorizations; this policy recovers at most ${max}`,
          });
          break;
        }
        recovered = classified.authorizationList.map((a) => recoverAuthority(a));
        classified.authorizationList.forEach((a, i) => {
          const rec = recovered[i]!;
          if (!rec.ok) {
            reasons.push({ code: "BAD_TUPLE_SIGNATURE", message: `tuple does not recover (${rec.error})`, tuple: i });
            return;
          }
          if (ctx.signer && sameAddress(rec.authority, ctx.signer)) {
            // The sender's nonce is bumped before tuples run, so its own tuple must carry tx nonce + 1.
            const own = this.checkAuthorization(a, classified.nonce + 1n, false, ctx, now);
            reasons.push(...own.map((r) => ({ ...r, tuple: i })));
          } else if (!p.allowSponsoring)
            reasons.push({
              code: "SPONSORS_OTHER_AUTHORITY",
              message: `tuple is signed by ${rec.authority}; this key would be relaying another account's delegation`,
              tuple: i,
            });
        });
        break;
      }
      case "legacy-tx":
        if (classified.chainId === null && !this.policy.allowUnprotectedLegacy)
          reasons.push({
            code: "NO_CHAIN_ID",
            message: "a legacy transaction without a chain id replays on every chain that shares the key",
          });
        if (!kinds.includes("legacy-tx"))
          reasons.push({ code: "KIND_NOT_ALLOWED", message: "legacy-tx is not in allowKinds" });
        break;
      default:
        if (!kinds.includes(classified.kind))
          reasons.push({ code: "KIND_NOT_ALLOWED", message: `${classified.kind} is not in allowKinds` });
    }
    const ownCode = ctx.ownCode === undefined ? undefined : toBytes(ctx.ownCode);
    if (ownCode === undefined && this.policy.requireOwnCode)
      reasons.push({
        code: "CONTEXT_MISSING",
        message:
          'this profile needs ctx.ownCode, eth_getCode of the key\'s own address ("0x" when it has none), on every request',
      });
    if (
      ownCode &&
      ownCode.length > 0 &&
      !this.trustedOwnCode(ownCode, ctx) &&
      !this.allowedWhileCompromised(classified, ctx, recovered)
    )
      reasons.unshift({
        code: "OWN_CODE_PRESENT",
        message: `this key's own account has code (${bytesToHex(ownCode).slice(0, 18)}…): sign nothing but the clear and break-glass transfers`,
      });
    const allow = reasons.length === 0;
    if (allow) {
      this.record(classified, ctx, now, recovered);
      reasons.push({ code: "ALLOWED", message: `${classified.kind} passes the policy` });
    }
    return { allow, classified, reasons };
  }

  /**
   * The safe way to put a raw-digest signer (KMS DIGEST, Web3Signer applyHash=false, a sign(hash) API) behind the
   * guard: the caller sends the preimage along, the guard checks keccak256(preimage) = digest, then judges the preimage.
   */
  checkDigest(
    digest: Uint8Array | string,
    preimage: Uint8Array | string | undefined,
    ctx: GuardContext = {},
  ): Decision {
    if (preimage === undefined) return this.check(digest, { as: "digest" }, ctx);
    const d = toBytes(digest);
    const p = toBytes(preimage);
    if (!equalBytes(keccak256(p), d)) {
      const classified = classifySigningInput(d, { as: "digest" });
      return {
        allow: false,
        classified,
        reasons: [{ code: "PREIMAGE_MISMATCH", message: "keccak256(preimage) is not the digest to be signed" }],
      };
    }
    return this.check(p, { as: "preimage", allow32ByteTransactions: true }, ctx);
  }

  /** Wraps a signing function so it only ever receives the exact bytes the policy allowed. */
  wrap<T>(
    sign: (input: Uint8Array) => T | Promise<T>,
    opts: ClassifyOptions,
  ): (input: Uint8Array | string, ctx?: GuardContext) => Promise<T> {
    return async (input, ctx = {}) => {
      const bytes = Uint8Array.from(toBytes(input));
      const decision = this.check(bytes, opts, ctx);
      if (!decision.allow) throw new GuardRefusal(decision);
      return sign(bytes);
    };
  }

  private checkAuthorization(
    auth: Authorization,
    liveNonce: bigint | undefined,
    selfSponsored: boolean | undefined,
    ctx: GuardContext,
    now: number,
  ): Reason[] {
    const p = this.policy.authorizations ?? {};
    const out: Reason[] = [];
    if (auth.chainId === 0n && !p.allowWildcardChain)
      out.push({ code: "WILDCARD_CHAIN_ID", message: "chain_id 0 is valid on every EIP-7702 chain" });
    const clearing = isClearing(auth);
    if (clearing) {
      if (p.allowClear === false) out.push({ code: "CLEAR_NOT_ALLOWED", message: "clearing is disabled by policy" });
    } else {
      const allowed = (p.allowDelegates ?? []).find((d) => sameAddress(d.address, auth.address));
      if (!allowed) out.push({ code: "DELEGATE_NOT_ALLOWED", message: `${auth.address} is not an allowed delegate` });
      else {
        const chains = allowed.chains ?? "any";
        if (chains !== "any" && !chains.includes(Number(auth.chainId)))
          out.push({ code: "DELEGATE_CHAIN_NOT_ALLOWED", message: `delegate not allowed on chain ${auth.chainId}` });
        if (allowed.codehash) {
          const seen = ctx.codehashes?.[auth.address.toLowerCase()];
          if (!seen || seen.toLowerCase() !== allowed.codehash.toLowerCase())
            out.push({
              code: "DELEGATE_CODEHASH_MISMATCH",
              message: seen
                ? `codehash ${seen} does not match the allowed ${allowed.codehash}`
                : "delegate codehash unknown",
            });
        }
      }
    }
    if (liveNonce === undefined) {
      if (p.requireNonce ?? true)
        out.push({
          code: "CONTEXT_MISSING",
          message: "an authorization needs ctx.nonce, the key's live nonce, to tell a live tuple from a future one",
        });
    } else {
      const expected = liveNonce + (selfSponsored ? 1n : 0n);
      if (auth.nonce !== expected)
        out.push({
          code: "NONCE_NOT_LIVE",
          message: `nonce ${auth.nonce} is not the live nonce ${expected}; a signed future nonce stays valid until the account reaches it`,
        });
    }
    const counted = this.seen.has(bytesToHex(authorizationDigest(auth)));
    if (ctx.signer && !clearing && !counted) {
      const max = p.maxPerWindow ?? 1;
      const windowMs = p.windowMs ?? 60_000;
      const recent = this.recent(ctx.signer, now, windowMs);
      if (recent.length >= max)
        out.push({
          code: "RATE_LIMITED",
          message: `${recent.length} authorization(s) already signed for this key in the last ${windowMs / 1000} s`,
        });
    }
    return out;
  }

  private recent(signer: string, now: number, windowMs: number): number[] {
    return (this.history.get(signer.toLowerCase()) ?? []).filter((t) => now - t >= 0 && now - t < windowMs);
  }

  /** The key's own code is a designator of an allowed delegate and the policy trusts that state. */
  private trustedOwnCode(ownCode: Uint8Array, ctx: GuardContext): boolean {
    const p = this.policy.authorizations ?? {};
    if (!p.trustAllowedDelegation) return false;
    const delegate = parseDelegation(ownCode);
    if (!delegate) return false;
    const allowed = (p.allowDelegates ?? []).find((d) => sameAddress(d.address, delegate));
    if (!allowed) return false;
    if (!allowed.codehash) return true;
    return ctx.codehashes?.[delegate.toLowerCase()]?.toLowerCase() === allowed.codehash.toLowerCase();
  }

  /** A transaction body that only evacuates to a listed cold address: plain ETH, or a token transfer. */
  private breakGlassBody(to: string | null, data: Hex): boolean {
    if (!to) return false;
    const cold = this.policy.breakGlass ?? [];
    const body = hexToBytes(data);
    if (body.length === 0) return cold.some((a) => sameAddress(a, to));
    if (!(this.policy.breakGlassTokens ?? []).some((t) => sameAddress(t, to))) return false;
    const hex = bytesToHex(body).slice(2);
    if (body.length !== 68 || hex.slice(0, 8) !== TRANSFER || !/^0{24}$/.test(hex.slice(8, 32))) return false;
    return cold.some((a) => sameAddress(a, `0x${hex.slice(32, 72)}`));
  }

  /** With the key's account delegated, only a self-clear and break-glass transfers pass. */
  private allowedWhileCompromised(c: Classified, ctx: GuardContext, recovered: AuthorityResult[]): boolean {
    if (!ctx.signer) return false;
    const signer = ctx.signer;
    if (c.kind === "eip7702-authorization") return isClearing(c.authorization);
    if (c.kind === "set-code-tx") {
      const ownClears =
        recovered.length === c.authorizationList.length &&
        c.authorizationList.every((a, i) => {
          const rec = recovered[i]!;
          return isClearing(a) && rec.ok && sameAddress(rec.authority, signer);
        });
      const inertBody = sameAddress(c.to, signer) && c.value === 0n && hexToBytes(c.data).length === 0;
      return ownClears && (inertBody || this.breakGlassBody(c.to, c.data));
    }
    if (c.kind === "typed-tx" || c.kind === "legacy-tx") return this.breakGlassBody(c.to, c.data);
    return false;
  }

  /** Counts the key's own delegating authorizations once each; relayed tuples and clears are not counted. */
  private record(c: Classified, ctx: GuardContext, now: number, recovered: AuthorityResult[]): void {
    if (!ctx.signer) return;
    const signer = ctx.signer;
    const own: Authorization[] = [];
    if (c.kind === "eip7702-authorization") own.push(c.authorization);
    if (c.kind === "set-code-tx")
      c.authorizationList.forEach((a, i) => {
        const rec = recovered[i];
        if (rec?.ok && sameAddress(rec.authority, signer)) own.push(a);
      });
    const windowMs = this.policy.authorizations?.windowMs ?? 60_000;
    for (const a of own) {
      const digest = bytesToHex(authorizationDigest(a));
      if (this.seen.has(digest)) continue;
      if (this.seen.size >= SEEN_LIMIT) this.seen.delete(this.seen.values().next().value!);
      this.seen.add(digest);
      if (isClearing(a)) continue;
      this.history.set(signer.toLowerCase(), [...this.recent(signer, now, windowMs), now]);
    }
  }
}
