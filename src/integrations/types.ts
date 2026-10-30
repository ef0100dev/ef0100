import type { GuardContext } from "../guard/policy.js";

/** What the account is about to sign, so the caller can supply the right facts (the live nonce, the own code). */
export type SigningKind = "hash" | "authorization" | "transaction" | "message" | "typed-data";
export type ContextSource = (kind: SigningKind) => GuardContext | Promise<GuardContext>;
