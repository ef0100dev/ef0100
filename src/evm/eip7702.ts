import {
  bytesToHex,
  concatBytes,
  hexToBytes,
  keccak256,
  toBytes,
  toChecksumAddress,
  ZERO_ADDRESS,
  type Hex,
} from "./bytes.js";
import { asAddress, asInt, asList, rlpEncode, rlpInt, type RlpItem } from "./rlp.js";
import { recoverAddress, type RecoverError } from "./secp256k1.js";

/** EIP-7702 constants (status Final). */
export const SET_CODE_TX_TYPE = 0x04;
export const AUTHORIZATION_MAGIC = 0x05;
export const DELEGATION_PREFIX = Uint8Array.of(0xef, 0x01, 0x00);
export const PER_EMPTY_ACCOUNT_COST = 25_000n;
export const PER_AUTH_BASE_COST = 12_500n;
export const MAX_AUTH_NONCE = 2n ** 64n - 1n;
/** keccak256 of empty code: what EXTCODEHASH returns after a delegation is cleared. */
export const EMPTY_CODE_HASH: Hex = "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";

export interface Authorization {
  chainId: bigint;
  /** The delegate. The zero address clears a delegation. */
  address: string;
  nonce: bigint;
}

export interface SignedAuthorization extends Authorization {
  yParity: number;
  r: bigint;
  s: bigint;
}

/** `0x05 ‖ rlp([chain_id, address, nonce])`: the exact bytes an authority's key signs (after keccak). */
export function authorizationPreimage(auth: Authorization): Uint8Array {
  return concatBytes(
    Uint8Array.of(AUTHORIZATION_MAGIC),
    rlpEncode([rlpInt(auth.chainId), hexToBytes(auth.address), rlpInt(auth.nonce)]),
  );
}

export function authorizationDigest(auth: Authorization): Uint8Array {
  return keccak256(authorizationPreimage(auth));
}

export type AuthorityResult =
  { ok: true; authority: string } | { ok: false; error: RecoverError | "NONCE_OVERFLOW" | "CHAIN_ID_OVERFLOW" };

/**
 * The signer of an authorization, with the checks EIP-7702 applies before using it:
 * nonce < 2^64 - 1, chain_id < 2^256, y_parity in {0, 1}, and s <= n/2.
 */
export function recoverAuthority(auth: SignedAuthorization): AuthorityResult {
  if (auth.nonce >= MAX_AUTH_NONCE) return { ok: false, error: "NONCE_OVERFLOW" };
  if (auth.chainId >= 2n ** 256n) return { ok: false, error: "CHAIN_ID_OVERFLOW" };
  const rec = recoverAddress(authorizationDigest(auth), auth.yParity, auth.r, auth.s, true);
  return rec.ok ? { ok: true, authority: rec.address } : { ok: false, error: rec.error };
}

/** Parses one authorization tuple `[chain_id, address, nonce, y_parity, r, s]`. */
export function decodeAuthorizationTuple(item: RlpItem, index = 0): SignedAuthorization {
  const t = asList(item, `authorization ${index}`);
  if (t.length !== 6) throw new TypeError(`authorization ${index}: expected 6 fields, got ${t.length}`);
  return {
    chainId: asInt(t[0], `authorization ${index} chain_id`),
    address: asAddress(t[1], `authorization ${index} address`),
    nonce: asInt(t[2], `authorization ${index} nonce`, 8),
    yParity: Number(asInt(t[3], `authorization ${index} y_parity`, 1)),
    r: asInt(t[4], `authorization ${index} r`),
    s: asInt(t[5], `authorization ${index} s`),
  };
}

export function encodeAuthorizationTuple(a: SignedAuthorization): RlpItem {
  return [rlpInt(a.chainId), hexToBytes(a.address), rlpInt(a.nonce), rlpInt(a.yParity), rlpInt(a.r), rlpInt(a.s)];
}

export function isClearing(auth: Authorization): boolean {
  return auth.address.toLowerCase() === ZERO_ADDRESS;
}

/** `0xef0100 ‖ address`: the 23-byte code an EOA carries while delegated. */
export function delegationCode(delegate: string): Hex {
  return bytesToHex(concatBytes(DELEGATION_PREFIX, hexToBytes(delegate)));
}

/** The delegate if `code` is exactly a delegation designator, otherwise null. */
export function parseDelegation(code: Uint8Array | string): string | null {
  const b = toBytes(code);
  if (b.length !== 23) return null;
  if (b[0] !== 0xef || b[1] !== 0x01 || b[2] !== 0x00) return null;
  return toChecksumAddress(b.subarray(3));
}

/** True when code starts with the 0xef0100 prefix at all, even if malformed (EIP-3541 bans 0xef contracts). */
export function hasDelegationPrefix(code: Uint8Array | string): boolean {
  const b = toBytes(code);
  return b.length >= 3 && b[0] === 0xef && b[1] === 0x01 && b[2] === 0x00;
}
