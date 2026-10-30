import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bigIntToFixed, keccak256, toChecksumAddress } from "./bytes.js";

export const SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
export const SECP256K1_HALF_N = SECP256K1_N / 2n;

export type RecoverError = "BAD_Y_PARITY" | "R_OUT_OF_RANGE" | "S_OUT_OF_RANGE" | "HIGH_S" | "NOT_RECOVERABLE";

export type Recovered = { ok: true; address: string } | { ok: false; error: RecoverError };

export function publicKeyToAddress(uncompressed: Uint8Array): string {
  if (uncompressed.length !== 65 || uncompressed[0] !== 4) throw new TypeError("expected a 65-byte uncompressed key");
  return toChecksumAddress(keccak256(uncompressed.subarray(1)).subarray(12));
}

/**
 * ecrecover over a 32-byte digest. With `requireLowS` (EIP-2 for transactions, and EIP-7702 for authorizations)
 * a signature with s > n/2 is rejected rather than normalised, exactly as clients do.
 */
export function recoverAddress(
  digest: Uint8Array,
  yParity: number | bigint,
  r: bigint,
  s: bigint,
  requireLowS = true,
): Recovered {
  const v = Number(yParity);
  if (v !== 0 && v !== 1) return { ok: false, error: "BAD_Y_PARITY" };
  if (r <= 0n || r >= SECP256K1_N) return { ok: false, error: "R_OUT_OF_RANGE" };
  if (s <= 0n || s >= SECP256K1_N) return { ok: false, error: "S_OUT_OF_RANGE" };
  if (requireLowS && s > SECP256K1_HALF_N) return { ok: false, error: "HIGH_S" };
  try {
    const point = new secp256k1.Signature(r, s, v).recoverPublicKey(digest);
    return { ok: true, address: publicKeyToAddress(point.toBytes(false)) };
  } catch {
    return { ok: false, error: "NOT_RECOVERABLE" };
  }
}

/** Signs a 32-byte digest with a local secret key (tests and demos only). Returns low-s and the y parity. */
export function signDigest(digest: Uint8Array, secretKey: Uint8Array): { yParity: number; r: bigint; s: bigint } {
  const sig = secp256k1.Signature.fromBytes(
    secp256k1.sign(digest, secretKey, { prehash: false, format: "recovered" }),
    "recovered",
  );
  return { yParity: sig.recovery!, r: sig.r, s: sig.s };
}

export function addressOfSecretKey(secretKey: Uint8Array): string {
  return publicKeyToAddress(secp256k1.getPublicKey(secretKey, false));
}

export function signatureBytes(sig: { yParity: number; r: bigint; s: bigint }): Uint8Array {
  const out = new Uint8Array(65);
  out.set(bigIntToFixed(sig.r, 32), 0);
  out.set(bigIntToFixed(sig.s, 32), 32);
  out[64] = 27 + sig.yParity;
  return out;
}
