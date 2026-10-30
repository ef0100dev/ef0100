import { keccak_256 } from "@noble/hashes/sha3.js";

export type Hex = `0x${string}`;

const HEX_RE = /^(0x)?[0-9a-fA-F]*$/;

/** Parses hex with or without 0x. Odd length and non-hex characters are errors, never padded or skipped. */
export function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== "string" || !HEX_RE.test(hex)) throw new TypeError(`not hex: ${String(hex).slice(0, 40)}`);
  const body = hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;
  if (body.length % 2 !== 0) throw new TypeError(`odd-length hex (${body.length} digits)`);
  const out = new Uint8Array(body.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(body.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function bytesToHex(bytes: Uint8Array): Hex {
  let s = "0x";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s as Hex;
}

export function toBytes(input: Uint8Array | string): Uint8Array {
  return typeof input === "string" ? hexToBytes(input) : input;
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export function bytesToBigInt(bytes: Uint8Array): bigint {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  return n;
}

/** Minimal big-endian encoding: 0 is the empty byte string, as RLP integers require. */
export function bigIntToBytes(n: bigint): Uint8Array {
  if (n < 0n) throw new RangeError("negative integer");
  if (n === 0n) return new Uint8Array(0);
  let hex = n.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  return hexToBytes(hex);
}

/** Big-endian, left-padded to `size` bytes. */
export function bigIntToFixed(n: bigint, size: number): Uint8Array {
  const b = bigIntToBytes(n);
  if (b.length > size) throw new RangeError(`integer does not fit in ${size} bytes`);
  const out = new Uint8Array(size);
  out.set(b, size - b.length);
  return out;
}

export function keccak256(data: Uint8Array): Uint8Array {
  return keccak_256(data);
}

export const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

export function isAddress(s: unknown): s is string {
  return typeof s === "string" && /^0x[0-9a-fA-F]{40}$/.test(s);
}

/** EIP-55 mixed-case checksum. Accepts any-case hex or 20 raw bytes. */
export function toChecksumAddress(address: string | Uint8Array): string {
  const bytes = typeof address === "string" ? hexToBytes(address) : address;
  if (bytes.length !== 20) throw new TypeError(`address must be 20 bytes, got ${bytes.length}`);
  const lower = bytesToHex(bytes).slice(2);
  const hash = bytesToHex(keccak256(new TextEncoder().encode(lower))).slice(2);
  let out = "0x";
  for (let i = 0; i < 40; i++) out += parseInt(hash[i]!, 16) >= 8 ? lower[i]!.toUpperCase() : lower[i]!;
  return out;
}

export function sameAddress(a: string | null | undefined, b: string | null | undefined): boolean {
  return !!a && !!b && a.toLowerCase() === b.toLowerCase();
}
