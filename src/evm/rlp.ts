import { bigIntToBytes, bytesToBigInt, toChecksumAddress } from "./bytes.js";

export type RlpItem = Uint8Array | RlpItem[];

export class RlpError extends Error {
  override name = "RlpError";
}

function encodeLength(len: number, offset: number): Uint8Array {
  if (len <= 55) return Uint8Array.of(offset + len);
  const lenBytes = bigIntToBytes(BigInt(len));
  return Uint8Array.of(offset + 55 + lenBytes.length, ...lenBytes);
}

export function rlpEncode(item: RlpItem): Uint8Array {
  if (item instanceof Uint8Array) {
    if (item.length === 1 && item[0]! < 0x80) return item;
    const head = encodeLength(item.length, 0x80);
    const out = new Uint8Array(head.length + item.length);
    out.set(head);
    out.set(item, head.length);
    return out;
  }
  const parts = item.map(rlpEncode);
  const total = parts.reduce((n, p) => n + p.length, 0);
  const head = encodeLength(total, 0xc0);
  const out = new Uint8Array(head.length + total);
  out.set(head);
  let o = head.length;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

/** Integer as an RLP string: minimal big-endian, 0 as the empty string. */
export function rlpInt(n: bigint | number): Uint8Array {
  return bigIntToBytes(BigInt(n));
}

/**
 * Strict decoder: rejects every non-canonical form geth rejects (single bytes below 0x80 wrapped in a string header,
 * long-form lengths that fit the short form, length prefixes with leading zeros) and any trailing bytes.
 */
export function rlpDecode(input: Uint8Array): RlpItem {
  const [item, end] = decodeAt(input, 0);
  if (end !== input.length) throw new RlpError(`trailing bytes: ${input.length - end} after the RLP item`);
  return item;
}

function readLength(input: Uint8Array, start: number, lenOfLen: number): number {
  if (start + lenOfLen > input.length) throw new RlpError("length prefix runs past the end");
  if (input[start] === 0) throw new RlpError("length prefix has a leading zero");
  let len = 0;
  for (let i = 0; i < lenOfLen; i++) len = len * 256 + input[start + i]!;
  if (len <= 55) throw new RlpError("long form used for a length that fits the short form");
  if (!Number.isSafeInteger(len)) throw new RlpError("length too large");
  return len;
}

function decodeAt(input: Uint8Array, pos: number): [RlpItem, number] {
  if (pos >= input.length) throw new RlpError("unexpected end of input");
  const b = input[pos]!;
  if (b < 0x80) return [input.subarray(pos, pos + 1), pos + 1];
  if (b <= 0xb7) {
    const len = b - 0x80;
    const start = pos + 1;
    if (start + len > input.length) throw new RlpError("string runs past the end");
    if (len === 1 && input[start]! < 0x80) throw new RlpError("single byte below 0x80 must not carry a string header");
    return [input.subarray(start, start + len), start + len];
  }
  if (b <= 0xbf) {
    const lenOfLen = b - 0xb7;
    const len = readLength(input, pos + 1, lenOfLen);
    const start = pos + 1 + lenOfLen;
    if (start + len > input.length) throw new RlpError("string runs past the end");
    return [input.subarray(start, start + len), start + len];
  }
  let len: number;
  let start: number;
  if (b <= 0xf7) {
    len = b - 0xc0;
    start = pos + 1;
  } else {
    const lenOfLen = b - 0xf7;
    len = readLength(input, pos + 1, lenOfLen);
    start = pos + 1 + lenOfLen;
  }
  const end = start + len;
  if (end > input.length) throw new RlpError("list runs past the end");
  const items: RlpItem[] = [];
  let p = start;
  while (p < end) {
    const [item, next] = decodeAt(input, p);
    if (next > end) throw new RlpError("list item runs past the list");
    items.push(item);
    p = next;
  }
  return [items, end];
}

export function asBytes(item: RlpItem | undefined, what: string): Uint8Array {
  if (!(item instanceof Uint8Array)) throw new RlpError(`${what}: expected a string, got a list`);
  return item;
}

export function asList(item: RlpItem | undefined, what: string): RlpItem[] {
  if (!Array.isArray(item)) throw new RlpError(`${what}: expected a list`);
  return item;
}

/** Canonical RLP integer: no leading zero bytes. `maxBytes` bounds the width (8 for u64 fields, 32 for u256). */
export function asInt(item: RlpItem | undefined, what: string, maxBytes = 32): bigint {
  const b = asBytes(item, what);
  if (b.length > maxBytes) throw new RlpError(`${what}: integer wider than ${maxBytes} bytes`);
  if (b.length > 0 && b[0] === 0) throw new RlpError(`${what}: integer has a leading zero byte`);
  return bytesToBigInt(b);
}

export function asAddress(item: RlpItem | undefined, what: string): string {
  const b = asBytes(item, what);
  if (b.length !== 20) throw new RlpError(`${what}: address must be 20 bytes, got ${b.length}`);
  return toChecksumAddress(b);
}

/** Destination field: 20 bytes, or the empty string for contract creation. */
export function asOptionalAddress(item: RlpItem | undefined, what: string): string | null {
  const b = asBytes(item, what);
  if (b.length === 0) return null;
  return asAddress(b, what);
}
