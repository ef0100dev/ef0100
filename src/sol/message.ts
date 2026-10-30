import { base58 } from "@scure/base";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, type Hex } from "../evm/bytes.js";

export interface CompiledInstruction {
  programIdIndex: number;
  accounts: number[];
  data: Uint8Array;
}

export interface LookupTableRef {
  table: string;
  writable: number[];
  readonly: number[];
}

export interface SolanaMessage {
  version: "legacy" | 0;
  header: { numRequiredSignatures: number; numReadonlySigned: number; numReadonlyUnsigned: number };
  staticKeys: string[];
  recentBlockhash: string;
  instructions: CompiledInstruction[];
  lookups: LookupTableRef[];
  /** sha256 of the message bytes, as hex. Ledger's Solana app shows the same hash in base58 (SolReport.messageHash). */
  sha256: Hex;
  bytes: Uint8Array;
}

export interface SolanaTransaction {
  signatures: string[];
  message: SolanaMessage;
}

class Reader {
  pos = 0;
  constructor(readonly b: Uint8Array) {}
  u8(what: string): number {
    if (this.pos >= this.b.length) throw new RangeError(`${what}: unexpected end`);
    return this.b[this.pos++]!;
  }
  bytes(n: number, what: string): Uint8Array {
    if (this.pos + n > this.b.length) throw new RangeError(`${what}: needs ${n} bytes`);
    const out = this.b.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }
  /** compact-u16 ("shortvec"): canonical, at most 3 bytes, at most 0xffff. */
  shortvec(what: string): number {
    let value = 0;
    for (let i = 0; i < 3; i++) {
      const byte = this.u8(what);
      value |= (byte & 0x7f) << (7 * i);
      if ((byte & 0x80) === 0) {
        if (i > 0 && byte === 0) throw new RangeError(`${what}: non-canonical compact-u16`);
        if (value > 0xffff) throw new RangeError(`${what}: compact-u16 overflow`);
        return value;
      }
    }
    throw new RangeError(`${what}: compact-u16 longer than 3 bytes`);
  }
}

export function decodeSolanaMessage(bytes: Uint8Array): SolanaMessage {
  const r = new Reader(bytes);
  const m = readMessage(r);
  if (r.pos !== bytes.length) throw new RangeError(`${bytes.length - r.pos} trailing bytes after the message`);
  return m;
}

function readMessage(r: Reader): SolanaMessage {
  const start = r.pos;
  let version: "legacy" | 0 = "legacy";
  let first = r.u8("header");
  if (first & 0x80) {
    const v = first & 0x7f;
    if (v !== 0) throw new RangeError(`unsupported message version ${v}`);
    version = 0;
    first = r.u8("header");
  }
  const header = {
    numRequiredSignatures: first,
    numReadonlySigned: r.u8("header"),
    numReadonlyUnsigned: r.u8("header"),
  };
  const nKeys = r.shortvec("account keys");
  const staticKeys: string[] = [];
  for (let i = 0; i < nKeys; i++) staticKeys.push(base58.encode(r.bytes(32, `account key ${i}`)));
  // The runtime refuses a message that loads the same account twice.
  if (new Set(staticKeys).size !== staticKeys.length) throw new RangeError("an account key appears twice");
  if (header.numRequiredSignatures === 0) throw new RangeError("a message needs at least one signer (the fee payer)");
  if (header.numRequiredSignatures > nKeys) throw new RangeError("more required signatures than account keys");
  if (header.numReadonlySigned >= header.numRequiredSignatures)
    throw new RangeError("the fee payer cannot be read-only");
  if (header.numReadonlyUnsigned > nKeys - header.numRequiredSignatures)
    throw new RangeError("more read-only unsigned keys than unsigned keys");
  const recentBlockhash = base58.encode(r.bytes(32, "recent blockhash"));
  const nIx = r.shortvec("instructions");
  const instructions: CompiledInstruction[] = [];
  for (let i = 0; i < nIx; i++) {
    const programIdIndex = r.u8(`instruction ${i} program`);
    const nAcc = r.shortvec(`instruction ${i} accounts`);
    const accounts: number[] = [];
    for (let j = 0; j < nAcc; j++) accounts.push(r.u8(`instruction ${i} account ${j}`));
    const dataLen = r.shortvec(`instruction ${i} data`);
    instructions.push({ programIdIndex, accounts, data: r.bytes(dataLen, `instruction ${i} data`) });
  }
  const lookups: LookupTableRef[] = [];
  if (version === 0) {
    const nL = r.shortvec("lookups");
    for (let i = 0; i < nL; i++) {
      const table = base58.encode(r.bytes(32, `lookup ${i}`));
      const nW = r.shortvec(`lookup ${i} writable`);
      const writable: number[] = [];
      for (let j = 0; j < nW; j++) writable.push(r.u8(`lookup ${i} writable ${j}`));
      const nR = r.shortvec(`lookup ${i} readonly`);
      const readonly: number[] = [];
      for (let j = 0; j < nR; j++) readonly.push(r.u8(`lookup ${i} readonly ${j}`));
      // Sanitize rejects a lookup that loads nothing.
      if (writable.length + readonly.length === 0) throw new RangeError(`lookup ${i} loads no accounts`);
      lookups.push({ table, writable, readonly });
    }
  }
  const total = nKeys + lookups.reduce((n, l) => n + l.writable.length + l.readonly.length, 0);
  if (total > 256) throw new RangeError("more than 256 accounts");
  instructions.forEach((ix, i) => {
    if (ix.programIdIndex >= nKeys) throw new RangeError(`instruction ${i}: program id must be a static key`);
    if (ix.programIdIndex === 0) throw new RangeError(`instruction ${i}: the fee payer cannot be a program`);
    ix.accounts.forEach((a, j) => {
      if (a >= total) throw new RangeError(`instruction ${i} account ${j}: index ${a} out of range`);
    });
  });
  const raw = r.b.subarray(start, r.pos);
  return {
    version,
    header,
    staticKeys,
    recentBlockhash,
    instructions,
    lookups,
    sha256: bytesToHex(sha256(raw)),
    bytes: raw,
  };
}

/** Wire format: compact-u16 signature count, 64-byte signatures, then the message. */
export function decodeSolanaTransaction(bytes: Uint8Array): SolanaTransaction {
  const r = new Reader(bytes);
  const nSig = r.shortvec("signatures");
  const signatures: string[] = [];
  for (let i = 0; i < nSig; i++) signatures.push(base58.encode(r.bytes(64, `signature ${i}`)));
  const message = readMessage(r);
  if (r.pos !== bytes.length) throw new RangeError(`${bytes.length - r.pos} trailing bytes after the transaction`);
  if (nSig !== message.header.numRequiredSignatures)
    throw new RangeError(`${nSig} signatures for ${message.header.numRequiredSignatures} required signers`);
  return { signatures, message };
}

/** Writable / signer flags for a static key index, from the message header. */
export function keyFlags(m: SolanaMessage, index: number): { signer: boolean; writable: boolean } {
  const { numRequiredSignatures: s, numReadonlySigned: rs, numReadonlyUnsigned: ru } = m.header;
  const n = m.staticKeys.length;
  if (index < s) return { signer: true, writable: index < s - rs };
  if (index < n) return { signer: false, writable: index < n - ru };
  // Loaded addresses follow the static keys: every table's writable entries, then every table's read-only entries.
  const writableLoaded = m.lookups.reduce((k, l) => k + l.writable.length, 0);
  return { signer: false, writable: index - n < writableLoaded };
}
