import { bytesToHex, concatBytes, hexToBytes, keccak256, toBytes, type Hex } from "./bytes.js";
import { decodeAuthorizationTuple, encodeAuthorizationTuple, type SignedAuthorization } from "./eip7702.js";
import {
  asAddress,
  asBytes,
  asInt,
  asList,
  asOptionalAddress,
  rlpDecode,
  rlpEncode,
  rlpInt,
  type RlpItem,
} from "./rlp.js";
import { recoverAddress } from "./secp256k1.js";

export type TxType = 0 | 1 | 2 | 3 | 4;

export interface AccessListEntry {
  address: string;
  storageKeys: Hex[];
}

export interface DecodedTx {
  type: TxType;
  hash: Hex;
  raw: Hex;
  chainId: bigint | null;
  nonce: bigint;
  gasLimit: bigint;
  gasPrice?: bigint;
  maxPriorityFeePerGas?: bigint;
  maxFeePerGas?: bigint;
  to: string | null;
  value: bigint;
  data: Hex;
  accessList: AccessListEntry[];
  authorizationList: SignedAuthorization[];
  yParity: number;
  r: bigint;
  s: bigint;
  /** keccak256 of the unsigned payload: what the sender's key signed. */
  signingHash: Hex;
  /** Recovered sender, or null if the signature does not recover. */
  from: string | null;
}

function decodeAccessList(item: RlpItem | undefined): AccessListEntry[] {
  return asList(item, "access_list").map((e, i) => {
    const pair = asList(e, `access_list ${i}`);
    if (pair.length !== 2) throw new TypeError(`access_list ${i}: expected [address, keys]`);
    return {
      address: asAddress(pair[0], `access_list ${i} address`),
      storageKeys: asList(pair[1], `access_list ${i} keys`).map((k, j) => {
        const b = asBytes(k, `access_list ${i} key ${j}`);
        if (b.length !== 32) throw new TypeError(`access_list ${i} key ${j}: expected 32 bytes`);
        return bytesToHex(b);
      }),
    };
  });
}

function encodeAccessList(list: AccessListEntry[]): RlpItem {
  return list.map((e) => [hexToBytes(e.address), e.storageKeys.map((k) => hexToBytes(k))]);
}

/** Decodes a signed transaction (legacy, 2930, 1559, 4844 or 7702) from its raw bytes and recovers the sender. */
export function decodeTransaction(input: Uint8Array | string): DecodedTx {
  let raw = toBytes(input);
  if (raw.length === 0) throw new TypeError("empty transaction");
  const first = raw[0]!;
  if (first >= 0xc0) return decodeLegacy(raw, bytesToHex(keccak256(raw)));
  if (first > 0x7f) throw new TypeError(`unknown transaction envelope 0x${first.toString(16)}`);
  const type = first as TxType;
  let f = asList(rlpDecode(raw.subarray(1)), `type ${type} payload`);
  // A blob transaction in its network form wraps the body with blobs, commitments and proofs (EIP-4844), plus a
  // wrapper version on EIP-7594 networks. The hash is over the canonical 0x03 || rlp(body) only.
  if (type === 3 && Array.isArray(f[0])) {
    if (f.length !== 4 && f.length !== 5)
      throw new TypeError(`type 3 network form: expected 4 or 5 items, got ${f.length}`);
    f = asList(f[0], "type 3 body");
    raw = concatBytes(Uint8Array.of(3), rlpEncode(f));
  }
  const hash = bytesToHex(keccak256(raw));
  const expected = { 1: 11, 2: 12, 3: 14, 4: 13 }[type as 1 | 2 | 3 | 4];
  if (!expected) throw new TypeError(`unsupported transaction type ${type}`);
  if (f.length !== expected) throw new TypeError(`type ${type}: expected ${expected} fields, got ${f.length}`);
  const unsigned = f.slice(0, expected - 3);
  const [yI, rI, sI] = f.slice(expected - 3);
  const signingHash = keccak256(concatBytes(Uint8Array.of(type), rlpEncode(unsigned)));
  const yParity = Number(asInt(yI, "y_parity", 1));
  const r = asInt(rI, "r");
  const s = asInt(sI, "s");
  const rec = recoverAddress(signingHash, yParity, r, s, true);
  const base = {
    type,
    hash,
    raw: bytesToHex(raw),
    chainId: asInt(f[0], "chain_id"),
    nonce: asInt(f[1], "nonce", 8),
    yParity,
    r,
    s,
    signingHash: bytesToHex(signingHash),
    from: rec.ok ? rec.address : null,
  };
  if (type === 1) {
    return {
      ...base,
      gasPrice: asInt(f[2], "gas_price"),
      gasLimit: asInt(f[3], "gas_limit", 8),
      to: asOptionalAddress(f[4], "to"),
      value: asInt(f[5], "value"),
      data: bytesToHex(asBytes(f[6], "data")),
      accessList: decodeAccessList(f[7]),
      authorizationList: [],
    };
  }
  const common = {
    ...base,
    maxPriorityFeePerGas: asInt(f[2], "max_priority_fee_per_gas"),
    maxFeePerGas: asInt(f[3], "max_fee_per_gas"),
    gasLimit: asInt(f[4], "gas_limit", 8),
    to: asOptionalAddress(f[5], "to"),
    value: asInt(f[6], "value"),
    data: bytesToHex(asBytes(f[7], "data")),
    accessList: decodeAccessList(f[8]),
  };
  if (type === 3 && common.to === null) throw new TypeError("type 3: destination must not be empty");
  if (type === 4) {
    if (common.to === null) throw new TypeError("type 4: destination must not be empty");
    const list = asList(f[9], "authorization_list");
    if (list.length === 0) throw new TypeError("type 4: authorization_list must not be empty");
    return { ...common, authorizationList: list.map((a, i) => decodeAuthorizationTuple(a, i)) };
  }
  return { ...common, authorizationList: [] };
}

function decodeLegacy(raw: Uint8Array, hash: Hex): DecodedTx {
  const f = asList(rlpDecode(raw), "legacy transaction");
  if (f.length !== 9) throw new TypeError(`legacy: expected 9 fields, got ${f.length}`);
  const v = asInt(f[6], "v");
  const r = asInt(f[7], "r");
  const s = asInt(f[8], "s");
  let chainId: bigint | null = null;
  let yParity: number;
  let unsigned: RlpItem[];
  if (v === 27n || v === 28n) {
    yParity = Number(v - 27n);
    unsigned = f.slice(0, 6);
  } else if (v >= 35n) {
    chainId = (v - 35n) / 2n;
    yParity = Number((v - 35n) % 2n);
    unsigned = [...f.slice(0, 6), rlpInt(chainId), new Uint8Array(0), new Uint8Array(0)];
  } else throw new TypeError(`legacy: invalid v ${v}`);
  const signingHash = keccak256(rlpEncode(unsigned));
  const rec = recoverAddress(signingHash, yParity, r, s, true);
  return {
    type: 0,
    hash,
    raw: bytesToHex(raw),
    chainId,
    nonce: asInt(f[0], "nonce", 8),
    gasPrice: asInt(f[1], "gas_price"),
    gasLimit: asInt(f[2], "gas_limit", 8),
    to: asOptionalAddress(f[3], "to"),
    value: asInt(f[4], "value"),
    data: bytesToHex(asBytes(f[5], "data")),
    accessList: [],
    authorizationList: [],
    yParity,
    r,
    s,
    signingHash: bytesToHex(signingHash),
    from: rec.ok ? rec.address : null,
  };
}

export interface UnsignedSetCodeTx {
  chainId: bigint;
  nonce: bigint;
  maxPriorityFeePerGas: bigint;
  maxFeePerGas: bigint;
  gasLimit: bigint;
  to: string;
  value: bigint;
  data: Hex;
  accessList: AccessListEntry[];
  authorizationList: SignedAuthorization[];
}

/** `0x04 ‖ rlp([...10 unsigned fields])`: the preimage the sender signs for a type-4 transaction. */
export function setCodeTxPreimage(tx: UnsignedSetCodeTx): Uint8Array {
  return concatBytes(
    Uint8Array.of(4),
    rlpEncode([
      rlpInt(tx.chainId),
      rlpInt(tx.nonce),
      rlpInt(tx.maxPriorityFeePerGas),
      rlpInt(tx.maxFeePerGas),
      rlpInt(tx.gasLimit),
      hexToBytes(tx.to),
      rlpInt(tx.value),
      hexToBytes(tx.data),
      encodeAccessList(tx.accessList),
      tx.authorizationList.map(encodeAuthorizationTuple),
    ]),
  );
}

export function serializeSetCodeTx(tx: UnsignedSetCodeTx, sig: { yParity: number; r: bigint; s: bigint }): Hex {
  const pre = setCodeTxPreimage(tx);
  const body = rlpDecode(pre.subarray(1)) as RlpItem[];
  return bytesToHex(
    concatBytes(Uint8Array.of(4), rlpEncode([...body, rlpInt(sig.yParity), rlpInt(sig.r), rlpInt(sig.s)])),
  );
}
