import { bytesToHex, equalBytes, toBytes, toChecksumAddress, type Hex } from "../evm/bytes.js";
import { decodeAuthorizationTuple, type Authorization, type SignedAuthorization } from "../evm/eip7702.js";
import { asAddress, asBytes, asInt, asList, asOptionalAddress, rlpDecode, type RlpItem } from "../evm/rlp.js";
import { decodeSolanaMessage, type SolanaMessage } from "../sol/message.js";

/**
 * What a signing request is, decided from the bytes the key would sign. Domain separation (0x05 for EIP-7702,
 * 0x19 0x01 for EIP-712, ...) only protects a signer that sees the preimage: a bare 32-byte digest is always
 * "raw-digest", because nothing about it says which of these it is.
 */
export type Classified =
  | { kind: "raw-digest"; digest: Hex }
  | { kind: "eip7702-authorization"; authorization: Authorization }
  | {
      kind: "set-code-tx";
      chainId: bigint;
      nonce: bigint;
      to: string;
      value: bigint;
      data: Hex;
      authorizationList: SignedAuthorization[];
    }
  | { kind: "typed-tx"; type: 1 | 2 | 3; chainId: bigint; nonce: bigint; to: string | null; value: bigint; data: Hex }
  | { kind: "legacy-tx"; chainId: bigint | null; nonce: bigint; to: string | null; value: bigint; data: Hex }
  | { kind: "eip712"; domainSeparator: Hex; structHash: Hex }
  | { kind: "personal-message"; message: Hex; text: string | null }
  | { kind: "eip191-data"; validator: string; data: Hex }
  | { kind: "solana-offchain-message"; body: Hex }
  | { kind: "solana-message"; message: SolanaMessage }
  | { kind: "unknown"; reason: string };

export type ClassifiedKind = Classified["kind"];

export interface ClassifyOptions {
  /** "preimage": the bytes to be hashed and signed. "digest": an already-hashed 32-byte value. */
  as: "preimage" | "digest";
  /** secp256k1 (EVM) by default; ed25519 signs raw message bytes (Solana). */
  curve?: "secp256k1" | "ed25519";
  /**
   * Accept a 32-byte input that decodes as a transaction. Off by default: a 32-byte digest can be ground until it also
   * parses as a tiny transaction, so a signer that hashes nothing would sign an authorization digest.
   */
  allow32ByteTransactions?: boolean;
}

const PERSONAL_PREFIX = new TextEncoder().encode("\x19Ethereum Signed Message:\n");
const SOLANA_OFFCHAIN = Uint8Array.of(0xff, ...new TextEncoder().encode("solana offchain"));

function tryRlpList(b: Uint8Array): RlpItem[] | null {
  try {
    const item = rlpDecode(b);
    return Array.isArray(item) ? item : null;
  } catch {
    return null;
  }
}

function utf8OrNull(b: Uint8Array): string | null {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(b);
  } catch {
    return null;
  }
}

const U64_MAX = 2n ** 64n - 1n;

/** A nonce as clients decode it: at most 8 bytes and below 2^64 - 1 (EIP-2681). */
function nonceOf(item: RlpItem | undefined): bigint {
  const n = asInt(item, "nonce", 8);
  if (n === U64_MAX) throw new Error("nonce is 2^64 - 1");
  return n;
}

function accessListOf(item: RlpItem | undefined): void {
  for (const entry of asList(item, "access_list")) {
    const pair = asList(entry, "access_list entry");
    if (pair.length !== 2) throw new Error("access_list entry must be [address, storage_keys]");
    asAddress(pair[0], "access_list address");
    for (const k of asList(pair[1], "storage_keys"))
      if (asBytes(k, "storage key").length !== 32) throw new Error("storage key must be 32 bytes");
  }
}

/** Field positions after chain_id and nonce for each typed envelope. */
const TYPED: Record<number, { fields: number; fees: number[]; gas: number; to: number }> = {
  1: { fields: 8, fees: [2], gas: 3, to: 4 },
  2: { fields: 9, fees: [2, 3], gas: 4, to: 5 },
  3: { fields: 11, fees: [2, 3], gas: 4, to: 5 },
  4: { fields: 10, fees: [2, 3], gas: 4, to: 5 },
};

/** Decodes the shared fields of a typed transaction the way an execution client does, or throws. */
function typedBody(f: RlpItem[], type: number) {
  const t = TYPED[type]!;
  const chainId = asInt(f[0], "chain_id");
  const nonce = nonceOf(f[1]);
  for (const i of t.fees) asInt(f[i], "fee");
  asInt(f[t.gas], "gas_limit", 8);
  const to = asOptionalAddress(f[t.to], "to");
  const value = asInt(f[t.to + 1], "value");
  const data = bytesToHex(asBytes(f[t.to + 2], "data"));
  accessListOf(f[t.to + 3]);
  return { chainId, nonce, to, value, data };
}

export function classifySigningInput(input: Uint8Array | string, opts: ClassifyOptions): Classified {
  const b = toBytes(input);
  if (opts.as === "digest") {
    if (b.length !== 32) return { kind: "unknown", reason: `a digest must be 32 bytes, got ${b.length}` };
    return { kind: "raw-digest", digest: bytesToHex(b) };
  }
  if (b.length === 0) return { kind: "unknown", reason: "empty input" };
  if ((opts.curve ?? "secp256k1") === "ed25519") return classifyEd25519(b);
  const c = classifyPreimage(b);
  if (b.length === 32 && (c.kind === "typed-tx" || c.kind === "legacy-tx") && !opts.allow32ByteTransactions)
    return {
      kind: "unknown",
      reason: "a 32-byte input that parses as a transaction is indistinguishable from a digest; pass it as a digest",
    };
  return c;
}

function classifyPreimage(b: Uint8Array): Classified {
  const head = b[0]!;
  if (head === 0x05) {
    const f = tryRlpList(b.subarray(1));
    if (f && f.length === 3) {
      try {
        return {
          kind: "eip7702-authorization",
          authorization: {
            chainId: asInt(f[0], "chain_id"),
            address: asAddress(f[1], "address"),
            nonce: asInt(f[2], "nonce", 8),
          },
        };
      } catch (e) {
        return { kind: "unknown", reason: `0x05 prefix but malformed authorization: ${(e as Error).message}` };
      }
    }
    return { kind: "unknown", reason: "0x05 prefix but not rlp([chain_id, address, nonce])" };
  }
  if (head === 0x04) {
    const f = tryRlpList(b.subarray(1));
    if (f && f.length === 10) {
      try {
        const body = typedBody(f, 4);
        if (!body.to) return { kind: "unknown", reason: "set-code transaction without a destination" };
        const authorizationList = asList(f[9], "authorization_list").map((a, i) => decodeAuthorizationTuple(a, i));
        if (authorizationList.length === 0)
          return { kind: "unknown", reason: "set-code transaction with an empty authorization list" };
        return { kind: "set-code-tx", ...body, to: body.to, authorizationList };
      } catch (e) {
        return { kind: "unknown", reason: `0x04 prefix but malformed set-code transaction: ${(e as Error).message}` };
      }
    }
    return { kind: "unknown", reason: "0x04 prefix but not an unsigned set-code transaction" };
  }
  if (head === 0x01 || head === 0x02 || head === 0x03) {
    const f = tryRlpList(b.subarray(1));
    const n = { 1: 8, 2: 9, 3: 11 }[head];
    if (f && f.length === n) {
      try {
        const body = typedBody(f, head);
        if (head === 3) {
          if (!body.to) return { kind: "unknown", reason: "blob transaction without a destination" };
          asInt(f[9], "max_fee_per_blob_gas");
          for (const h of asList(f[10], "blob_versioned_hashes"))
            if (asBytes(h, "blob hash").length !== 32) throw new Error("blob versioned hash must be 32 bytes");
        }
        return { kind: "typed-tx", type: head, ...body };
      } catch (e) {
        return { kind: "unknown", reason: `typed transaction ${head} is malformed: ${(e as Error).message}` };
      }
    }
    return { kind: "unknown", reason: `0x0${head} prefix but not an unsigned typed transaction` };
  }
  if (head === 0x19 && b.length >= 2) {
    const v = b[1]!;
    if (v === 0x01) {
      if (b.length !== 66) return { kind: "unknown", reason: "EIP-712 input must be 0x1901 ‖ 32 ‖ 32 bytes" };
      return { kind: "eip712", domainSeparator: bytesToHex(b.subarray(2, 34)), structHash: bytesToHex(b.subarray(34)) };
    }
    if (
      v === 0x45 &&
      b.length >= PERSONAL_PREFIX.length &&
      equalBytes(b.subarray(0, PERSONAL_PREFIX.length), PERSONAL_PREFIX)
    ) {
      const rest = b.subarray(PERSONAL_PREFIX.length);
      // The length is a decimal prefix of unknown width, and the message itself may start with digits: try each width.
      const digits = /^[0-9]{1,20}/.exec(new TextDecoder().decode(rest.subarray(0, 20)))?.[0] ?? "";
      for (let k = 1; k <= digits.length; k++) {
        const prefix = digits.slice(0, k);
        if (k > 1 && prefix[0] === "0") break;
        if (Number(prefix) === rest.length - k) {
          const message = rest.subarray(k);
          return { kind: "personal-message", message: bytesToHex(message), text: utf8OrNull(message) };
        }
      }
      return { kind: "unknown", reason: "personal_sign prefix with a length that does not match the message" };
    }
    if (v === 0x00) {
      if (b.length < 22) return { kind: "unknown", reason: "EIP-191 version 0 needs a 20-byte validator address" };
      return { kind: "eip191-data", validator: toChecksumAddress(b.subarray(2, 22)), data: bytesToHex(b.subarray(22)) };
    }
    return { kind: "unknown", reason: `EIP-191 version 0x${v.toString(16).padStart(2, "0")} is not handled` };
  }
  if (head >= 0xc0) {
    const f = tryRlpList(b);
    if (f && (f.length === 6 || f.length === 9)) {
      try {
        let chainId: bigint | null = null;
        if (f.length === 9) {
          chainId = asInt(f[6], "chain_id");
          if (asInt(f[7], "r") !== 0n || asInt(f[8], "s") !== 0n)
            return { kind: "unknown", reason: "EIP-155 preimage must end in (chain_id, 0, 0)" };
        }
        const nonce = nonceOf(f[0]);
        asInt(f[1], "gas_price");
        asInt(f[2], "gas_limit", 8);
        return {
          kind: "legacy-tx",
          chainId,
          nonce,
          to: asOptionalAddress(f[3], "to"),
          value: asInt(f[4], "value"),
          data: bytesToHex(asBytes(f[5], "data")),
        };
      } catch (e) {
        return { kind: "unknown", reason: `legacy transaction is malformed: ${(e as Error).message}` };
      }
    }
    return { kind: "unknown", reason: "RLP list that is not an unsigned legacy transaction" };
  }
  return { kind: "unknown", reason: `no signing domain starts with 0x${head.toString(16).padStart(2, "0")}` };
}

function classifyEd25519(b: Uint8Array): Classified {
  if (b.length >= SOLANA_OFFCHAIN.length && equalBytes(b.subarray(0, SOLANA_OFFCHAIN.length), SOLANA_OFFCHAIN))
    return { kind: "solana-offchain-message", body: bytesToHex(b.subarray(SOLANA_OFFCHAIN.length)) };
  try {
    return { kind: "solana-message", message: decodeSolanaMessage(b) };
  } catch (e) {
    return { kind: "unknown", reason: `not a Solana transaction message: ${(e as Error).message}` };
  }
}
