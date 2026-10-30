import { bytesToHex, keccak256, toBytes, toChecksumAddress, type Hex } from "./bytes.js";

/** Function selectors worth naming when they appear in a delegate's code. */
export const KNOWN_SELECTORS: Record<string, string> = {
  "0x8a179be4": "sweep(address,address[])",
  "0x043ff9d2": "callExecute(address,address,uint256,bytes)",
  "0x01e33667": "withdrawToken(address,address,uint256)",
  "0x4782f779": "withdrawETH(address,uint256)",
  "0x97dc97cb": "authorizedCaller()",
  "0xb61d27f6": "execute(address,uint256,bytes)",
  "0xe9ae5c53": "execute(bytes32,bytes)",
  "0x34fcd5be": "executeBatch((address,uint256,bytes)[])",
  "0x47e1da2a": "executeBatch(address[],uint256[],bytes[])",
  "0xac9650d8": "multicall(bytes[])",
  "0x70a08231": "balanceOf(address)",
  "0xa9059cbb": "transfer(address,uint256)",
  "0x23b872dd": "transferFrom(address,address,uint256)",
  "0x095ea7b3": "approve(address,uint256)",
  "0x1626ba7e": "isValidSignature(bytes32,bytes)",
  "0x18160ddd": "totalSupply()",
  "0x313ce567": "decimals()",
  "0xdd62ed3e": "allowance(address,address)",
};

export type Trait =
  | "ERC20_TOKEN"
  | "SWEEPS_TOKENS"
  | "HARDCODED_ADDRESS"
  | "CHECKS_CALLER"
  | "RESERVES_ONE_ETHER"
  | "ARBITRARY_CALL"
  | "DELEGATECALL"
  | "SELFDESTRUCT";

export interface CodeFingerprint {
  size: number;
  codehash: Hex;
  selectors: { selector: string; name?: string }[];
  hardcodedAddresses: string[];
  traits: Trait[];
  /**
   * True when the traits match the shape of known 7702 sweepers: token sweep + a single privileged caller, in code that
   * is not itself a token. A heuristic over a static read: it can miss sweepers and it is not a verdict.
   */
  sweeperLike: boolean;
}

const MASK20 = "0x" + "ff".repeat(20);

/**
 * Executable part of Solidity/Vyper output: strips the trailing CBOR metadata (a map of one to five entries, as with
 * bytecode_hash=none) when its length marker is sane.
 */
function executable(code: Uint8Array): Uint8Array {
  if (code.length < 4) return code;
  const metaLen = (code[code.length - 2]! << 8) | code[code.length - 1]!;
  const head = code[code.length - 2 - metaLen];
  if (metaLen > 0 && metaLen + 2 < code.length && head !== undefined && head >= 0xa1 && head <= 0xa5) {
    return code.subarray(0, code.length - 2 - metaLen);
  }
  return code;
}

/** Twenty bytes that are all printable ASCII are text (a revert string, a name), not an address. */
const isText = (b: Uint8Array) => b.every((c) => c >= 0x20 && c <= 0x7e);

/**
 * A static walk over the bytecode: PUSH immediates (including selectors the optimizer stored shifted, as
 * `PUSH4 v PUSH1 k SHL`), hardcoded addresses and a few opcodes. It reads code; it does not execute it.
 */
export function fingerprintCode(input: Uint8Array | string): CodeFingerprint {
  const code = toBytes(input);
  const body = executable(code);
  const selectors = new Set<string>();
  const addrs = new Set<string>();
  const ops = new Set<number>();
  let reserveOneEther = false;
  for (let i = 0; i < body.length; i++) {
    const op = body[i]!;
    ops.add(op);
    if (op >= 0x60 && op <= 0x7f) {
      const n = op - 0x5f;
      // A PUSH whose immediate runs past the end is data (a constructor tail, an unstripped trailer): stop the walk.
      if (i + 1 + n > body.length) break;
      const imm = body.subarray(i + 1, i + 1 + n);
      if (n === 4) {
        selectors.add(bytesToHex(imm));
        // PUSH4 v, PUSH1 k, SHL: the optimizer's way of materialising (v << (k - 224)) as a selector.
        if (body[i + 5] === 0x60 && body[i + 7] === 0x1b) {
          const k = body[i + 6]!;
          if (k > 224 && k < 256) {
            const v = BigInt(bytesToHex(imm));
            const s = (v << BigInt(k - 224)) & 0xffffffffn;
            selectors.add("0x" + s.toString(16).padStart(8, "0"));
          }
        }
      }
      if (n === 20) {
        const h = bytesToHex(imm);
        if (h !== MASK20 && !isText(imm)) addrs.add(toChecksumAddress(imm));
      }
      if (n === 8 && bytesToHex(imm) === "0x0de0b6b3a7640000") reserveOneEther = true;
      i += n;
    }
  }
  const named = [...selectors]
    .filter((s) => KNOWN_SELECTORS[s])
    .map((s) => ({ selector: s, name: KNOWN_SELECTORS[s] }));
  const traits: Trait[] = [];
  const token = selectors.has("0x18160ddd") || (selectors.has("0x313ce567") && selectors.has("0xdd62ed3e"));
  if (token) traits.push("ERC20_TOKEN");
  if (selectors.has("0x70a08231") && selectors.has("0xa9059cbb")) traits.push("SWEEPS_TOKENS");
  if (addrs.size) traits.push("HARDCODED_ADDRESS");
  if (ops.has(0x33) && addrs.size) traits.push("CHECKS_CALLER");
  if (reserveOneEther) traits.push("RESERVES_ONE_ETHER");
  if (ops.has(0xf1) && ops.has(0x37)) traits.push("ARBITRARY_CALL");
  if (ops.has(0xf4)) traits.push("DELEGATECALL");
  if (ops.has(0xff)) traits.push("SELFDESTRUCT");
  return {
    size: code.length,
    codehash: bytesToHex(keccak256(code)),
    selectors: named,
    hardcodedAddresses: [...addrs],
    traits,
    sweeperLike: !token && traits.includes("SWEEPS_TOKENS") && traits.includes("CHECKS_CALLER"),
  };
}
