import {
  getTypesForEIP712Domain,
  hashDomain,
  hashStruct,
  serializeTransaction,
  toPrefixedMessage,
  type LocalAccount,
  type SignableMessage,
  type TypedDataDefinition,
} from "viem";
import { concatBytes, hexToBytes, type Hex } from "../evm/bytes.js";
import { authorizationPreimage } from "../evm/eip7702.js";
import { Guard, GuardRefusal, type GuardContext } from "../guard/policy.js";

import type { ContextSource, SigningKind } from "./types.js";

export type { ContextSource, SigningKind } from "./types.js";

/** `0x19 0x01 ‖ domainSeparator ‖ structHash`: the bytes whose keccak256 an EIP-712 signature covers. */
export function typedDataPreimage(td: TypedDataDefinition): Uint8Array {
  const domain = td.domain ?? {};
  const types = { EIP712Domain: getTypesForEIP712Domain({ domain }), ...td.types };
  const separator = hexToBytes(hashDomain({ domain, types }) as Hex);
  if (td.primaryType === "EIP712Domain") return concatBytes(Uint8Array.of(0x19, 0x01), separator);
  const struct = hexToBytes(
    hashStruct({ data: td.message as Record<string, unknown>, primaryType: td.primaryType as string, types }) as Hex,
  );
  return concatBytes(Uint8Array.of(0x19, 0x01), separator, struct);
}

/**
 * Wraps a viem LocalAccount so every signature goes through the guard first, judged from the exact bytes the account
 * would sign. A refusal throws GuardRefusal and the key is never asked. `context` supplies what the guard cannot know
 * by itself: the key's live nonce for authorizations and `ownCode` (eth_getCode of the account's own address, "0x" for
 * none); the signer defaults to the account's address.
 */
export function guardAccount<A extends LocalAccount>(account: A, guard: Guard, context: ContextSource = () => ({})): A {
  const ctx = async (kind: SigningKind): Promise<GuardContext> => ({
    signer: account.address,
    ...(await context(kind)),
  });
  const judge = async (bytes: Uint8Array, as: "preimage" | "digest", kind: SigningKind) => {
    const d = guard.check(bytes, { as }, await ctx(kind));
    if (!d.allow) throw new GuardRefusal(d);
  };
  const wrapped: LocalAccount = {
    ...account,
    async signMessage(p: { message: SignableMessage }) {
      await judge(hexToBytes(toPrefixedMessage(p.message) as Hex), "preimage", "message");
      return account.signMessage(p);
    },
    async signTransaction(tx, opts) {
      const serializer = (opts?.serializer ?? serializeTransaction) as (t: typeof tx) => Hex | Promise<Hex>;
      await judge(hexToBytes(await serializer(tx)), "preimage", "transaction");
      return account.signTransaction(tx, opts);
    },
    async signTypedData(td) {
      await judge(typedDataPreimage(td as TypedDataDefinition), "preimage", "typed-data");
      return account.signTypedData(td);
    },
  };
  if (account.sign) {
    const sign = account.sign;
    wrapped.sign = async (p) => {
      await judge(hexToBytes(p.hash as Hex), "digest", "hash");
      return sign(p);
    };
  }
  if (account.signAuthorization) {
    const signAuthorization = account.signAuthorization;
    wrapped.signAuthorization = async (p) => {
      const address = ("contractAddress" in p && p.contractAddress) || ("address" in p && p.address);
      if (!address) throw new TypeError("authorization without a delegate address");
      await judge(
        authorizationPreimage({ chainId: BigInt(p.chainId), address, nonce: BigInt(p.nonce) }),
        "preimage",
        "authorization",
      );
      return signAuthorization(p);
    };
  }
  return wrapped as A;
}
