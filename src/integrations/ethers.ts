import {
  Transaction,
  TypedDataEncoder,
  getBytes,
  resolveAddress,
  toUtf8Bytes,
  type AbstractSigner,
  type AuthorizationRequest,
  type TransactionRequest,
  type TypedDataDomain,
  type TypedDataField,
} from "ethers";
import { concatBytes } from "../evm/bytes.js";
import { authorizationPreimage } from "../evm/eip7702.js";
import { Guard, GuardRefusal, type GuardContext } from "../guard/policy.js";
import type { ContextSource, SigningKind } from "./types.js";

export type { ContextSource, SigningKind } from "./types.js";

/** EIP-191: `0x19 "Ethereum Signed Message:\n" ‖ length ‖ message`, the bytes `signMessage` hashes. */
export function messagePreimage(message: string | Uint8Array): Uint8Array {
  const body = typeof message === "string" ? toUtf8Bytes(message) : message;
  return concatBytes(toUtf8Bytes(`\x19Ethereum Signed Message:\n${body.length}`), body);
}

/** `0x19 0x01 ‖ domainSeparator ‖ structHash`, the bytes an EIP-712 signature covers. */
export function typedDataPreimageEthers(
  domain: TypedDataDomain,
  types: Record<string, TypedDataField[]>,
  value: Record<string, unknown>,
): Uint8Array {
  return concatBytes(
    Uint8Array.of(0x19, 0x01),
    getBytes(TypedDataEncoder.hashDomain(domain)),
    getBytes(TypedDataEncoder.from(types).hash(value)),
  );
}

type Signer = AbstractSigner & {
  authorize?: (auth: AuthorizationRequest) => Promise<unknown>;
  populateAuthorization?: (auth: AuthorizationRequest) => Promise<AuthorizationRequest>;
};

/**
 * Puts an ethers v6 signer behind the guard. The signer's own `signTransaction`, `signMessage`, `signTypedData` and
 * `authorize` are replaced on that instance, so calls from inside ethers (`sendTransaction` signs through
 * `this.signTransaction`) are judged too; a refusal throws GuardRefusal before the key is used. `connect()` returns a
 * guarded signer as well. The signer is returned for chaining; it is the same object.
 */
export function guardSigner<S extends AbstractSigner>(signer: S, guard: Guard, context: ContextSource = () => ({})): S {
  const s = signer as Signer;
  const original = {
    signTransaction: s.signTransaction.bind(s),
    signMessage: s.signMessage.bind(s),
    signTypedData: s.signTypedData.bind(s),
    authorize: s.authorize?.bind(s),
    populateAuthorization: s.populateAuthorization?.bind(s),
    connect: s.connect.bind(s),
  };
  const ctx = async (kind: SigningKind): Promise<GuardContext> => ({
    signer: await s.getAddress(),
    ...(await context(kind)),
  });
  const judge = async (bytes: Uint8Array, kind: SigningKind) => {
    const d = guard.check(bytes, { as: "preimage" }, await ctx(kind));
    if (!d.allow) throw new GuardRefusal(d);
  };
  s.signTransaction = async (tx: TransactionRequest) => {
    const t: TransactionRequest = { ...tx };
    delete t.from;
    if (t.to != null) t.to = await resolveAddress(t.to, s.provider);
    await judge(
      getBytes(Transaction.from(t as Parameters<typeof Transaction.from>[0]).unsignedSerialized),
      "transaction",
    );
    return original.signTransaction(tx);
  };
  s.signMessage = async (message: string | Uint8Array) => {
    await judge(messagePreimage(message), "message");
    return original.signMessage(message);
  };
  s.signTypedData = async (domain, types, value) => {
    await judge(typedDataPreimageEthers(domain, types, value), "typed-data");
    return original.signTypedData(domain, types, value);
  };
  if (original.authorize && original.populateAuthorization) {
    const authorize = original.authorize;
    const populate = original.populateAuthorization;
    s.authorize = async (auth: AuthorizationRequest) => {
      const full = await populate(auth);
      const address = await resolveAddress(full.address, s.provider);
      await judge(
        authorizationPreimage({ chainId: BigInt(full.chainId ?? 0), address, nonce: BigInt(full.nonce ?? 0) }),
        "authorization",
      );
      return authorize(full);
    };
  }
  s.connect = ((provider) => guardSigner(original.connect(provider) as S, guard, context)) as S["connect"];
  return signer;
}
