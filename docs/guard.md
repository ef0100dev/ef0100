# Guard

`Guard` sits in front of whatever holds the key: a KMS key, an HSM, an MPC service, a local account. It decides from
the bytes it is asked to sign, plus a few facts the caller supplies about the key (its address, its live nonce, its
own code). What it cannot decode it refuses.

```ts
import { Guard, GuardRefusal, keccak256, profiles } from "ef0100";

const guard = new Guard(profiles.hotWallet);

// 1. You have the preimage: judge it, then hash and sign.
const d = guard.check(preimage, { as: "preimage" }, { signer, nonce, ownCode });

// 2. Your signer takes a 32-byte digest: send the preimage along.
const d2 = guard.checkDigest(digest, preimage, { signer, nonce, ownCode });

// 3. Wrap a digest signer so it only ever signs the hash of bytes the guard allowed.
const sign = guard.wrap((bytes) => kms.signDigest(keccak256(bytes)), { as: "preimage" });
await sign(preimage, { signer, nonce, ownCode }); // throws GuardRefusal
```

`wrap` copies the input before judging it and signs that copy, so a buffer the caller changes afterwards is not what
gets signed.

## The context

| Field | Used for |
|---|---|
| `signer` | The key being asked. Required for an authorization (`CONTEXT_MISSING` without it), for rate limits and for the own-code rule. |
| `nonce` | The key's pending nonce. Required for an authorization unless the policy sets `requireNonce: false`. |
| `selfSponsored` | The key will send the type-4 transaction itself, so its authorization must carry nonce + 1. Set it only from the component that submits that transaction: an authorization for nonce + 1 that is never sent stays usable after the key's next transaction. |
| `ownCode` | `eth_getCode` of the key's own address. Anything non-empty switches the guard to the compromised rules below. |
| `codehashes` | Current codehash of each delegate, for delegates pinned by codehash. |
| `now` | Milliseconds. A time in the future does not count against the rate-limit window. |

## What it classifies

The first bytes of a secp256k1 preimage name its signing domain. An ed25519 key gets Solana kinds only; a
secp256k1 key gets EVM kinds only, because Solana message headers can start with the same bytes. Transaction fields
are decoded as strictly as an execution client decodes them (gas at most 8 bytes, a nonce below 2^64 - 1, access
lists shaped as lists).

| Kind | Preimage |
|---|---|
| `eip7702-authorization` | `0x05 ‖ rlp([chain_id, address, nonce])` |
| `set-code-tx` | `0x04 ‖ rlp([...10 fields])`, with its destination, value, calldata and a non-empty authorization list |
| `typed-tx` | `0x01`, `0x02`, `0x03` (a blob transaction needs a destination) |
| `legacy-tx` | an RLP list of 6 fields, or 9 ending in `(chain_id, 0, 0)` |
| `eip712` | `0x19 0x01 ‖ domainSeparator ‖ structHash` |
| `personal-message` | `0x19 "Ethereum Signed Message:\n" ‖ length ‖ message` (the message may itself start with digits) |
| `eip191-data` | `0x19 0x00 ‖ validator ‖ data` |
| `solana-message`, `solana-offchain-message` | ed25519 keys |
| `raw-digest` | 32 bytes passed as a digest |
| `unknown` | everything else, including a 32-byte input that only parses as a transaction: a digest can be ground until it does (`allow32ByteTransactions` opts in) |

## Reason codes

| Code | When |
|---|---|
| `NO_PREIMAGE` | A bare 32-byte digest. Nothing about it says whether it is an authorization. |
| `PREIMAGE_MISMATCH` | `checkDigest` was given a preimage whose keccak256 is not the digest. |
| `UNKNOWN_INPUT` | The bytes match no signing domain. |
| `KIND_NOT_ALLOWED` | A known kind outside `allowKinds` (default: typed, set-code and legacy transactions, EIP-712, personal messages; the hot-wallet profile allows transactions only). |
| `CONTEXT_MISSING` | An authorization without `ctx.signer`, or without `ctx.nonce` while `requireNonce` is on (the default). |
| `NO_CHAIN_ID` | A legacy transaction without a chain id, which replays on every chain the key uses (`allowUnprotectedLegacy` opts in). |
| `TOO_MANY_TUPLES` | A set-code transaction with more tuples than `maxTuples` (default 16); each tuple costs an ecrecover. |
| `DELEGATE_NOT_ALLOWED` | An authorization to a delegate not in `authorizations.allowDelegates`. |
| `DELEGATE_CHAIN_NOT_ALLOWED` | An allowed delegate on a chain it is not allowed on. |
| `DELEGATE_CODEHASH_MISMATCH` | The allowed delegate's current codehash (passed in `ctx.codehashes`) is not the pinned one. |
| `WILDCARD_CHAIN_ID` | `chain_id 0`: valid on every EIP-7702 chain where the nonce matches. |
| `CLEAR_NOT_ALLOWED` | Clearing was disabled by policy (it is allowed by default). |
| `NONCE_NOT_LIVE` | The authorization's nonce is not the pending nonce (pending + 1 when self-sponsored). A signed future nonce stays valid until the account reaches it. |
| `RATE_LIMITED` | More delegating authorizations for this key than `maxPerWindow` in `windowMs`. Clears do not count, and a transaction carrying a tuple this guard already allowed does not count it again. |
| `SPONSORS_OTHER_AUTHORITY` | A set-code transaction carrying another account's tuple, without `allowSponsoring`. |
| `BAD_TUPLE_SIGNATURE` | A tuple in a set-code transaction does not recover. |
| `OWN_CODE_PRESENT` | `ctx.ownCode` is not empty: the key's own account is delegated or is a contract. See below. |

## Once the key's own account has code

From that moment the guard signs only:

- the clear: an authorization to `0x0`, or a set-code transaction whose every tuple is the key's own clear, sent to
  the key itself with no value and no calldata;
- break-glass evacuation: plain ETH (no calldata) to an address in `breakGlass`, or `transfer(to, amount)` on a token
  in `breakGlassTokens` whose `to` is in `breakGlass`. A token contract alone opens nothing: `approve`,
  `transferFrom` and any other call are refused.

A set-code transaction that carries the clear and moves value or calls something in the same breath is refused: the
tuples run first, so the delegation would be gone and the payload would still execute.

With `trustAllowedDelegation` (on in `profiles.user`), code that is the designator of an allowed delegate does not
count as compromise, so a wallet that delegates on purpose keeps working.

## Profiles

- `profiles.hotWallet`: transactions only (no EIP-712, which can carry a token permit, and no personal messages), no
  delegate allowed, clearing allowed, one delegating authorization per key per 10 minutes.
- `profiles.user`: Simple7702Account and the MetaMask delegator allowed, three per 10 minutes, and being delegated to
  one of them is not treated as compromise. Allowing a delegate is a decision, not a safety label: anyone who can sign
  for the key can use the same delegate.

## The incident as a test, and what it does not show

`ef0100 guard test` runs the `hotWallet` profile against the 50 tuples of 2026-10-29 (as preimages and as digests),
the nine rehearsal tuples and the wallet's own clear: 50/50, 50/50 and 9/9 refused, the clear signed. The reasons it
prints are counted from the decisions, not written by hand.

That is a regression fixture. The profile refuses the 50 tuples because it allows no delegate at all, which is what
deny-by-default is for, not evidence that a rule distinguished a malicious authorization from a benign one. The claim
the test supports is narrow: if the guard sits in the signing path, these signatures are refused. How the real ones
were produced is not public.

`ownCode` is the rule that works without knowing anything about the attack: once `eth_getCode` on the key's own
address returns anything, the key signs only the clear and break-glass transfers. On 2026-10-29 the wallet's own
transactions kept being signed after its code changed.
