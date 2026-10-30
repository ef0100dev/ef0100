# Security

ef0100 decides whether bytes get signed. Treat it as part of your signing path, and review it as you would anything
else that stands between a request and a key.

## Status

- **ef0100 has not been audited by an independent firm.** Every release runs its tests against the real bytes of the
  2026-10-29 incident and cross-checks decoding and signatures against viem, but tests are not an audit.
- It cannot stop a stolen raw key: whoever holds the key signs without asking anyone.
- It does not claim it would have stopped the 2026-10-29 drain. How those signatures were produced is not public.
- Only the latest 0.x release receives security fixes.

## Reporting a vulnerability

Please report privately, not in a public issue: use the **"Report a vulnerability"** button on
https://github.com/ef0100dev/ef0100/security (GitHub private vulnerability reporting). Include the bytes or the transaction
hash and the command or call that shows the problem. We aim to acknowledge reports within 3 days and to ship a fix for
confirmed issues as fast as their severity requires, with credit unless you prefer otherwise.

## What counts

- The guard signing something its policy says it must refuse, or classifying bytes as the wrong kind.
- `processAuthorizationList` giving a verdict that differs from what an execution client does with the same list and
  state.
- A decoder accepting bytes a client rejects (non-canonical RLP, high-s signatures, malformed messages), or rejecting
  bytes a client accepts.
- Anything that prints a private RPC endpoint's credentials.
