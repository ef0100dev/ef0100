# Changelog

ef0100 follows the versioning rules in [CONTRIBUTING.md](CONTRIBUTING.md): until 1.0, a minor version may change the API,
the CLI output, reason codes or exit codes, and says so here.

## Unreleased

## 0.1.10 — 2026-10-30

- `readOwnCode(address, urls, { quorum, block })` reads `eth_getCode` from several endpoints in parallel and returns it
  only when they agree (default: all of them); otherwise throws `OwnCodeUnconfirmed`, endpoints named by host only. One
  endpoint that lies `"0x"` can no longer switch off the own-code rule.

## 0.1.9 — 2026-10-30

- Audit trail: `new Guard(policy, { onDecision })` reports every decision as `{ at, kind, allow, reasons, signer, digest }`
  (digest = keccak256 of the bytes judged); a throwing logger never changes a decision. `guard serve --log` prints
  them as JSON lines.

## 0.1.8 — 2026-10-30

- `ef0100/ethers`: `guardSigner(signer, guard, context)` puts an ethers v6 signer behind the guard: `signTransaction`,
  `signMessage`, `signTypedData` and `authorize` are judged from their bytes, including when ethers calls them itself
  (`sendTransaction` is refused before broadcast); `connect()` stays guarded. ethers is an optional peer dependency.

## 0.1.7 — 2026-10-30

- `ef0100/viem`: `guardAccount(account, guard, context)` wraps a viem LocalAccount so `sign`, `signAuthorization`,
  `signTransaction`, `signMessage` and `signTypedData` are judged from the bytes they would sign; a refusal throws
  `GuardRefusal` before the key is asked. viem is an optional peer dependency. Also `typedDataPreimage`.

## 0.1.6 — 2026-10-30

- Changed: the `hotWallet` profile now requires `ctx.ownCode` on every request (`requireOwnCode`, new policy field) and
  refuses with `CONTEXT_MISSING` without it. Pass `"0x"` when the key's account has no code. Before, a caller that
  left it out silently lost the own-code rule. `classify` gains `--own-code` (default `0x`, stated in the output);
  `guard test` passes the wallet's real state (no code for the 50 tuples, the sweeper's designator for the clear).
- Tests: the guard's less travelled rules (`test/guard-branches.test.ts`): codehash pinning, chain limits, clearing turned
  off, trusting an allowed own delegation, plain-ETH and token break-glass, bad tuples in a set-code transaction,
  kinds outside `allowKinds`, a 32-byte input that parses as a transaction, and the seen-set past 10,000 entries.
  `src/guard/policy.ts` coverage: lines 91.8% → 99.3%, branches 80.8% → 93.2%.
- `pnpm coverage` with per-file floors for the guard, `guard serve`, RLP and the bytecode fingerprint; CI runs it.

## 0.1.5 — 2026-10-30

- `action.yml`: `uses: ef0100dev/ef0100@<tag>` runs `scan` in GitHub Actions and fails the job on a delegation; inputs are
  validated before they reach the shell, an unanswered chain is a warning by default.
- CI: a nightly fuzz run (`.github/workflows/fuzz.yml`): both fuzz suites and the guard invariants at 100,000 runs per
  property, seeded with the run id so every night tries new inputs; a failure prints its seed.

## 0.1.4 — 2026-10-30

- `guard serve`: the guard over HTTP on 127.0.0.1 (`POST /check`, `GET /health`) for signers in other languages.
  No keys; foreign `Host` and any `Origin` refused (DNS rebinding), bodies capped at 256 KiB.
- Tests: Solana fuzz (`test/sol-fuzz.test.ts`): damaged copies of the bundled mainnet transactions through the decoder,
  the pre-signing check and the ed25519 classifier; each returns or refuses, and none fails in its own code.

## 0.1.3 — 2026-10-30

- Tests: guard invariants over random authorizations (`test/invariants.test.ts`): never chain_id 0, never a nonce other
  than the live one, never an unlisted delegate, never more than `maxPerWindow` in any window, and only the clear once
  the key's own account has code; plus the control that an allowed delegate at the live nonce is signed.
- `watch --webhook <url>`: each alarm and each clear posted as JSON, readable in Slack and Discord as is. https only
  (http to localhost for a relay), no redirects, the URL never printed; a failed delivery never stops the watch.
- `pnpm bench`: median and p99 per call for the guard and the decoders (`bench/guard.bench.mjs`).

## 0.1.2 — 2026-10-30

- `watch <address…>`: runs `scan` every slot (12 s, or `--every`) and prints one line, in UTC, when a delegation
  appears, changes or clears on any chain. An endpoint that stops answering never reads as a change. `--exit-on-change`
  exits 1 at the first delegation that is not allowed (2 for a known-malicious or sweeper-like delegate); `--json`
  prints one object per event. The diff is a pure function (`diffScan`), exported with the library.
- Releases are published from GitHub Actions through npm trusted publishing, with provenance.
- Tests: a seeded fuzz suite over the decoders, the guard and viem-signed authorizations (`test/fuzz.test.ts`;
  `EF0100_FUZZ_RUNS` raises the count).

0.1.1 was tagged but never published: its release run stopped before npm.

## 0.1.0 — 2026-10-30

The first release: a decoder, a guard and a replay built from the bytes of the 2026-10-29 hot-wallet drain. Not
externally audited (see SECURITY.md); every behaviour below is pinned by a test.

### Added
- `ef0100 replay`: the drain from bundled bytes, offline, as one 80-column frame whose counts are computed, not typed;
  `--table` for all 50 tuples, `--timeline` for the 3h49m36s, `--flows` for the first hop out of both collectors (the
  three large ETH transfers decode from bundled raw bytes), `--json` for the frame's numbers plus the clear, the EOA
  log, the raw byte count and the flows. Every view checks `SHA256SUMS` first and exits 3 on a mismatch.
- `ef0100 decode`: any transaction (a blob transaction's network form included); for type 4, tuple by tuple against
  the state it ran on (previous block plus every earlier transaction in the same block). Raw bytes are looked up by
  hash, state is read on the chain the transaction names, and NONCE_SPRAY fires on any run of two or more nonces from
  one authority, gaps and repeats included.
- `ef0100 scan` (and `ef0100 <address>`): delegation status on 11 EVM chains, the delegate's bytecode read; one chain
  or one delegate that misbehaves only affects its own rows.
- `ef0100 classify` and the `Guard` class: bare digests refused; authorizations need the key and its live nonce
  (CONTEXT_MISSING), an allowed delegate, a real chain id and a rate limit that counts each authorization once;
  relayed tuples refused; at most 16 tuples recovered; once the key's own account has code, only a self-clear with no
  payload and break-glass transfers to listed cold addresses pass. Profiles `hotWallet` (transactions only) and `user`.
  `checkDigest` judges a digest by its preimage; `wrap` signs a private copy of what it judged.
- `ef0100 recipient`: holds transfers to a delegated, contract or USDT/USDC-blacklisted address, with each chain's own
  blacklist call (Ethereum, Arbitrum, Avalanche, Polygon, Base, Optimism) and an unread blacklist reported as unread.
- `ef0100 clear`: the unsigned self-sponsored transaction that clears a delegation; reproduces the 2026-10-29 clear byte
  for byte.
- `ef0100 code`: static bytecode fingerprints, including selectors the optimizer stored shifted; the sweeper-like trait
  is a heuristic that skips ERC-20 tokens. The registry knows both incident sweepers and CrimeEnjoyor by codehash.
- `ef0100 sol` and `ef0100 sol nonces`: a Solana pre-signing check. System (account creation, seed transfers, Assign,
  nonces), Stake (initialization and authorities), SPL Token and Token-2022 (batch, unwrap, transfer with fee, mint),
  the upgradeable loader, ComputeBudget fees and Squads v4 (vault and batch messages read with the same rules, buffers,
  execution, spending limits). An instruction it does not read is reported, not passed. A transaction fetched by
  signature must be the one named and must verify.
- `ef0100 oracle`: a raw-digest signature read back as a valid authorization, with a public test key so the output is
  the same everywhere.
- One exit-code table for every command: 0 ok, 1 finding, 2 refused or known-malicious, 3 bundled data mismatch,
  64 usage, 69 no endpoint answered. RPC errors print the endpoint's host only and strip terminal control characters.
- Fixtures, each directory with its own `SHA256SUMS`: the delegation and clearing transactions, four rehearsal
  transactions, the main sweep, three onward transfers, both sweepers' bytecode and CrimeEnjoyor's, the drain ledger,
  block 26,300,753, the wallet's history for 2,086 blocks, the first-hop snapshot, and six Solana transactions (the
  2026-10-29 SOL leg, a routine withdrawal batch from the same wallet that day, and four from other incidents).
- Releases: a manual workflow that must run on the tag; build and test in one job, publish with npm trusted publishing
  from another that holds the only OIDC token; actions pinned by commit.
