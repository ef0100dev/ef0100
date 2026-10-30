# Changelog

ef0100 follows the versioning rules in [CONTRIBUTING.md](CONTRIBUTING.md): until 1.0, a minor version may change the API,
the CLI output, reason codes or exit codes, and says so here.

## Unreleased

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
