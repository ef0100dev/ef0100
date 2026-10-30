# CLI

```
npx ef0100 <command> [options]
```

It never asks for or signs with your keys; `oracle` signs with a public test key. `replay`, `classify`, `guard test`
and `oracle` work offline; the others read public chain data.

## Commands

### `replay [2026-10-29]`

The 2026-10-29 drain, rebuilt from bytes bundled in the package. Prints one 80-column frame (animated on a terminal;
`--speed 0` prints the final frame). `binance-2026-10-29` is accepted as an alias.

- `--table`: all 50 tuples with their verdicts, the findings, the state change and the delegate's bytecode summary.
- `--timeline`: every call, the two largest top-ups, the freezes and the clear, in UTC, with the amounts each call
  moved. Other inflows landed while the wallet was delegated and left with later sweeps.
- `--flows`: where the swept value went next: what reached each collector, by source, the large ETH transfers out of
  them (each decoded from bundled raw bytes) and a dated snapshot of their other outgoing transactions.
- `--json`: the frame's numbers plus the clear, the EOA log, the raw byte count and the flows. Every view checks the
  bundled data against `SHA256SUMS` first and exits 3 on a mismatch.

### `scan <address…>` (or just `<address…>`)

`eth_getCode` and the nonce for each address on 11 chains (Ethereum, Base, Arbitrum One, OP Mainnet, BNB Smart Chain,
Polygon PoS, Gnosis, Unichain, Linea, Avalanche C-Chain, Scroll). For a delegated account it reads the delegate's code
and matches it against the registry and the sweeper fingerprint.

- `--chains <k,k>`: only these chains.
- `--allow <address>`: a delegate you set on purpose (repeatable); it no longer raises the exit code.
- `--cross-check`: ask every endpoint of each chain instead of the first that answers. If any one of them sees a
  delegation (or other code), the row reports it, with an `endpoints disagree` line naming what each returned (hosts
  only; `disagreement` in `--json`). One endpoint that lags or lies can't hide a delegation. It costs one request per
  endpoint and waits for the slowest. Also on `watch`.

### `watch <address…>`

Runs `scan` again every slot and prints one line, in UTC, whenever a delegation appears, changes or clears on any of
the chains. The first scan is the baseline. An endpoint that does not answer never reads as a change: the address keeps
its last known state, and the outage is printed once when it starts and once when it ends.

- `--every <seconds>`: seconds between scans (default 12, one Ethereum slot; at least 2).
- `--chains <k,k>`, `--allow <address>`: as for `scan`. An allowed delegate is still printed, without an alarm.
- `--exit-on-change`: exit at the first delegation that is not allowed, with 1, or 2 for a known-malicious or
  sweeper-like delegate. Without it, `watch` runs until it is stopped.
- `--json`: one JSON object per event (`baseline`, `delegated`, `redelegated`, `cleared`, `code`, `unreachable`,
  `back`), for a pager or a log pipeline.
- `--webhook <url>`: POST each alarm and each clear as JSON: `text` (Slack), `content` (Discord) and the event. https
  only, or http to localhost for a local relay; redirects are refused. The URL is a credential and is never printed
  (only its host, when a delivery fails). A failed delivery is printed and the watch keeps running.

### In GitHub Actions

`ef0100dev/ef0100` is also an action that runs `scan` and fails the job when an address is delegated. On a schedule
it is a cheap alarm for treasury and hot-wallet addresses:

```yaml
on:
  schedule:
    - cron: "*/10 * * * *"
jobs:
  delegations:
    runs-on: ubuntu-latest
    steps:
      - uses: ef0100dev/ef0100@v0.1.12
        with:
          addresses: |
            0x1111111111111111111111111111111111111111
            0x2222222222222222222222222222222222222222
          # chains: ethereum,base
          # allow: 0x… (a delegate you set on purpose)
```

Exit 1 fails the job for a delegation, 2 for a sweeper-like or known-malicious delegate. A chain that does not answer
is a warning unless `fail-on-unreachable: "true"`. Every input is checked before it reaches the shell.

### `decode <txhash|raw>`

Decodes any transaction, including a blob transaction in its network form. For type 4 it rebuilds each authority's
state at the moment the transaction ran: nonce, code and balance at the end of the previous block (an archive read),
then every earlier transaction in the same block, including their own authorization lists. Then it runs the list
exactly as clients do and prints a verdict per tuple. Raw bytes are looked up by their hash first, so a mined
transaction is replayed against the state it ran on; only a transaction no endpoint knows is replayed against the
latest state, and the output says which. When an authority had code while earlier transactions in the block ran, the
simulation is marked approximate: code can change a nonce (CREATE).

- `--chain <key>`, `--rpc <url>`. A typed or EIP-155 transaction names its chain, and state is read there; an explicit
  `--chain` that disagrees is an error.
- `--watch <address>`: a critical finding when this address signs a delegating authorization (repeatable).

### `classify <hex>`

What a key is being asked to sign, and whether the guard would sign it.

- `--digest`: the hex is a bare 32-byte digest (always refused: no preimage). A 32-byte input that only parses as a
  transaction is refused either way.
- `--signer <address>`, `--nonce <n>`, `--self` (self-sponsored: the authorization carries nonce + 1).
- `--own-code <hex>`: `eth_getCode` of the signer's own address. Defaults to `0x` (none), and the output says so.
- `--profile hot-wallet|user`, `--allow-delegate <address>` (repeatable).

### `guard serve`

The guard over HTTP, for a signer written in any language. Listens on `127.0.0.1` only (there is no option to listen
elsewhere), holds no keys and signs nothing: it answers whether the guard would sign.

```sh
npx ef0100 guard serve --port 8787 --profile hot-wallet
curl -s 127.0.0.1:8787/check -H 'content-type: application/json' \
  -d '{"preimage":"0x05…","signer":"0x28C6…1d60","nonce":"18914809","ownCode":"0x"}'
# {"allow":false,"kind":"eip7702-authorization","reasons":[{"code":"DELEGATE_NOT_ALLOWED",…}]}
```

- `POST /check` with `preimage`, or `digest` (with its `preimage` when the signer only sees hashes), plus `signer`,
  `nonce` (a number, or a decimal or `0x` string), `ownCode` and `selfSponsored`. Answers `{allow, kind, reasons}`.
- `GET /health` answers `{ok, version}`.
- One guard per process, so its rate limit spans requests.
- `--log`: one JSON line per decision on stdout (`at`, `kind`, `allow`, `reasons`, `signer`, `digest`), for an audit
  trail; no key material and no request bytes.
- With the hot-wallet profile every request must carry `ownCode` (`"0x"` when the key's account has none), or it is
  refused with `CONTEXT_MISSING`.
- `--rpc <url>` (repeatable) makes the server read the signer's own code itself, per request, from those endpoints:
  every answer must match and at least `--quorum` must answer (default 2). A request's own `ownCode`, if it sends one,
  counts as one more answer, so a caller that says `"0x"` while the endpoints see a delegation is refused. No signer,
  or no agreement, means no own code and `CONTEXT_MISSING`. The response adds `ownCodeAnswers` (endpoints by host
  only). Malformed requests are rejected before any endpoint is asked.

  ```sh
  npx ef0100 guard serve --rpc "$RPC_A" --rpc "$RPC_B" --rpc "$RPC_C" --log
  ```
- A request whose `Host` is not `127.0.0.1:<port>` or `localhost:<port>`, or that carries an `Origin` header, gets 403:
  a web page cannot reach it through DNS rebinding. Bodies above 256 KiB get 413, malformed ones 400.

### `guard test`

The `hotWallet` profile against the incident's 50 tuples as preimages and as digests, the rehearsal tuples, and the
wallet's own clearing authorization. These are regression fixtures: see [guard.md](guard.md).

### `recipient <address>`

Should funds go here right now? Holds the transfer when the address is delegated (to anything not passed with
`--allow`), is a contract, or is on the USDT or USDC blacklist. Blacklists are read on Ethereum (Tether's
`isBlackListed`, Circle's `isBlacklisted`), on Arbitrum, Avalanche and Polygon (Tether's `isBlocked`, Circle's
`isBlacklisted`) and on Base and Optimism (Circle's `isBlacklisted`). Anywhere else, or when a call fails, the output
says the blacklist was not checked; it never reports an unread blacklist as clean.

### `clear <address>`

The unsigned self-sponsored type-4 transaction that clears a delegation: the authorization to sign first (address
`0x0`, nonce + 1), then the transaction. Reads the pending nonce and fees unless `--nonce`, `--max-fee` and
`--priority-fee` are given. While an account is delegated, geth keeps at most one of its transactions in flight: send
the clear when nothing else from it is pending, or submit it privately.

### `code <address|hex>`

A static read of bytecode: named selectors (including `PUSH4 v PUSH1 k SHL`, the shifted form the optimizer uses),
hardcoded addresses (printable ASCII is not counted) and traits. `sweeperLike` is a heuristic: token balance and
transfer selectors, a `CALLER` opcode and a hardcoded address, in code that does not itself implement a token. It can
miss a sweeper (an ETH forwarder with its destination in storage has none of these traits) and it is a hint, not a
verdict. Known sweepers are matched by address and by codehash.

### `owncode <address>`

`eth_getCode` of an address, from several endpoints at once, used only when every endpoint that answers returns the
same bytes and at least `--quorum` of them answered (default 2). Without `--rpc` it asks the chain's public endpoints;
with `--rpc` (repeatable) it asks only yours, which is what a signing service should do: point it at independent
providers. Exit 0 when they agree there is no code, 1 when they agree on code (a delegation designator is shown with its
delegate), 69 when they disagree or too few answered. Then don't pass an own code to the guard at all: the hot-wallet
profile refuses with `CONTEXT_MISSING`. Never fall back to `0x`.

```sh
npx ef0100 owncode 0x28C6c06298d514Db089934071355E5743bf21d60 --rpc "$RPC_A" --rpc "$RPC_B" --rpc "$RPC_C" --json
```

### `sol <signature|base64>`

A Solana transaction before signing. By signature it is fetched from a public endpoint (or `EF0100_RPC_SOLANA`).

- `--template <nonce-authority>`: the signer's routine is to advance a durable nonce whose authority is this key.
  Anything else is `TEMPLATE_DRIFT`.
- `--routine`: plain SOL transfers are this signer's job (an exchange withdrawal wallet).
- `--balance <lamports>`: flag a transaction that moves 20% or more of it. Fetched transactions use the fee payer's
  balance before the transaction.

### `sol nonces <pubkey>`

Every durable-nonce account whose authority is this key. Public endpoints may refuse `getProgramAccounts` on the System
program; set `EF0100_RPC_SOLANA`.

### `oracle`

Signs the 32-byte digest of the applied tuple with Anvil's account #0 (a public test key: never fund it) and reads the
signature back as an authorization. The output is identical on every machine.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Clean, allowed, or every expectation met |
| 1 | A finding: delegated, a spray, a review |
| 2 | Refused, or delegated to a known-malicious or sweeper-like delegate |
| 3 | Bundled data does not match `SHA256SUMS` |
| 64 | Usage error |
| 69 | No endpoint answered; for `owncode`, the endpoints disagree or too few answered |
| 70 | Internal error |

## Endpoints

Keyless public endpoints by default. `EF0100_RPC_<CHAIN>` (for example `EF0100_RPC_ETHEREUM`) or `--rpc <url>`
(repeatable) puts yours first for live and historical reads; `owncode` asks only the `--rpc` endpoints when you give any. Historical reads fall back to keyless archive gateways. Error messages
print an endpoint's host only.
