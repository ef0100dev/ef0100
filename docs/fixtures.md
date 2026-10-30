# Fixtures

Everything ef0100 says about 2026-10-29 is computed from the files in `fixtures/`. They ship in the npm package. Each
of `fixtures/2026-10-29/`, `fixtures/registry/` and `fixtures/solana/` has a `SHA256SUMS` listing every file in it;
every `ef0100 replay` view and `guard test` check them before printing, and CI checks them on every push.

Not every file proves the same thing. A raw transaction authenticates itself; a block count read from an explorer does
not. This page says which is which.

## Authenticated by their own bytes

| File | What proves it |
|---|---|
| `2026-10-29/raw/0xad99…298b.rlp.hex` | The delegation transaction, 4,916 bytes. `keccak256(raw)` is its hash, and all 50 tuples recover to `0x28C6c06298d514Db089934071355E5743bf21d60` (checked against viem). |
| `2026-10-29/raw/0xafbf…7209.rlp.hex` | The clearing transaction. `keccak256(raw)` is its hash; `planClearDelegation()` rebuilds it byte for byte from its own signatures. |
| `2026-10-29/raw/0x16b5…`, `0xec5a…`, `0xb214…`, `0x7c52…` | The attacker's rehearsal transactions on their own test wallets. Each hashes to its name. |
| `2026-10-29/raw/0x53bd…88e2f3.rlp.hex` | The main sweep: `sweep(address,address[])` called on the delegated wallet. Hashes to its name. |
| `2026-10-29/raw/0x551d…2c76`, `0x4818…e84a`, `0x9edf…6071` | The three large ETH transfers out of collector R1. Each hashes to its name, recovers to R1, and carries the recipient and value `onward.json` states (checked when the incident loads). |
| `registry/crimeenjoyor_runtime.hex` | The runtime of a known ETH-forwarding 7702 sweeper. Its keccak256 is the codehash the registry matches. |
| `solana/cases.json` | Six Solana transactions (wire format, base64): the 2026-10-29 SOL leg, a routine withdrawal batch from the same wallet that day, and four from other incidents. Each verifies its own ed25519 signature over its message with the fee payer's key, so the bytes are what that key signed. |

A raw transaction proves what was signed. It does not by itself prove that the transaction was included in a given
block; that would take rebuilding the block's transactions root (on the roadmap).

## Attested by an RPC or an explorer

| File | Source | Checked against |
|---|---|---|
| `2026-10-29/evm/code_nonce_timeline.json` | `eth_getCode` and `eth_getTransactionCount` at historical blocks from keyless archive endpoints | `wallet_blocks.json` |
| `2026-10-29/evm/wallet_blocks.json` | The wallet's own transactions per block and its nonce after each block, from Blockscout's address history, blocks 26,300,485–26,302,570; one transaction the list missed (block 26,302,532) was added from an RPC read | The archive timeline; nonce continuity over all 2,086 blocks (the only skips are the two nonces an authorization used). The per-block counts in the replay are summed from this file. |
| `2026-10-29/evm/onward.json` | The first hop: the three transfers out of R1 (block, time and status from receipts), explorer labels, and a dated snapshot of both collectors' outgoing transactions from Blockscout | The bundled raw transactions; the ledger for what reached each collector |
| `2026-10-29/evm/drain_ledger.csv` | Token transfers and internal ETH transfers per transaction, from Blockscout | `events.json` (block and time of every call) |
| `2026-10-29/evm/events.json` | Hashes, blocks and UTC times of every call through the delegation, the two largest top-ups and the clear, read with `eth_getTransactionByHash` and receipts | The ledger |
| `2026-10-29/evm/block_26300753.json` | The 209 transactions of block 26,300,753 (index, hash, sender, nonce, type, authorization list) | `decode`'s same-block replay in `test/live.test.ts` |
| `2026-10-29/evm/sweeper_v1_runtime.hex`, `sweeper_v2_runtime.hex` | `eth_getCode` of the two sweepers | The registry's codehashes |
| `2026-10-29/evm/golden.json` | Per-tuple verdicts and the nonce reconstruction, derived from the raw transaction and the archive reads | The tests |
| `2026-10-29/evm/mempool_visibility.json` | Flashbots Mempool Dumpster for 2026-10-29: which of these transactions any of its sources observed | None (a single dataset) |

The two largest top-ups' senders (`0xEae7…A4F4`, `0x2213…BC9e`) are not verified as belonging to the exchange;
ef0100 calls them top-ups, in the CLI and here, and says nothing about who sent them. Other inflows landed while the
wallet was delegated and left with the later sweeps.

## Sourced, not bundled for any verdict

`docs/data/legs-2026-10-29.json` lists the drain's other legs (BTC, XRPL, Solana, OP, Tron, a second Ethereum wallet,
Avalanche) with an example transaction each. Those amounts were read from explorers and the incident research and are
not recomputed from bytes in this repository, so the CLI does not print them. `docs/data/btc-first-seen-2026-10-29.txt`
records when one observer first saw each BTC transaction.
