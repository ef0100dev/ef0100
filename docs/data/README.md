# Sourced data

Files here are context, not evidence: nothing in ef0100 computes a verdict from them, and the CLI does not print them.

- `legs-2026-10-29.json`: every leg of the drain found on chain, with one example transaction each. Amounts were read
  from explorers and the incident research. Owner labels marked "unverified" rest on explorer labels or activity.
- `btc-first-seen-2026-10-29.txt`: when one observer (BlockCypher) first saw each of the 11 BTC transactions, and the
  block time they were confirmed in. A single observer's first-seen time is an upper bound on the broadcast time.
