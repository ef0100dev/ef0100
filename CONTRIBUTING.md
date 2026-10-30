# Contributing

## Setup

- Node.js 22.12 or later and pnpm (`corepack enable`).
- `pnpm install && pnpm build && pnpm test`.

## Before a pull request

- `pnpm lint` (prettier and the type checks) and `pnpm test` pass.
- New behaviour has a test, and a new detector or decoder has a fixture from a real transaction: the raw bytes, a test
  that the bytes hash to the transaction hash (EVM) or verify their own signature (Solana), and the verdict expected.
- A detector also gets a negative test: a real transaction it must not flag.
- Changes to a fixture regenerate `fixtures/2026-10-29/SHA256SUMS` in the same commit.
- Claims in the README, the CLI output and the docs stay exact: say which numbers come from bundled bytes and which
  from an RPC or an explorer, and never present an inference as a fact.
- Times are UTC.

## Versioning

Before 1.0:
- a **minor** release (0.x → 0.y) may change the library API, the CLI's output format, reason codes or exit codes, and
  says so under "Breaking" in CHANGELOG.md;
- a **patch** release fixes bugs without changing any of those.

Runtime dependencies are pinned to exact versions and only change in a minor release.

Every change adds its entry under `## Unreleased` in CHANGELOG.md.
