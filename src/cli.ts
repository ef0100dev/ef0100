#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { bytesToHex, hexToBytes, isAddress, type Hex } from "./evm/bytes.js";
import { CHAINS, findChain, withRpcOverrides } from "./evm/chains.js";
import { authorizationDigest, authorizationPreimage, delegationCode, recoverAuthority } from "./evm/eip7702.js";
import { fingerprintCode } from "./evm/fingerprint.js";
import { inspectTransaction } from "./evm/inspect.js";
import { lookupDelegate } from "./evm/registry.js";
import { checkRecipient } from "./evm/recipient.js";
import { planClearDelegation } from "./evm/remediate.js";
import { RpcError, cleanText, rpcBatchAny } from "./evm/rpc.js";
import { addressOfSecretKey, signDigest } from "./evm/secp256k1.js";
import { scanAddresses } from "./evm/scan.js";
import { createGuardServer } from "./guard/serve.js";
import { redactRpc } from "./evm/rpc.js";
import {
  checkWebhookUrl,
  diffScan,
  isAlarm,
  isNotifiable,
  postWebhook,
  type WatchEvent,
  type WatchState,
} from "./evm/watch.js";
import { Guard, profiles, type Decision, type GuardPolicy } from "./guard/policy.js";
import { loadIncident, verifyFixtures, type Incident } from "./incident.js";
import { checkSolanaTransaction } from "./sol/check.js";
import { getSolanaTransaction, listNonceAccounts, solanaEndpoints } from "./sol/rpc.js";
import {
  renderFindings,
  renderFrame,
  renderOutcomes,
  renderTable,
  renderTimeline,
  renderFlows,
  type GuardSummary,
} from "./cli/render.js";
import { int, pad, short, style } from "./cli/style.js";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };

/** One table for every command, kept stable as public API (sysexits codes for usage and availability). */
export const EXIT = {
  ok: 0,
  finding: 1,
  refused: 2,
  knownBad: 2,
  fixtureMismatch: 3,
  usage: 64,
  unavailable: 69,
  software: 70,
} as const;

const HELP = `ef0100 ${pkg.version}: decode, replay and refuse EIP-7702 delegations

usage
  ef0100 replay [2026-10-29]           the 2026-10-29 drain from its own bytes, offline
         --table                       all 50 tuples with their verdicts
         --timeline                    the 3h49m36s the delegation was live
         --flows                       where the swept value went: the first hop out of both collectors
  ef0100 decode <txhash|raw>           a type-4 transaction, tuple by tuple, against the state it ran on
  ef0100 scan <address…>               is any of these accounts delegated, on 11 EVM chains? (also: ef0100 <address>)
  ef0100 watch <address…>              scan again every slot; one line, in UTC, whenever a delegation appears, changes or clears
  ef0100 classify <hex>                what a key is being asked to sign, and whether the guard would sign it
  ef0100 guard test                    the guard against the incident's tuples, digests and clear
  ef0100 guard serve                   the guard on http://127.0.0.1:8787/check for signers in any language (--port, --profile)
  ef0100 oracle                        why a raw-digest signer is an authorization signer (public test key)
  ef0100 recipient <address>           top-up guard: should funds go to this address right now?
  ef0100 clear <address>               unsigned self-sponsored transaction that clears a delegation
  ef0100 code <address|hex>            what a delegate's bytecode does (static read, no execution)
  ef0100 sol <signature|base64>        Solana pre-signing check: durable nonces, Assign, authorities, Squads
         --template <nonce-authority>  the signer's routine: durable nonces from its own pool
         --routine                     plain SOL transfers are this signer's job (exchange withdrawals)
         --balance <lamports>          flag a transaction that moves 20% or more of it
  ef0100 sol nonces <pubkey>           nonce accounts this key controls (public endpoints may refuse; set EF0100_RPC_SOLANA)

options
  --chain <key>        ethereum (default), base, arbitrum, optimism, bsc, polygon, gnosis, unichain, linea,
                       avalanche, scroll
  --chains <k,k>       scan only these chains (default: all of them)
  --rpc <url>          your own endpoint for --chain (also EF0100_RPC_<CHAIN>, e.g. EF0100_RPC_ETHEREUM)
  --watch <address>    decode: critical finding when this address signs an authorization (repeatable)
  --allow <address>    scan, watch: a delegate you set on purpose does not count (repeatable)
  --every <seconds>    watch: seconds between scans (default 12, one Ethereum slot; at least 2)
  --exit-on-change     watch: exit at the first delegation that is not allowed (1, or 2 for a sweeper)
  --webhook <url>      watch: POST each alarm and clear as JSON (Slack text, Discord content); https only
  --profile <name>     classify: hot-wallet (default) or user
  --digest             classify: the hex is a bare 32-byte digest, not a preimage
  --signer <address>   classify: the key being asked; --nonce <n> its pending nonce; --self for nonce + 1
  --own-code <hex>     classify: eth_getCode of the signer's own address (default 0x, none)
  --speed <n>          replay animation speed; 0 prints the final frame (default when not a terminal)
  --json               machine-readable output

exit codes
  0 clean or allowed · 1 finding (delegated, spray, review) · 2 refused, or a known-malicious or sweeper-like
  delegate · 3 bundled data does not match SHA256SUMS · 64 usage · 69 no endpoint answered

It reads public chain data over keyless endpoints by default. It never asks for or signs with your keys; oracle signs with a public test key.
`;

const json = (v: unknown) =>
  JSON.stringify(
    v,
    (_k, x) =>
      typeof x === "bigint"
        ? x.toString()
        : x instanceof Map
          ? Object.fromEntries(x)
          : x instanceof Uint8Array
            ? bytesToHex(x)
            : x,
    2,
  );

class UsageError extends Error {}
const usage = (msg: string): never => {
  throw new UsageError(msg);
};

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Short labels for the guard test's table; the guard's own messages carry the detail. */
const REASON_LABEL: Record<string, string> = {
  NO_PREIMAGE: "no preimage",
  DELEGATE_NOT_ALLOWED: "delegate not allowed",
  NONCE_NOT_LIVE: "off the live nonce",
  RATE_LIMITED: "rate-limited",
  CONTEXT_MISSING: "own code not given",
};

interface GuardTestRow {
  name: string;
  requests: number;
  refused: number;
  /** How many requests carried each reason code. */
  reasons: Record<string, number>;
  why: string;
}

function guardRow(name: string, decisions: Decision[], allowedWhy?: string): GuardTestRow {
  const reasons: Record<string, number> = {};
  for (const d of decisions)
    for (const code of new Set(d.reasons.map((r) => r.code))) reasons[code] = (reasons[code] ?? 0) + 1;
  const refused = decisions.filter((d) => !d.allow).length;
  const n = decisions.length;
  const parts = Object.entries(reasons)
    .filter(([code]) => code !== "ALLOWED")
    .sort((a, b) => b[1] - a[1])
    .map(([code, c], i) => {
      const label = REASON_LABEL[code] ?? code.toLowerCase().replaceAll("_", " ");
      return c === n ? label : `${c}${i === 0 ? "" : " also"} ${label}`;
    });
  return { name, requests: n, refused, reasons, why: refused === 0 && allowedWhy ? allowedWhy : parts.join("; ") };
}

function guardSummary(inc: Incident): GuardSummary & {
  rehearsalTuples: number;
  rehearsalRefused: number;
  rows: GuardTestRow[];
} {
  const auths = inc.delegation.tx.authorizationList;
  const g = new Guard(profiles.hotWallet);
  const pre = auths.map((a, i) =>
    g.check(
      authorizationPreimage(a),
      { as: "preimage" },
      { signer: inc.authority, nonce: inc.delegation.authorityNonceAtTx, now: i, ownCode: "0x" },
    ),
  );
  const dig = auths.map((a) =>
    new Guard(profiles.hotWallet).check(
      authorizationDigest(a),
      { as: "digest" },
      { signer: inc.authority, ownCode: "0x" },
    ),
  );
  const clearTuple = inc.clear.tx.authorizationList[0]!;
  const clear = new Guard(profiles.hotWallet).check(
    authorizationPreimage(clearTuple),
    { as: "preimage" },
    {
      signer: inc.authority,
      nonce: inc.clear.tx.nonce,
      selfSponsored: true,
      ownCode: delegationCode(auths[0]!.address),
    },
  );
  const rehearsal = inc.rehearsals.flatMap((t) => t.authorizationList);
  const rg = new Guard(profiles.hotWallet);
  const reh = rehearsal.map((a, i) => {
    const rec = recoverAuthority(a);
    // Judged as if each tuple were live, so only the delegate rule decides.
    return rg.check(
      authorizationPreimage(a),
      { as: "preimage" },
      { signer: rec.ok ? rec.authority : undefined, nonce: a.nonce, now: i, ownCode: "0x" },
    );
  });
  const rows = [
    guardRow("2026-10-29 tuples", pre),
    guardRow(`same ${auths.length}, as bare digests`, dig),
    guardRow(`rehearsal tuples (${inc.rehearsals.length} txs)`, reh),
    guardRow("2026-10-29 clear", [clear], "authorizes 0x0, nonce = tx nonce + 1"),
  ];
  return {
    preimagesRefused: rows[0]!.refused,
    digestsRefused: rows[1]!.refused,
    total: auths.length,
    clearAllowed: clear.allow,
    rehearsalTuples: rehearsal.length,
    rehearsalRefused: rows[2]!.refused,
    rows,
  };
}

async function replay(o: { table?: boolean; timeline?: boolean; flows?: boolean; json?: boolean; speed?: string }) {
  const sums = verifyFixtures();
  const inc = loadIncident();
  const guard = guardSummary(inc);
  if (o.json) {
    console.log(
      json({
        fixtures: sums,
        delegation: {
          tx: inc.delegation.tx.hash,
          block: inc.delegation.block,
          index: inc.delegation.index,
          utc: inc.delegation.utc,
          authority: inc.authority,
          authorityNonceAtTx: inc.delegation.authorityNonceAtTx,
          outcomes: inc.delegation.result.outcomes,
          findings: inc.delegation.findings,
          after: inc.delegation.result.after,
        },
        calls: inc.calls,
        refills: inc.refills,
        totals: inc.totals,
        timing: inc.timing,
        throughput: inc.throughput,
        onward: inc.onward,
        clear: {
          tx: inc.clear.tx.hash,
          block: inc.clear.block,
          utc: inc.clear.utc,
          nonce: inc.clear.tx.authorizationList[0]!.nonce,
          gasUsed: inc.clear.gasUsed,
        },
        eoaLog: inc.eoaLog,
        rawBytes: inc.delegation.tx.raw.length / 2 - 1,
        guard,
      }),
    );
    return sums.ok ? EXIT.ok : EXIT.fixtureMismatch;
  }
  if (!sums.ok && (o.table || o.timeline || o.flows))
    console.log(style.red(`\n  bundled data does not match SHA256SUMS: ${sums.mismatched.join(", ")}`));
  if (o.table) console.log(renderTable(inc));
  if (o.timeline) console.log(renderTimeline(inc));
  if (o.flows) console.log(renderFlows(inc));
  if (!o.table && !o.timeline && !o.flows) {
    const meta = { version: pkg.version, fixturesOk: sums.ok, guard };
    const speed = o.speed === undefined ? (process.stdout.isTTY && !process.env.CI ? 1 : 0) : Number(o.speed);
    if (!(speed > 0)) console.log(renderFrame(inc, meta));
    else await animate(inc, meta, speed);
    console.log("");
  }
  return sums.ok ? EXIT.ok : EXIT.fixtureMismatch;
}

/** About 6 s at speed 1: the cursor walks 50 tuples, then 17 blocks run to the sweep. Redraws in place. */
async function animate(inc: Incident, meta: Parameters<typeof renderFrame>[1], speed: number) {
  const n = inc.delegation.tx.authorizationList.length;
  const draw = (cursor: number, blocks: number, first = false) => {
    const frame = renderFrame(inc, meta, { cursor, blocks });
    const lines = frame.split("\n").length;
    process.stdout.write(
      (first ? "" : `\x1b[${lines}A`) +
        frame
          .split("\n")
          .map((l) => `\x1b[2K${l}`)
          .join("\n") +
        "\n",
    );
  };
  process.stdout.write("\x1b[?25l");
  try {
    draw(0, 0, true);
    for (let c = 1; c <= n; c++) {
      draw(c, 0);
      await sleep((c === inc.delegation.result.applied[0]!.index + 1 ? 700 : 60) / speed);
    }
    for (let b = 1; b <= inc.timing.blocksToFirstSweep; b++) {
      draw(n, b);
      await sleep(90 / speed);
    }
    draw(n, Infinity);
  } finally {
    process.stdout.write("\x1b[?25h");
  }
}

/** Anvil and Hardhat account #0. Public on purpose: the output must be reproducible. Never send funds to it. */
const PUBLIC_TEST_KEY = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

function oracle(asJson: boolean) {
  const inc = loadIncident();
  const tuple = inc.delegation.tx.authorizationList[inc.delegation.result.applied[0]!.index]!;
  const sk = hexToBytes(PUBLIC_TEST_KEY);
  const me = addressOfSecretKey(sk);
  const auth = { chainId: tuple.chainId, address: tuple.address, nonce: tuple.nonce };
  const digest = bytesToHex(authorizationDigest(auth));
  // The signer is handed 32 bytes and nothing else, as a KMS DIGEST call or a sign(hash) API would be.
  const sig = signDigest(hexToBytes(digest), sk);
  const recovered = recoverAuthority({ ...auth, ...sig });
  const valid = recovered.ok && recovered.authority === me;
  if (asJson) {
    console.log(json({ testKey: me, digest, signature: sig, validAuthorization: valid }));
    return valid ? EXIT.ok : EXIT.finding;
  }
  const h = (x: bigint) => short("0x" + x.toString(16).padStart(64, "0"), 10, 4);
  console.log(`
  ${style.dim(pad("key", 10))}${short(me)} ${style.dim("public test key (anvil #0): never fund it")}
  ${style.dim(pad("tuple", 10))}chain ${auth.chainId} · ${short(auth.address)} · nonce ${int(auth.nonce)} ${style.dim("(2026-10-29 tuple #15)")}
  ${style.dim(pad("digest", 10))}${digest}

  ${style.dim(pad("asked", 10))}sign these 32 bytes ${style.dim("(no preimage, as a raw-digest API receives them)")}
  ${style.dim(pad("got", 10))}yParity ${sig.yParity} · r ${h(sig.r)} · s ${h(sig.s)}
  ${style.dim(pad("read as", 10))}EIP-7702 authorization for the tuple → authority ${recovered.ok ? short(recovered.authority) : "none"} ${valid ? style.red(style.bold("valid")) : "invalid"}

  Any API that signs a bare 32-byte digest will sign this authorization.
  ${style.dim("viem's signAuthorization() returns the same bytes; test/crosscheck.test.ts checks it.")}
`);
  return valid ? EXIT.ok : EXIT.finding;
}

async function main(argv: string[]): Promise<number> {
  const { values: o, positionals: pos } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      chain: { type: "string" },
      chains: { type: "string" },
      rpc: { type: "string" },
      watch: { type: "string", multiple: true },
      allow: { type: "string", multiple: true },
      json: { type: "boolean" },
      table: { type: "boolean" },
      timeline: { type: "boolean" },
      flows: { type: "boolean" },
      speed: { type: "string" },
      digest: { type: "boolean" },
      signer: { type: "string" },
      nonce: { type: "string" },
      self: { type: "boolean" },
      profile: { type: "string" },
      template: { type: "string" },
      routine: { type: "boolean" },
      balance: { type: "string" },
      "allow-delegate": { type: "string", multiple: true },
      "max-fee": { type: "string" },
      every: { type: "string" },
      "exit-on-change": { type: "boolean" },
      webhook: { type: "string" },
      port: { type: "string" },
      "own-code": { type: "string" },
      "priority-fee": { type: "string" },
      help: { type: "boolean", short: "h" },
      version: { type: "boolean", short: "v" },
    },
  });
  if (o.version) return (console.log(pkg.version), EXIT.ok);
  let [cmd, ...rest] = pos;
  if (o.help || !cmd) return (console.log(HELP), o.help ? EXIT.ok : EXIT.usage);
  if (isAddress(cmd)) {
    rest = [cmd, ...rest];
    cmd = "scan";
  }
  const overrides: Record<string, string> = o.rpc ? { [o.chain ?? "ethereum"]: o.rpc } : {};
  const chains = withRpcOverrides(CHAINS, process.env, overrides);
  const chain = () => findChain(o.chain ?? "ethereum", chains) ?? usage(`unknown chain ${o.chain}`);

  switch (cmd) {
    case "replay": {
      const id = rest[0] ?? "2026-10-29";
      if (!["2026-10-29", "binance-2026-10-29"].includes(id)) usage(`no bundled incident ${id}; try 2026-10-29`);
      return replay(o);
    }

    case "scan": {
      if (!rest.length) usage("scan needs at least one address");
      const only = o.chains?.split(",").map((k) => findChain(k.trim(), chains) ?? usage(`unknown chain ${k}`));
      const res = await scanAddresses(rest, { chains: only ?? chains, allow: o.allow });
      if (o.json) console.log(json(res));
      else {
        for (const address of [...new Set(res.rows.map((r) => r.address))]) {
          console.log(`\n  ${style.bold(address)}`);
          for (const r of res.rows.filter((x) => x.address === address)) {
            const name = pad(r.chain.name, 19);
            if (r.state === "error") console.log(`  ${name} ${style.yellow("no answer")}  ${style.dim(r.error ?? "")}`);
            else if (r.state === "delegated") {
              const bad = r.entry?.verdict === "malicious" || r.delegateCode?.sweeperLike;
              const label = r.entry
                ? r.entry.label
                : r.delegateCode?.sweeperLike
                  ? "sweeper-like code"
                  : "not in the registry";
              const mark = bad ? style.red(style.bold("DELEGATED")) : style.yellow("delegated");
              console.log(`  ${name} ${mark}  → ${r.delegate}  ${style.dim(label)}`);
            } else
              console.log(
                `  ${name} ${style.dim(r.state === "contract" ? "contract" : "no delegation")}${style.dim(`  nonce ${int(r.nonce ?? 0n)}`)}`,
              );
          }
        }
        const verdicts = {
          0: style.green("clean"),
          1: style.yellow("delegated"),
          2: style.red(style.bold("DELEGATED TO A SWEEPER")),
          69: style.yellow("incomplete: a chain did not answer"),
        } as const;
        console.log(`\n  ${verdicts[res.exitCode]}\n`);
      }
      return res.exitCode;
    }

    case "watch": {
      if (!rest.length) usage("watch needs at least one address");
      const only = o.chains?.split(",").map((k) => findChain(k.trim(), chains) ?? usage(`unknown chain ${k}`));
      const every = o.every == null ? 12 : Number(o.every);
      if (!Number.isFinite(every) || every < 2) usage("--every is in seconds, at least 2");
      const allow = new Set((o.allow ?? []).map((a) => a.toLowerCase()));
      const list = only ?? chains;
      let hook: string | undefined;
      if (o.webhook) {
        try {
          hook = checkWebhookUrl(o.webhook).href;
        } catch (e) {
          usage((e as Error).message);
        }
      }
      const clock = (iso: string) => style.dim(`${iso.slice(11, 19)} UTC`);
      const line = (e: WatchEvent): string | undefined => {
        const where = `${pad(findChain(e.chain, chains)?.name ?? e.chain, 19)} ${short(e.address)}`;
        switch (e.kind) {
          case "baseline":
            return e.state === "delegated"
              ? `${clock(e.at)}  ${where}  ${e.allowed ? style.dim("delegated (allowed)") : style.yellow("delegated")} → ${e.delegate}  ${style.dim(e.label ?? "")}`
              : undefined;
          case "delegated":
          case "redelegated": {
            const mark = e.allowed
              ? style.dim(e.kind)
              : e.bad
                ? style.red(style.bold("DELEGATED"))
                : style.yellow(e.kind.toUpperCase());
            const from = e.previous ? style.dim(` (was ${short(e.previous)})`) : "";
            return `${clock(e.at)}  ${where}  ${mark} → ${e.delegate}${from}  ${style.dim(e.label ?? "")}`;
          }
          case "cleared":
            return `${clock(e.at)}  ${where}  ${style.green("cleared")}${style.dim(` (was ${short(e.previous ?? "?")})`)}`;
          case "code":
            return `${clock(e.at)}  ${where}  ${style.yellow("code appeared")}`;
          case "unreachable":
            return `${clock(e.at)}  ${where}  ${style.yellow("no answer")}  ${style.dim(e.error ?? "")}`;
          case "back":
            return `${clock(e.at)}  ${where}  ${style.dim("answering again")}`;
        }
      };
      if (!o.json)
        console.log(
          `\n  ${style.bold("watch")} ${rest.length} address${rest.length === 1 ? "" : "es"} on ${list.length} chain${list.length === 1 ? "" : "s"}, every ${every} s ${style.dim("(ctrl-c to stop)")}\n`,
        );
      let state: WatchState | undefined;
      for (;;) {
        const res = await scanAddresses(rest, { chains: list, allow: o.allow });
        const first = !state;
        const { events, next } = diffScan(state, res.rows, allow, new Date());
        state = next;
        for (const e of events) {
          if (o.json) console.log(JSON.stringify(e));
          else {
            const text = line(e);
            if (text) console.log(`  ${text}`);
          }
        }
        if (first && !o.json) {
          const clean = events.filter((e) => e.kind === "baseline" && e.state !== "delegated").length;
          console.log(
            `  ${clock(new Date().toISOString())}  ${style.dim(`baseline: ${clean} of ${res.rows.length} chain-address pairs with no delegation`)}`,
          );
        }
        if (hook)
          for (const e of events.filter(isNotifiable)) {
            const sent = await postWebhook(hook, e);
            if (!sent.ok && !o.json)
              console.log(
                `  ${clock(new Date().toISOString())}  ${style.yellow("webhook not delivered")}  ${style.dim(`${redactRpc(hook)} ${sent.status ?? sent.error ?? ""}`)}`,
              );
          }
        const alarms = events.filter(isAlarm);
        if (o["exit-on-change"] && alarms.length) return alarms.some((e) => e.bad) ? EXIT.knownBad : EXIT.finding;
        await new Promise((r) => setTimeout(r, every * 1000));
      }
    }

    case "decode": {
      const input = rest[0] ?? usage("decode needs a transaction hash or raw transaction hex");
      const res = await inspectTransaction(input, { chain: chain(), chains, chainLocked: !!o.chain, watch: o.watch });
      const exit = res.findings.some((f) => f.code === "KNOWN_MALICIOUS_DELEGATE")
        ? EXIT.knownBad
        : res.findings.some((f) => f.severity === "critical")
          ? EXIT.finding
          : EXIT.ok;
      if (o.json) {
        const { key, id, name } = res.chain;
        return (console.log(json({ ...res, chain: { key, id, name } })), exit);
      }
      const t = res.tx;
      console.log(
        `\n  ${style.bold(`type ${t.type}`)} ${t.hash}  ${style.dim(`${res.chain.name}${t.chainId != null ? `, chain id ${t.chainId}` : ""}`)}`,
      );
      console.log(`  from ${t.from ?? "?"} ${style.dim(`(nonce ${t.nonce})`)} → ${t.to ?? "create"}`);
      if (res.mined) console.log(style.dim(`  block ${int(res.mined.block)}, index ${res.mined.index}`));
      if (t.type !== 4)
        return (console.log(style.dim("\n  not a set-code transaction: no authorization list\n")), EXIT.ok);
      for (const [a, s] of res.state) console.log(style.dim(`  ${short(a)} nonce ${int(s.nonce)} (${s.source})`));
      console.log("");
      if (res.result) console.log(renderOutcomes(res.result.outcomes, (a) => short(a ?? "?")).join("\n"));
      if (res.findings.length) console.log(`\n${style.bold("  findings")}\n${renderFindings(res.findings).join("\n")}`);
      for (const n of res.notes) console.log(style.dim(`  note: ${n}`));
      console.log("");
      return exit;
    }

    case "classify": {
      const input = rest[0] ?? usage("classify needs the hex bytes a key would sign");
      const base: GuardPolicy = o.profile === "user" ? profiles.user : profiles.hotWallet;
      const extra = (o["allow-delegate"] ?? []).map((address) => ({ address }));
      const policy: GuardPolicy = {
        ...base,
        authorizations: {
          ...base.authorizations,
          allowDelegates: [...(base.authorizations?.allowDelegates ?? []), ...extra],
        },
      };
      const ownCode = o["own-code"] ?? "0x";
      if (!/^0x([0-9a-fA-F]{2})*$/.test(ownCode)) usage("--own-code is the hex of eth_getCode on the key's address");
      const d = new Guard(policy).check(
        input,
        { as: o.digest ? "digest" : "preimage" },
        {
          signer: o.signer,
          nonce: o.nonce ? BigInt(o.nonce) : undefined,
          selfSponsored: o.self,
          ownCode: ownCode as `0x${string}`,
        },
      );
      if (o.json) return (console.log(json(d)), d.allow ? EXIT.ok : EXIT.refused);
      const c = d.classified;
      console.log("");
      console.log(`  ${style.dim(pad("kind", 10))}${c.kind}`);
      if (c.kind === "eip7702-authorization") {
        const a = c.authorization;
        console.log(
          `  ${style.dim(pad("fields", 10))}chain_id ${a.chainId} · delegate ${a.address} · nonce ${int(a.nonce)}`,
        );
        const e = lookupDelegate(a.address);
        if (e) console.log(`  ${style.dim(pad("registry", 10))}${e.verdict} · ${e.label}`);
      }
      if (c.kind === "set-code-tx")
        console.log(
          `  ${style.dim(pad("fields", 10))}chain_id ${c.chainId} · nonce ${c.nonce} · to ${c.to} · ${c.authorizationList.length} tuple(s)`,
        );
      if (c.kind === "raw-digest") {
        const inc = loadIncident();
        const i = inc.delegation.tx.authorizationList.findIndex((a) => bytesToHex(authorizationDigest(a)) === c.digest);
        if (i >= 0) console.log(`  ${style.dim(pad("note", 10))}this is the digest of 2026-10-29 tuple #${i}`);
      }
      console.log(
        `  ${style.dim(pad("verdict", 10))}${d.allow ? style.green("SIGN") : style.red(style.bold("REFUSE"))}  ${style.dim(`profile ${o.profile ?? "hot-wallet"}`)}`,
      );
      if (o["own-code"] === undefined)
        console.log(
          `  ${pad("", 10)}${style.dim("own code assumed empty; pass --own-code <eth_getCode of the signer> to check that too")}`,
        );
      for (const r of d.reasons)
        console.log(
          `  ${pad("", 10)}${pad(r.code, 26)} ${style.dim(r.message)}${r.tuple !== undefined ? style.dim(` (tuple ${r.tuple})`) : ""}`,
        );
      console.log("");
      return d.allow ? EXIT.ok : EXIT.refused;
    }

    case "guard": {
      if (rest[0] === "serve") {
        if (o.profile && o.profile !== "user" && o.profile !== "hot-wallet") usage("--profile is hot-wallet or user");
        const port = o.port == null ? 8787 : Number(o.port);
        if (!Number.isInteger(port) || port < 1 || port > 65535) usage("--port is 1 to 65535");
        const server = createGuardServer(new Guard(o.profile === "user" ? profiles.user : profiles.hotWallet), {
          version: pkg.version,
        });
        await new Promise<void>((resolve, reject) => {
          server.once("error", reject);
          server.listen(port, "127.0.0.1", () => resolve());
        });
        console.log(
          `\n  ${style.bold("guard serve")}  http://127.0.0.1:${port}/check  ${style.dim(`profile ${o.profile ?? "hot-wallet"} · 127.0.0.1 only · no keys`)}\n`,
        );
        return new Promise<number>(() => {});
      }
      if (rest[0] !== "test") usage("try: ef0100 guard test, ef0100 guard serve, or ef0100 classify <hex>");
      const sums = verifyFixtures();
      const inc = loadIncident();
      const g = guardSummary(inc);
      if (!sums.ok) {
        console.error(style.red(`  bundled data does not match SHA256SUMS: ${sums.mismatched.join(", ")}`));
        return EXIT.fixtureMismatch;
      }
      const pass =
        g.preimagesRefused === g.total &&
        g.digestsRefused === g.total &&
        g.rehearsalRefused === g.rehearsalTuples &&
        g.clearAllowed;
      if (o.json) return (console.log(json(g)), pass ? EXIT.ok : EXIT.finding);
      console.log(`
  ${style.bold("guard test")}  ${style.dim("profile hot-wallet")}
${g.rows
  .map((r) => {
    const verdict = r.refused ? style.red(pad(`REFUSE ${r.refused}`, 10)) : style.green(pad(`ALLOW ${r.requests}`, 10));
    return `  ${pad(r.name, 28)} ${pad(String(r.requests), 4, "right")}  ${verdict} ${style.dim(r.why)}`;
  })
  .join("\n")}
  ${pass ? style.green("4/4 expectations pass") : style.red("an expectation failed")}

  ${style.dim("What the guard decides when it sits in the signing path. How the real signatures were produced is not public.")}
`);
      return pass ? EXIT.ok : EXIT.finding;
    }

    case "oracle":
      return oracle(!!o.json);

    case "recipient": {
      const address = rest[0] ?? usage("recipient needs an address");
      if (!isAddress(address)) usage(`not an address: ${address}`);
      const r = await checkRecipient(address, { chain: chain(), allowDelegates: o.allow });
      if (o.json) return (console.log(json(r)), r.allow ? EXIT.ok : EXIT.refused);
      console.log(
        `\n  ${r.allow ? style.green("SEND") : style.red(style.bold("HOLD"))}  ${address}  ${style.dim(r.chain)}`,
      );
      for (const x of r.reasons) console.log(`  ${pad(x.code, 24)} ${style.dim(x.message)}`);
      const unread = (["usdt", "usdc"] as const).filter((k) => r.blacklists[k] === null).map((k) => k.toUpperCase());
      const read = (["usdt", "usdc"] as const).filter((k) => r.blacklists[k] === false).map((k) => k.toUpperCase());
      if (r.allow)
        console.log(
          style.dim(
            `  no delegation, no contract code${read.length ? `, not on the ${read.join(" or ")} blacklist` : ""}`,
          ),
        );
      if (unread.length) console.log(style.dim(`  ${unread.join(" and ")} blacklist not checked on ${r.chain}`));
      console.log("");
      return r.allow ? EXIT.ok : EXIT.refused;
    }

    case "clear": {
      const authority = rest[0] ?? usage("clear needs the delegated address");
      if (!isAddress(authority)) usage(`not an address: ${authority}`);
      const c = chain();
      let nonce = o.nonce ? BigInt(o.nonce) : undefined;
      let maxFee = o["max-fee"] ? BigInt(o["max-fee"]) : undefined;
      let tip = o["priority-fee"] ? BigInt(o["priority-fee"]) : undefined;
      if (nonce === undefined || maxFee === undefined || tip === undefined) {
        const [n, gp, pf] = (await rpcBatchAny(c.rpc, [
          { method: "eth_getTransactionCount", params: [authority, "pending"] },
          { method: "eth_gasPrice", params: [] },
          { method: "eth_maxPriorityFeePerGas", params: [] },
        ])) as string[];
        nonce ??= BigInt(n!);
        tip ??= BigInt(pf!);
        maxFee ??= BigInt(gp!) * 2n + tip;
      }
      const plan = planClearDelegation({
        chainId: BigInt(c.id),
        authority,
        nonce,
        maxFeePerGas: maxFee,
        maxPriorityFeePerGas: tip,
      });
      if (o.json) return (console.log(json(plan)), EXIT.ok);
      console.log(`
  ${style.bold("clear the delegation of")} ${authority} ${style.dim(`on ${c.name}`)}
  ${style.dim("one self-sponsored type-4 transaction: the account sends it to itself and authorizes 0x0")}

  1. the account's key signs this authorization
     chain_id ${plan.authorization.chainId} · address 0x0 · nonce ${plan.authorization.nonce} ${style.dim("(tx nonce + 1)")}
     preimage ${plan.authorizationPreimage}
     digest   ${plan.authorizationDigest}
  2. then a type-4 transaction from ${short(authority)} to itself
     nonce ${plan.input.nonce} · gas ${int(plan.input.gasLimit)} · max fee ${int(plan.input.maxFeePerGas)} wei · tip ${int(plan.input.maxPriorityFeePerGas)} wei

  ${style.dim("Unsigned data only. In code: planClearDelegation() → clearDelegationTx() → serialize().")}
  ${style.dim("If others hold authorizations signed for future nonces, they stay valid until the nonce passes them.")}
  ${style.dim("While the account is delegated, geth keeps one of its transactions in flight: send the clear when nothing")}
  ${style.dim("else from it is pending, or submit it privately.")}
`);
      return EXIT.ok;
    }

    case "sol": {
      const urls = solanaEndpoints(process.env, o.chain === "solana" ? o.rpc : undefined);
      if (rest[0] === "nonces") {
        const who = rest[1] ?? usage("sol nonces needs a public key");
        let list;
        try {
          list = await listNonceAccounts(who, urls);
        } catch (e) {
          throw new RpcError(
            `${(e as Error).message}. Public Solana endpoints may refuse getProgramAccounts on the System program; set EF0100_RPC_SOLANA to your own endpoint`,
            urls[0]!,
          );
        }
        if (o.json) return (console.log(json(list)), list.length ? EXIT.finding : EXIT.ok);
        console.log(`\n  ${style.bold(`${list.length} nonce account(s)`)} with authority ${who}`);
        for (const a of list) console.log(`  ${a.address}  ${style.dim(`nonce ${a.nonce}`)}`);
        console.log(
          style.dim(
            `\n  A transaction signed against any of these stays valid until that nonce advances. Advance or close the ones\n  you no longer use; each AdvanceNonceAccount voids every transaction signed against the old value.\n`,
          ),
        );
        return list.length ? EXIT.finding : EXIT.ok;
      }
      const input = rest[0] ?? usage("sol needs a transaction signature or base64 bytes");
      let raw: Uint8Array;
      let balance = o.balance ? BigInt(o.balance) : undefined;
      if (/^[1-9A-HJ-NP-Za-km-z]{80,90}$/.test(input)) {
        const t = await getSolanaTransaction(input, urls);
        raw = t.raw;
        balance ??= t.feePayerPreBalance ?? undefined;
      } else raw = Uint8Array.from(Buffer.from(input, "base64"));
      const r = checkSolanaTransaction(raw, {
        template: o.template ? { nonceAuthority: o.template } : undefined,
        routineTransfers: o.routine,
        balance: balance !== undefined ? { lamports: balance } : undefined,
      });
      if (o.json)
        return (
          console.log(json(r)),
          r.verdict === "BLOCK" ? EXIT.refused : r.verdict === "REVIEW" ? EXIT.finding : EXIT.ok
        );
      const tag =
        r.verdict === "BLOCK"
          ? style.red(style.bold("BLOCK"))
          : r.verdict === "REVIEW"
            ? style.yellow("REVIEW")
            : style.green("OK");
      console.log(
        `\n  ${tag}  ${style.dim(`${r.message.version === 0 ? "v0" : "legacy"} message · fee payer ${short(r.feePayer)} · ${r.message.instructions.length} instruction(s)`)}`,
      );
      console.log(style.dim(`  message hash ${r.messageHash} (compare with a Ledger's blind-signing screen)`));
      for (const x of r.findings) {
        const sev =
          x.severity === "critical"
            ? style.red(pad("critical", 8))
            : x.severity === "high"
              ? style.yellow(pad("high", 8))
              : style.dim(pad(x.severity, 8));
        console.log(`  ${sev} ${pad(x.code, 34)} ${x.instruction ? style.dim(x.instruction + " ") : ""}${x.message}`);
      }
      console.log("");
      return r.verdict === "BLOCK" ? EXIT.refused : r.verdict === "REVIEW" ? EXIT.finding : EXIT.ok;
    }

    case "code": {
      const target = rest[0] ?? usage("code needs an address or bytecode hex");
      let code: Hex = target as Hex;
      if (isAddress(target)) {
        const [c] = (await rpcBatchAny(chain().rpc, [{ method: "eth_getCode", params: [target, "latest"] }])) as Hex[];
        code = c!;
      }
      const f = fingerprintCode(code);
      if (o.json) return (console.log(json(f)), f.sweeperLike ? EXIT.knownBad : EXIT.ok);
      console.log(
        `\n  ${style.bold(`${int(f.size)} bytes`)}  codehash ${f.codehash}  ${f.sweeperLike ? style.red(style.bold("sweeper-like")) : ""}`,
      );
      for (const s of f.selectors) console.log(`  ${s.selector}  ${s.name}`);
      if (f.hardcodedAddresses.length) console.log(style.dim(`  hardcoded: ${f.hardcodedAddresses.join(", ")}`));
      console.log(style.dim(`  traits: ${f.traits.join(", ") || "none"}\n`));
      return f.sweeperLike ? EXIT.knownBad : EXIT.ok;
    }

    default:
      return usage(`unknown command ${cmd}`);
  }
}

main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (e) => {
    if (e instanceof UsageError || String((e as { code?: string }).code ?? "").startsWith("ERR_PARSE_ARGS")) {
      process.stderr.write(`ef0100: ${e.message}\n\n${HELP}`);
      process.exit(EXIT.usage);
    }
    process.stderr.write(`ef0100: ${cleanText((e as Error).message)}\n`);
    process.exit(e instanceof RpcError ? EXIT.unavailable : EXIT.software);
  },
);
