import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  analyzeAuthorizationList,
  processAuthorizationList,
  type Finding,
  type ProcessResult,
} from "./evm/authlist.js";
import { delegationCode } from "./evm/eip7702.js";
import { fingerprintCode, type CodeFingerprint } from "./evm/fingerprint.js";
import { decodeTransaction, type DecodedTx } from "./evm/tx.js";

const root = new URL("../fixtures/2026-10-29/", import.meta.url);
const read = (p: string) => readFileSync(new URL(p, root), "utf8");
const rawTx = (hash: string) => read(`raw/${hash}.rlp.hex`).trim();

export interface Movement {
  symbol: string;
  amount: string;
}

export interface IncidentCall {
  tx: string;
  block: number;
  utc: string;
  kind: "sweep" | "callExecute" | "poll";
  label: string;
  to: string;
  eth: string;
  usdt: string;
  usdc: string;
  tokens: number;
}

export interface IncidentRefill {
  tx: string;
  block: number;
  utc: string;
  symbol: string;
  amount: string;
  sweptBy: string;
  sweptAfterSeconds: number;
}

/** Value that reached a collector, grouped by where it came from and how. */
export interface CollectorInflow {
  collector: string;
  address: string;
  from: string;
  via: "delegation" | "signed transfers";
  eth: string;
  usdt: string;
  usdc: string;
  /** Other token contracts in the same transfers. */
  otherTokens: number;
}

/** An ETH transfer out of a collector, decoded from its bundled raw bytes. */
export interface OnwardTransfer {
  tx: string;
  block: number;
  utc: string;
  collector: string;
  from: string;
  to: string;
  eth: string;
  bytes: number;
}

/** A collector's outgoing transactions at the snapshot, with the routers it used most. */
export interface CollectorActivity {
  collector: string;
  address: string;
  txs: number;
  failed: number;
  firstUtc: string;
  lastUtc: string;
  routers: { name: string; address: string; txs: number }[];
}

/** A run of blocks and the wallet's own transactions in it. */
export interface OwnTxSpan {
  from: number;
  to: number;
  blocks: number;
  txs: number;
  maxPerBlock: number;
}

export interface Incident {
  id: "2026-10-29";
  chainId: bigint;
  authority: string;
  authorityLabel: string;
  operator: string;
  delegate: string;
  smartAccount: string;
  delegation: {
    tx: DecodedTx;
    /** The hash the bundled records name; keccak256 of the raw bytes must equal it. */
    recordedHash: string;
    block: number;
    index: number;
    utc: string;
    authorityNonceAtTx: bigint;
    ownTxSameBlock: { tx: string; index: number; nonce: bigint };
    window: { openedUtc: string; openedBlock: number; closedUtc: string; closedBlock: number };
    result: ProcessResult;
    findings: Finding[];
  };
  clear: { tx: DecodedTx; block: number; utc: string; gasUsed: number; result: ProcessResult };
  /** The attacker's own test wallets, delegated and swept hours before. */
  rehearsals: DecodedTx[];
  /** A log emitted by the EOA's address: only possible while it runs a delegate's code. */
  eoaLog: { tx: string; address: string; topics: string[]; data: string; event: string; note: string };
  /** The wallet's own transactions per block before, during and after the delegation, summed from `wallet_blocks.json`. */
  throughput: {
    before: OwnTxSpan;
    during: OwnTxSpan;
    after: OwnTxSpan;
  };
  sweeper: { v2: CodeFingerprint; v1: CodeFingerprint };
  calls: IncidentCall[];
  refills: IncidentRefill[];
  freezes: { utc: string; issuer: string; what: string }[];
  /**
   * The first hop: what reached the two collectors, the large ETH transfers out of them (each decoded from bundled
   * raw bytes) and a dated snapshot of their other outgoing transactions.
   */
  onward: {
    snapshotUtc: string;
    labels: Record<string, string>;
    inflows: CollectorInflow[];
    transfers: OnwardTransfer[];
    activity: CollectorActivity[];
  };
  /** Everything that left through the delegation: sweeps from the wallet, plus USDC pulled out of its smart account. */
  totals: { eth: string; usdt: string; usdc: string; tokenContracts: number; sweptTokenContracts: number };
  timing: {
    secondsToFirstSweep: number;
    blocksToFirstSweep: number;
    delegatedSeconds: number;
  };
}

interface EventsFile {
  chainId: number;
  authority: string;
  authorityLabel: string;
  operator: string;
  delegate: string;
  smartAccount: string;
  collectors: Record<string, string>;
  delegation: {
    tx: string;
    block: number;
    index: number;
    utc: string;
    authorityNonceAtTx: number;
    ownTxSameBlock: { tx: string; index: number; nonce: number };
    windowOpenedUtc: string;
    windowOpenedBlock: number;
    windowClosedUtc: string;
    windowClosedBlock: number;
  };
  clear: { tx: string; block: number; utc: string; senderNonce: number; gasUsed: number };
  eoaLog: Incident["eoaLog"];
  calls: { tx: string; block: number; utc: string; kind: IncidentCall["kind"]; to: string; label: string }[];
  refills: { tx: string; block: number; utc: string; symbol: string; amount: string; sweptBy: string }[];
  freezes: { utc: string; issuer: string; what: string }[];
}

/** Decimal string sums without floating point. */
function addDecimal(a: string, b: string): string {
  const [ai = "0", af = ""] = a.split(".");
  const [bi = "0", bf = ""] = b.split(".");
  const scale = Math.max(af.length, bf.length);
  const n = BigInt(ai + af.padEnd(scale, "0")) + BigInt(bi + bf.padEnd(scale, "0"));
  const s = n.toString().padStart(scale + 1, "0");
  const int = s.slice(0, s.length - scale);
  const frac = s.slice(s.length - scale).replace(/0+$/, "");
  return frac ? `${int}.${frac}` : int;
}

interface LedgerRow {
  tx: string;
  mechanism: string;
  source: string;
  receiver_label: string;
  symbol: string;
  asset: string;
  amount: string;
}

function ledger(): LedgerRow[] {
  const [header, ...lines] = read("evm/drain_ledger.csv").trim().split(/\r?\n/);
  const cols = header!.split(",");
  return lines.map((l) => {
    const v = l.split(",");
    const o: Record<string, string> = {};
    cols.forEach((c, i) => (o[c] = v[i] ?? ""));
    return o as unknown as LedgerRow;
  });
}

const seconds = (a: string, b: string) => (Date.parse(b) - Date.parse(a)) / 1000;

function weiOf(eth: string): bigint {
  const [i = "0", f = ""] = eth.split(".");
  return BigInt(i) * 10n ** 18n + BigInt(f.padEnd(18, "0").slice(0, 18) || "0");
}

interface OnwardFile {
  snapshotUtc: string;
  labels: Record<string, string>;
  transfers: { tx: string; block: number; utc: string; from: string; to: string; eth: string }[];
  activity: CollectorActivity[];
}

const REHEARSALS = [
  "0x16b5acc35a82d194aadb21a4a56d666310fe83982c387c974f4796275f499dca",
  "0xec5af21dc34fc8a3ac131f694aa0df5b27c0525ea3a71d97daa7e597abcb21d9",
  "0xb2148eb825cac75efe0ae7fb5c319e6b66df62631738ba252185960e50dc5782",
  "0x7c5206cb7aa77ce5b54f030e94ad127af0184e856689526602ffcd21a238e95d",
];

/** Checks every bundled fixture (the incident, the registry bytecode and the Solana cases) against its SHA256SUMS. */
export function verifyFixtures(): { ok: boolean; checked: number; mismatched: string[] } {
  const mismatched: string[] = [];
  let checked = 0;
  for (const dir of [root, new URL("../registry/", root), new URL("../solana/", root)]) {
    const lines = readFileSync(new URL("SHA256SUMS", dir), "utf8").trim().split(/\r?\n/);
    for (const line of lines) {
      const [sum, file] = line.split(/\s+/);
      const actual = createHash("sha256")
        .update(readFileSync(new URL(file!, dir)))
        .digest("hex");
      checked++;
      if (actual !== sum) mismatched.push(new URL(file!, dir).pathname.split("/fixtures/")[1]!);
    }
  }
  return { ok: mismatched.length === 0, checked, mismatched };
}

let cached: Incident | undefined;

/** The 2026-10-29 drain, rebuilt from the bundled raw transactions and chain records. Nothing is fetched. */
export function loadIncident(): Incident {
  if (cached) return cached;
  const ev = JSON.parse(read("evm/events.json")) as EventsFile;
  const chainId = BigInt(ev.chainId);
  const tx = decodeTransaction(rawTx(ev.delegation.tx));
  const at = BigInt(ev.delegation.authorityNonceAtTx);
  const result = processAuthorizationList(tx, {
    chainId,
    state: (a) => (a.toLowerCase() === ev.authority.toLowerCase() ? { nonce: at, code: "0x" } : undefined),
  });
  const clearTx = decodeTransaction(rawTx(ev.clear.tx));
  const clearResult = processAuthorizationList(clearTx, {
    chainId,
    state: () => ({ nonce: BigInt(ev.clear.senderNonce), code: delegationCode(ev.delegate) }),
  });

  const rows = ledger();
  const callRows = (h: string) => rows.filter((r) => r.tx === h);
  const sum = (h: string, sym: string) =>
    callRows(h)
      .filter((r) => r.symbol === sym)
      .reduce((s, r) => addDecimal(s, r.amount), "0");
  const calls: IncidentCall[] = ev.calls.map((c) => ({
    ...c,
    to: ev.collectors[c.to] ?? c.to,
    eth: sum(c.tx, "ETH"),
    usdt: sum(c.tx, "USDT"),
    usdc: sum(c.tx, "USDC"),
    tokens: new Set(
      callRows(c.tx)
        .filter((r) => r.symbol !== "ETH")
        .map((r) => r.asset),
    ).size,
  }));
  const viaDelegation = rows.filter((r) => r.mechanism.startsWith("eip7702"));
  const totals = {
    eth: viaDelegation.filter((r) => r.symbol === "ETH").reduce((s, r) => addDecimal(s, r.amount), "0"),
    usdt: viaDelegation.filter((r) => r.symbol === "USDT").reduce((s, r) => addDecimal(s, r.amount), "0"),
    usdc: viaDelegation.filter((r) => r.symbol === "USDC").reduce((s, r) => addDecimal(s, r.amount), "0"),
    tokenContracts: new Set(viaDelegation.filter((r) => r.symbol !== "ETH").map((r) => r.asset)).size,
    sweptTokenContracts: new Set(
      viaDelegation.filter((r) => r.mechanism === "eip7702_sweep" && r.symbol !== "ETH").map((r) => r.asset),
    ).size,
  };
  const firstSweep = calls.find((c) => c.kind === "sweep")!;
  const onwardFile = JSON.parse(read("evm/onward.json")) as OnwardFile;
  const sources = new Map<string, string>();
  for (const a of [ev.authority, ev.smartAccount, ...Object.keys(onwardFile.labels)]) sources.set(a.toLowerCase(), a);
  const inflowKey = (r: LedgerRow) =>
    `${r.receiver_label}|${r.source}|${r.mechanism.startsWith("eip7702") ? "d" : "s"}`;
  const groups = new Map<string, LedgerRow[]>();
  for (const r of rows) groups.set(inflowKey(r), [...(groups.get(inflowKey(r)) ?? []), r]);
  const inflows: CollectorInflow[] = [...groups.values()].map((g) => {
    const r0 = g[0]!;
    const total = (sym: string) => g.filter((r) => r.symbol === sym).reduce((s, r) => addDecimal(s, r.amount), "0");
    return {
      collector: r0.receiver_label,
      address: ev.collectors[r0.receiver_label] ?? r0.receiver_label,
      from: sources.get(r0.source.toLowerCase()) ?? r0.source,
      via: r0.mechanism.startsWith("eip7702") ? "delegation" : "signed transfers",
      eth: total("ETH"),
      usdt: total("USDT"),
      usdc: total("USDC"),
      otherTokens: new Set(g.filter((r) => !["ETH", "USDT", "USDC"].includes(r.symbol)).map((r) => r.asset)).size,
    };
  });
  const transfers: OnwardTransfer[] = onwardFile.transfers.map((t) => {
    const raw = rawTx(t.tx);
    const d = decodeTransaction(raw);
    const from = ev.collectors[t.from] ?? t.from;
    const ok =
      d.hash === t.tx &&
      d.from?.toLowerCase() === from.toLowerCase() &&
      d.to?.toLowerCase() === t.to.toLowerCase() &&
      d.value === weiOf(t.eth);
    if (!ok) throw new Error(`onward.json: ${t.tx} does not match its bundled raw bytes`);
    return {
      tx: t.tx,
      block: t.block,
      utc: t.utc,
      collector: t.from,
      from,
      to: t.to,
      eth: t.eth,
      bytes: raw.length / 2 - 1,
    };
  });
  cached = {
    id: "2026-10-29",
    chainId,
    authority: ev.authority,
    authorityLabel: ev.authorityLabel,
    operator: ev.operator,
    delegate: ev.delegate,
    smartAccount: ev.smartAccount,
    delegation: {
      tx,
      recordedHash: ev.delegation.tx,
      block: ev.delegation.block,
      index: ev.delegation.index,
      utc: ev.delegation.utc,
      authorityNonceAtTx: at,
      ownTxSameBlock: { ...ev.delegation.ownTxSameBlock, nonce: BigInt(ev.delegation.ownTxSameBlock.nonce) },
      window: {
        openedUtc: ev.delegation.windowOpenedUtc,
        openedBlock: ev.delegation.windowOpenedBlock,
        closedUtc: ev.delegation.windowClosedUtc,
        closedBlock: ev.delegation.windowClosedBlock,
      },
      result,
      findings: analyzeAuthorizationList(tx, { watch: [ev.authority] }),
    },
    clear: { tx: clearTx, block: ev.clear.block, utc: ev.clear.utc, gasUsed: ev.clear.gasUsed, result: clearResult },
    rehearsals: REHEARSALS.map((h) => decodeTransaction(rawTx(h))),
    eoaLog: ev.eoaLog,
    throughput: (() => {
      const w = JSON.parse(read("evm/wallet_blocks.json")) as {
        delegated: [number, number];
        rows: [number, number, number][];
      };
      const [delegatedFrom, delegatedTo] = w.delegated;
      const span = (from: number, to: number): OwnTxSpan => {
        const rows = w.rows.filter(([b]) => b >= from && b <= to);
        return {
          from,
          to,
          blocks: to - from + 1,
          txs: rows.reduce((n, r) => n + r[1], 0),
          maxPerBlock: Math.max(...rows.map((r) => r[1])),
        };
      };
      return {
        before: span(w.rows[0]![0], delegatedFrom - 1),
        during: span(delegatedFrom + 1, delegatedTo),
        after: span(ev.clear.block + 1, w.rows.at(-1)![0]),
      };
    })(),
    sweeper: {
      v2: fingerprintCode(read("evm/sweeper_v2_runtime.hex").trim()),
      v1: fingerprintCode(read("evm/sweeper_v1_runtime.hex").trim()),
    },
    calls,
    refills: ev.refills.map((r) => ({
      ...r,
      sweptAfterSeconds: seconds(r.utc, calls.find((c) => c.tx === r.sweptBy)!.utc),
    })),
    freezes: ev.freezes,
    totals,
    onward: {
      snapshotUtc: onwardFile.snapshotUtc,
      labels: onwardFile.labels,
      inflows,
      transfers,
      activity: onwardFile.activity,
    },
    timing: {
      secondsToFirstSweep: seconds(ev.delegation.utc, firstSweep.utc),
      blocksToFirstSweep: firstSweep.block - ev.delegation.block,
      delegatedSeconds: seconds(ev.delegation.utc, ev.clear.utc),
    },
  };
  return cached;
}
