import type { AuthOutcome, Finding } from "../evm/authlist.js";
import { delegationCode, isClearing, recoverAuthority } from "../evm/eip7702.js";
import { sameAddress } from "../evm/bytes.js";
import type { Incident } from "../incident.js";
import { amount, duration, hhmmss, int, pad, short, style } from "./style.js";

const sevTag = (s: Finding["severity"]) =>
  s === "critical"
    ? style.red(style.bold("critical"))
    : s === "warn"
      ? style.yellow("warn    ")
      : style.dim("info    ");

export function renderFindings(findings: Finding[]): string[] {
  return findings.map((f) => `  ${sevTag(f.severity)}  ${pad(f.code, 25)} ${f.message}`);
}

const verdict = (o: AuthOutcome) => {
  switch (o.status) {
    case "applied":
      return o.effect === "clear" ? style.green("APPLIED  clears the delegation") : style.red(style.bold("APPLIED"));
    case "nonce-ahead":
      return style.dim(`skip     nonce ahead (+${int(o.nonce - o.authorityNonce!)})`);
    case "nonce-used":
      return style.dim(`skip     nonce used (−${int(o.authorityNonce! - o.nonce)})`);
    default:
      return style.dim(`skip     ${o.status}`);
  }
};

export function renderOutcomes(outcomes: AuthOutcome[], label: (a: string | null) => string): string[] {
  const lines = [
    style.dim(`  ${pad("#", 4, "right")}  ${pad("nonce", 12)} ${pad("signed by", 14)} ${pad("delegate", 14)} verdict`),
  ];
  for (const o of outcomes) {
    const row = `  ${pad(String(o.index), 4, "right")}  ${pad(int(o.nonce), 12)} ${pad(label(o.authority), 14)} ${pad(short(o.delegate), 14)} ${verdict(o)}`;
    lines.push(o.status === "applied" && o.effect !== "clear" ? style.inverse(row) : row);
  }
  return lines;
}

export interface GuardSummary {
  preimagesRefused: number;
  digestsRefused: number;
  total: number;
  clearAllowed: boolean;
}

export interface FrameState {
  /** Tuples already compared (0..50). The default, 50, is the final frame. */
  cursor: number;
  /** Blocks elapsed after inclusion, up to the first sweep. */
  blocks: number;
}

/**
 * The verdict frame: everything the replay proves, in 80 columns. The animation redraws it with a cursor walking the
 * tuples, the wallet's nonce ticking once, and the blocks running to the sweep; the last frame is the same text.
 */
export function renderFrame(
  inc: Incident,
  meta: { version: string; fixturesOk: boolean; guard: GuardSummary },
  state: FrameState = { cursor: 50, blocks: Infinity },
): string {
  const d = inc.delegation;
  const tx = d.tx;
  const n = tx.authorizationList.length;
  const hit = d.result.applied[0]!;
  const done = state.cursor >= n;
  const ahead = d.result.outcomes.filter((o) => o.status === "nonce-ahead").length;
  const used = d.result.outcomes.filter((o) => o.status === "nonce-used").length;
  const passedHit = state.cursor > hit.index;
  const applied = d.result.applied.length;
  const recovered = tx.authorizationList.filter((a) => {
    const r = recoverAuthority(a);
    return r.ok && sameAddress(r.authority, inc.authority);
  }).length;
  const clearTuple = inc.clear.tx.authorizationList[0]!;
  const selfSponsored = sameAddress(inc.clear.tx.from, inc.authority);
  const liveNonce = passedHit ? d.authorityNonceAtTx + 1n : d.authorityNonceAtTx;

  let strip = "";
  for (let i = 0; i < n; i++) {
    if (i >= state.cursor) strip += style.dim(i === state.cursor ? "▸" : " ");
    else if (i === hit.index) strip += style.red("█");
    else strip += style.dim("·");
  }
  const marks = pad("#0", hit.index) + pad(`#${hit.index}`, n - 3 - hit.index) + `#${n - 1}`;
  const tally = done
    ? pad(`${ahead} ahead`, hit.index) + pad(`${applied} applied`, n - hit.index - 15) + `${used} already used`
    : style.dim(`comparing tuple #${state.cursor} with the wallet's nonce ${int(liveNonce)}`);

  const sweep = inc.calls[0]!;
  const blocks = Math.min(state.blocks, inc.timing.blocksToFirstSweep);
  const swept = done && blocks >= inc.timing.blocksToFirstSweep;
  const t = inc.throughput;
  const label = (k: string) => style.dim(pad(k, 9));
  const out = [
    "",
    `${style.bold("ef0100")} ${meta.version} · replay 2026-10-29 · offline · fixtures sha256 ${meta.fixturesOk ? "ok" : style.red("MISMATCH")}`,
    "",
    `  ${label("tx")}${short(tx.hash, 10, 10)} · type 4 · block ${int(d.block)} · ${hhmmss(d.utc)} UTC`,
    `  ${label("bytes")}${int(tx.raw.length / 2 - 1)} · keccak(raw) ${tx.hash === d.recordedHash ? "= tx hash" : style.red("≠ the recorded tx hash")}`,
    `  ${label("signers")}${recovered}/${n} tuples recover to ${short(inc.authority)} ${style.dim(`(explorer label: ${inc.authorityLabel})`)}`,
    `  ${label("nonce")}${short(inc.authority)} at tx index ${d.index}: ${
      done
        ? `${style.bold(int(d.authorityNonceAtTx))} ${style.dim(`→ ${int(d.authorityNonceAtTx + 1n)} at #${hit.index}`)}`
        : `${style.bold(int(liveNonce))}${passedHit ? style.red("  +1") : ""}`
    }`,
    "",
    `  ${strip}`,
    style.dim(`  ${marks}`),
    `  ${tally}`,
    "",
    `  ${label("code")}${done ? `0x → ${style.red(delegationCode(hit.delegate).replace("0xef0100", "0xef0100 ").toLowerCase())}` : passedHit ? style.red("delegated") : "0x"}`,
    `  ${label("sweep")}${
      done
        ? swept
          ? `+${inc.timing.blocksToFirstSweep} blocks · +${inc.timing.secondsToFirstSweep} s · ${amount(sweep.eth, 4)} ETH · ${sweep.tokens} token transfers`
          : style.dim(`+${blocks} blocks…`)
        : ""
    }`,
    `  ${label("logs")}${swept ? `the EOA emitted ${inc.eoaLog.event.split("(")[0]}(2); EOAs don't emit logs` : ""}`,
    `  ${label("own txs")}${swept ? `≤${t.before.maxPerBlock} per block before · ≤${t.during.maxPerBlock} per block for the ${int(t.during.blocks)} delegated` : ""}`,
    `  ${label("top-ups")}${swept ? inc.refills.map((r) => `${amount(r.amount)} ${r.symbol} swept in ${r.sweptAfterSeconds} s`).join(" · ") : ""}`,
    `  ${label("clear")}${swept ? `+${duration(inc.timing.delegatedSeconds)} · ${selfSponsored ? "self-sponsored" : "sponsored"} · auth → ${isClearing(clearTuple) ? "0x0" : short(clearTuple.address)} · ${int(inc.clear.gasUsed)} gas` : ""}`,
    "",
    `  ${label("guard")}${swept ? `${style.bold(`REFUSE ${meta.guard.preimagesRefused}/${meta.guard.total}`)} authorizations · ${style.bold(`REFUSE ${meta.guard.digestsRefused}/${meta.guard.total}`)} bare digests` : ""}`,
    `  ${pad("", 9)}${swept ? `${meta.guard.clearAllowed ? style.green("ALLOW 1/1") : style.red("REFUSE 1/1")} the clear` : ""}`,
    "",
    swept ? `  ${style.bold(`${n} signed. ${applied} applied.`)}` : "",
  ];
  return out.join("\n");
}

/** `--table`: all 50 tuples with their verdicts, the findings and the state change. */
export function renderTable(inc: Incident): string {
  const d = inc.delegation;
  const who = (a: string | null) =>
    a && a.toLowerCase() === inc.authority.toLowerCase() ? inc.authorityLabel : short(a ?? "?");
  const hit = d.result.applied[0]!;
  const out: string[] = [""];
  out.push(
    `  ${style.bold(`type 4 · ${d.tx.hash}`)}`,
    style.dim(
      `  ${inc.authorityLabel}'s nonce when the list ran: ${int(d.authorityNonceAtTx)} (its own tx ${short(d.ownTxSameBlock.tx, 10, 4)} used ${int(d.ownTxSameBlock.nonce)} at index ${d.ownTxSameBlock.index}, ${d.index - d.ownTxSameBlock.index} slots earlier)`,
    ),
    "",
    ...renderOutcomes(d.result.outcomes, who),
    "",
    style.bold("  findings"),
    ...renderFindings(d.findings),
    "",
    style.bold(`  after block ${int(d.block)}`),
    `  code   0x → ${style.red(delegationCode(hit.delegate).toLowerCase())}`,
    `  nonce  ${int(d.ownTxSameBlock.nonce)} → ${int(d.result.after.get(inc.authority)!.nonce)}   ${style.dim(`no transaction ever used ${int(hit.nonce)}: the authorization consumed it`)}`,
    "",
  );
  const v2 = inc.sweeper.v2;
  const order = ["0x8a179be4", "0x043ff9d2", "0xb61d27f6", "0x01e33667", "0x4782f779", "0x97dc97cb"];
  const sel = v2.selectors
    .filter((s) => order.includes(s.selector))
    .sort((a, b) => order.indexOf(a.selector) - order.indexOf(b.selector));
  out.push(
    style.bold(`  the delegate ${short(inc.delegate)}`) +
      style.dim(`  ${int(v2.size)} bytes · ${v2.sweeperLike ? "sweeper-like" : "unclassified"}`),
    style.dim(`  ${sel.map((s) => s.name).join(" · ")}`),
    style.dim(
      `  hardcoded caller ${v2.hardcodedAddresses.map((a) => short(a)).join(", ")}${v2.traits.includes("RESERVES_ONE_ETHER") ? " · keeps 1 ETH behind" : ""}`,
    ),
    "",
  );
  return out.join("\n");
}

/** `--timeline`: the 3h49m36s the delegation was live, from the chain's own records. */
export function renderTimeline(inc: Incident): string {
  const d = inc.delegation;
  const hit = d.result.applied[0]!;
  const startMs = Date.parse(d.utc);
  const rows: { t: string; text: string }[] = [];
  rows.push({
    t: d.window.openedUtc,
    text: style.dim(
      `the wallet's nonce enters the signed range (${int(d.tx.authorizationList.at(-1)!.nonce)} is live, then used, in this block)`,
    ),
  });
  rows.push({
    t: d.utc,
    text: style.red(`delegated: tuple #${hit.index} applies in block ${int(d.block)}, index ${d.index}`),
  });
  for (const c of inc.calls) {
    const parts: string[] = [];
    if (c.eth !== "0") parts.push(`${amount(c.eth)} ETH`);
    if (c.usdt !== "0") parts.push(`${amount(c.usdt)} USDT`);
    if (c.usdc !== "0") parts.push(`${amount(c.usdc)} USDC`);
    const others = c.tokens - (c.usdt !== "0" ? 1 : 0) - (c.usdc !== "0" ? 1 : 0);
    if (others > 0) parts.push(`${others} other tokens`);
    const since = c === inc.calls[0] ? style.dim(`+${(Date.parse(c.utc) - startMs) / 1000} s`) : "";
    const what =
      c.kind === "callExecute"
        ? `${parts.join(" · ")} out of smart account ${short(inc.smartAccount)}`
        : parts.length
          ? parts.join(" · ")
          : style.dim("nothing left to take");
    rows.push({ t: c.utc, text: `${pad(c.label, 30)} ${pad(since, 8)} ${what}` });
  }
  for (const r of inc.refills)
    rows.push({
      t: r.utc,
      text: `${pad(style.yellow(`top-up: ${amount(r.amount)} ${r.symbol} arrives`), 39)} ${style.yellow(`swept ${r.sweptAfterSeconds} s later`)}`,
    });
  for (const f of inc.freezes) rows.push({ t: f.utc, text: style.dim(`${f.issuer} ${f.what}`) });
  rows.push({
    t: inc.clear.utc,
    text: style.green(
      `cleared: ${short(inc.clear.tx.hash, 10, 4)} self-sponsored, authorizes 0x0 at nonce ${int(inc.clear.tx.authorizationList[0]!.nonce)}`,
    ),
  });
  rows.sort((a, b) => a.t.localeCompare(b.t));
  const out = [
    "",
    style.bold(`  through the delegation`) +
      style.dim(
        `  ${duration(inc.timing.delegatedSeconds)} live · ${inc.calls.length} calls by ${short(inc.operator)} · UTC`,
      ),
    ...rows.map((r) => `  ${style.dim(hhmmss(r.t))}  ${r.text}`),
    "",
    `  out through the delegation: ${style.bold(`${amount(inc.totals.eth)} ETH · ${amount(inc.totals.usdt)} USDT`)} ${style.dim(`· ${inc.totals.sweptTokenContracts} token contracts swept`)}`,
    `  ${" ".repeat(27)} ${style.bold(`+ ${amount(inc.totals.usdc)} USDC`)} ${style.dim("out of the smart account it owned")}`,
    style.dim(
      `  The first sweep came ${inc.timing.blocksToFirstSweep} blocks (${inc.timing.secondsToFirstSweep} s) after inclusion. The two top-ups shown are the largest; other`,
    ),
    style.dim(
      `  inflows landed while it was delegated and left with later sweeps. The delegation tx is absent from Flashbots`,
    ),
    style.dim(`  Mempool Dumpster: strong evidence of private order flow, not proof.`),
    "",
  ];
  return out.join("\n");
}

/** The first hop as a tree per collector: what came in, the ETH that left as plain transfers, and the rest. */
export function renderFlows(inc: Incident): string {
  const o = inc.onward;
  const when = (iso: string) => `${iso.slice(5, 10)} ${iso.slice(11, 19)}`;
  const label = (a: string) => {
    if (a.toLowerCase() === inc.authority.toLowerCase()) return `${short(a)} ${inc.authorityLabel}`;
    if (a.toLowerCase() === inc.smartAccount.toLowerCase()) return `${short(a)} its smart account`;
    const named = Object.entries(o.labels).find(([k]) => k.toLowerCase() === a.toLowerCase());
    return named ? `${short(a)} ${named[1]}` : short(a);
  };
  const money = (r: { eth: string; usdt: string; usdc: string; otherTokens: number }) =>
    [
      r.eth !== "0" ? `${amount(r.eth)} ETH` : "",
      r.usdt !== "0" ? `${amount(r.usdt)} USDT` : "",
      r.usdc !== "0" ? `${amount(r.usdc)} USDC` : "",
      r.otherTokens ? `+${r.otherTokens} tokens` : "",
    ]
      .filter(Boolean)
      .join("  ");
  const out = [
    "",
    `  ${style.bold("where the swept value went")} ${style.dim(`· first hop on Ethereum · snapshot ${when(o.snapshotUtc)} UTC`)}`,
  ];
  for (const name of ["R1", "R2"]) {
    const address = inc.onward.inflows.find((r) => r.collector === name)?.address;
    if (!address) continue;
    const rows: string[] = [];
    for (const r of o.inflows.filter((x) => x.collector === name))
      rows.push(
        `◀ ${pad(money(r), 47)} ${style.dim(`${label(r.from)}, ${r.via === "delegation" ? "delegation" : "signed transfers"}`)}`,
      );
    for (const t of o.transfers.filter((x) => x.collector === name))
      rows.push(
        `▶ ${pad(`${amount(t.eth)} ETH`, 12, "right")} → ${pad(short(t.to), 12)} ${style.dim(`${when(t.utc)}  ${short(t.tx)}  ${t.bytes} B decoded`)}`,
      );
    const a = o.activity.find((x) => x.collector === name);
    if (a) {
      const top = a.routers.slice(0, 2).map((r) => `${r.name} ${r.txs}`);
      const more = a.routers.length > 2 ? `, +${a.routers.length - 2} routers` : "";
      rows.push(
        `▶ ${style.dim(`${int(a.txs)} txs ${when(a.firstUtc).slice(0, 11)}–${when(a.lastUtc).slice(0, 11)}: ${top.join(", ")}${more}`)}`,
      );
    }
    const frozen = inc.freezes.filter((f) => f.what.includes(name));
    out.push("", `  ${style.bold(name)}  ${address}`);
    rows.forEach((r, i) => out.push(`  ${i === rows.length - 1 && !frozen.length ? "└─" : "├─"}${r}`));
    if (frozen.length)
      out.push(
        `  └─${style.red("■")} ${style.dim(`blacklisted by ${frozen.map((f) => `${f.issuer} ${f.utc.slice(11, 19)}`).join(", ")} UTC`)}`,
      );
  }
  out.push(
    "",
    style.dim("  ◀ in, ▶ out. Each ETH transfer decodes from raw bytes bundled in the package; the"),
    style.dim("  transaction counts are a Blockscout snapshot; labels are explorer labels, not ownership."),
    "",
  );
  return out.join("\n");
}
