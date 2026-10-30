import type { ScanRow } from "./scan.js";

export type WatchEventKind = "baseline" | "delegated" | "cleared" | "redelegated" | "code" | "unreachable" | "back";

export interface WatchEvent {
  /** ISO 8601, UTC. */
  at: string;
  kind: WatchEventKind;
  chain: string;
  address: string;
  state: ScanRow["state"];
  delegate?: string;
  /** The delegate before a redelegation or a clear. */
  previous?: string;
  label?: string;
  /** A known-malicious or sweeper-like delegate. */
  bad?: boolean;
  /** The delegate was passed with --allow. */
  allowed?: boolean;
  nonce?: string;
  error?: string;
}

export interface WatchState {
  /** The last answer per chain and address; an unanswered poll keeps the previous one. */
  rows: Map<string, ScanRow>;
  /** Chain and address pairs whose endpoints did not answer the last poll. */
  down: Set<string>;
}

const keyOf = (r: ScanRow) => `${r.chain.key}:${r.address.toLowerCase()}`;

function labelOf(r: ScanRow): string | undefined {
  if (r.state !== "delegated") return undefined;
  if (r.entry) return r.entry.label;
  return r.delegateCode?.sweeperLike ? "sweeper-like code" : "not in the registry";
}

/**
 * Compares one scan with the previous one and returns what changed, per chain and address. The first scan of a pair
 * is its baseline. An endpoint that does not answer never reads as a change of state: the pair keeps its last known
 * answer and is reported once as unreachable, then once as back.
 */
export function diffScan(
  prev: WatchState | undefined,
  rows: ScanRow[],
  allow: ReadonlySet<string> = new Set(),
  at: Date = new Date(),
): { events: WatchEvent[]; next: WatchState } {
  const next: WatchState = { rows: new Map(prev?.rows ?? []), down: new Set(prev?.down ?? []) };
  const events: WatchEvent[] = [];
  const iso = at.toISOString();
  for (const r of rows) {
    const key = keyOf(r);
    const base = {
      at: iso,
      chain: r.chain.key,
      address: r.address,
      state: r.state,
      ...(r.nonce != null ? { nonce: r.nonce.toString() } : {}),
    };
    if (r.state === "error") {
      if (!next.down.has(key)) events.push({ ...base, kind: "unreachable", ...(r.error ? { error: r.error } : {}) });
      next.down.add(key);
      continue;
    }
    if (next.down.delete(key) && next.rows.has(key)) events.push({ ...base, kind: "back" });
    const before = next.rows.get(key);
    next.rows.set(key, r);
    const facts = {
      ...(r.delegate ? { delegate: r.delegate } : {}),
      ...(labelOf(r) ? { label: labelOf(r) } : {}),
      ...(r.state === "delegated"
        ? {
            bad: r.entry?.verdict === "malicious" || !!r.delegateCode?.sweeperLike,
            allowed: allow.has(r.delegate!.toLowerCase()),
          }
        : {}),
    };
    if (!before) {
      events.push({ ...base, kind: "baseline", ...facts });
      continue;
    }
    const was = before.state;
    if (was !== "delegated" && r.state === "delegated") events.push({ ...base, kind: "delegated", ...facts });
    else if (was === "delegated" && r.state !== "delegated")
      events.push({ ...base, kind: r.state === "contract" ? "code" : "cleared", previous: before.delegate! });
    else if (was === "delegated" && r.delegate!.toLowerCase() !== before.delegate!.toLowerCase())
      events.push({ ...base, kind: "redelegated", ...facts, previous: before.delegate! });
    else if (was === "eoa" && r.state === "contract") events.push({ ...base, kind: "code" });
  }
  return { events, next };
}

/** A change worth an alarm: a new or changed delegation the caller did not allow. */
export function isAlarm(e: WatchEvent): boolean {
  return (e.kind === "delegated" || e.kind === "redelegated" || e.kind === "code") && !e.allowed;
}

/** One line a person can read in a chat channel. Addresses are full: a short form cannot be checked against anything. */
export function describeEvent(e: WatchEvent): string {
  const at = `${e.at.slice(0, 19).replace("T", " ")} UTC`;
  switch (e.kind) {
    case "delegated":
    case "redelegated":
      return `${e.bad ? "DELEGATED TO A SWEEPER" : e.kind === "delegated" ? "Delegated" : "Redelegated"}: ${e.address} on ${e.chain} → ${e.delegate}${e.label ? ` (${e.label})` : ""}${e.previous ? `, was ${e.previous}` : ""} · ${at}`;
    case "cleared":
      return `Cleared: ${e.address} on ${e.chain}, no delegation now${e.previous ? ` (was ${e.previous})` : ""} · ${at}`;
    case "code":
      return `Code appeared: ${e.address} on ${e.chain} · ${at}`;
    case "unreachable":
      return `No answer: ${e.chain} for ${e.address} · ${at}`;
    case "back":
      return `Answering again: ${e.chain} for ${e.address} · ${at}`;
    case "baseline":
      return `Watching ${e.address} on ${e.chain}: ${e.state} · ${at}`;
  }
}

/** Events worth a message: alarms, and a clear, so the channel also hears when it is over. */
export function isNotifiable(e: WatchEvent): boolean {
  return isAlarm(e) || e.kind === "cleared";
}

/**
 * A webhook URL is a credential: anyone holding it can post to the channel. Only https is accepted, or http to this
 * machine for a local relay.
 */
export function checkWebhookUrl(url: string): URL {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    throw new TypeError("--webhook is not a URL");
  }
  const local = u.hostname === "localhost" || u.hostname === "127.0.0.1" || u.hostname === "[::1]";
  if (u.protocol !== "https:" && !(u.protocol === "http:" && local))
    throw new TypeError("--webhook must be https (or http to localhost)");
  return u;
}

/**
 * Posts one event as JSON: `text` for Slack, `content` for Discord, and the event itself for anything else. Never
 * throws: a failed delivery is returned, so the watch keeps running.
 */
export async function postWebhook(
  url: string,
  e: WatchEvent,
  opts: { fetch?: typeof fetch; timeoutMs?: number } = {},
): Promise<{ ok: boolean; status?: number; error?: string }> {
  const text = describeEvent(e);
  try {
    const res = await (opts.fetch ?? fetch)(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ text, content: text, event: e }),
      signal: AbortSignal.timeout(opts.timeoutMs ?? 5000),
      redirect: "error",
    });
    return res.ok ? { ok: true, status: res.status } : { ok: false, status: res.status };
  } catch (err) {
    return { ok: false, error: (err as Error).name === "TimeoutError" ? "timeout" : "unreachable" };
  }
}
