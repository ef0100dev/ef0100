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
