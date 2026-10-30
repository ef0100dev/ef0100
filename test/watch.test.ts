import { describe, expect, it } from "vitest";
import type { ScanRow } from "../src/evm/scan.ts";
import { diffScan, isAlarm } from "../src/evm/watch.ts";

const B14 = "0x28C6c06298d514Db089934071355E5743bf21d60";
const SWEEPER = "0x63e842B054Bd624a465454D533C33F573e9c6fAe";
const OTHER = "0x00000000000000000000000000000000000000Aa";
const eth = { id: 1, key: "ethereum", name: "Ethereum" };
const base = { id: 8453, key: "base", name: "Base" };

const eoa = (chain = eth, nonce = 18914809n): ScanRow => ({ chain, address: B14, state: "eoa", nonce });
const delegated = (delegate = SWEEPER, chain = eth, sweeperLike = true): ScanRow => ({
  chain,
  address: B14,
  state: "delegated",
  nonce: 18914810n,
  delegate,
  delegateCode: { sweeperLike } as ScanRow["delegateCode"],
});
const down = (chain = eth): ScanRow => ({ chain, address: B14, state: "error", error: "timeout" });
const at = new Date("2026-10-29T20:20:59Z");

describe("watch", () => {
  it("reports the first scan as a baseline and raises no alarm for it", () => {
    const { events } = diffScan(undefined, [eoa(), eoa(base)], new Set(), at);
    expect(events.map((e) => [e.kind, e.chain])).toEqual([
      ["baseline", "ethereum"],
      ["baseline", "base"],
    ]);
    expect(events.some(isAlarm)).toBe(false);
    expect(events[0].at).toBe("2026-10-29T20:20:59.000Z");
  });

  it("raises an alarm when a delegation appears, flags a sweeper and keeps quiet while nothing changes", () => {
    const a = diffScan(undefined, [eoa()]);
    const b = diffScan(a.next, [delegated()], new Set(), at);
    expect(b.events).toHaveLength(1);
    expect(b.events[0]).toMatchObject({ kind: "delegated", delegate: SWEEPER, bad: true, allowed: false });
    expect(isAlarm(b.events[0])).toBe(true);
    expect(diffScan(b.next, [delegated()]).events).toEqual([]);
  });

  it("reports a clear with the delegate it replaced", () => {
    const a = diffScan(undefined, [delegated()]);
    const b = diffScan(a.next, [eoa(eth, 18914905n)]);
    expect(b.events).toEqual([expect.objectContaining({ kind: "cleared", previous: SWEEPER, state: "eoa" })]);
    expect(b.events.some(isAlarm)).toBe(false);
  });

  it("reports a redelegation to another address as an alarm", () => {
    const a = diffScan(undefined, [delegated(OTHER, eth, false)]);
    const b = diffScan(a.next, [delegated(SWEEPER)]);
    expect(b.events[0]).toMatchObject({ kind: "redelegated", previous: OTHER, delegate: SWEEPER });
    expect(isAlarm(b.events[0])).toBe(true);
  });

  it("does not alarm on a delegate passed with --allow", () => {
    const a = diffScan(undefined, [eoa()]);
    const b = diffScan(a.next, [delegated(OTHER, eth, false)], new Set([OTHER.toLowerCase()]));
    expect(b.events[0]).toMatchObject({ kind: "delegated", allowed: true });
    expect(isAlarm(b.events[0])).toBe(false);
  });

  it("never reads an unanswered poll as a change, and reports the outage once each way", () => {
    const a = diffScan(undefined, [delegated()]);
    const b = diffScan(a.next, [down()]);
    expect(b.events.map((e) => e.kind)).toEqual(["unreachable"]);
    const c = diffScan(b.next, [down()]);
    expect(c.events).toEqual([]);
    const d = diffScan(c.next, [delegated()]);
    expect(d.events.map((e) => e.kind)).toEqual(["back"]);
    const e = diffScan(d.next, [eoa()]);
    expect(e.events.map((x) => x.kind)).toEqual(["cleared"]);
  });

  it("treats a chain that never answered as having no baseline yet", () => {
    const a = diffScan(undefined, [down()]);
    expect(a.events.map((e) => e.kind)).toEqual(["unreachable"]);
    const b = diffScan(a.next, [eoa()]);
    expect(b.events.map((e) => e.kind)).toEqual(["baseline"]);
  });
});
