const enabled = (() => {
  if (typeof process === "undefined") return false;
  if (process.env.NO_COLOR !== undefined && process.env.NO_COLOR !== "") return false;
  const force = process.env.FORCE_COLOR;
  if (force !== undefined && force !== "") return force !== "0" && force !== "false";
  return !!process.stdout.isTTY;
})();

const wrap = (open: number, close: number) => (s: string) => (enabled ? `\x1b[${open}m${s}\x1b[${close}m` : s);

export const style = {
  bold: wrap(1, 22),
  dim: wrap(2, 22),
  red: wrap(31, 39),
  green: wrap(32, 39),
  yellow: wrap(33, 39),
  cyan: wrap(36, 39),
  inverse: wrap(7, 27),
};

export const stripAnsi = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, "");

export function pad(s: string, width: number, align: "left" | "right" = "left"): string {
  const len = stripAnsi(s).length;
  if (len >= width) return s;
  return align === "left" ? s + " ".repeat(width - len) : " ".repeat(width - len) + s;
}

export const short = (a: string, head = 6, tail = 4) =>
  a.length > head + tail + 1 ? `${a.slice(0, head)}…${a.slice(-tail)}` : a;

export function int(n: bigint | number): string {
  return BigInt(n).toLocaleString("en-US");
}

/** Decimal string rounded half-up to `places` digits, with thousands separators. Integers stay integers. */
export function amount(s: string, places = 2): string {
  const [i = "0", f = ""] = s.split(".");
  if (!f.replace(/0+$/, "")) return BigInt(i).toLocaleString("en-US");
  const scaled = BigInt(i + f.padEnd(places + 1, "0").slice(0, places + 1));
  const rounded = (scaled + 5n) / 10n;
  const str = rounded.toString().padStart(places + 1, "0");
  const head = BigInt(str.slice(0, str.length - places)).toLocaleString("en-US");
  return `${head}.${str.slice(str.length - places)}`;
}

export function duration(seconds: number): string {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.round(seconds % 60);
  return h
    ? `${h}h${String(m).padStart(2, "0")}m${String(s).padStart(2, "0")}s`
    : m
      ? `${m}m${String(s).padStart(2, "0")}s`
      : `${s}s`;
}

export const hhmmss = (iso: string) => iso.slice(11, 19);
