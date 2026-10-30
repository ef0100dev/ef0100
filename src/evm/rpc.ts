/** Scheme and host only: paths, query strings and credentials can all carry API keys. Safe to print. */
export function redactRpc(url: string): string {
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.host}`;
  } catch {
    return "(invalid url)";
  }
}

/**
 * Text that came from an endpoint, made safe for a terminal and a log: control characters (escape sequences that move
 * the cursor, write the clipboard or forge lines) become "?", and any URL is cut to its host.
 */
export function cleanText(s: string): string {
  return s
    .replace(/https?:\/\/[^\s"'<>)]+/g, (u) => redactRpc(u))
    .replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g, "?");
}

export class RpcError extends Error {
  override name = "RpcError";
  constructor(
    message: string,
    url: string,
    readonly code?: number,
  ) {
    super(cleanText(message));
    this.url = redactRpc(url);
  }
  readonly url: string;
}

export interface RpcCall {
  method: string;
  params: unknown[];
}

export interface RpcOptions {
  timeoutMs?: number;
  fetch?: typeof fetch;
}

let nextId = 1;

/** One JSON-RPC batch against one endpoint. Results come back in call order; a per-call error rejects the batch. */
export async function rpcBatch(url: string, calls: RpcCall[], opts: RpcOptions = {}): Promise<unknown[]> {
  if (calls.length === 0) return [];
  const f = opts.fetch ?? fetch;
  const ids = calls.map(() => nextId++);
  const body = JSON.stringify(
    calls.map((c, i) => ({ jsonrpc: "2.0", id: ids[i], method: c.method, params: c.params })),
  );
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), opts.timeoutMs ?? 12_000);
  let json: unknown;
  try {
    // The timer covers the body too: an endpoint that sends headers and then stalls must not hang the caller.
    const res = await f(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
      signal: ctl.signal,
    });
    if (!res.ok) throw new RpcError(`HTTP ${res.status}`, url, res.status);
    const text = await res.text();
    try {
      json = JSON.parse(text);
    } catch {
      throw new RpcError("the response is not JSON", url);
    }
  } catch (e) {
    if (e instanceof RpcError) throw e;
    throw new RpcError(`${(e as Error).name === "AbortError" ? "timeout" : (e as Error).message}`, url);
  } finally {
    clearTimeout(timer);
  }
  const list = Array.isArray(json) ? json : [json];
  const byId = new Map<number, { result?: unknown; error?: { code: number; message: string } }>();
  for (const r of list as { id: number; result?: unknown; error?: { code: number; message: string } }[])
    byId.set(r.id, r);
  return ids.map((id, i) => {
    const r = byId.get(id);
    if (!r) throw new RpcError(`no response for ${calls[i]!.method}`, url);
    if (r.error) throw new RpcError(`${calls[i]!.method}: ${r.error.message}`, url, r.error.code);
    return r.result;
  });
}

/** Tries each endpoint in turn and returns the first that answers the whole batch. */
export async function rpcBatchAny(urls: string[], calls: RpcCall[], opts: RpcOptions = {}): Promise<unknown[]> {
  const errors: string[] = [];
  for (const url of urls) {
    try {
      return await rpcBatch(url, calls, opts);
    } catch (e) {
      errors.push(`${redactRpc(url)}: ${(e as Error).message}`);
    }
  }
  throw new RpcError(`every endpoint failed (${errors.join("; ")})`, urls[0] ?? "");
}

export async function rpc<T>(urls: string[], method: string, params: unknown[], opts: RpcOptions = {}): Promise<T> {
  const [r] = await rpcBatchAny(urls, [{ method, params }], opts);
  return r as T;
}

export const toQuantity = (n: bigint | number): string => "0x" + BigInt(n).toString(16);
