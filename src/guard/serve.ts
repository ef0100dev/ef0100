import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { bytesToHex, hexToBytes, isAddress, type Hex } from "../evm/bytes.js";
import { agreedOwnCode, ownCodeAnswers, type OwnCodeAnswer } from "../evm/owncode.js";
import type { RpcOptions } from "../evm/rpc.js";
import { Guard } from "./policy.js";

/** Bodies above this are refused before they are parsed: a signing request is a few hundred bytes. */
export const MAX_BODY = 256 * 1024;

export interface CheckRequest {
  preimage?: string;
  digest?: string;
  signer?: string;
  nonce?: string | number;
  ownCode?: string;
  selfSponsored?: boolean;
  curve?: "secp256k1" | "ed25519";
}

class BadRequest extends Error {}

function toNonce(n: CheckRequest["nonce"]): bigint | undefined {
  if (n === undefined || n === null) return undefined;
  if (typeof n === "number" && Number.isSafeInteger(n) && n >= 0) return BigInt(n);
  if (typeof n === "string" && /^(0x[0-9a-fA-F]{1,16}|[0-9]{1,20})$/.test(n)) return BigInt(n);
  throw new BadRequest("nonce must be a non-negative integer, as a number or a decimal or 0x string");
}

function toHex(s: unknown, what: string): Uint8Array | undefined {
  if (s === undefined) return undefined;
  if (typeof s !== "string" || !/^0x([0-9a-fA-F]{2})*$/.test(s))
    throw new BadRequest(`${what} must be 0x-prefixed hex`);
  return hexToBytes(s as Hex);
}

function asRequest(body: unknown): CheckRequest {
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new BadRequest("the body must be a JSON object");
  const r = body as CheckRequest;
  toHex(r.ownCode, "ownCode");
  toNonce(r.nonce);
  if (!toHex(r.preimage, "preimage") && !toHex(r.digest, "digest"))
    throw new BadRequest("send preimage, or digest (with its preimage)");
  return r;
}

/**
 * One request against the guard. Throws BadRequest for input that is not a request at all. `ownCode`, when given,
 * replaces the request's own: the server read it itself (see ServeOwnCode), `undefined` meaning it could not.
 */
export function decide(guard: Guard, body: unknown, server?: { ownCode: Uint8Array | undefined }) {
  const r = asRequest(body);
  const preimage = toHex(r.preimage, "preimage");
  const digest = toHex(r.digest, "digest");
  const ownCode = server ? server.ownCode : toHex(r.ownCode, "ownCode");
  const ctx = {
    ...(r.signer !== undefined ? { signer: String(r.signer) } : {}),
    ...(toNonce(r.nonce) !== undefined ? { nonce: toNonce(r.nonce)! } : {}),
    ...(ownCode ? { ownCode } : {}),
    ...(r.selfSponsored === true ? { selfSponsored: true } : {}),
  };
  const d = digest
    ? guard.checkDigest(digest, preimage, ctx)
    : guard.check(preimage!, { as: "preimage", ...(r.curve ? { curve: r.curve } : {}) }, ctx);
  return { allow: d.allow, kind: d.classified.kind, reasons: d.reasons };
}

/** Where the server reads the signer's own code itself, instead of trusting the request's. */
export interface ServeOwnCode extends RpcOptions {
  urls: string[];
  /** How many endpoints must answer; every answer must match. Default: all of them. */
  quorum?: number;
}

/**
 * eth_getCode of the request's signer from every endpoint. The request's own `ownCode`, if any, counts as one more
 * answer, so a caller that says "0x" while an endpoint sees a delegation is refused. No signer, no own code.
 */
export async function serverOwnCode(cfg: ServeOwnCode, body: unknown) {
  const r = asRequest(body);
  const claimed = toHex(r.ownCode, "ownCode");
  if (typeof r.signer !== "string" || !isAddress(r.signer))
    return { ownCode: undefined, answers: [] as OwnCodeAnswer[] };
  const answers = await ownCodeAnswers(r.signer, cfg.urls, cfg);
  const all = claimed ? [...answers, { endpoint: "request", code: bytesToHex(claimed) }] : answers;
  try {
    return { ownCode: hexToBytes(agreedOwnCode(all, cfg.quorum ?? cfg.urls.length)), answers: all };
  } catch {
    return { ownCode: undefined, answers: all };
  }
}

/**
 * A local HTTP front for one Guard, for signers written in other languages. It answers on 127.0.0.1 only, holds no
 * keys and signs nothing. Requests that name another Host, or carry an Origin (a browser), are refused: a web page
 * must not be able to spend the key's rate limit or read decisions through DNS rebinding.
 */
export function createGuardServer(guard: Guard, opts: { version?: string; ownCode?: ServeOwnCode } = {}): Server {
  if (opts.ownCode) {
    const n = opts.ownCode.urls.length;
    const q = opts.ownCode.quorum ?? n;
    if (n === 0) throw new TypeError("ownCode.urls needs at least one endpoint");
    if (!Number.isInteger(q) || q < 1 || q > n) throw new TypeError(`ownCode.quorum must be between 1 and ${n}`);
  }
  const send = (res: ServerResponse, status: number, body: unknown) => {
    const text = JSON.stringify(body, (_k, v) => (typeof v === "bigint" ? v.toString() : v));
    res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
    res.end(text);
  };
  return createServer((req: IncomingMessage, res: ServerResponse) => {
    const port = (req.socket.localPort ?? 0).toString();
    const host = (req.headers.host ?? "").toLowerCase();
    if (host !== `127.0.0.1:${port}` && host !== `localhost:${port}`)
      return send(res, 403, { error: "Host must be 127.0.0.1 or localhost" });
    if (req.headers.origin !== undefined) return send(res, 403, { error: "browser requests are refused" });
    if (req.url === "/health" && req.method === "GET") return send(res, 200, { ok: true, version: opts.version });
    if (req.url !== "/check") return send(res, 404, { error: "POST /check, or GET /health" });
    if (req.method !== "POST") return send(res, 405, { error: "POST /check" });
    const chunks: Buffer[] = [];
    let size = 0;
    let over = false;
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > MAX_BODY) over = true;
      else chunks.push(c);
    });
    req.on("end", async () => {
      if (over) return send(res, 413, { error: `body above ${MAX_BODY} bytes` });
      let body: unknown;
      try {
        body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      } catch {
        return send(res, 400, { error: "the body is not JSON" });
      }
      try {
        if (!opts.ownCode) return send(res, 200, decide(guard, body));
        const read = await serverOwnCode(opts.ownCode, body);
        return send(res, 200, { ...decide(guard, body, read), ownCodeAnswers: read.answers });
      } catch (e) {
        if (e instanceof BadRequest) return send(res, 400, { error: e.message });
        return send(res, 400, { error: "the request could not be read" });
      }
    });
  });
}
