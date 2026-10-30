import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { hexToBytes, type Hex } from "../evm/bytes.js";
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

/** One request against the guard. Throws BadRequest for input that is not a request at all. */
export function decide(guard: Guard, body: unknown) {
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new BadRequest("the body must be a JSON object");
  const r = body as CheckRequest;
  const preimage = toHex(r.preimage, "preimage");
  const digest = toHex(r.digest, "digest");
  const ownCode = toHex(r.ownCode, "ownCode");
  if (!preimage && !digest) throw new BadRequest("send preimage, or digest (with its preimage)");
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

/**
 * A local HTTP front for one Guard, for signers written in other languages. It answers on 127.0.0.1 only, holds no
 * keys and signs nothing. Requests that name another Host, or carry an Origin (a browser), are refused: a web page
 * must not be able to spend the key's rate limit or read decisions through DNS rebinding.
 */
export function createGuardServer(guard: Guard, opts: { version?: string } = {}): Server {
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
    req.on("end", () => {
      if (over) return send(res, 413, { error: `body above ${MAX_BODY} bytes` });
      let body: unknown;
      try {
        body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      } catch {
        return send(res, 400, { error: "the body is not JSON" });
      }
      try {
        return send(res, 200, decide(guard, body));
      } catch (e) {
        if (e instanceof BadRequest) return send(res, 400, { error: e.message });
        return send(res, 400, { error: "the request could not be read" });
      }
    });
  });
}
