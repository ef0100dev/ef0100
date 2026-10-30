import { isAddress, toBytes, bytesToHex, type Hex } from "./bytes.js";
import { cleanText, redactRpc, rpcBatch, type RpcOptions } from "./rpc.js";

export class OwnCodeUnconfirmed extends Error {
  override name = "OwnCodeUnconfirmed";
}

export interface OwnCodeOptions extends RpcOptions {
  /** How many endpoints must return the same code. Default: all of them. */
  quorum?: number;
  /** Block tag or number to read at. Default "latest". */
  block?: string;
}

/**
 * eth_getCode of the signer's own address, read from several endpoints at once and accepted only when enough of them
 * return the same bytes. A single endpoint that lies "0x" would switch off the own-code rule; with this, a lie or an
 * outage throws OwnCodeUnconfirmed instead, the caller passes no ownCode, and the hot-wallet profile refuses
 * (CONTEXT_MISSING). The endpoints should be independent providers.
 */
export async function readOwnCode(address: string, urls: string[], opts: OwnCodeOptions = {}): Promise<Hex> {
  if (!isAddress(address)) throw new TypeError(`not an address: ${address}`);
  if (urls.length === 0) throw new TypeError("readOwnCode needs at least one endpoint");
  const quorum = opts.quorum ?? urls.length;
  if (!Number.isInteger(quorum) || quorum < 1 || quorum > urls.length)
    throw new TypeError(`quorum must be between 1 and ${urls.length}`);
  const answers = await Promise.all(
    urls.map(async (url) => {
      try {
        const [code] = await rpcBatch(
          url,
          [{ method: "eth_getCode", params: [address, opts.block ?? "latest"] }],
          opts,
        );
        return { url, code: bytesToHex(toBytes(code as string)) };
      } catch (e) {
        return { url, error: cleanText((e as Error).message) };
      }
    }),
  );
  const tally = new Map<string, number>();
  for (const a of answers) if (a.code !== undefined) tally.set(a.code, (tally.get(a.code) ?? 0) + 1);
  const best = [...tally.entries()].sort((x, y) => y[1] - x[1])[0];
  if (best && best[1] >= quorum && [...tally.values()].filter((n) => n >= quorum).length === 1) return best[0] as Hex;
  const summary = answers
    .map(
      (a) =>
        `${redactRpc(a.url)}: ${a.code !== undefined ? `${a.code.slice(0, 10)}${a.code.length > 10 ? "…" : ""}` : a.error}`,
    )
    .join("; ");
  throw new OwnCodeUnconfirmed(`own code not confirmed by ${quorum} of ${urls.length} endpoints (${summary})`);
}
