import { isAddress, toBytes, bytesToHex, type Hex } from "./bytes.js";
import { cleanText, redactRpc, rpcBatch, type RpcOptions } from "./rpc.js";

/** What one endpoint said. `endpoint` is the URL cut to its host, safe to print or log. */
export interface OwnCodeAnswer {
  endpoint: string;
  code?: Hex;
  error?: string;
}

export class OwnCodeUnconfirmed extends Error {
  override name = "OwnCodeUnconfirmed";
  constructor(
    message: string,
    readonly answers: OwnCodeAnswer[],
  ) {
    super(message);
  }
}

export interface OwnCodeOptions extends RpcOptions {
  /** How many endpoints must answer. Every answer must still match. Default: all of them. */
  quorum?: number;
  /** Block tag or number to read at. Default "latest". */
  block?: string;
}

function checkInput(address: string, urls: string[], quorum: number | undefined): number {
  if (!isAddress(address)) throw new TypeError(`not an address: ${address}`);
  if (urls.length === 0) throw new TypeError("readOwnCode needs at least one endpoint");
  const q = quorum ?? urls.length;
  if (!Number.isInteger(q) || q < 1 || q > urls.length)
    throw new TypeError(`quorum must be between 1 and ${urls.length}`);
  return q;
}

/** eth_getCode of an address from every endpoint at once. An endpoint that fails or returns non-hex has an error. */
export async function ownCodeAnswers(
  address: string,
  urls: string[],
  opts: Omit<OwnCodeOptions, "quorum"> = {},
): Promise<OwnCodeAnswer[]> {
  checkInput(address, urls, 1);
  return Promise.all(
    urls.map(async (url): Promise<OwnCodeAnswer> => {
      const endpoint = redactRpc(url);
      try {
        const [code] = await rpcBatch(
          url,
          [{ method: "eth_getCode", params: [address, opts.block ?? "latest"] }],
          opts,
        );
        return { endpoint, code: bytesToHex(toBytes(code as string)) };
      } catch (e) {
        return { endpoint, error: cleanText((e as Error).message) };
      }
    }),
  );
}

/**
 * The code every answering endpoint returned, if at least `quorum` answered. Two answers that differ always throw,
 * whatever the count: a lagging or lying endpoint can make the guard refuse, never make it sign.
 */
export function agreedOwnCode(answers: OwnCodeAnswer[], quorum = answers.length): Hex {
  if (!Number.isInteger(quorum) || quorum < 1) throw new TypeError("quorum must be a whole number, at least 1");
  const codes = answers.flatMap((a) => (a.code === undefined ? [] : [a.code]));
  const distinct = new Set(codes);
  if (distinct.size === 1 && codes.length >= quorum) return codes[0]!;
  const summary = answers
    .map(
      (a) =>
        `${a.endpoint}: ${a.code !== undefined ? `${a.code.slice(0, 10)}${a.code.length > 10 ? "…" : ""}` : a.error}`,
    )
    .join("; ");
  const why =
    distinct.size > 1 ? "endpoints disagree" : `${codes.length} of ${answers.length} answered, ${quorum} needed`;
  throw new OwnCodeUnconfirmed(`own code not confirmed: ${why} (${summary})`, answers);
}

/**
 * eth_getCode of the signer's own address, read from several endpoints at once and accepted only when every one that
 * answered returned the same bytes, and at least `quorum` answered (default: all). A single endpoint that lies "0x"
 * would switch off the own-code rule; with this, a lie, a lagging node or an outage throws OwnCodeUnconfirmed instead,
 * the caller passes no ownCode, and the hot-wallet profile refuses (CONTEXT_MISSING). Use independent providers.
 */
export async function readOwnCode(address: string, urls: string[], opts: OwnCodeOptions = {}): Promise<Hex> {
  const quorum = checkInput(address, urls, opts.quorum);
  return agreedOwnCode(await ownCodeAnswers(address, urls, opts), quorum);
}
