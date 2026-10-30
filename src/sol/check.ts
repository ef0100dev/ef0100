import { base58 } from "@scure/base";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, equalBytes } from "../evm/bytes.js";
import { decodeSolanaTransaction, keyFlags, type SolanaMessage } from "./message.js";

export const PROGRAMS = {
  system: "11111111111111111111111111111111",
  stake: "Stake11111111111111111111111111111111111111",
  token: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
  token2022: "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
  bpfUpgradeable: "BPFLoaderUpgradeab1e11111111111111111111111",
  computeBudget: "ComputeBudget111111111111111111111111111111",
  ata: "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
  memo: "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
  squadsV4: "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf",
  lookupTable: "AddressLookupTab1e1111111111111111111111111",
} as const;
const KNOWN = new Set<string>(Object.values(PROGRAMS));
const CLOCK = "SysvarC1ock11111111111111111111111111111111";

export type SolSeverity = "critical" | "high" | "medium" | "info";

export interface SolFinding {
  severity: SolSeverity;
  code: string;
  message: string;
  instruction?: string;
}

export interface SolPolicy {
  /** Keys this signer controls. Defaults to the message's signers. */
  signers?: string[];
  /** Destinations and authorities that need no review. */
  allowlist?: string[];
  /**
   * The signer's routine template. Hot wallet 5tzF… (labelled Binance) signed 1,149 sampled transactions; 1,144 start
   * with AdvanceNonce from its own nonce pool, and the 5 that do not are the theft transfers.
   */
  template?: { nonceAuthority: string };
  /** Plain SOL transfers are the signer's job (an exchange withdrawal wallet): report them as info, not for review. */
  routineTransfers?: boolean;
  /** Balance before signing, in lamports, and the largest share one transaction may move (default 0.2). */
  balance?: { lamports: bigint; maxFraction?: number };
}

export interface SolReport {
  verdict: "BLOCK" | "REVIEW" | "OK";
  findings: SolFinding[];
  message: SolanaMessage;
  feePayer: string;
  signers: string[];
  /** The nonce account ix0 advances, and the signers ix0 carries (the runtime accepts any of them as the authority). */
  durableNonce?: { account: string; authority: string | null; signers: string[] };
  /** Lamports the signer's keys can lose: transfers, account funding, unwrapped SOL and the fee. */
  outLamports: bigint;
  /** sha256 of the message in base58: the hash a Ledger shows when blind signing a Solana transaction. */
  messageHash: string;
}

const view = (d: Uint8Array) => new DataView(d.buffer, d.byteOffset, d.byteLength);
const u32 = (d: Uint8Array, o = 0) => view(d).getUint32(o, true);
const u64 = (d: Uint8Array, o = 0) => view(d).getBigUint64(o, true);
const key = (d: Uint8Array, o: number) => base58.encode(d.subarray(o, o + 32));
const sol = (lamports: bigint) => {
  const s = lamports.toString().padStart(10, "0");
  return `${BigInt(s.slice(0, -9)).toLocaleString("en-US")}.${s.slice(-9).replace(/0+$/, "") || "0"}`;
};
const disc = (name: string) => sha256(new TextEncoder().encode(`global:${name}`)).subarray(0, 8);
/** A bincode String: u64 length, then the bytes. Returns the offset just past it. */
const skipString = (d: Uint8Array, o: number) => o + 8 + Number(u64(d, o));

const SQUADS = new Map<string, string>(
  [
    "vault_transaction_create",
    "vault_transaction_create_from_buffer",
    "transaction_buffer_create",
    "transaction_buffer_extend",
    "transaction_buffer_close",
    "proposal_create",
    "proposal_approve",
    "proposal_reject",
    "proposal_cancel",
    "proposal_activate",
    "vault_transaction_execute",
    "config_transaction_create",
    "config_transaction_execute",
    "batch_create",
    "batch_add_transaction",
    "batch_execute_transaction",
    "spending_limit_use",
    "multisig_add_member",
    "multisig_remove_member",
    "multisig_change_threshold",
    "multisig_set_time_lock",
    "multisig_set_config_authority",
    "multisig_set_rent_collector",
    "multisig_add_spending_limit",
    "multisig_remove_spending_limit",
    "program_config_set_authority",
    "program_config_set_multisig_creation_fee",
    "program_config_set_treasury",
  ].map((n) => [bytesToHex(disc(n)), n]),
);
const ADMIN_CALLS = new Map<string, string>(
  [
    "update_admin",
    "set_admin",
    "transfer_admin",
    "set_authority",
    "update_authority",
    "transfer_ownership",
    "set_owner",
    "accept_admin",
    "update_upgrade_authority",
  ].map((n) => [bytesToHex(disc(n)), n]),
);
const TOKEN_AUTHORITY = [
  "MintTokens",
  "FreezeAccount",
  "AccountOwner",
  "CloseAccount",
  "TransferFeeConfig",
  "WithheldWithdraw",
  "CloseMint",
  "InterestRate",
  "PermanentDelegate",
  "ConfidentialTransferMint",
  "TransferHookProgramId",
  "ConfidentialTransferFeeConfig",
  "MetadataPointer",
  "GroupPointer",
  "GroupMemberPointer",
  "ScaledUiAmount",
  "Pause",
];
/** Token instructions that move nothing and change no authority. */
const TOKEN_BENIGN: Record<number, string> = {
  0: "InitializeMint",
  1: "InitializeAccount",
  2: "InitializeMultisig",
  5: "Revoke",
  11: "ThawAccount",
  16: "InitializeAccount2",
  17: "SyncNative",
  18: "InitializeAccount3",
  19: "InitializeMultisig2",
  20: "InitializeMint2",
  21: "GetAccountDataSize",
  22: "InitializeImmutableOwner",
  23: "AmountToUiAmount",
  24: "UiAmountToAmount",
};
const PRIVILEGED = new Set([
  "GOVERNANCE_AUTHORITY_TRANSFER",
  "SQUADS_CONFIG_CHANGE",
  "SQUADS_VAULT_TX_CREATE",
  "SQUADS_BUFFER",
  "SQUADS_EXECUTE",
  "STAKE_AUTHORITY_CHANGE",
  "TOKEN_SET_AUTHORITY",
  "ACCOUNT_OWNER_CHANGE",
  "PROGRAM_AUTHORITY_OR_CODE_CHANGE",
  "NONCE_AUTHORITY_CHANGE",
]);
const DEFAULT_CU_LIMIT = 1_400_000n;
const PRIORITY_FEE_CAP = 10_000_000n;

interface Ctx {
  mine: Set<string>;
  allow: Set<string>;
  policy: SolPolicy;
  f: (severity: SolSeverity, code: string, message: string, at: string) => void;
  /** Counts lamports leaving `from` when it is one of the signer's keys. */
  out: (lamports: bigint, from: string | undefined) => void;
}

const ok = (c: Ctx, a: string | undefined) => !!a && (c.mine.has(a) || c.allow.has(a));
const unrecognized = (c: Ctx, program: string, tag: number | string, at: string) =>
  c.f("high", "UNRECOGNIZED_INSTRUCTION", `${program} instruction ${tag} is not one this check reads; simulate it`, at);

function systemIx(acc: string[], d: Uint8Array, at: string, index: number, c: Ctx): void {
  const tag = u32(d);
  const created = (lamports: bigint, owner: string, to: string, base?: string) => {
    c.out(lamports, acc[0]);
    const tokenAccount = (owner === PROGRAMS.token || owner === PROGRAMS.token2022) && lamports <= 10_000_000n;
    if (owner !== PROGRAMS.system && !tokenAccount)
      c.f(
        "critical",
        "ACCOUNT_OWNER_CHANGE",
        `creates ${to}${base ? ` (base ${base})` : ""} funded with ${sol(lamports)} SOL and owned by ${owner}: that program, not the key, controls those lamports`,
        at,
      );
    else if (tokenAccount)
      c.f("medium", "ACCOUNT_CREATE", `creates token account ${to} with ${sol(lamports)} SOL of rent`, at);
    else
      c.f(
        ok(c, to) && c.policy.routineTransfers ? "info" : "high",
        "SOL_TRANSFER",
        `creates ${to}${base ? ` (base ${base})` : ""} and moves ${sol(lamports)} SOL into it from ${acc[0]}`,
        at,
      );
  };
  if (tag === 0 && d.length >= 52) created(u64(d, 4), key(d, 20), acc[1] ?? "?");
  else if (tag === 3 && d.length >= 44) {
    const o = skipString(d, 36);
    created(u64(d, o), key(d, o + 16), acc[1] ?? "?", key(d, 4));
  } else if (tag === 2 && d.length >= 12) {
    const lamports = u64(d, 4);
    c.out(lamports, acc[0]);
    const routine = c.allow.has(acc[1]!) || c.policy.routineTransfers;
    c.f(routine ? "info" : "high", "SOL_TRANSFER", `transfer ${sol(lamports)} SOL ${acc[0]} → ${acc[1]}`, at);
  } else if (tag === 11 && d.length >= 12) {
    const lamports = u64(d, 4);
    c.out(lamports, acc[1]);
    c.f(
      c.allow.has(acc[2]!) ? "info" : "high",
      "SOL_TRANSFER",
      `transfer ${sol(lamports)} SOL from seed account ${acc[0]} (base ${acc[1]}) → ${acc[2]}`,
      at,
    );
  } else if (tag === 1 || tag === 9 || tag === 10) {
    const owner = tag === 1 ? key(d, 4) : key(d, d.length - 32);
    c.f(
      "critical",
      "ACCOUNT_OWNER_CHANGE",
      `System ${tag === 1 ? "Assign" : tag === 9 ? "AllocateWithSeed" : "AssignWithSeed"} makes ${owner} the owner of ${acc[0]}: it can then debit every lamport sent there, and the key can no longer pay fees from it`,
      at,
    );
  } else if (tag === 8)
    c.f(
      c.mine.has(acc[0]!) ? "high" : "medium",
      "ACCOUNT_ALLOCATE",
      `Allocate gives ${acc[0]} data: an account with data can no longer pay fees or send a System transfer`,
      at,
    );
  else if (tag === 7) c.f("critical", "NONCE_AUTHORITY_CHANGE", `nonce account ${acc[0]} authority → ${key(d, 4)}`, at);
  else if (tag === 5 && d.length >= 12) {
    c.out(u64(d, 4), acc[4]);
    c.f("high", "NONCE_WITHDRAW", `withdraw ${sol(u64(d, 4))} SOL from nonce account ${acc[0]} → ${acc[1]}`, at);
  } else if (tag === 6) c.f("medium", "NONCE_INIT", `new nonce account ${acc[0]} with authority ${key(d, 4)}`, at);
  else if (tag === 4) {
    if (index !== 0) c.f("medium", "ADVANCE_NONCE_NOT_FIRST", "AdvanceNonceAccount outside position 0", at);
  } else if (tag === 12) c.f("info", "NONCE_UPGRADE", `upgrade nonce account ${acc[0]}`, at);
  else unrecognized(c, "System", tag, at);
}

function stakeIx(acc: string[], d: Uint8Array, at: string, c: Ctx): void {
  const tag = u32(d);
  const authorities = (staker: string, withdrawer: string, how: string) =>
    c.f(
      ok(c, staker) && ok(c, withdrawer) ? "info" : "critical",
      "STAKE_AUTHORITY_CHANGE",
      `${how} stake ${acc[0]} with staker ${staker} and withdrawer ${withdrawer}`,
      at,
    );
  if (tag === 0 && d.length >= 68) authorities(key(d, 4), key(d, 36), "initialize");
  else if (tag === 9) authorities(acc[2] ?? "?", acc[3] ?? "?", "initialize (checked)");
  else if (tag === 1 && d.length >= 40) {
    const to = key(d, 4);
    const kind = u32(d, 36) === 1 ? "Withdrawer" : "Staker";
    c.f(ok(c, to) ? "info" : "critical", "STAKE_AUTHORITY_CHANGE", `stake ${acc[0]} ${kind} authority → ${to}`, at);
  } else if (tag === 10 && d.length >= 8) {
    const kind = u32(d, 4) === 1 ? "Withdrawer" : "Staker";
    // The program takes the Clock sysvar at position 1 when it is passed; without it the new authority moves up.
    const to = (acc[1] === CLOCK ? acc[3] : acc[2]) ?? "?";
    c.f(
      ok(c, to) ? "info" : "critical",
      "STAKE_AUTHORITY_CHANGE",
      `stake ${acc[0]} ${kind} authority → ${to} (checked)`,
      at,
    );
  } else if (tag === 8 || tag === 11)
    c.f("critical", "STAKE_AUTHORITY_CHANGE", `stake authorize-with-seed on ${acc[0]}`, at);
  else if (tag === 4 && d.length >= 12)
    c.f(
      ok(c, acc[1]) ? "info" : "high",
      "STAKE_WITHDRAW",
      `withdraw ${sol(u64(d, 4))} SOL from stake ${acc[0]} → ${acc[1]}`,
      at,
    );
  else if (tag === 6 || tag === 12) c.f("high", "STAKE_LOCKUP_CHANGE", `lockup or custodian change on ${acc[0]}`, at);
  else if (tag === 3 || tag === 16 || tag === 17)
    c.f("medium", "STAKE_MOVE", `moves stake or lamports out of ${acc[0]} into ${acc[1]}`, at);
  else if ([2, 5, 7, 13, 14, 15].includes(tag)) c.f("info", "STAKE_OTHER", `stake instruction ${tag} on ${acc[0]}`, at);
  else unrecognized(c, "Stake", tag, at);
}

function tokenIx(prog: string, acc: string[], d: Uint8Array, at: string, c: Ctx, depth = 0): void {
  const tag = d[0]!;
  const t22 = prog === PROGRAMS.token2022;
  if (TOKEN_BENIGN[tag]) {
    c.f("info", "TOKEN_OTHER", `${TOKEN_BENIGN[tag]} on ${acc[0]}`, at);
    return;
  }
  if (tag === 6 && d.length >= 3) {
    const kind = TOKEN_AUTHORITY[d[1]!] ?? `type ${d[1]}`;
    const to = d[2] === 1 && d.length >= 35 ? key(d, 3) : null;
    const grave = ["AccountOwner", "CloseAccount", "MintTokens", "FreezeAccount", "PermanentDelegate"].includes(kind);
    c.f(
      to && c.allow.has(to) ? "info" : grave ? "critical" : "high",
      "TOKEN_SET_AUTHORITY",
      `SetAuthority ${kind} on ${acc[0]} → ${to ?? "none"}${!t22 && kind === "AccountOwner" ? " (legacy SPL Token allows this even on associated token accounts)" : ""}`,
      at,
    );
  } else if ((tag === 4 || tag === 13) && d.length >= 9) {
    const amount = u64(d, 1);
    const delegate = tag === 4 ? acc[1] : acc[2];
    const max = amount === 2n ** 64n - 1n;
    c.f(
      max ? "critical" : "high",
      "TOKEN_APPROVE",
      `Approve ${delegate} for ${max ? "an unlimited amount" : amount} on ${acc[0]}`,
      at,
    );
  } else if (tag === 9)
    c.f(ok(c, acc[1]) ? "info" : "high", "TOKEN_CLOSE", `CloseAccount ${acc[0]}: its lamports go to ${acc[1]}`, at);
  else if ((tag === 3 || tag === 12) && d.length >= 9) {
    const dest = tag === 3 ? acc[1] : acc[2];
    c.f(
      c.allow.has(dest!) ? "info" : "high",
      "TOKEN_TRANSFER",
      `token transfer of raw amount ${u64(d, 1)} from ${acc[0]} → ${dest}`,
      at,
    );
  } else if ((tag === 7 || tag === 14) && d.length >= 9)
    c.f("high", "TOKEN_MINT", `mint raw amount ${u64(d, 1)} of ${acc[0]} → ${acc[1]}`, at);
  else if ((tag === 8 || tag === 15) && d.length >= 9)
    c.f("medium", "TOKEN_BURN", `burn raw amount ${u64(d, 1)} from ${acc[0]}`, at);
  else if (tag === 10) c.f("medium", "TOKEN_FREEZE", `freeze ${acc[0]}`, at);
  else if (t22 && tag === 26 && d.length >= 2) {
    const sub = d[1]!;
    if (sub === 1 && d.length >= 19)
      c.f(
        c.allow.has(acc[2]!) ? "info" : "high",
        "TOKEN_TRANSFER",
        `TransferCheckedWithFee of raw amount ${u64(d, 2)} from ${acc[0]} → ${acc[2]}`,
        at,
      );
    else if (sub === 2 || sub === 3)
      c.f("high", "TOKEN_WITHHELD_WITHDRAW", `withdraw withheld transfer fees → ${acc[1]}`, at);
    else if (sub === 0 || sub === 4) c.f("info", "TOKEN_OTHER", `transfer-fee extension instruction ${sub}`, at);
    else c.f("medium", "TOKEN_FEE_CONFIG", `transfer-fee extension instruction ${sub} on ${acc[0]}`, at);
  } else if (t22 && tag === 38)
    c.f("high", "TOKEN_WITHDRAW_EXCESS_LAMPORTS", `withdraw excess lamports from ${acc[0]} → ${acc[1]}`, at);
  else if (tag === 45 && d.length >= 2) {
    // unwrap_lamports: native SOL out of a wrapped-SOL account, all of it when no amount is given.
    const amount = d[1] === 1 && d.length >= 10 ? u64(d, 2) : null;
    if (amount !== null) c.out(amount, acc[2]);
    c.f(
      ok(c, acc[1]) ? "info" : amount === null ? "critical" : "high",
      "TOKEN_UNWRAP_LAMPORTS",
      `unwrap ${amount === null ? "the whole balance" : `${sol(amount)} SOL`} of ${acc[0]} → ${acc[1]}`,
      at,
    );
  } else if (tag === 255) {
    if (depth > 0) {
      c.f(
        "critical",
        "TOKEN_BATCH_NESTED",
        "a batch inside a batch, which the program rejects; the bytes are not what they claim",
        at,
      );
      return;
    }
    // batch: [u8 accounts, u8 length, data] records; each takes the next accounts in order.
    let p = 1;
    let k = 0;
    let j = 0;
    while (p < d.length) {
      const nAcc = d[p]!;
      const len = d[p + 1];
      if (len === undefined || p + 2 + len > d.length) {
        c.f("high", "MALFORMED_INSTRUCTION", "token batch record runs past the instruction data", at);
        return;
      }
      const sub = d.subarray(p + 2, p + 2 + len);
      if (sub.length) tokenIx(prog, acc.slice(k, k + nAcc), sub, `${at}.batch${j}`, c, depth + 1);
      k += nAcc;
      p += 2 + len;
      j++;
    }
  } else unrecognized(c, t22 ? "Token-2022" : "Token", tag, at);
}

function loaderIx(acc: string[], d: Uint8Array, at: string, c: Ctx): void {
  const tag = u32(d);
  const names: Record<number, string> = {
    3: "Upgrade",
    4: "SetAuthority",
    5: "Close",
    7: "SetAuthorityChecked",
    8: "Migrate",
  };
  if (names[tag])
    c.f("critical", "PROGRAM_AUTHORITY_OR_CODE_CHANGE", `upgradeable loader ${names[tag]} on ${acc[0] ?? "?"}`, at);
  else if (tag === 6 || tag === 9)
    c.f(
      c.mine.has(acc[tag === 6 ? 3 : 4] ?? "") ? "high" : "medium",
      "PROGRAM_EXTEND",
      `ExtendProgram charges ${acc[tag === 6 ? 3 : 4] ?? "the payer"} rent for ${acc[0]}'s data; the upgrade authority can reclaim it with Close`,
      at,
    );
  else if (tag === 0 || tag === 1) c.f("info", "PROGRAM_BUFFER", `program buffer write on ${acc[0]}`, at);
  else if (tag === 2) c.f("medium", "PROGRAM_DEPLOY", `deploys a program from ${acc[2] ?? "a buffer"}`, at);
  else unrecognized(c, "upgradeable loader", tag, at);
}

/** Squads v4 TransactionMessage: u8 counts, u8-prefixed keys and instructions, u16-prefixed data, then lookups. */
function squadsMessage(msg: Uint8Array) {
  let p = 0;
  const numSigners = msg[p++]!;
  p += 2;
  const nKeys = msg[p++]!;
  const keys: string[] = [];
  for (let i = 0; i < nKeys; i++, p += 32) keys.push(key(msg, p));
  const nIx = msg[p++]!;
  const ixs: { program: string | null; accounts: (string | null)[]; data: Uint8Array }[] = [];
  for (let i = 0; i < nIx; i++) {
    const pid = msg[p++]!;
    const nAcc = msg[p++]!;
    const accounts = [...msg.subarray(p, p + nAcc)].map((k) => keys[k] ?? null);
    p += nAcc;
    const len = msg[p]! | (msg[p + 1]! << 8);
    p += 2;
    ixs.push({ program: keys[pid] ?? null, accounts, data: msg.subarray(p, p + len) });
    p += len;
  }
  return { numSigners, keys, ixs, lookups: p < msg.length ? msg[p]! : 0 };
}

function squadsIx(acc: string[], d: Uint8Array, at: string, c: Ctx): void {
  const name = SQUADS.get(bytesToHex(d.subarray(0, 8)));
  const inner = (offset: number) => {
    if (d.length < offset + 4) return;
    const len = u32(d, offset);
    let parsed: ReturnType<typeof squadsMessage>;
    try {
      parsed = squadsMessage(d.subarray(offset + 4, offset + 4 + len));
    } catch {
      c.f("high", "SQUADS_INNER_UNREADABLE", "the vault message does not parse", at);
      return;
    }
    c.f(
      "high",
      "SQUADS_VAULT_TX_CREATE",
      `a vault transaction with ${parsed.ixs.length} inner instruction(s): read the inner message, not the wrapper`,
      at,
    );
    if (parsed.lookups)
      c.f(
        "high",
        "LOOKUP_TABLES",
        `the vault message loads accounts from ${parsed.lookups} lookup table(s); resolve them before signing`,
        at,
      );
    // Inside the vault, the signers are the vault and its ephemeral PDAs.
    const vault: Ctx = { ...c, mine: new Set(parsed.keys.slice(0, parsed.numSigners)) };
    parsed.ixs.forEach((x, j) => {
      const where = `${at}.inner${j}`;
      if (!x.program) {
        c.f("high", "SQUADS_INNER_UNRESOLVED", "an inner program id comes from a lookup table", where);
        return;
      }
      const admin = ADMIN_CALLS.get(bytesToHex(x.data.subarray(0, 8)));
      if (admin) {
        c.f(
          "critical",
          "GOVERNANCE_AUTHORITY_TRANSFER",
          `${x.program} :: ${admin}(${x.data.length >= 40 ? key(x.data, 8) : "?"}) inside the vault`,
          where,
        );
        return;
      }
      if (KNOWN.has(x.program))
        instruction(
          x.program,
          x.accounts.map((a) => a ?? "?"),
          x.data,
          where,
          -1,
          vault,
        );
      else
        c.f(
          "high",
          "SQUADS_INNER_UNKNOWN",
          `${x.program} with data ${bytesToHex(x.data.subarray(0, 8))}… inside the vault`,
          where,
        );
    });
  };
  switch (name) {
    case "vault_transaction_create":
      return inner(10);
    case "batch_add_transaction":
      return inner(9);
    case "transaction_buffer_create":
    case "transaction_buffer_extend":
    case "vault_transaction_create_from_buffer":
      return c.f(
        "high",
        "SQUADS_BUFFER",
        `Squads ${name}: the vault message is assembled from a buffer; fetch it, check final_buffer_hash and read it before signing`,
        at,
      );
    case "config_transaction_create":
    case "multisig_add_member":
    case "multisig_remove_member":
    case "multisig_change_threshold":
    case "multisig_set_time_lock":
    case "multisig_set_config_authority":
    case "multisig_add_spending_limit":
      return c.f(
        "critical",
        "SQUADS_CONFIG_CHANGE",
        `Squads ${name}: members, threshold, timelock, config authority or a vote-free spending limit`,
        at,
      );
    case "multisig_set_rent_collector":
    case "program_config_set_authority":
    case "program_config_set_treasury":
      return c.f("high", "SQUADS_CONFIG_CHANGE", `Squads ${name}`, at);
    case "vault_transaction_execute":
    case "config_transaction_execute":
    case "batch_execute_transaction":
      return c.f(
        "high",
        "SQUADS_EXECUTE",
        `Squads ${name}: executes at once if the threshold is met and the timelock is zero`,
        at,
      );
    case "spending_limit_use":
      return c.f(
        "high",
        "SQUADS_SPENDING_LIMIT_USE",
        `spends raw amount ${d.length >= 16 ? u64(d, 8) : "?"} from the vault without a vote → ${acc[8] ?? acc[4] ?? "?"}`,
        at,
      );
    case "proposal_approve":
      return c.f("medium", "SQUADS_APPROVE", "Squads proposal_approve", at);
    case undefined:
      return c.f(
        "high",
        "UNRECOGNIZED_INSTRUCTION",
        `Squads instruction ${bytesToHex(d.subarray(0, 8))} is not one this check reads`,
        at,
      );
    default:
      return c.f("info", "SQUADS_OTHER", `Squads ${name}`, at);
  }
}

function instruction(prog: string, acc: string[], d: Uint8Array, at: string, index: number, c: Ctx): void {
  try {
    if (prog === PROGRAMS.system && d.length >= 4) systemIx(acc, d, at, index, c);
    else if (prog === PROGRAMS.stake && d.length >= 4) stakeIx(acc, d, at, c);
    else if ((prog === PROGRAMS.token || prog === PROGRAMS.token2022) && d.length) tokenIx(prog, acc, d, at, c);
    else if (prog === PROGRAMS.bpfUpgradeable && d.length >= 4) loaderIx(acc, d, at, c);
    else if (prog === PROGRAMS.squadsV4 && d.length >= 8) squadsIx(acc, d, at, c);
    else if (prog === PROGRAMS.lookupTable && d.length >= 4 && u32(d) === 4)
      c.f(
        ok(c, acc[2]) ? "info" : "medium",
        "LOOKUP_TABLE_CLOSE",
        `closes lookup table ${acc[0]}; its rent goes to ${acc[2]}`,
        at,
      );
    else if (
      [PROGRAMS.system, PROGRAMS.stake, PROGRAMS.token, PROGRAMS.token2022, PROGRAMS.bpfUpgradeable].includes(
        prog as never,
      )
    )
      c.f("high", "MALFORMED_INSTRUCTION", `${prog} instruction with too little data`, at);
  } catch {
    c.f("high", "MALFORMED_INSTRUCTION", `instruction data for ${prog} is shorter than its layout`, at);
  }
}

/**
 * A static pre-signing check of a Solana transaction. It reads instruction data the way the programs do and flags
 * what can move funds or authority later: durable nonces, account creation and Assign, SetAuthority, Approve, stake
 * authorities, loader upgrades, priority fees and Squads vault messages (decoded with the same rules). An
 * instruction it does not read is reported, not passed. Actions hidden inside cross-program calls need simulation;
 * the check says so.
 */
export function checkSolanaTransaction(raw: Uint8Array, policy: SolPolicy = {}): SolReport {
  const { message: m } = decodeSolanaTransaction(raw);
  const total = m.staticKeys.length + m.lookups.reduce((n, l) => n + l.writable.length + l.readonly.length, 0);
  const keys = (i: number) => (i < m.staticKeys.length ? m.staticKeys[i]! : `lookup#${i - m.staticKeys.length}`);
  const signers = m.staticKeys.slice(0, m.header.numRequiredSignatures);
  const mine = new Set(policy.signers ?? signers);
  const allow = new Set(policy.allowlist ?? []);
  const findings: SolFinding[] = [];
  let outLamports = 0n;
  const c: Ctx = {
    mine,
    allow,
    policy,
    f: (severity, code, message, instruction) => findings.push({ severity, code, message, instruction }),
    out: (lamports, from) => {
      if (from && mine.has(from)) outLamports += lamports;
    },
  };

  if (m.lookups.length)
    c.f(
      "high",
      "LOOKUP_TABLES",
      `${total - m.staticKeys.length} account(s) come from address lookup tables; resolve them against chain state before signing`,
      "message",
    );

  let durable: SolReport["durableNonce"];
  const first = m.instructions[0];
  if (first && keys(first.programIdIndex) === PROGRAMS.system && first.data.length >= 4 && u32(first.data) === 4) {
    // The runtime accepts AdvanceNonce when the stored authority is any signer of the instruction, not only account 2.
    const ixSigners = [...new Set(first.accounts.filter((a) => keyFlags(m, a).signer).map(keys))];
    const authority = first.accounts.length > 2 ? keys(first.accounts[2]!) : null;
    durable = { account: keys(first.accounts[0]!), authority, signers: ixSigners };
    const own = !!policy.template && ixSigners.length === 1 && ixSigners[0] === policy.template.nonceAuthority;
    c.f(
      own ? "info" : ixSigners.some((s) => mine.has(s)) ? "high" : "critical",
      "DURABLE_NONCE",
      `never expires until nonce account ${durable.account} is advanced; signers on that instruction: ${ixSigners.join(", ") || "none"}; the blockhash field is the stored nonce`,
      "ix0",
    );
  }

  let cuLimit: bigint | null = null;
  let cuPrice = 0n;
  m.instructions.forEach((ix, i) => {
    const at = `ix${i}`;
    const prog = keys(ix.programIdIndex);
    const acc = ix.accounts.map(keys);
    const d = ix.data;
    if (prog === PROGRAMS.computeBudget) {
      if (d[0] === 2 && d.length >= 5) cuLimit = BigInt(u32(d, 1));
      else if (d[0] === 3 && d.length >= 9) cuPrice = u64(d, 1);
      return;
    }
    if (KNOWN.has(prog)) return instruction(prog, acc, d, at, i, c);
    const signerAccs = ix.accounts.filter((a) => keyFlags(m, a).signer).map(keys);
    const yours = signerAccs.filter((a) => mine.has(a));
    const others = signerAccs.filter((a) => !mine.has(a));
    if (yours.length)
      c.f(
        "critical",
        "UNKNOWN_PROGRAM_WITH_SIGNER",
        `${prog} receives your signature (${yours.join(", ")}); through cross-program calls it can transfer, Approve, SetAuthority or Assign. Simulate before signing`,
        at,
      );
    else if (others.length)
      c.f(
        "medium",
        "UNKNOWN_PROGRAM_WITH_COSIGNER",
        `${prog} receives a co-signer's signature (${others.join(", ")})`,
        at,
      );
    else c.f("medium", "UNKNOWN_PROGRAM", `${prog}, no signer passed`, at);
  });

  // The fee: 5,000 lamports per signature plus the priority fee over the compute-unit limit (all of it to the leader).
  const limit: bigint = cuLimit ?? DEFAULT_CU_LIMIT;
  const priority = (limit * cuPrice + 999_999n) / 1_000_000n;
  const fee = 5_000n * BigInt(m.header.numRequiredSignatures) + priority;
  c.out(fee, m.staticKeys[0]);
  if (priority > PRIORITY_FEE_CAP)
    c.f(
      "high",
      "PRIORITY_FEE",
      `priority fee of up to ${sol(priority)} SOL (${limit} units at ${cuPrice} micro-lamports)`,
      "ComputeBudget",
    );

  if (policy.template) {
    if (!durable)
      c.f(
        "critical",
        "TEMPLATE_DRIFT",
        `this signer's routine transactions advance a durable nonce whose authority is ${policy.template.nonceAuthority}; this one uses a recent blockhash`,
        "message",
      );
    else if (!(durable.signers.length === 1 && durable.signers[0] === policy.template.nonceAuthority))
      c.f(
        "critical",
        "TEMPLATE_DRIFT",
        `the nonce instruction's signers (${durable.signers.join(", ") || "none"}) are not exactly the routine authority`,
        "ix0",
      );
  }
  if (policy.balance && policy.balance.lamports > 0n) {
    const max = policy.balance.maxFraction ?? 0.2;
    const share = Number((outLamports * 10_000n) / policy.balance.lamports) / 10_000;
    if (share >= max)
      c.f(
        "critical",
        "BALANCE_FRACTION",
        `moves ${(share * 100).toFixed(1)}% of the signer's SOL (${sol(outLamports)} of ${sol(policy.balance.lamports)})`,
        "message",
      );
  }
  const live = findings.filter((x) => x.severity !== "info");
  const ownTemplate =
    !!durable &&
    !!policy.template &&
    durable.signers.length === 1 &&
    durable.signers[0] === policy.template.nonceAuthority;
  if (durable && !ownTemplate && live.some((x) => PRIVILEGED.has(x.code)))
    c.f(
      "critical",
      "DURABLE_NONCE_ON_PRIVILEGED_ACTION",
      "an authority change bound to a durable nonce can be executed whenever the holder of the signed bytes chooses",
      "message",
    );
  const codes = new Set(live.map((x) => x.code));
  if (codes.has("SQUADS_APPROVE") && codes.has("SQUADS_EXECUTE"))
    c.f(
      "high",
      "APPROVE_AND_EXECUTE_SAME_TX",
      "approval and execution in one transaction leave no window to react",
      "message",
    );
  const authorityChanges = live.filter(
    (x) => x.code === "STAKE_AUTHORITY_CHANGE" || x.code === "TOKEN_SET_AUTHORITY",
  ).length;
  if (authorityChanges >= 2)
    c.f("critical", "BULK_AUTHORITY_CHANGE", `${authorityChanges} authority changes in one transaction`, "message");

  const rank: Record<SolSeverity, number> = { critical: 0, high: 1, medium: 2, info: 3 };
  findings.sort((a, b) => rank[a.severity] - rank[b.severity]);
  const verdict = findings.some((x) => x.severity === "critical")
    ? "BLOCK"
    : findings.some((x) => x.severity === "high")
      ? "REVIEW"
      : "OK";
  return {
    verdict,
    findings,
    message: m,
    feePayer: m.staticKeys[0]!,
    signers,
    durableNonce: durable,
    outLamports,
    messageHash: base58.encode(sha256(m.bytes)),
  };
}

/** Nonce accounts are 80 bytes; the authority sits at offset 8. A getProgramAccounts filter lists every one a key controls. */
export function nonceAccountsFilter(authority: string) {
  return [{ dataSize: 80 }, { memcmp: { offset: 8, bytes: authority } }];
}

export function isSystemAdvanceNonce(m: SolanaMessage): boolean {
  const ix = m.instructions[0];
  return (
    !!ix &&
    m.staticKeys[ix.programIdIndex] === PROGRAMS.system &&
    equalBytes(ix.data.subarray(0, 4), Uint8Array.of(4, 0, 0, 0))
  );
}
