import type { Hex } from "./bytes.js";

export type DelegateVerdict = "malicious" | "wallet";

export interface DelegateEntry {
  address: string;
  /** Chain ids the entry was observed on, or "any". The same address can hold different code on each chain. */
  chains: "any" | number[];
  /** keccak256 of the runtime code where it was observed. A match by address alone is weaker than a codehash match. */
  codehash?: Hex;
  verdict: DelegateVerdict;
  label: string;
  /** Where the entry comes from: a transaction hash, a spec, or a vendor document. */
  source: string;
  notes?: string;
}

/**
 * Delegates seen in the wild. "wallet" means a widely deployed wallet delegate, not "safe": anyone who can sign for
 * a key can delegate it to a wallet delegate and then move funds through that delegate's batch execution.
 */
export const DELEGATES: readonly DelegateEntry[] = [
  {
    address: "0x63e842B054Bd624a465454D533C33F573e9c6fAe",
    chains: [1],
    codehash: "0x7de93915e2660a045483ed0a02aef8c882d62179d69702e21cd4c97a92870e5d",
    verdict: "malicious",
    label: "sweeper v2 of the 2026-10-29 hot-wallet drain",
    source: "0xad99264d5532ae0dd04b2004eebda05f25657e70dacb764f7ac8d4ccd051298b",
    notes:
      "1,674-byte runtime. One hardcoded caller (0x7C8601d4645b93cea45F71e118A729332e6B5CA0), sweep(address,address[]) and callExecute(address,address,uint256,bytes), keeps 1 ETH behind.",
  },
  {
    address: "0x19beE294A6DaAb49c9e5Ab69A5Da6C035C70f2bf",
    chains: [1],
    codehash: "0xa42078db11cfbd35decee884187db19554fd1bce19223588b9f1c393eadac742",
    verdict: "malicious",
    label: "sweeper v1 of the 2026-10-29 hot-wallet drain (rehearsals)",
    source: "0x6b76e8748ba1c6bc81e674c830a0b3603db6bde04ec4bd4a2d3126c1a12706d8",
    notes: "1,256-byte runtime, same caller as v2, no callExecute. Used on the attacker's own test wallets.",
  },
  {
    address: "0x84D05511614272694D3a9cebE896514DBDE51F40",
    chains: [1],
    codehash: "0xcec1a70dd492f9f27ed0f1059c1e6e79c3c771a9226e3c22705d9c5d1a7ecba1",
    verdict: "malicious",
    label: "CrimeEnjoyor ETH sweeper",
    source: "Verified source on Etherscan; Wintermute's write-up of 7702 drainers (2025)",
    notes:
      "1,042-byte runtime. Forwards any ETH it receives to a destination held in storage: no token selectors and no hardcoded address, so the static traits do not flag it. Clones match by codehash.",
  },
  {
    address: "0x4Cd241E8d1510e30b2076397afc7508Ae59C66c9",
    chains: "any",
    verdict: "wallet",
    label: "Simple7702Account (eth-infinitism)",
    source: "eth-infinitism/account-abstraction; Ledger app-ethereum default 7702 allowlist",
  },
  {
    address: "0x63c0c19a282a1B52b07dD5a65b58948A07DAE32B",
    chains: "any",
    verdict: "wallet",
    label: "MetaMask EIP-7702 delegator",
    source: "MetaMask delegation framework",
    notes: "Most common wallet delegate on mainnet. Not on Ledger's current 7702 allowlist.",
  },
];

export function lookupDelegate(
  address: string,
  registry: readonly DelegateEntry[] = DELEGATES,
): DelegateEntry | undefined {
  const a = address.toLowerCase();
  return registry.find((e) => e.address.toLowerCase() === a);
}

export function lookupCodehash(
  codehash: string,
  registry: readonly DelegateEntry[] = DELEGATES,
): DelegateEntry | undefined {
  const h = codehash.toLowerCase();
  return registry.find((e) => e.codehash?.toLowerCase() === h);
}
