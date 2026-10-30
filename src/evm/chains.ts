export interface Chain {
  id: number;
  key: string;
  name: string;
  /** Keyless public endpoints, tried in order. All answer CORS requests from browsers. */
  rpc: string[];
  /** Keyless endpoints that serve historical state (eth_getTransactionCount / eth_getCode at old blocks). */
  archive?: string[];
  explorer: string;
}

/** EVM chains to scan. A 0xef0100 designator can only exist where EIP-7702 is live; elsewhere the prefix is banned. */
export const CHAINS: readonly Chain[] = [
  {
    id: 1,
    key: "ethereum",
    name: "Ethereum",
    rpc: [
      "https://ethereum-rpc.publicnode.com",
      "https://rpc.flashbots.net",
      "https://gateway.tenderly.co/public/mainnet",
    ],
    archive: ["https://gateway.tenderly.co/public/mainnet", "https://eth.drpc.org"],
    explorer: "https://eth.blockscout.com",
  },
  {
    id: 8453,
    key: "base",
    name: "Base",
    rpc: ["https://base-rpc.publicnode.com", "https://mainnet.base.org"],
    explorer: "https://base.blockscout.com",
  },
  {
    id: 42161,
    key: "arbitrum",
    name: "Arbitrum One",
    rpc: ["https://arbitrum-one-rpc.publicnode.com", "https://arb1.arbitrum.io/rpc"],
    explorer: "https://arbitrum.blockscout.com",
  },
  {
    id: 10,
    key: "optimism",
    name: "OP Mainnet",
    rpc: ["https://optimism-rpc.publicnode.com", "https://mainnet.optimism.io"],
    explorer: "https://optimism.blockscout.com",
  },
  {
    id: 56,
    key: "bsc",
    name: "BNB Smart Chain",
    rpc: ["https://bsc-rpc.publicnode.com", "https://bsc-dataseed.bnbchain.org"],
    explorer: "https://bscscan.com",
  },
  {
    id: 137,
    key: "polygon",
    name: "Polygon PoS",
    rpc: ["https://polygon-bor-rpc.publicnode.com", "https://polygon-rpc.com"],
    explorer: "https://polygon.blockscout.com",
  },
  {
    id: 100,
    key: "gnosis",
    name: "Gnosis",
    rpc: ["https://gnosis-rpc.publicnode.com", "https://rpc.gnosischain.com"],
    explorer: "https://gnosis.blockscout.com",
  },
  {
    id: 130,
    key: "unichain",
    name: "Unichain",
    rpc: ["https://unichain-rpc.publicnode.com", "https://mainnet.unichain.org"],
    explorer: "https://unichain.blockscout.com",
  },
  {
    id: 59144,
    key: "linea",
    name: "Linea",
    rpc: ["https://linea-rpc.publicnode.com", "https://rpc.linea.build"],
    explorer: "https://lineascan.build",
  },
  {
    id: 43114,
    key: "avalanche",
    name: "Avalanche C-Chain",
    rpc: ["https://avalanche-c-chain-rpc.publicnode.com", "https://api.avax.network/ext/bc/C/rpc"],
    explorer: "https://snowtrace.io",
  },
  {
    id: 534352,
    key: "scroll",
    name: "Scroll",
    rpc: ["https://scroll-rpc.publicnode.com", "https://rpc.scroll.io"],
    explorer: "https://scroll.blockscout.com",
  },
];

export function findChain(keyOrId: string | number, chains: readonly Chain[] = CHAINS): Chain | undefined {
  const k = String(keyOrId).toLowerCase();
  return chains.find((c) => c.key === k || String(c.id) === k || c.name.toLowerCase() === k);
}

/**
 * Puts your own endpoints first: EF0100_RPC_<KEY> (e.g. EF0100_RPC_ETHEREUM) from the environment, then explicit
 * overrides. A private endpoint is tried for live and historical reads alike; the public ones stay as fallbacks.
 */
export function withRpcOverrides(
  chains: readonly Chain[] = CHAINS,
  env: Record<string, string | undefined> = typeof process === "undefined" ? {} : process.env,
  overrides: Record<string, string | string[]> = {},
): Chain[] {
  return chains.map((c) => {
    const mine = [overrides[c.key], overrides[String(c.id)], env[`EF0100_RPC_${c.key.toUpperCase()}`]]
      .flat()
      .filter((u): u is string => !!u);
    if (!mine.length) return c;
    return { ...c, rpc: [...mine, ...c.rpc], archive: [...mine, ...(c.archive ?? [])] };
  });
}
