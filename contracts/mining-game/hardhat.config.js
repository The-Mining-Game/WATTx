import "@nomicfoundation/hardhat-toolbox";
import dotenv from "dotenv";
dotenv.config();

/** @type import('hardhat/config').HardhatUserConfig */
export default {
  solidity: {
    version: "0.8.24",
    settings: {
      viaIR: true,
      optimizer: {
        enabled: true,
        runs: 200,
      },
    },
  },
  networks: {
    hardhat: {
      chainId: 31337,
    },
    localhost: {
      url: "http://127.0.0.1:8545",
    },
    // WATTx EVM (Local regtest, via janus). Chain ids MUST match janus
    // pkg/qtum/qtum.go ChainId(): main 22356 / test 22357 / regtest 22358.
    // The old 7979 collided with DOS Chain in the chainlist registry.
    wattx_local: {
      url: process.env.WATTX_LOCAL_RPC || "http://127.0.0.1:23890",
      chainId: 22358,
      // "remote" = let the WATTx node sign. An empty array would still install
      // hardhat's local-accounts provider, which rejects any address it has no
      // key for -- and the node's wallet is exactly that (no key export, the
      // daemon is built without BDB, so descriptor wallets only).
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : "remote",
    },
    // WATTx EVM (Testnet)
    wattx_testnet: {
      url: process.env.WATTX_TESTNET_RPC || "http://testnet.wattx.io:8545",
      chainId: 22357,
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : [],
    },
    // WATTx EVM (Mainnet)
    wattx_mainnet: {
      url: process.env.WATTX_MAINNET_RPC || "http://mainnet.wattx.io:8545",
      chainId: 22356,
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : [],
    },
    // Polygon (where existing contracts are deployed)
    polygon: {
      // polygon-rpc.com is dead (401 "API key disabled")
      url: process.env.POLYGON_RPC || "https://polygon.drpc.org",
      chainId: 137,
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : [],
    },
    polygon_mumbai: {
      url: process.env.POLYGON_MUMBAI_RPC || "https://rpc-mumbai.maticvigil.com",
      chainId: 80001,
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : [],
    },
    // Altcoinchain
    altcoinchain: {
      url: process.env.ALTCOINCHAIN_RPC || "http://127.0.0.1:8646",
      chainId: 2330,
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : [],
    },
  },
  etherscan: {
    apiKey: {
      polygon: process.env.POLYGONSCAN_API_KEY || "",
      polygonMumbai: process.env.POLYGONSCAN_API_KEY || "",
    },
  },
  paths: {
    sources: "./contracts",
    tests: "./test",
    cache: "./cache",
    artifacts: "./artifacts",
  },
};
