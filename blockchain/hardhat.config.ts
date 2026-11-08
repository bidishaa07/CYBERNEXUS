import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import * as dotenv from "dotenv";

dotenv.config({ path: "../.env" });

const rpcUrl = process.env.BLOCKCHAIN_RPC_URL || "";
const privateKey = process.env.BLOCKCHAIN_PRIVATE_KEY || "";
const chainId = Number(process.env.BLOCKCHAIN_CHAIN_ID || "11155111");

const config: HardhatUserConfig = {
  solidity: { version: "0.8.24", settings: { optimizer: { enabled: true, runs: 200 } } },
  networks: {
    hardhat: {},
    sepolia: {
      url: rpcUrl,
      chainId,
      accounts: privateKey ? [privateKey] : []
    }
  },
  etherscan: { apiKey: process.env.ETHERSCAN_API_KEY || "" }
};

export default config;
