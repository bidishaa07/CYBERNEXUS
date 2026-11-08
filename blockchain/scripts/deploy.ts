import { ethers, artifacts } from "hardhat";
import * as fs from "fs";
import * as path from "path";
import * as dotenv from "dotenv";

dotenv.config({ path: path.resolve(__dirname, "../../.env") });

async function main() {
  const rpc = process.env.BLOCKCHAIN_RPC_URL || "";
  const privateKey = process.env.BLOCKCHAIN_PRIVATE_KEY || "";
  const expectedChainId = Number(process.env.BLOCKCHAIN_CHAIN_ID || "11155111");
  if (!rpc) throw new Error("BLOCKCHAIN_RPC_URL is required");
  if (!/^0x[0-9a-fA-F]{64}$/.test(privateKey)) throw new Error("BLOCKCHAIN_PRIVATE_KEY must be a 32-byte hex private key in the local ignored .env");
  if (expectedChainId !== 11155111) throw new Error("Deployment is restricted to Ethereum Sepolia (chain ID 11155111)");

  const network = await ethers.provider.getNetwork();
  if (Number(network.chainId) !== expectedChainId) throw new Error(`Connected chain ${network.chainId} does not match configured chain ${expectedChainId}`);
  const [deployer] = await ethers.getSigners();
  if (!deployer) throw new Error("No deployer signer is available");
  const balance = await ethers.provider.getBalance(deployer.address);
  if (balance === 0n) throw new Error(`Deployer ${deployer.address} has no Sepolia ETH for deployment`);
  console.log(`Deploying from ${deployer.address} on chain ${network.chainId}`);
  console.log(`Deployer balance: ${ethers.formatEther(balance)} ETH`);

  const factory = await ethers.getContractFactory("ThreatIntelligence", deployer);
  const contract = await factory.deploy(deployer.address);
  const deployment = contract.deploymentTransaction();
  if (!deployment) throw new Error("Deployment transaction was not created");
  console.log(`Deployment transaction: ${deployment.hash}`);
  await deployment.wait(2);
  const address = await contract.getAddress();
  console.log(`Contract address: ${address}`);

  const artifact = await artifacts.readArtifact("ThreatIntelligence");
  const outputDir = path.resolve(__dirname, "../../backend/app/artifacts");
  fs.mkdirSync(outputDir, { recursive: true });
  fs.writeFileSync(path.join(outputDir, "ThreatIntelligence.json"), JSON.stringify({ address, abi: artifact.abi, network: "sepolia", chainId: expectedChainId, deploymentTransaction: deployment.hash }, null, 2) + "\n", { encoding: "utf8", mode: 0o600 });

  const envPath = path.resolve(__dirname, "../../.env");
  if (fs.existsSync(envPath)) {
    const current = fs.readFileSync(envPath, "utf8");
    const line = `BLOCKCHAIN_CONTRACT_ADDRESS=${address}`;
    const updated = /^BLOCKCHAIN_CONTRACT_ADDRESS=.*$/m.test(current)
      ? current.replace(/^BLOCKCHAIN_CONTRACT_ADDRESS=.*$/m, line)
      : `${current.trimEnd()}\n${line}\n`;
    fs.writeFileSync(envPath, updated, { encoding: "utf8", mode: 0o600 });
  }
  console.log(`ABI written to ${path.relative(process.cwd(), path.join(outputDir, "ThreatIntelligence.json"))}`);
  console.log("Deployment confirmed with 2 block confirmations.");
}

main().catch((error) => { console.error(error instanceof Error ? error.message : "Deployment failed"); process.exitCode = 1; });
