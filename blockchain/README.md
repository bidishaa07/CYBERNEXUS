# ThreatIntelligence contract

This is an independent Hardhat project for the CYBERNEXUS decentralized threat-intelligence commitment layer. The existing application backend is FastAPI/SQLAlchemy rather than NestJS/Prisma; deployment artifacts are copied to `backend/app/artifacts/` for that Python integration boundary.

## Safety

- Use a dedicated Sepolia test wallet only.
- Fund it with Sepolia ETH.
- Put `BLOCKCHAIN_PRIVATE_KEY` only in the ignored repository-root `.env`; never commit it or send it in chat.
- The contract stores commitments and minimal metadata only. Do not put reports, email content, personal information or private evidence on-chain.
- The deployment script validates Sepolia chain ID `11155111`, checks the signer balance, waits for two confirmations and writes the real address only after confirmation.

## Setup

From `blockchain/`:

```powershell
npm install
```

Configure the repository-root `.env`:

```env
BLOCKCHAIN_RPC_URL=https://eth-sepolia.g.alchemy.com/v2/YOUR_ALCHEMY_KEY
BLOCKCHAIN_PRIVATE_KEY=0xYOUR_DEDICATED_SEPOLIA_TEST_WALLET_KEY
BLOCKCHAIN_CHAIN_ID=11155111
BLOCKCHAIN_NETWORK_KEY=sepolia
BLOCKCHAIN_NETWORK_NAME=sepolia
ETHERSCAN_API_KEY=
```

The private key is used only by the local deployment process and is not used by the backend runtime.

## Backend integration

After a confirmed deployment, the deploy script writes `backend/app/artifacts/ThreatIntelligence.json`. The FastAPI adapter uses that ABI and the configured contract address. Administrator-only endpoints are available through the existing API:

- `GET /api/threat-intelligence/blockchain/status` validates RPC reachability, chain ID and deployed bytecode without exposing secrets.
- `POST /api/threat-intelligence/reports/{report_id}/revisions/{revision_id}/blockchain/submit` submits an approved local revision through the configured testnet signer and persists transaction metadata.
- `GET /api/threat-intelligence/blockchain/transactions/{transaction_id}` refreshes the receipt and confirmation state.

Transactions are marked `CONFIRMED` only when the receipt succeeds, the configured confirmation count is reached and the expected `ReportAnchored` or `RevisionAnchored` event matches the report and commitment. RPC failures remain `UNKNOWN`; no duplicate submission is performed for an existing pending/submitted transaction.

## Compile and test

```powershell
npm run build
npm test
```

Tests cover initial anchoring, duplicate rejection, hash verification, revisions, validation/dispute events, authorization and invalid inputs.

## Deploy to Sepolia

```powershell
npm run deploy:sepolia
```

The command prints the confirmed deployment transaction hash and contract address, writes `backend/app/artifacts/ThreatIntelligence.json`, and updates the local ignored `.env` with `BLOCKCHAIN_CONTRACT_ADDRESS`. It fails closed if the signer is missing, the chain is not Sepolia, or the wallet has no Sepolia ETH.

## Verify on Etherscan

After deployment, set `ETHERSCAN_API_KEY` locally and run:

```powershell
npx hardhat verify --network sepolia DEPLOYED_ADDRESS DEPLOYER_ADDRESS
```

Never claim deployment success from a printed or copied address alone; verify the transaction receipt and address on Sepolia.
