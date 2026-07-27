// Deploy the Mining Game contract set onto a WATTx EVM node (via janus).
//
//   npx hardhat run scripts/deploy-wattx.js --network wattx_local
//
// WATTx is Qtum-derived, so the EVM is reached through janus and differs from a
// stock geth node in two ways that shape this script:
//
//   1. There are no unlocked JSON-RPC accounts to enumerate -- `eth_accounts`
//      returns null, so `ethers.getSigners()` is empty. Signing is delegated to
//      the node's own wallet via eth_sendTransaction, which means we address the
//      deployer by its EVM-form (hex) address. Set WATTX_DEPLOYER to the output
//      of `wattx-cli gethexaddress <your base58 address>`.
//   2. On regtest nothing is mined on its own: a sent transaction sits in the
//      mempool forever and `wait()` would hang. So each send is followed by an
//      explicit block generation. Set WATTX_MINE=1 (regtest only).
//
// Deploy order follows the dependency graph: token and NFT first, then the
// contracts that take their addresses, then the wiring (minter/operator grants).
import { execFileSync } from "node:child_process";
import { dirname } from "node:path";
import { writeFileSync } from "node:fs";
import hre from "hardhat";
const { ethers } = hre;

const DEPLOYER = process.env.WATTX_DEPLOYER;
const MINE = process.env.WATTX_MINE === "1";
const CLI = process.env.WATTX_CLI || `${process.env.HOME}/WATTx-testnet/dist/wattx-cli`;
const DATADIR = process.env.WATTX_DATADIR || `${process.env.HOME}/.wattx-rtest`;
const MINE_TO = process.env.WATTX_MINE_TO; // base58 address to receive regtest coinbases

function mine(n = 1) {
  if (!MINE) return;
  execFileSync(CLI, [`-datadir=${DATADIR}`, "-regtest", "generatetoaddress", String(n), MINE_TO],
    { env: { ...process.env, LD_LIBRARY_PATH: dirname(CLI) }, stdio: "ignore" });
}

// Send, then mine, then wait -- in that order, or the wait never resolves.
//
// The address MUST come from the receipt. ethers predicts a contract address
// from (sender, nonce) per Ethereum's CREATE rule, but WATTx/Qtum derives it
// from the creating transaction id instead, so the predicted value is fiction --
// it came back identical for all seven contracts. Rebind to the real address or
// every subsequent call hits a non-contract and reverts with "invalid address".
async function deploy(name, signer, args = []) {
  const factory = await ethers.getContractFactory(name, signer);
  const pending = await factory.deploy(...args);
  mine();
  const receipt = await pending.deploymentTransaction().wait();
  const addr = receipt.contractAddress;
  if (!addr) throw new Error(`${name}: receipt carried no contractAddress`);
  const short = name.split(":").pop();
  console.log(`  ${short.padEnd(16)} ${addr}`);
  return new ethers.Contract(addr, factory.interface, signer);
}

async function send(label, promise) {
  const tx = await promise;
  mine();
  await tx.wait();
  console.log(`  wired: ${label}`);
}

async function main() {
  if (!DEPLOYER) throw new Error("set WATTX_DEPLOYER to the deployer's hex (EVM) address");
  if (MINE && !MINE_TO) throw new Error("set WATTX_MINE_TO to a base58 address for regtest coinbases");

  const net = await ethers.provider.getNetwork();
  const signer = await ethers.provider.getSigner(DEPLOYER);
  const bal = await ethers.provider.getBalance(DEPLOYER);
  console.log(`WATTx EVM chainId ${net.chainId}  block ${await ethers.provider.getBlockNumber()}`);
  console.log(`deployer ${DEPLOYER}  balance ${ethers.formatEther(bal)} WTX\n`);

  // Fully-qualified names: several of these basenames also exist under
  // artifacts/ from other sources, and hardhat refuses an ambiguous lookup.
  console.log("deploying:");
  // The WATTx EVM reports msg.value in SATOSHIS (8 decimals), not wei -- measured,
  // not assumed: 1e18 sent over the RPC arrives as 1e8, a factor of exactly 1e10.
  // So the mint price is constructed satoshi-denominated. Passing an `ether`
  // literal here would demand 1e9 WTX and make minting impossible.
  const WEI_PER_SAT = 10n ** 10n;
  const mintPrice = ethers.parseEther("0.1") / WEI_PER_SAT;   // 0.1 WTX = 1e7 sat

  const watt = await deploy("contracts/testing/MockWATT.sol:MockWATT", signer);
  const wattAddr = await watt.getAddress();
  const nft = await deploy("contracts/nfts/MiningRigNFT.sol:MiningRigNFT", signer, [mintPrice]);
  const gamePool = await deploy("contracts/game/GamePool.sol:GamePool", signer);
  const engine = await deploy("contracts/game/MiningEngine.sol:MiningEngine", signer,
    [wattAddr, await gamePool.getAddress()]);
  const staking = await deploy("contracts/game/StakingPool.sol:StakingPool", signer, [wattAddr]);
  const registry = await deploy("contracts/game/PoolRegistry.sol:PoolRegistry", signer, [wattAddr]);
  const bridge = await deploy("contracts/game/WTXBridge.sol:WTXBridge", signer, [wattAddr]);

  // Same wiring the test suite performs, in the same order.
  console.log("\nwiring:");
  await send("gamePool -> engine", gamePool.setMiningEngine(await engine.getAddress()));
  await send("engine -> staking", engine.setStakingPool(await staking.getAddress()));
  await send("engine accepts rig NFT", engine.addNFTContract(await nft.getAddress()));
  await send("staking accepts rig NFT", staking.addNFTContract(await nft.getAddress()));
  await send("staking -> engine", staking.setMiningEngine(await engine.getAddress()));
  await send("rig NFT authorizes engine", nft.setAuthorizedContract(await engine.getAddress(), true));
  await send("rig NFT authorizes staking", nft.setAuthorizedContract(await staking.getAddress(), true));

  const out = {
    chainId: Number(net.chainId),
    deployer: DEPLOYER,
    MockWATT: wattAddr,
    MiningRigNFT: await nft.getAddress(),
    GamePool: await gamePool.getAddress(),
    MiningEngine: await engine.getAddress(),
    StakingPool: await staking.getAddress(),
    PoolRegistry: await registry.getAddress(),
    WTXBridge: await bridge.getAddress(),
  };
  console.log("\ndeployed set:");
  console.log(JSON.stringify(out, null, 2));
  writeFileSync(
    `deployments-wattx-${net.chainId}.json`, JSON.stringify(out, null, 2) + "\n");
}

main().catch((e) => { console.error(e); process.exitCode = 1; });
