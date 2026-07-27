// Prove the deployed Mining Game actually runs on WATTx -- deployment only
// proves bytecode landed. Reads state back, mints a rig, and reads its traits.
//
//   npx hardhat run scripts/verify-wattx.js --network wattx_local
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname } from "node:path";
import hre from "hardhat";
const { ethers } = hre;

const DEPLOYER = process.env.WATTX_DEPLOYER;
const CLI = process.env.WATTX_CLI || `${process.env.HOME}/WATTx-testnet/dist/wattx-cli`;
const DATADIR = process.env.WATTX_DATADIR || `${process.env.HOME}/.wattx-rtest`;
const MINE_TO = process.env.WATTX_MINE_TO;

function mine(n = 1) {
  execFileSync(CLI, [`-datadir=${DATADIR}`, "-regtest", "generatetoaddress", String(n), MINE_TO],
    { env: { ...process.env, LD_LIBRARY_PATH: dirname(CLI) }, stdio: "ignore" });
}

async function main() {
  const net = await ethers.provider.getNetwork();
  const d = JSON.parse(readFileSync(`deployments-wattx-${net.chainId}.json`, "utf8"));
  const signer = await ethers.provider.getSigner(DEPLOYER);

  const nft = await ethers.getContractAt("contracts/nfts/MiningRigNFT.sol:MiningRigNFT", d.MiningRigNFT, signer);
  const watt = await ethers.getContractAt("contracts/testing/MockWATT.sol:MockWATT", d.MockWATT, signer);
  const engine = await ethers.getContractAt("contracts/game/MiningEngine.sol:MiningEngine", d.MiningEngine, signer);

  console.log(`chain ${net.chainId}\n`);
  console.log("reading deployed state:");
  console.log(`  NFT           ${await nft.name()} / ${await nft.symbol()}`);
  console.log(`  WATT          ${await watt.name()} / ${await watt.symbol()}`);
  console.log(`  mint price    ${await nft.mintPrice()} sat (${Number(await nft.mintPrice())/1e8} WTX)`);
  console.log(`  engine wired  stakingPool=${await engine.stakingPool()}`);
  console.log(`  NFT authorizes engine: ${await nft.authorizedContracts(d.MiningEngine)}`);

  const before = await nft.totalSupply();
  console.log(`\nminting a rig (supply ${before}):`);
  // Two different scales, and they must not be confused:
  //   * the contract stores mintPrice in SATOSHIS, because that is what the
  //     WATTx EVM reports as msg.value (8 decimals);
  //   * the `value` field sent over the JSON-RPC is divided by 1e10 on its way
  //     in, so a caller must scale the satoshi figure UP by 1e10.
  // Net effect for a user: sending "0.1" in ordinary 18-decimal terms pays
  // 0.1 WTX and satisfies a 1e7-satoshi price. gasLimit is explicit because
  // janus under-estimates cold storage writes and the tx dies out-of-gas.
  const WEI_PER_SAT = 10n ** 10n;
  const price = await nft.mintPrice();
  const tx = await nft.mint({ value: price * WEI_PER_SAT, gasLimit: 800000 });
  mine();
  const rcpt = await tx.wait();
  console.log(`  mined in block ${rcpt.blockNumber}, status ${rcpt.status}`);

  const after = await nft.totalSupply();
  const id = after;
  const t = await nft.getRigTraits(id);
  console.log(`  supply ${before} -> ${after}`);
  console.log(`  rig #${id} owner ${await nft.ownerOf(id)}`);
  console.log(`  traits: hashRate=${t.hashRate} algorithm=${t.algorithm} efficiency=${t.efficiency} ` +
              `watt/hr=${t.wattConsumption} rarity=${t.rarity} cooling=${t.cooling} durability=${t.durability}`);
  console.log(`  effective power ${await nft.getEffectivePower(id)}`);

  if (after !== before + 1n) throw new Error("supply did not increase -- mint did not take effect");

  // The mint alone only proves one contract works. Exercise the loop that makes
  // this a game: WATT is minted, the rig is staked, then withdrawn -- each step
  // crossing a contract boundary (NFT <-> StakingPool) and each verified by
  // reading chain state back, not by trusting the receipt.
  const GAS = { gasLimit: 900000 };
  const staking = await ethers.getContractAt("contracts/game/StakingPool.sol:StakingPool", d.StakingPool, signer);
  const nftAddr = d.MiningRigNFT;

  console.log("\nWATT (ERC20 -- unaffected by the native 8-decimal quirk):");
  let tx2 = await watt.mint(DEPLOYER, ethers.parseEther("1000000"), GAS); mine(); await tx2.wait();
  console.log(`  balance ${ethers.formatEther(await watt.balanceOf(DEPLOYER))} WATT`);

  console.log("\nstaking rig #" + id + ":");
  tx2 = await nft.approve(d.StakingPool, id, GAS); mine(); await tx2.wait();
  tx2 = await staking.stake(nftAddr, id, GAS); mine(); await tx2.wait();
  const stakedOwner = await nft.ownerOf(id);
  console.log(`  isStaked      ${await nft.isStaked(id)}`);
  console.log(`  custody       ${stakedOwner === d.StakingPool ? "StakingPool (escrowed)" : stakedOwner}`);
  console.log(`  stake weight  ${await staking.getStakeWeight(nftAddr, id)}`);
  if (!(await nft.isStaked(id))) throw new Error("stake did not take effect on-chain");
  if (stakedOwner !== d.StakingPool) throw new Error("NFT was not escrowed by the staking pool");

  console.log("\nunstaking:");
  tx2 = await staking.unstake(nftAddr, id, GAS); mine(); await tx2.wait();
  console.log(`  isStaked      ${await nft.isStaked(id)}`);
  console.log(`  returned to   ${await nft.ownerOf(id)}`);
  if (await nft.isStaked(id)) throw new Error("unstake did not clear staked flag");
  if ((await nft.ownerOf(id)) !== ethers.getAddress(DEPLOYER)) throw new Error("NFT not returned to owner");

  console.log("\nOK: mint -> stake -> unstake all executed on WATTx and verified by reading chain state.");
}

main().catch((e) => { console.error(e); process.exitCode = 1; });
