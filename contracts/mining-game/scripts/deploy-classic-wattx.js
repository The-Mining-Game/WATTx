/* Deploy the CLASSIC Mining Game set (the contracts the staking dapp speaks)
 * to WATTx mainnet through janus, mirroring the live ALT/Polygon parameters.
 *
 *   WATTX_DEPLOYER=0x... npx hardhat run scripts/deploy-classic-wattx.js --network wattx_janus_main
 *
 * Notes that bite (see deploy-wattx.js and project memory):
 *  - Addresses MUST come from receipts; ethers' CREATE prediction is fiction here.
 *  - janus under-estimates gas — every tx passes an explicit gasLimit.
 *  - msg.value is denominated in SATOSHIS inside the EVM: the multisender's
 *    0.05-ether constructor default would mean 500M WTX, so ethFee is reset to
 *    5_000_000 sat = 0.05 WTX post-deploy.
 *  - The NFT here carries the freemint fix (persistent one-per-address gate);
 *    everything else is byte-identical to the ALT/Polygon deployments.
 */
import { writeFileSync } from "node:fs";
import hre from "hardhat";
const { ethers } = hre;

const DEPLOYER = process.env.WATTX_DEPLOYER;
if (!DEPLOYER) throw new Error("set WATTX_DEPLOYER to the funded hex address");

const GAS_DEPLOY = 8_000_000n;
const GAS_CALL = 500_000n;

// Live ALT staking parameters, read off 0xe4630453... on 2026-08-01.
const STAKE_WEIGHTS = { 1: 1, 2: 42, 3: 9, 4: 11, 5: 18 };
const MIN_STAKE_SECONDS = { 1: 43200, 2: 3600, 3: 3600, 4: 3600, 5: 3600 };
const REWARDS_TOKEN_AMOUNT = 173611111111111n; // 0.000173611 WATT per interval-weight
const STAKING_TIME = 60;
// Live Polygon WATT-staking terms (contract was never on ALT).
const WATT_STAKE_ARGS = [30, 30, 30, 1]; // rate, maturity, penalization, lower

async function deploy(name, signer, args = []) {
  const factory = await ethers.getContractFactory(name, signer);
  const pending = await factory.deploy(...args, { gasLimit: GAS_DEPLOY });
  const receipt = await pending.deploymentTransaction().wait();
  const addr = receipt.contractAddress;
  if (!addr) throw new Error(`${name}: receipt carried no contractAddress`);
  console.log(`  ${name.split(":").pop().padEnd(18)} ${addr}`);
  return new ethers.Contract(addr, factory.interface, signer);
}

async function send(label, promise) {
  const tx = await promise;
  const r = await tx.wait();
  if (r.status !== 1) throw new Error(`${label}: tx reverted`);
  console.log(`  wired: ${label}`);
}

const main = async () => {
  const signer = await ethers.getSigner(DEPLOYER);
  const net = await ethers.provider.getNetwork();
  console.log(`deployer ${DEPLOYER} on chain ${net.chainId}`);

  console.log("deploying:");
  const watt = await deploy("contracts/classic/Watt.sol:WATT", signer);
  const nft = await deploy("contracts/classic/MiningGameNft.sol:MiningGame", signer);
  const staker = await deploy("contracts/classic/MiningGameStaker.sol:MiningGameStaker", signer, [
    await nft.getAddress(),
    await watt.getAddress()
  ]);
  const wattStake = await deploy("contracts/classic/WATTstake.sol:Stakes", signer, [
    await watt.getAddress(),
    DEPLOYER,
    ...WATT_STAKE_ARGS
  ]);
  const multisender = await deploy("contracts/classic/multimultisender.sol:TokenMultisender", signer);

  console.log("wiring:");
  await send("WATT.updateStaking(staker)", watt.updateStaking(await staker.getAddress(), true, { gasLimit: GAS_CALL }));
  for (const [id, w] of Object.entries(STAKE_WEIGHTS)) {
    await send(`staker.setStakeWeight(${id}, ${w})`, staker.setStakeWeight(id, w, { gasLimit: GAS_CALL }));
  }
  for (const [id, s] of Object.entries(MIN_STAKE_SECONDS)) {
    await send(`staker.setMinimumStakingTime(${id}, ${s})`, staker.setMinimumStakingTime(id, s, { gasLimit: GAS_CALL }));
  }
  for (let id = 1; id <= 5; id++) {
    await send(`staker.setCanDeposit(${id})`, staker.setCanDeposit(id, true, { gasLimit: GAS_CALL }));
  }
  await send("staker.setStakingTime(60)", staker.setStakingTime(STAKING_TIME, { gasLimit: GAS_CALL }));
  await send("staker.setRewardsTokenAmount", staker.setRewardsTokenAmount(REWARDS_TOKEN_AMOUNT, { gasLimit: GAS_CALL }));
  // satoshi-denominated msg.value: 5_000_000 sat = 0.05 WTX
  await send("multisender.setEthFee(0.05 WTX)", multisender.setEthFee(5_000_000n, { gasLimit: GAS_CALL }));

  const out = {
    chainId: Number(net.chainId),
    deployer: DEPLOYER,
    contracts: {
      wattToken: await watt.getAddress(),
      miningGameNft: await nft.getAddress(),
      miningGameStaking: await staker.getAddress(),
      miningGameWattStaking: await wattStake.getAddress(),
      multiSend: await multisender.getAddress()
    }
  };
  writeFileSync(new URL(`../deployments-classic-wattx-${net.chainId}.json`, import.meta.url), JSON.stringify(out, null, 2));
  console.log("saved deployments-classic-wattx-" + net.chainId + ".json");
};

main().catch((e) => { console.error(e); process.exit(1); });
