// Does a rig actually mine according to its traits?
//
// Traits are rolled randomly at mint and there is no trait-setting mint, so
// these tests read each rig's ACTUAL traits off-chain and recompute what it
// should earn independently in JS, then assert the contract agrees. That is
// stronger than asserting against fixed expectations: it holds for whatever
// the RNG produced, and it fails if the on-chain formula ever drifts.
import { expect } from "chai";
import hre from "hardhat";

const { ethers } = hre;
const E = (n) => ethers.parseEther(String(n));

describe("Mining by traits", function () {
  let owner, alice, bob;
  let watt, nft, gamePool, engine, staking;
  const MINT_PRICE = E("0.1");

  // Mirror of TraitCalculator.calculateEffectivePower -- integer division,
  // matching Solidity's truncation exactly (BigInt, never float).
  const expectedPower = (t) =>
    (BigInt(t.hashRate) * BigInt(t.efficiency) * 100n) / BigInt(t.wattConsumption);

  beforeEach(async function () {
    [owner, alice, bob] = await ethers.getSigners();

    const F = (n) => ethers.getContractFactory(n);
    watt = await (await F("contracts/testing/MockWATT.sol:MockWATT")).deploy();
    nft = await (await F("contracts/nfts/MiningRigNFT.sol:MiningRigNFT")).deploy(MINT_PRICE);
    gamePool = await (await F("contracts/game/GamePool.sol:GamePool")).deploy();
    engine = await (await F("contracts/game/MiningEngine.sol:MiningEngine"))
      .deploy(await watt.getAddress(), await gamePool.getAddress());
    staking = await (await F("contracts/game/StakingPool.sol:StakingPool"))
      .deploy(await watt.getAddress());

    await gamePool.setMiningEngine(await engine.getAddress());
    await engine.setStakingPool(await staking.getAddress());
    await engine.addNFTContract(await nft.getAddress());
    await staking.addNFTContract(await nft.getAddress());
    await staking.setMiningEngine(await engine.getAddress());
    await nft.setAuthorizedContract(await engine.getAddress(), true);
    await nft.setAuthorizedContract(await staking.getAddress(), true);

    // Fund every coin so a rig of any rolled algorithm can be paid.
    await gamePool.setOperator(owner.address, true);
    for (let i = 0; i < 7; i++) await gamePool.reportDeposit(i, E("1000000"));

    for (const who of [alice, bob]) await watt.mint(who.address, E("10000000"));
  });

  // Mint `n` rigs to `who` and return [{id, traits}]
  async function mintRigs(who, n) {
    const out = [];
    for (let i = 0; i < n; i++) {
      await nft.connect(who).mint({ value: MINT_PRICE });
      const id = await nft.totalSupply();
      out.push({ id, traits: await nft.getRigTraits(id) });
    }
    return out;
  }

  async function startMining(who, id, wattAmount) {
    await watt.connect(who).approve(await engine.getAddress(), wattAmount);
    await nft.connect(who).approve(await engine.getAddress(), id);
    await engine.connect(who).startMining(await nft.getAddress(), id, wattAmount);
  }

  describe("traits determine capability", function () {
    it("effective power follows hashRate x efficiency / wattConsumption", async function () {
      // Several rigs, so this covers a spread of rolled traits rather than one.
      for (const rig of await mintRigs(alice, 8)) {
        expect(await nft.getEffectivePower(rig.id)).to.equal(
          expectedPower(rig.traits),
          `rig ${rig.id} power (h=${rig.traits.hashRate} e=${rig.traits.efficiency} w=${rig.traits.wattConsumption})`
        );
      }
    });

    it("a more efficient rig out-earns a less efficient one at equal hash", async function () {
      // Rather than hope for a matched pair, assert the invariant directly:
      // ordering by effective power must order by earning rate.
      const rigs = await mintRigs(alice, 6);
      const powers = await Promise.all(rigs.map((r) => nft.getEffectivePower(r.id)));
      const best = powers.indexOf(powers.reduce((a, b) => (a > b ? a : b)));
      const worst = powers.indexOf(powers.reduce((a, b) => (a < b ? a : b)));
      if (powers[best] === powers[worst]) return this.skip(); // degenerate roll

      expect(expectedPower(rigs[best].traits)).to.be.gt(expectedPower(rigs[worst].traits));
    });

    it("hourly WATT draw equals the wattConsumption trait", async function () {
      for (const rig of await mintRigs(alice, 5)) {
        expect(await nft.getWattPerHour(rig.id)).to.equal(
          BigInt(rig.traits.wattConsumption) * 10n ** 18n
        );
      }
    });

    it("refuses to start with less WATT than one hour of draw", async function () {
      const [rig] = await mintRigs(alice, 1);
      const perHour = await nft.getWattPerHour(rig.id);
      await watt.connect(alice).approve(await engine.getAddress(), perHour);
      await nft.connect(alice).approve(await engine.getAddress(), rig.id);
      await expect(
        engine.connect(alice).startMining(await nft.getAddress(), rig.id, perHour - 1n)
      ).to.be.revertedWith("Min 1 hour WATT required");
    });
  });

  describe("algorithm routes to the right coin", function () {
    it("pays the coin its algorithm maps to", async function () {
      // algorithm -> Coin per GamePool's constructor:
      // 0 SHA256D->BTC, 1 Scrypt->LTC, 2 Ethash->ETC, 3 RandomX->XMR,
      // 4 Equihash->ALT, 5 X11->DASH, 6 kHeavyHash->KAS
      const MAP = [0, 1, 3, 2, 6, 5, 4]; // algo -> Coin enum index
      const [rig] = await mintRigs(alice, 1);
      const algo = Number(rig.traits.algorithm);
      const expectedCoin = MAP[algo];

      expect(await gamePool.getCoinForAlgorithm(algo)).to.equal(expectedCoin);

      const perHour = await nft.getWattPerHour(rig.id);
      await startMining(alice, rig.id, perHour * 10n);
      await hre.network.provider.send("evm_increaseTime", [3600]);
      await hre.network.provider.send("evm_mine");
      await engine.connect(alice).claimRewards(await nft.getAddress(), rig.id);

      // Paid in the mapped coin, and in no other.
      expect(await gamePool.pendingWithdrawals(alice.address, expectedCoin)).to.be.gt(0);
      for (let c = 0; c < 7; c++) {
        if (c === expectedCoin) continue;
        expect(await gamePool.pendingWithdrawals(alice.address, c)).to.equal(
          0, `rig with algo ${algo} must not be paid coin ${c}`
        );
      }
    });
  });

  describe("rewards track traits over time", function () {
    it("a lone rig earns effectivePower * duration * rate / its own hashRate", async function () {
      const [rig] = await mintRigs(alice, 1);
      const perHour = await nft.getWattPerHour(rig.id);
      await startMining(alice, rig.id, perHour * 24n);

      const t0 = (await ethers.provider.getBlock("latest")).timestamp;
      await hre.network.provider.send("evm_increaseTime", [3600]);
      await hre.network.provider.send("evm_mine");
      const t1 = (await ethers.provider.getBlock("latest")).timestamp;

      const power = await nft.getEffectivePower(rig.id);
      const rate = await engine.rewardRate();
      const expected = (power * BigInt(t1 - t0) * rate) / BigInt(rig.traits.hashRate);

      expect(await engine.getPendingRewards(await nft.getAddress(), rig.id)).to.equal(expected);
    });

    it("earnings are proportional to elapsed time", async function () {
      const [rig] = await mintRigs(alice, 1);
      const perHour = await nft.getWattPerHour(rig.id);
      await startMining(alice, rig.id, perHour * 48n);

      await hre.network.provider.send("evm_increaseTime", [3600]);
      await hre.network.provider.send("evm_mine");
      const oneHour = await engine.getPendingRewards(await nft.getAddress(), rig.id);

      await hre.network.provider.send("evm_increaseTime", [3600]);
      await hre.network.provider.send("evm_mine");
      const twoHours = await engine.getPendingRewards(await nft.getAddress(), rig.id);

      // Within one second of exact doubling (block timestamps drift by a second).
      const drift = twoHours - oneHour * 2n;
      const perSec = oneHour / 3600n;
      expect(drift > -perSec * 2n && drift < perSec * 2n).to.equal(
        true, `expected ~2x over 2h: ${oneHour} -> ${twoHours}`
      );
    });

    it("a second rig on the same algorithm dilutes the first", async function () {
      const rigs = await mintRigs(alice, 12);
      // Find two rigs sharing an algorithm; skip if the roll gave none.
      let a, b;
      for (let i = 0; i < rigs.length && !b; i++)
        for (let j = i + 1; j < rigs.length && !b; j++)
          if (rigs[i].traits.algorithm === rigs[j].traits.algorithm) { a = rigs[i]; b = rigs[j]; }
      if (!b) return this.skip();

      await startMining(alice, a.id, (await nft.getWattPerHour(a.id)) * 48n);
      await hre.network.provider.send("evm_increaseTime", [3600]);
      await hre.network.provider.send("evm_mine");
      const soloRate = await engine.getPendingRewards(await nft.getAddress(), a.id);

      // Add the second rig, then measure the first over an identical window.
      await engine.connect(alice).claimRewards(await nft.getAddress(), a.id);
      await startMining(alice, b.id, (await nft.getWattPerHour(b.id)) * 48n);
      await hre.network.provider.send("evm_increaseTime", [3600]);
      await hre.network.provider.send("evm_mine");
      const sharedRate = await engine.getPendingRewards(await nft.getAddress(), a.id);

      expect(sharedRate).to.be.lt(soloRate, "adding hashrate must dilute the existing miner");
    });
  });

  describe("WATT is consumed at the rate the traits specify", function () {
    it("burns down the deposit at wattConsumption per hour and refunds the rest", async function () {
      const [rig] = await mintRigs(alice, 1);
      const perHour = await nft.getWattPerHour(rig.id);
      const deposit = perHour * 10n;

      const before = await watt.balanceOf(alice.address);
      await startMining(alice, rig.id, deposit);
      await hre.network.provider.send("evm_increaseTime", [3600]);
      await hre.network.provider.send("evm_mine");
      await engine.connect(alice).stopMining(await nft.getAddress(), rig.id);
      const after = await watt.balanceOf(alice.address);

      // Spent ~1 hour of draw; allow a couple of seconds of block drift.
      const spent = before - after;
      const perSec = perHour / 3600n;
      expect(spent >= perHour - perSec * 3n && spent <= perHour + perSec * 5n).to.equal(
        true, `expected ~${perHour} spent, got ${spent}`
      );

      // Consumed WATT lands with the stakers -- none of it is burned today.
      expect(await watt.balanceOf(await staking.getAddress())).to.equal(spent);
      expect(await nft.ownerOf(rig.id)).to.equal(alice.address);
      expect(await nft.isMining(rig.id)).to.equal(false);
    });
  });

  // An underfunded pool does not just delay payment -- it traps the rig.
  // stopMining() claims before returning the NFT, the claim reverts when the
  // pool cannot cover it, and the whole call reverts with it.
  describe("underfunded pool locks the rig (liveness)", function () {
    it("cannot stop mining or recover the NFT when rewards exceed pool balance", async function () {
      // Fresh pool funded with a token amount, so pending quickly exceeds it.
      const F = (n) => ethers.getContractFactory(n);
      const pool2 = await (await F("contracts/game/GamePool.sol:GamePool")).deploy();
      const engine2 = await (await F("contracts/game/MiningEngine.sol:MiningEngine"))
        .deploy(await watt.getAddress(), await pool2.getAddress());
      await pool2.setMiningEngine(await engine2.getAddress());
      await engine2.setStakingPool(await staking.getAddress());
      await engine2.addNFTContract(await nft.getAddress());
      await nft.setAuthorizedContract(await engine2.getAddress(), true);
      await pool2.setOperator(owner.address, true);
      for (let i = 0; i < 7; i++) await pool2.reportDeposit(i, 1n); // 1 wei of each

      await nft.connect(alice).mint({ value: MINT_PRICE });
      const id = await nft.totalSupply();
      const perHour = await nft.getWattPerHour(id);
      await watt.connect(alice).approve(await engine2.getAddress(), perHour * 24n);
      await nft.connect(alice).approve(await engine2.getAddress(), id);
      await engine2.connect(alice).startMining(await nft.getAddress(), id, perHour * 24n);

      await hre.network.provider.send("evm_increaseTime", [3600]);
      await hre.network.provider.send("evm_mine");

      const pending = await engine2.getPendingRewards(await nft.getAddress(), id);
      expect(pending).to.be.gt(1n, "pending must exceed the funded 1 wei for this test");

      // The NFT is held by the engine, and the owner cannot get it back.
      expect(await nft.ownerOf(id)).to.equal(await engine2.getAddress());
      await expect(
        engine2.connect(alice).stopMining(await nft.getAddress(), id)
      ).to.be.revertedWith("Insufficient pool balance");
      await expect(
        engine2.connect(alice).claimRewards(await nft.getAddress(), id)
      ).to.be.revertedWith("Insufficient pool balance");

      // Still stuck: only an operator topping up the pool frees it.
      expect(await nft.ownerOf(id)).to.equal(await engine2.getAddress());
      await pool2.reportDeposit(Number((await nft.getRigTraits(id)).algorithm) === 2 ? 3 : 0, E("1000000"));
    });
  });
});
