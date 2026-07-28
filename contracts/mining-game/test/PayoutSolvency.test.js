// Can the EVM side mint claims to coins that do not exist?
//
// PayoutHub is an EVM ledger of debts denominated in coins that live on OTHER
// chains -- HTH masternode payouts, ALT, WTX, Bitcoin. Nothing it tracks is
// held in the contract. So there are two separate questions, and they have
// different answers:
//
//   1. Can the LEDGER create entitlement out of nothing? (arithmetic)
//   2. Is what the ledger believes actually backed by real coins? (trust)
//
// These tests establish exactly where the boundary is, so nobody mistakes the
// first guarantee for the second.
import { expect } from "chai";
import hre from "hardhat";

const { ethers } = hre;
const E = (n) => ethers.parseEther(String(n));
const PoS = 1, Masternode = 2;
const ANY = 255;

describe("Payout solvency: EVM ledger vs. real UTXO coins", function () {
  let owner, miner, miner2, poolOwner, operator, attacker;
  let watt, nft, hub, engine, staking;
  const MINT_PRICE = E("0.1");
  let HTH;

  beforeEach(async function () {
    [owner, miner, miner2, poolOwner, operator, attacker] = await ethers.getSigners();
    const F = (n) => ethers.getContractFactory(n);

    watt = await (await F("contracts/testing/MockWATT.sol:MockWATT")).deploy();
    nft = await (await F("contracts/nfts/MiningRigNFT.sol:MiningRigNFT")).deploy(MINT_PRICE);
    hub = await (await F("contracts/game/PayoutHub.sol:PayoutHub")).deploy();
    staking = await (await F("contracts/game/StakingPool.sol:StakingPool")).deploy(await watt.getAddress());
    engine = await (await F("contracts/game/NodeMiningEngine.sol:NodeMiningEngine"))
      .deploy(await watt.getAddress(), await hub.getAddress());

    await hub.setEngine(await engine.getAddress(), true);
    await hub.setOperator(operator.address, true);
    await engine.setStakingPool(await staking.getAddress());
    await engine.setNFTContract(await nft.getAddress(), true);
    await nft.setAuthorizedContract(await engine.getAddress(), true);

    HTH = Number(await hub.targetCount());
    await hub.registerTarget("HTH", "Help The Homeless masternode", Masternode, 0);

    for (const w of [miner, miner2]) await watt.mint(w.address, E("10000000"));
  });

  async function mintRig(to) {
    await nft.connect(to).mint({ value: MINT_PRICE });
    return { id: await nft.totalSupply() };
  }
  async function start(who, rig, poolId, hours = 24n) {
    const perHour = await nft.getWattPerHour(rig.id);
    await watt.connect(who).approve(await engine.getAddress(), perHour * hours);
    await nft.connect(who).approve(await engine.getAddress(), rig.id);
    await engine.connect(who).startMining(await nft.getAddress(), rig.id, perHour * hours, poolId);
  }
  const advance = async (s) => {
    await hre.network.provider.send("evm_increaseTime", [s]);
    await hre.network.provider.send("evm_mine");
  };

  // ---------------------------------------------------------------------
  // 1. WHAT IS GUARANTEED: the ledger conserves value.
  // ---------------------------------------------------------------------
  describe("the ledger cannot create entitlement from nothing", function () {
    it("holds balance + credited == deposited, no matter how much is mined", async function () {
      await hub.connect(operator).reportDeposit(HTH, E("1000"));

      const poolId = Number(await engine.poolCount());
      await engine.connect(poolOwner).createPool(HTH, ANY, 2500, 4000, "hth", "http://n:1");

      const r1 = await mintRig(miner);
      const r2 = await mintRig(miner2);
      await start(miner, r1, poolId);
      await start(miner2, r2, poolId);

      // Mine hard, claim repeatedly -- try to shake loose more than exists.
      for (let i = 0; i < 5; i++) {
        await advance(86400);
        await engine.connect(miner).claim(await nft.getAddress(), r1.id);
        await engine.connect(miner2).claim(await nft.getAddress(), r2.id);
      }

      const t = await hub.getTarget(HTH);
      const credited =
        (await hub.pending(miner.address, HTH)) +
        (await hub.pending(miner2.address, HTH)) +
        (await hub.pending(poolOwner.address, HTH));

      expect(t.balance + credited).to.equal(t.totalDeposited, "value was created or destroyed");
      expect(credited).to.be.lte(t.totalDeposited, "credited more than was ever deposited");
      expect(t.totalDistributed).to.equal(credited);
    });

    it("stops crediting once the deposit is exhausted", async function () {
      await hub.connect(operator).reportDeposit(HTH, 1000n);
      const poolId = Number(await engine.poolCount());
      await engine.connect(poolOwner).createPool(HTH, ANY, 0, 0, "hth", "http://n:1");

      const rig = await mintRig(miner);
      await start(miner, rig, poolId);
      await advance(86400);
      await engine.connect(miner).claim(await nft.getAddress(), rig.id);
      await advance(86400);
      await engine.connect(miner).claim(await nft.getAddress(), rig.id);

      expect(await hub.pending(miner.address, HTH)).to.equal(1000n);
      expect(await hub.balanceOfTarget(HTH)).to.equal(0);
    });

    it("only a registered engine may credit", async function () {
      await hub.connect(operator).reportDeposit(HTH, E("100"));
      await expect(hub.connect(attacker).credit(attacker.address, HTH, E("100")))
        .to.be.revertedWith("Not engine");
    });

    it("only an operator may report a deposit", async function () {
      await expect(hub.connect(attacker).reportDeposit(HTH, E("1000000")))
        .to.be.revertedWith("Not operator");
    });

    it("withdrawal cannot exceed what is pending", async function () {
      await hub.connect(operator).reportDeposit(HTH, E("10"));
      const poolId = Number(await engine.poolCount());
      await engine.connect(poolOwner).createPool(HTH, ANY, 0, 0, "hth", "http://n:1");
      const rig = await mintRig(miner);
      await start(miner, rig, poolId);
      await advance(3600);
      await engine.connect(miner).claim(await nft.getAddress(), rig.id);

      const owed = await hub.pending(miner.address, HTH);
      await expect(
        hub.connect(operator).confirmWithdrawal(miner.address, HTH, owed + 1n, "txid")
      ).to.be.revertedWith("Exceeds pending");
    });
  });

  // ---------------------------------------------------------------------
  // 2. WHAT IS *NOT* GUARANTEED: that the ledger matches reality.
  //    These tests pass by DEMONSTRATING the hole, not by proving safety.
  // ---------------------------------------------------------------------
  describe("UNBACKED: the ledger trusts the operator completely", function () {
    it("an operator can report a deposit of coins that do not exist", async function () {
      // Nothing here proves a single HTH ever arrived at a masternode. The
      // contract accepts an operator's word as the origin of all value.
      await hub.connect(operator).reportDeposit(HTH, E("1000000000"));
      expect(await hub.balanceOfTarget(HTH)).to.equal(E("1000000000"));

      const poolId = Number(await engine.poolCount());
      await engine.connect(poolOwner).createPool(HTH, ANY, 0, 0, "hth", "http://n:1");
      const rig = await mintRig(miner);
      await start(miner, rig, poolId);
      await advance(86400);
      await engine.connect(miner).claim(await nft.getAddress(), rig.id);

      // A real, on-chain, arithmetically-sound claim to coins that may not
      // exist. The EVM cannot tell the difference.
      expect(await hub.pending(miner.address, HTH)).to.be.gt(0);
    });

    it("an operator can mark a payout settled without any real transaction", async function () {
      await hub.connect(operator).reportDeposit(HTH, E("100"));
      const poolId = Number(await engine.poolCount());
      await engine.connect(poolOwner).createPool(HTH, ANY, 0, 0, "hth", "http://n:1");
      const rig = await mintRig(miner);
      await start(miner, rig, poolId);
      await advance(3600);
      await engine.connect(miner).claim(await nft.getAddress(), rig.id);

      const owed = await hub.pending(miner.address, HTH);
      expect(owed).to.be.gt(0);

      // "txid" is an arbitrary string. It is never checked against the HTH
      // chain, and no proof of payment is required.
      await hub.connect(operator).confirmWithdrawal(miner.address, HTH, owed, "not-a-real-txid");

      expect(await hub.pending(miner.address, HTH)).to.equal(0);
      expect(await hub.totalClaimed(miner.address, HTH)).to.equal(owed);
      // The miner's debt is discharged on-chain whether or not they were paid.
    });

    it("nothing ties a target to a real chain -- any symbol can be registered", async function () {
      const fake = Number(await hub.targetCount());
      await hub.registerTarget("NOTREAL", "A chain that does not exist", PoS, 999999);
      await hub.connect(operator).reportDeposit(fake, E("50000"));
      expect(await hub.balanceOfTarget(fake)).to.equal(E("50000"));
    });
  });
});
