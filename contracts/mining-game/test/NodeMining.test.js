// Pointing a rig at somebody's node: PoS chains and masternodes as payout
// targets, the pool owner's cut of rewards, and the WATT burn split.
import { expect } from "chai";
import hre from "hardhat";

const { ethers } = hre;
const E = (n) => ethers.parseEther(String(n));
const DEAD = "0x000000000000000000000000000000000000dEaD";
const ANY = 255;
const BPS = 10000n;
const BURN_BPS = 5000n; // protocol constant

// PayoutHub.TargetKind
const PoW = 0, PoS = 1, Masternode = 2, Hybrid = 3;

describe("Node mining: PoS / masternode payouts, owner fees, WATT burn", function () {
  let owner, miner, poolOwner, staker;
  let watt, nft, hub, engine, staking;
  const MINT_PRICE = E("0.1");
  let T = {}; // symbol -> targetId

  beforeEach(async function () {
    [owner, miner, poolOwner, staker] = await ethers.getSigners();
    const F = (n) => ethers.getContractFactory(n);

    watt = await (await F("contracts/testing/MockWATT.sol:MockWATT")).deploy();
    nft = await (await F("contracts/nfts/MiningRigNFT.sol:MiningRigNFT")).deploy(MINT_PRICE);
    hub = await (await F("contracts/game/PayoutHub.sol:PayoutHub")).deploy();
    staking = await (await F("contracts/game/StakingPool.sol:StakingPool"))
      .deploy(await watt.getAddress());
    engine = await (await F("contracts/game/NodeMiningEngine.sol:NodeMiningEngine"))
      .deploy(await watt.getAddress(), await hub.getAddress());

    await hub.setEngine(await engine.getAddress(), true);
    await hub.setOperator(owner.address, true);
    await engine.setStakingPool(await staking.getAddress());
    await engine.setNFTContract(await nft.getAddress(), true);
    await nft.setAuthorizedContract(await engine.getAddress(), true);

    // The targets actually wanted: masternode, two hybrid-PoS chains the
    // operator runs nodes for, plus a PoW coin to prove routing still works.
    const reg = async (sym, name, kind, chainId) => {
      const id = await hub.targetCount();
      await hub.registerTarget(sym, name, kind, chainId);
      T[sym] = Number(id);
    };
    await reg("HTH", "Help The Homeless masternode", Masternode, 0);
    await reg("ALT", "Altcoinchain hybrid PoS", Hybrid, 2330);
    await reg("WTX", "WATTxchain hybrid PoS", Hybrid, 22356);
    await reg("BTN", "Bitnet PoS", PoS, 0);
    await reg("BTC", "Bitcoin", PoW, 0);

    for (const id of Object.values(T)) await hub.reportDeposit(id, E("1000000"));
    await watt.mint(miner.address, E("10000000"));
  });

  async function mintRig(to = miner) {
    await nft.connect(to).mint({ value: MINT_PRICE });
    const id = await nft.totalSupply();
    return { id, traits: await nft.getRigTraits(id) };
  }

  async function makePool(targetId, { algo = ANY, fee = 0, wattCut = 0, name = "pool" } = {}) {
    const id = await engine.poolCount();
    await engine.connect(poolOwner).createPool(targetId, algo, fee, wattCut, name, "http://node:8545");
    return Number(id);
  }

  async function start(rig, poolId, hours = 24n) {
    const perHour = await nft.getWattPerHour(rig.id);
    await watt.connect(miner).approve(await engine.getAddress(), perHour * hours);
    await nft.connect(miner).approve(await engine.getAddress(), rig.id);
    await engine.connect(miner).startMining(await nft.getAddress(), rig.id, perHour * hours, poolId);
  }

  const advance = async (secs) => {
    await hre.network.provider.send("evm_increaseTime", [secs]);
    await hre.network.provider.send("evm_mine");
  };

  describe("payout targets beyond mined coins", function () {
    it("registers masternode, PoS and hybrid targets alongside PoW", async function () {
      expect(await hub.targetCount()).to.equal(5);
      const hth = await hub.getTarget(T.HTH);
      expect(hth.symbol).to.equal("HTH");
      expect(hth.kind).to.equal(Masternode);
      const alt = await hub.getTarget(T.ALT);
      expect(alt.kind).to.equal(Hybrid);
      expect(alt.chainId).to.equal(2330n);
      expect((await hub.getTarget(T.BTN)).kind).to.equal(PoS);
    });

    it("pays a rig in the pool's target, whatever the rig's algorithm is", async function () {
      // The point of the redesign: a rig rolled for some PoW algorithm still
      // earns HTH when pointed at an HTH masternode pool.
      const rig = await mintRig();
      const poolId = await makePool(T.HTH, { algo: ANY });
      await start(rig, poolId);
      await advance(3600);
      await engine.connect(miner).claim(await nft.getAddress(), rig.id);

      expect(await hub.pending(miner.address, T.HTH)).to.be.gt(0);
      for (const sym of ["ALT", "WTX", "BTN", "BTC"]) {
        expect(await hub.pending(miner.address, T[sym])).to.equal(0, `must not be paid ${sym}`);
      }
    });

    it("an algorithm-locked pool refuses a rig that does not match", async function () {
      const rig = await mintRig();
      const algo = Number(rig.traits.algorithm);
      const wrong = (algo + 1) % 7;
      const poolId = await makePool(T.BTC, { algo: wrong });

      const perHour = await nft.getWattPerHour(rig.id);
      await watt.connect(miner).approve(await engine.getAddress(), perHour * 24n);
      await nft.connect(miner).approve(await engine.getAddress(), rig.id);
      await expect(
        engine.connect(miner).startMining(await nft.getAddress(), rig.id, perHour * 24n, poolId)
      ).to.be.revertedWith("Wrong algorithm for pool");
    });

    it("traits still set the rate, diluted by the pool's own hashrate", async function () {
      const rig = await mintRig();
      const poolId = await makePool(T.ALT);
      await start(rig, poolId);

      const t0 = (await ethers.provider.getBlock("latest")).timestamp;
      await advance(3600);
      const t1 = (await ethers.provider.getBlock("latest")).timestamp;

      const power = await nft.getEffectivePower(rig.id);
      const rate = await engine.rewardRate();
      const expected = (power * BigInt(t1 - t0) * rate) / BigInt(rig.traits.hashRate);
      expect(await engine.pendingRewards(await nft.getAddress(), rig.id)).to.equal(expected);
    });
  });

  describe("pool owner's cut of rewards", function () {
    it("splits gross into the owner's chosen fee and the miner's remainder", async function () {
      const FEE = 2500n; // 25%
      const rig = await mintRig();
      const poolId = await makePool(T.WTX, { fee: Number(FEE) });
      await start(rig, poolId);
      await advance(3600);

      const gross = await engine.pendingRewards(await nft.getAddress(), rig.id);
      await engine.connect(miner).claim(await nft.getAddress(), rig.id);

      const minerGot = await hub.pending(miner.address, T.WTX);
      const ownerGot = await hub.pending(poolOwner.address, T.WTX);

      // gross grows by one block's worth between read and claim; compare ratio.
      expect(ownerGot + minerGot).to.be.gte(gross);
      const total = ownerGot + minerGot;
      expect(ownerGot).to.equal((total * FEE) / BPS);
      expect(minerGot).to.equal(total - (total * FEE) / BPS);
    });

    it("a 100% fee leaves the miner nothing -- uncapped, as specified", async function () {
      const rig = await mintRig();
      const poolId = await makePool(T.HTH, { fee: 10000 });
      await start(rig, poolId);
      await advance(3600);
      await engine.connect(miner).claim(await nft.getAddress(), rig.id);

      expect(await hub.pending(miner.address, T.HTH)).to.equal(0);
      expect(await hub.pending(poolOwner.address, T.HTH)).to.be.gt(0);
    });

    it("the owner can raise the fee on an open session, and it is emitted", async function () {
      const rig = await mintRig();
      const poolId = await makePool(T.ALT, { fee: 0 });
      await start(rig, poolId);
      await advance(3600);
      await engine.connect(miner).claim(await nft.getAddress(), rig.id);
      const afterFree = await hub.pending(miner.address, T.ALT);
      expect(afterFree).to.be.gt(0);

      // Mid-session change: the audit trail miners have.
      await expect(engine.connect(poolOwner).setPoolFees(poolId, 9000, 0))
        .to.emit(engine, "PoolFeeChanged").withArgs(poolId, 0, 9000, 0, 0);

      await advance(3600);
      await engine.connect(miner).claim(await nft.getAddress(), rig.id);

      // Second hour is taxed at 90%: the owner now holds the bulk of it.
      const ownerGot = await hub.pending(poolOwner.address, T.ALT);
      const minerSecondHour = (await hub.pending(miner.address, T.ALT)) - afterFree;
      expect(ownerGot).to.be.gt(minerSecondHour * 5n);
      // Already-credited rewards are untouched by the change.
      expect(await hub.pending(miner.address, T.ALT)).to.be.gte(afterFree);
    });

    it("non-owners cannot change a pool's fees", async function () {
      const poolId = await makePool(T.ALT, { fee: 100 });
      await expect(engine.connect(miner).setPoolFees(poolId, 0, 0))
        .to.be.revertedWith("Not pool owner");
    });
  });

  describe("WATT: fixed burn, then the owner's cut of what is left", function () {
    it("burns 50% and splits the rest by the pool's chosen cut", async function () {
      const OWNER_CUT = 4000n; // 40% of the non-burned half
      const rig = await mintRig();
      const poolId = await makePool(T.HTH, { wattCut: Number(OWNER_CUT) });
      await start(rig, poolId);
      await advance(3600);
      await engine.connect(miner).claim(await nft.getAddress(), rig.id);

      const burned = await watt.balanceOf(DEAD);
      const ownerWatt = await watt.balanceOf(poolOwner.address);
      const stakerWatt = await watt.balanceOf(await staking.getAddress());
      const consumed = burned + ownerWatt + stakerWatt;

      expect(consumed).to.be.gt(0, "no WATT was consumed");
      expect(burned).to.equal((consumed * BURN_BPS) / BPS);

      const rest = consumed - burned;
      expect(ownerWatt).to.equal((rest * OWNER_CUT) / BPS);
      expect(stakerWatt).to.equal(rest - (rest * OWNER_CUT) / BPS);
    });

    it("the burn floor holds even when the owner claims all of the remainder", async function () {
      const rig = await mintRig();
      const poolId = await makePool(T.ALT, { wattCut: 10000 });
      await start(rig, poolId);
      await advance(3600);
      await engine.connect(miner).claim(await nft.getAddress(), rig.id);

      const burned = await watt.balanceOf(DEAD);
      const ownerWatt = await watt.balanceOf(poolOwner.address);
      const consumed = burned + ownerWatt;

      expect(burned).to.be.gt(0, "burn must happen regardless of pool settings");
      // Exact truncation: the burn rounds down, so an odd amount leaves the
      // owner one wei more. Stakers get nothing at a 100% owner cut.
      expect(burned).to.equal((consumed * BURN_BPS) / BPS);
      expect(ownerWatt).to.equal(consumed - burned);
      expect(await watt.balanceOf(await staking.getAddress())).to.equal(0);
    });

    it("consumes WATT at the rig's wattConsumption trait and refunds the rest", async function () {
      const rig = await mintRig();
      const poolId = await makePool(T.BTN);
      const perHour = await nft.getWattPerHour(rig.id);
      const before = await watt.balanceOf(miner.address);

      await start(rig, poolId, 10n);
      await advance(3600);
      await engine.connect(miner).stopMining(await nft.getAddress(), rig.id);

      const spent = before - (await watt.balanceOf(miner.address));
      const perSec = perHour / 3600n;
      expect(spent >= perHour - perSec * 3n && spent <= perHour + perSec * 5n).to.equal(
        true, `expected ~${perHour} consumed, got ${spent}`
      );
    });
  });

  describe("an underfunded target must not strand the rig", function () {
    it("returns the NFT and records the shortfall instead of reverting", async function () {
      // A target with almost nothing behind it.
      const id = Number(await hub.targetCount());
      await hub.registerTarget("POOR", "Underfunded chain", PoS, 0);
      await hub.reportDeposit(id, 1n);

      const rig = await mintRig();
      const poolId = await makePool(id);
      await start(rig, poolId);
      await advance(3600);

      const pending = await engine.pendingRewards(await nft.getAddress(), rig.id);
      expect(pending).to.be.gt(1n);

      // The regression: this used to revert and lock the NFT in the engine.
      await expect(engine.connect(miner).stopMining(await nft.getAddress(), rig.id))
        .to.emit(engine, "Unpaid");

      expect(await nft.ownerOf(rig.id)).to.equal(miner.address);
      expect(await nft.isMining(rig.id)).to.equal(false);
      expect(await hub.balanceOfTarget(id)).to.equal(0);
    });

    it("credits what the target can cover rather than nothing", async function () {
      const id = Number(await hub.targetCount());
      await hub.registerTarget("THIN", "Thin chain", PoS, 0);
      await hub.reportDeposit(id, 1000n);

      const rig = await mintRig();
      const poolId = await makePool(id);
      await start(rig, poolId);
      await advance(3600);
      await engine.connect(miner).claim(await nft.getAddress(), rig.id);

      expect(await hub.pending(miner.address, id)).to.equal(1000n);
      expect(await hub.balanceOfTarget(id)).to.equal(0);
    });
  });

  describe("pool lifecycle", function () {
    it("an inactive pool takes no new miners but existing ones can still leave", async function () {
      const rig = await mintRig();
      const poolId = await makePool(T.WTX);
      await start(rig, poolId);

      await engine.connect(poolOwner).setPoolActive(poolId, false);

      const rig2 = await mintRig();
      const perHour = await nft.getWattPerHour(rig2.id);
      await watt.connect(miner).approve(await engine.getAddress(), perHour * 24n);
      await nft.connect(miner).approve(await engine.getAddress(), rig2.id);
      await expect(
        engine.connect(miner).startMining(await nft.getAddress(), rig2.id, perHour * 24n, poolId)
      ).to.be.revertedWith("Pool inactive");

      await advance(600);
      await engine.connect(miner).stopMining(await nft.getAddress(), rig.id);
      expect(await nft.ownerOf(rig.id)).to.equal(miner.address);
    });

    it("tracks the pool's hashrate as rigs join and leave", async function () {
      const rig = await mintRig();
      const poolId = await makePool(T.ALT);
      expect((await engine.getPool(poolId)).hashRate).to.equal(0);

      await start(rig, poolId);
      expect((await engine.getPool(poolId)).hashRate).to.equal(BigInt(rig.traits.hashRate));
      expect((await engine.getPool(poolId)).minersActive).to.equal(1);

      await advance(600);
      await engine.connect(miner).stopMining(await nft.getAddress(), rig.id);
      expect((await engine.getPool(poolId)).hashRate).to.equal(0);
      expect((await engine.getPool(poolId)).minersActive).to.equal(0);
    });
  });
});
