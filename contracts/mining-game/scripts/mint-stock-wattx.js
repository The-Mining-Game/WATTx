/* Owner-mint the WATTx NFT inventory to the new deployer:
 *   - team shop stock, mirroring the DEAD Polygon deployer's unsold holdings
 *     (key lost with the founder: id1 8932, id2 63, id4 4141, id5 2049)
 *   - the Polygon clone-claim pool from snapshot polygon@block-54116965-filtered
 *     (id1 7477, id2 37, id3 4997, id4 740, id5 559)
 * Minted as per-id totals; the split lives in the snapshot's policy block.
 * Fits the contract's supply caps exactly (id2 63+37 == cap 100).
 *
 *   WATTX_DEPLOYER=0x... npx hardhat run scripts/mint-stock-wattx.js --network wattx_janus_main
 */
import hre from "hardhat";
const { ethers } = hre;

const DEPLOYER = process.env.WATTX_DEPLOYER;
const NFT = "0x566808D0747662d0a0eeC68A854b695C01BE76a6";
const MINTS = { 1: 8932 + 7477, 2: 63 + 37, 3: 0 + 4997, 4: 4141 + 740, 5: 2049 + 559 };

const main = async () => {
  const signer = await ethers.getSigner(DEPLOYER);
  const factory = await ethers.getContractFactory("contracts/classic/MiningGameNft.sol:MiningGame", signer);
  const nft = new ethers.Contract(NFT, factory.interface, signer);
  for (const [id, amount] of Object.entries(MINTS)) {
    if (!amount) continue;
    const tx = await nft.ownermint(id, amount, { gasLimit: 500_000n });
    const r = await tx.wait();
    if (r.status !== 1) throw new Error(`ownermint(${id}) reverted`);
    console.log(`minted id${id} x${amount}, balance now`, (await nft.balanceOf(DEPLOYER, id)).toString());
  }
};
main().catch((e) => { console.error(e); process.exit(1); });
