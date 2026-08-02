// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_PARAMS_H
#define BITCOIN_CONSENSUS_PARAMS_H

#include <uint256.h>
#include <consensus/amount.h>

#include <chrono>
#include <limits>
#include <map>
#include <vector>

namespace Consensus {

/**
 * A buried deployment is one where the height of the activation has been hardcoded into
 * the client implementation long after the consensus change has activated. See BIP 90.
 */
enum BuriedDeployment : int16_t {
    // buried deployments get negative values to avoid overlap with DeploymentPos
    DEPLOYMENT_HEIGHTINCB = std::numeric_limits<int16_t>::min(),
    DEPLOYMENT_CLTV,
    DEPLOYMENT_DERSIG,
    DEPLOYMENT_CSV,
    DEPLOYMENT_SEGWIT,
};
constexpr bool ValidDeployment(BuriedDeployment dep) { return dep <= DEPLOYMENT_SEGWIT; }

enum DeploymentPos : uint16_t {
    DEPLOYMENT_TESTDUMMY,
    DEPLOYMENT_TAPROOT, // Deployment of Schnorr/Taproot (BIPs 340-342)
    // NOTE: Also add new deployments to VersionBitsDeploymentInfo in deploymentinfo.cpp
    MAX_VERSION_BITS_DEPLOYMENTS
};
constexpr bool ValidDeployment(DeploymentPos dep) { return dep < MAX_VERSION_BITS_DEPLOYMENTS; }

/**
 * Struct for each individual consensus rule change using BIP9.
 */
struct BIP9Deployment {
    /** Bit position to select the particular bit in nVersion. */
    int bit{28};
    /** Start MedianTime for version bits miner confirmation. Can be a date in the past */
    int64_t nStartTime{NEVER_ACTIVE};
    /** Timeout/expiry MedianTime for the deployment attempt. */
    int64_t nTimeout{NEVER_ACTIVE};
    /** If lock in occurs, delay activation until at least this block
     *  height.  Note that activation will only occur on a retarget
     *  boundary.
     */
    int min_activation_height{0};

    /** Constant for nTimeout very far in the future. */
    static constexpr int64_t NO_TIMEOUT = std::numeric_limits<int64_t>::max();

    /** Special value for nStartTime indicating that the deployment is always active.
     *  This is useful for testing, as it means tests don't need to deal with the activation
     *  process (which takes at least 3 BIP9 intervals). Only tests that specifically test the
     *  behaviour during activation cannot use this. */
    static constexpr int64_t ALWAYS_ACTIVE = -1;

    /** Special value for nStartTime indicating that the deployment is never active.
     *  This is useful for integrating the code changes for a new feature
     *  prior to deploying it on some or all networks. */
    static constexpr int64_t NEVER_ACTIVE = -2;
};

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    uint256 hashGenesisBlock;
    int nSubsidyHalvingInterval;
    int nSubsidyHalvingIntervalV2;
    /**
     * Hashes of blocks that
     * - are known to be consensus valid, and
     * - buried in the chain, and
     * - fail if the default script verify flags are applied.
     */
    std::map<uint256, uint32_t> script_flag_exceptions;
    /** Block height and hash at which BIP34 becomes active */
    int BIP34Height;
    uint256 BIP34Hash;
    /** Block height at which BIP65 becomes active */
    int BIP65Height;
    /** Block height at which BIP66 becomes active */
    int BIP66Height;
    /** Block height at which CSV (BIP68, BIP112 and BIP113) becomes active */
    int CSVHeight;
    /** Block height at which Segwit (BIP141, BIP143 and BIP147) becomes active.
     * Note that segwit v0 script rules are enforced on all blocks except the
     * BIP 16 exception blocks. */
    int SegwitHeight;
    /** Don't warn about unknown BIP 9 activations below this height.
     * This prevents us from warning about the CSV and segwit activations. */
    int MinBIP9WarningHeight;
    /** Block height at which QIP5 becomes active */
    int QIP5Height;
    /** Block height at which QIP6 becomes active */
    int QIP6Height;
    /** Block height at which QIP7 becomes active */
    int QIP7Height;
    /** Block height at which QIP9 becomes active */
    int QIP9Height;
    /** Block height at which Offline Staking becomes active */
    int nOfflineStakeHeight;
    /** Block height at which Reduce Block Time becomes active */
    int nReduceBlocktimeHeight;
    /** Block height at which EVM Muir Glacier fork becomes active */
    int nMuirGlacierHeight;
    /** Block height at which EVM London fork becomes active */
    int nLondonHeight;
    /** Block height at which EVM Shanghai fork becomes active */
    int nShanghaiHeight;
    /** Block height at which EVM Cancun fork becomes active */
    int nCancunHeight;
    /** Block height at which EVM Pectra fork becomes active */
    int nPectraHeight;
    /**
     * Minimum blocks including miner confirmation of the total of 2016 blocks in a retargeting period,
     * (nPowTargetTimespan / nPowTargetSpacing) which is also used for BIP9 deployments.
     * Examples: 1916 for 95%, 1512 for testchains.
     */
    uint32_t nRuleChangeActivationThreshold;
    uint32_t nMinerConfirmationWindow;
    BIP9Deployment vDeployments[MAX_VERSION_BITS_DEPLOYMENTS];
    /** Proof of work parameters */
    uint256 powLimit;
    uint256 posLimit;
    uint256 QIP9PosLimit;
    uint256 RBTPosLimit;
    bool fPowAllowMinDifficultyBlocks;
    /**
      * Enforce BIP94 timewarp attack mitigation. On testnet4 this also enforces
      * the block storm mitigation.
      */
    bool enforce_BIP94;
    bool fPowNoRetargeting;
    /**
     * Height at which proof-of-work difficulty starts retargeting when
     * fPowNoRetargeting is set.
     *
     * Mainnet launched with fPowNoRetargeting = true — a regtest-only setting —
     * which pinned difficulty to the genesis value forever: blocks arrived at
     * ~37s against a 120s target and emission ran at triple the intended rate.
     * Turning the flag off outright would change the expected nBits of every
     * block already mined and invalidate the existing chain, so retargeting
     * instead begins at this height and earlier blocks keep the launch rule.
     * Set to std::numeric_limits<int>::max() to keep difficulty fixed (regtest).
     */
    int nPowRetargetHeight;
    bool fPoSNoRetargeting;
    int64_t nPowTargetSpacing;
    int64_t nRBTPowTargetSpacing;
    int64_t nPowTargetTimespan;
    int64_t nPowTargetTimespanV2;
    int64_t nRBTPowTargetTimespan;
    std::chrono::seconds TargetSpacingChrono(int height) const
    {
        return std::chrono::seconds{TargetSpacing(height)};
    }
    int64_t DifficultyAdjustmentInterval(int height) const
    {
        int64_t targetTimespan = TargetTimespan(height);
        int64_t targetSpacing = TargetSpacing(height);
        return targetTimespan / targetSpacing;
    }
    /** The best chain should have at least this much work */
    uint256 nMinimumChainWork;
    /** By default assume that the signatures in ancestors of this block are valid */
    uint256 defaultAssumeValid;

    /**
     * If true, witness commitments contain a payload equal to a Bitcoin Script solution
     * to the signet challenge. See BIP325.
     */
    bool signet_blocks{false};
    std::vector<uint8_t> signet_challenge;

    int DeploymentHeight(BuriedDeployment dep) const
    {
        switch (dep) {
        case DEPLOYMENT_HEIGHTINCB:
            return BIP34Height;
        case DEPLOYMENT_CLTV:
            return BIP65Height;
        case DEPLOYMENT_DERSIG:
            return BIP66Height;
        case DEPLOYMENT_CSV:
            return CSVHeight;
        case DEPLOYMENT_SEGWIT:
            return SegwitHeight;
        } // no default case, so the compiler can warn about missing cases
        return std::numeric_limits<int>::max();
    }

    /** WATTx Hybrid Consensus: When set to 0, enables hybrid PoW/PoS from block 1.
     *  Both PoW and PoS blocks are valid with equal rewards.
     *  PoS becomes possible once coins reach maturity (coinbaseMaturity blocks). */
    int nLastPOWBlock;
    int nFirstMPoSBlock;
    int nMPoSRewardRecipients;
    int nFixUTXOCacheHFHeight;
    int nEnableHeaderSignatureHeight;
    /** Block sync-checkpoint span*/
    int nCheckpointSpan;
    int nRBTCheckpointSpan;
    /** WATTx max-reorg-depth guard: refuse to reorg the active chain deeper than
     *  this many blocks below the current tip. Stops a node that was partitioned
     *  from the network (e.g. a solo miner) from replacing the canonical chain with
     *  a long private fork on reconnect. 0 disables the guard (used for regtest). */
    int nMaxReorgDepth{0};
    uint160 delegationsAddress;
    uint160 historyStorageAddress;
    int nLastMPoSBlock;
    int nLastBigReward;
    uint32_t nStakeTimestampMask;
    uint32_t nRBTStakeTimestampMask;
    int64_t nBlocktimeDownscaleFactor;
    /** Coinbase transaction outputs can only be spent after this number of new blocks (network rule) */
    int nCoinbaseMaturity;
    /** Maturity used below nCoinbaseMaturityV2Height (the chain's launch value). */
    int nCoinbaseMaturityV1{1};
    /** Height from which the longer coinbase/coinstake maturity applies. */
    int nCoinbaseMaturityV2Height{0};
    int nRBTCoinbaseMaturity;
    /** Base minimum confirmations for coins to be eligible for staking (halves with each reward halving) */
    int nStakeMinConfirmations{500};
    /** Minimum stake confirmations floor (won't go below this) */
    int nMinStakeConfirmationsFloor{10};

    /** Get stake min confirmations at a given height (halves with each reward halving)
     *  Era 0: 500 blocks, Era 1: 250, Era 2: 125, Era 3: 62, etc.
     *  This creates easier PoS entry as PoW rewards decrease */
    int StakeMinConfirmations(int height) const
    {
        if (height <= nLastBigReward) {
            return nStakeMinConfirmations;
        }

        // Calculate halving era
        int subsidyHalvingInterval = SubsidyHalvingInterval(height);
        int subsidyHalvingWeight = SubsidyHalvingWeight(height);
        int halvings = (subsidyHalvingWeight - 1) / subsidyHalvingInterval;

        // Halve stake maturity for each halving era
        int stakeMaturity = nStakeMinConfirmations;
        for (int i = 0; i < halvings && stakeMaturity > nMinStakeConfirmationsFloor; i++) {
            stakeMaturity /= 2;
        }

        // Enforce minimum floor
        return std::max(stakeMaturity, nMinStakeConfirmationsFloor);
    }

    int64_t StakeTimestampMask(int height) const
    {
        // After PoS difficulty fix: enforce 16-second timestamp granularity
        // to prevent rapid-fire staking (was 1-second with mask=0)
        if (height >= nPoSDifficultyFixHeight) {
            return 15; // 16-second intervals (mask 0xF)
        }
        return height < nReduceBlocktimeHeight ? nStakeTimestampMask : nRBTStakeTimestampMask;
    }
    int64_t MinStakeTimestampMask() const
    {
        return nRBTStakeTimestampMask;
    }
    int SubsidyHalvingInterval(int height) const
    {
        return height < nReduceBlocktimeHeight ? nSubsidyHalvingInterval : nSubsidyHalvingIntervalV2;
    }
    int64_t BlocktimeDownscaleFactor(int height) const
    {
        return height < nReduceBlocktimeHeight ? 1 : nBlocktimeDownscaleFactor;
    }
    int64_t TargetSpacing(int height) const
    {
        return height < nReduceBlocktimeHeight ? nPowTargetSpacing : nRBTPowTargetSpacing;
    }
    int SubsidyHalvingWeight(int height) const
    {
        if(height <= nLastBigReward)
            return 0;

        int blocktimeDownscaleFactor = BlocktimeDownscaleFactor(height);
        int blockCount = height - nLastBigReward;
        int beforeDownscale = blocktimeDownscaleFactor == 1 ? 0 : nReduceBlocktimeHeight - nLastBigReward - 1;
        int subsidyHalvingWeight = blockCount - beforeDownscale + beforeDownscale * blocktimeDownscaleFactor;
        return subsidyHalvingWeight;
    }
    int64_t TimestampDownscaleFactor(int height) const
    {
        return height < nReduceBlocktimeHeight ? 1 : (nStakeTimestampMask + 1) / (nRBTStakeTimestampMask + 1);
    }
    int64_t TargetTimespan(int height) const
    {
        return height < QIP9Height ? nPowTargetTimespan : 
            (height < nReduceBlocktimeHeight ? nPowTargetTimespanV2 : nRBTPowTargetTimespan);
    }
    int CheckpointSpan(int height) const
    {
        return height < nReduceBlocktimeHeight ? nCheckpointSpan : nRBTCheckpointSpan;
    }
    /**
     * Confirmations before a coinbase or coinstake output can be spent.
     *
     * The chain launched with 1, which contradicts a 100-block reorg limit: a
     * two-block reorg could orphan a coinbase that had already been spent. It
     * cannot simply be raised, because proof-of-stake blocks already on the
     * chain spend outputs younger than the new value and would be rejected on
     * revalidation, so the longer maturity starts at nCoinbaseMaturityV2Height
     * and earlier blocks keep the rule they were mined under.
     */
    int CoinbaseMaturity(int height) const
    {
        if (height < nCoinbaseMaturityV2Height) return nCoinbaseMaturityV1;
        return height < nReduceBlocktimeHeight ? nCoinbaseMaturity : nRBTCoinbaseMaturity;
    }
    int MaxCheckpointSpan() const
    {
        return nCheckpointSpan <= nRBTCheckpointSpan ? nRBTCheckpointSpan : nCheckpointSpan;
    }

    //////////////////////////////////////////////////
    // WATTx X25X Multi-Algorithm PoW Parameters
    //////////////////////////////////////////////////

    /** Height at which RandomX mining activates (hard fork) */
    int nRandomXActivationHeight{210000};  // RandomX activates at block 210,000 (same as X25X)

    /** Height at which X25X multi-algorithm mining activates (hard fork) */
    int nX25XActivationHeight{210000};  // Set to actual fork height before deployment

    /** Check if RandomX mining is active at given height */
    bool IsRandomXActive(int height) const {
        return height >= nRandomXActivationHeight;
    }

    /** Block reward share for miner (PoW) - percentage of base reward */
    int nPoWRewardPercent{100}; // 100% = full 5 WATTx to PoW miner

    /** Block reward share for validator (PoS) - percentage of base reward */
    int nPoSRewardPercent{100}; // 100% = full 5 WATTx to PoS validator

    /** Supported algorithms for X25X merged mining */
    /** Miners can submit proofs from: SHA256, Scrypt, X11, Ethash, RandomX, etc. */
    /** The X25X chain validates these proofs and adjusts difficulty per-algorithm */

    /** Number of blocks to look back for difficulty adjustment per algorithm */
    int nX25XDifficultyLookback{144}; // ~1 day at 10-min blocks

    /** Check if X25X multi-algorithm mining is active at given height */
    bool IsX25XActive(int height) const {
        return height >= nX25XActivationHeight;
    }

    //////////////////////////////////////////////////
    // WATTx Trust Tier System Parameters
    //////////////////////////////////////////////////

    /** Minimum stake required to become a validator (in satoshis) */
    int64_t nMinValidatorStake{100000LL * 100000000LL}; // 100,000 WATTx

    /** Heartbeat interval - validators must broadcast heartbeat every N blocks */
    int nHeartbeatInterval{600}; // Every 10 minutes at 1s blocks

    /** Uptime tracking window in blocks (~30 days at 1s blocks) */
    int nUptimeWindow{2592000};

    /** Trust tier uptime thresholds (in percentage * 10, e.g., 950 = 95.0%) */
    int nBronzeUptimeThreshold{950};   // 95.0% uptime for Bronze
    int nSilverUptimeThreshold{970};   // 97.0% uptime for Silver
    int nGoldUptimeThreshold{990};     // 99.0% uptime for Gold
    int nPlatinumUptimeThreshold{999}; // 99.9% uptime for Platinum

    /** Base block reward in satoshis (5 WATTx per block for each PoW/PoS) */
    /** 50% to PoW miners, 50% to PoS stakers - each receives this amount */
    /** Base block reward in satoshis: 50 WTX.
     *  With a 210,000-block halving interval the full series totals exactly
     *  21,000,000 WTX. */
    int64_t nBaseBlockReward{5000000000};

    /** Height at which trust tier system activates */
    int nTrustTierActivationHeight{1001}; // After PoW phase

    /** Delegation maturity - blocks before a pending delegation becomes active */
    int nDelegationMaturity{1000};

    /** Delegation unbonding period - blocks to wait after undelegation before withdrawal */
    int nDelegationUnbondingPeriod{10000};

    //////////////////////////////////////////////////
    // WATTx-Monero Merged Mining (AuxPoW) Parameters
    //////////////////////////////////////////////////

    /** Height at which AuxPoW (merged mining with Monero) becomes active */
    int nAuxPowActivationHeight{210000}; // Activate merged mining at block 210,000

    /** WATTx chain ID for merged mining (prevents cross-chain replay) */
    int32_t nAuxPowChainId{0x5754}; // "WT" in hex

    /** Allow standalone (non-merged) mining after AuxPoW activation */
    bool fAllowStandaloneMining{true};

    /** Maximum time difference between parent block and aux block timestamps */
    int64_t nMaxAuxPowTimeDiff{7200}; // 2 hours

    /** Check if AuxPoW is active at given height */
    bool IsAuxPowActive(int height) const {
        return height >= nAuxPowActivationHeight;
    }

    //////////////////////////////////////////////////
    // WATTx EVM Transaction Anchoring Parameters
    //////////////////////////////////////////////////

    /** Height at which EVM transaction anchoring to Monero becomes active */
    int nEVMAnchorActivationHeight{210000}; // Activate EVM anchoring at block 210,000

    /** Check if EVM anchoring is active at given height */
    bool IsEVMAnchorActive(int height) const {
        return height >= nEVMAnchorActivationHeight;
    }

    //////////////////////////////////////////////////
    // WATTx PoS Difficulty Fix (Hard Fork)
    //////////////////////////////////////////////////

    /** Height at which PoS difficulty fix activates.
     *  Fixes: RBTPosLimit too easy (2^228), stakeTimestampMask=0 (1-sec grinding),
     *  and weak difficulty adjustment causing ~10s blocks instead of 120s target.
     *  After this height: tighter PoS limit, 16-second timestamp granularity. */
    int nPoSDifficultyFixHeight{std::numeric_limits<int>::max()}; // Disabled by default

    /** Tighter PoS difficulty limit after the fix (matches QTUM standard ~2^214).
     *  Replaces the broken RBTPosLimit (2^228) which was 16,384x too easy. */
    uint256 FixedRBTPosLimit;

    /** Check if PoS difficulty fix is active at given height */
    bool IsPoSDifficultyFixActive(int height) const {
        return height >= nPoSDifficultyFixHeight;
    }

    //////////////////////////////////////////////////
    // WATTx FCMP (Full-Chain Membership Proofs) Parameters
    //////////////////////////////////////////////////

    /** Height at which FCMP privacy transactions become active */
    int nFcmpActivationHeight{std::numeric_limits<int>::max()}; // Disabled by default

    /** Height at which FCMP coinbase/coinstake rewards become active */
    int nFcmpCoinbaseActivationHeight{std::numeric_limits<int>::max()}; // Disabled by default

    /** FCMP output maturity - blocks before FCMP outputs can be spent */
    int nFcmpMaturity{10};

    /** FCMP coinbase maturity - blocks before FCMP coinbase outputs can be spent */
    int nFcmpCoinbaseMaturity{100};

    /** Check if FCMP is active at given height */
    bool IsFcmpActive(int height) const {
        return height >= nFcmpActivationHeight;
    }

    /** Check if FCMP coinbase rewards are active at given height */
    bool IsFcmpCoinbaseActive(int height) const {
        return height >= nFcmpCoinbaseActivationHeight;
    }

    //////////////////////////////////////////////////
    // WATTx Privacy Transaction Parameters
    //////////////////////////////////////////////////

    /** Block height at which privacy transactions become valid */
    int nPrivacyActivationHeight{210000};

    /** Check if privacy transactions are active at given height */
    bool IsPrivacyActive(int height) const {
        return height >= nPrivacyActivationHeight;
    }
};

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_PARAMS_H
