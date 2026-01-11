// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/chainparams.h>

#include <chainparamsseeds.h>
#include <consensus/amount.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <consensus/consensus.h>
#include <hash.h>
#include <kernel/messagestartchars.h>
#include <logging.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <uint256.h>
#include <arith_uint256.h>
#include <util/chaintype.h>
#include <util/strencodings.h>
#include <util/convert.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <type_traits>

///////////////////////////////////////////// // qtum
#include <libdevcore/SHA3.h>
#include <libdevcore/RLP.h>
#include "arith_uint256.h"
/////////////////////////////////////////////

using namespace util::hex_literals;

// Workaround MSVC bug triggering C7595 when calling consteval constructors in
// initializer lists.
// A fix may be on the way:
// https://developercommunity.visualstudio.com/t/consteval-conversion-function-fails/1579014
#if defined(_MSC_VER)
auto consteval_ctor(auto&& input) { return input; }
#else
#define consteval_ctor(input) (input)
#endif

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.version = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 00 << 488804799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    genesis.hashStateRoot = uint256(h256Touint(dev::h256("e965ffd002cd6ad0e2dc402b8044de833e06b23127ea8c3d80aec91410771495"))); // qtum
    genesis.hashUTXORoot = uint256(h256Touint(dev::sha3(dev::rlp("")))); // qtum
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 */

// WATTx Mainnet Genesis - Operation Absolute Resolve
static CBlock CreateMainnetGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "Operation Absolute Resolve - Maduro Captured 03/Jan/2026 11:11 PM CST";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

// WATTx Testnet Genesis - Fresh chain for testing
static CBlock CreateTestnetGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "WATTx Testnet Launch - Jan 2026 - Fast Sync Testing";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

// WATTx Signet Genesis
static CBlock CreateSigNetGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "WATTx SigNet Genesis - Custom Challenge";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * WATTx Main network - Tiered Proof of Stake with Trust Scoring
 * Fair launch, no premine, 1-second blocks
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        m_chain_type = ChainType::MAIN;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 1051200; // WATTx halving every ~4 years at 2min blocks
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256{}; // Will be set after genesis mining
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.CSVHeight = 0;
        consensus.SegwitHeight = 0;
        consensus.MinBIP9WarningHeight = 0;
        consensus.QIP5Height = 0;
        consensus.QIP6Height = 0;
        consensus.QIP7Height = 0;
        consensus.QIP9Height = 0;
        consensus.nOfflineStakeHeight = 1; // Enable offline staking from start
        consensus.nReduceBlocktimeHeight = 0; // 1-second blocks from genesis
        consensus.nMuirGlacierHeight = 0;
        consensus.nLondonHeight = 0;
        consensus.nShanghaiHeight = 0;
        consensus.nCancunHeight = 0;
        consensus.nPectraHeight = 0;
        consensus.powLimit = uint256{"0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.posLimit = uint256{"00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.QIP9PosLimit = uint256{"0000000000001fffffffffffffffffffffffffffffffffffffffffffffffffff"};
        // WATTx: Much easier PoS limit for small stakes with 1-second blocks
        // Original was 0000000000003fff... (48 bits zeros, ~2^208) - way too hard for small stakes
        // New is 0000000fff... (28 bits zeros, ~2^228) - allows blocks every ~10s with 25M satoshis
        consensus.RBTPosLimit = uint256{"0000000fffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        // WATTx: 2-minute block time (120 seconds)
        consensus.nPowTargetTimespan = 1200; // 10 blocks at 2min = 20 minutes
        consensus.nPowTargetTimespanV2 = 1200;
        consensus.nRBTPowTargetTimespan = 1200;
        consensus.nPowTargetSpacing = 120; // 2 minutes per block
        consensus.nRBTPowTargetSpacing = 120;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.enforce_BIP94 = false;
        consensus.fPowNoRetargeting = true;
        consensus.fPoSNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 540; // 90% of 600
        consensus.nMinerConfirmationWindow = 600; // 10 minutes worth of blocks
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0;

        // Taproot active from genesis
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0;

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        /**
         * WATTx network magic bytes
         */
        pchMessageStart[0] = 0x57; // 'W'
        pchMessageStart[1] = 0x41; // 'A'
        pchMessageStart[2] = 0x54; // 'T'
        pchMessageStart[3] = 0x58; // 'X'
        nDefaultPort = 1337;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 1;
        m_assumed_chain_state_size = 1;

        // WATTx Mainnet Genesis Block - Operation Absolute Resolve
        // Message: "Operation Absolute Resolve - Maduro Captured 03/Jan/2026 11:11 PM CST"
        genesis = CreateMainnetGenesisBlock(1735430400, 0, 0x1f00ffff, 1, 500000000);

        // Mine mainnet genesis (finds valid nonce)
        arith_uint256 bnTarget;
        bnTarget.SetCompact(genesis.nBits);
        printf("Mining WATTx MAINNET genesis...\n");
        printf("MerkleRoot: %s\n", genesis.hashMerkleRoot.GetHex().c_str());
        for (genesis.nNonce = 0; genesis.nNonce < 0xFFFFFFFF; genesis.nNonce++) {
            uint256 hash = genesis.GetHash();
            if (UintToArith256(hash) <= bnTarget) {
                printf("MAINNET FOUND! nNonce=%u\n", genesis.nNonce);
                printf("hashGenesisBlock=%s\n", hash.GetHex().c_str());
                break;
            }
            if (genesis.nNonce % 100000 == 0) printf("mainnet nonce=%u\n", genesis.nNonce);
        }
        consensus.hashGenesisBlock = genesis.GetHash();

        // WATTx seed nodes (to be configured)
        vSeeds.emplace_back("seed1.wattxchange.app");
        vSeeds.emplace_back("seed2.wattxchange.app");
        vSeeds.emplace_back("seed3.wattxchange.app");

        // WATTx addresses start with 'W' (base58 prefix 73)
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,73);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,75);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};
        // Dilithium (quantum-resistant) addresses start with 'Q' (base58 prefix 58)
        base58Prefixes[DILITHIUM_ADDRESS] = std::vector<unsigned char>(1,58);

        bech32_hrp = "wx";

        vFixedSeeds.clear(); // New chain, no fixed seeds yet

        fDefaultConsistencyChecks = false;
        fMineBlocksOnDemand = false;
        m_is_mockable_chain = false;
        fHasHardwareWalletSupport = true;

        checkpointData = {
            {
                // Will be updated after mining mainnet genesis with Gapcoin fields
            }
        };

        m_assumeutxo_data = {
            {}
        };

        chainTxData = ChainTxData{
            .nTime    = 1735430400,
            .tx_count = 0,
            .dTxRate  = 0,
        };

        // WATTx-specific parameters
        consensus.nBlocktimeDownscaleFactor = 1; // No downscaling
        consensus.nCoinbaseMaturity = 1; // WATTx: PoW rewards spendable after 1 confirmation
        consensus.nRBTCoinbaseMaturity = 1;
        consensus.nStakeMinConfirmations = 10; // WATTx: Coins need 10 confirmations to stake
        consensus.nSubsidyHalvingIntervalV2 = 1051200; // ~4 years at 2min blocks (525600 min/year * 2)
        consensus.nMinValidatorStake = 20000 * COIN; // 20,000 WATTx minimum for super staking validator

        consensus.nLastPOWBlock = 0x7fffffff; // Allow indefinite PoW mining until hybrid consensus activation
        consensus.nLastBigReward = 0; // Fair launch - no big rewards, 0.08333333 WATTx from block 1
        consensus.nMPoSRewardRecipients = 10;
        consensus.nFirstMPoSBlock = consensus.nLastPOWBlock +
                                    consensus.nMPoSRewardRecipients +
                                    consensus.nCoinbaseMaturity;
        consensus.nLastMPoSBlock = 0; // Disable MPoS, use tiered PoS

        consensus.nFixUTXOCacheHFHeight = 0;
        consensus.nEnableHeaderSignatureHeight = 0;
        consensus.nCheckpointSpan = consensus.nCoinbaseMaturity;
        consensus.nRBTCheckpointSpan = consensus.nRBTCoinbaseMaturity;
        consensus.delegationsAddress = uint160(ParseHex("0000000000000000000000000000000000000086"));
        consensus.historyStorageAddress = uint160(ParseHex("0000F90827F1C53a10cb7A02335B175320002935"));
        consensus.nStakeTimestampMask = 0; // 1-second precision for 1s blocks
        consensus.nRBTStakeTimestampMask = 0;

        // WATTx Trust Tier parameters (to be added to consensus struct)
        // consensus.nMinValidatorStake = 100000 * COIN;
        // consensus.nBronzeUptime = 95;
        // consensus.nSilverUptime = 97;
        // consensus.nGoldUptime = 99;
        // consensus.nPlatinumUptime = 999; // 99.9%
    }
};

/**
 * Testnet (v3): public test network which is reset from time to time.
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        m_chain_type = ChainType::TESTNET;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 985500; // qtum halving every 4 years
        consensus.script_flag_exceptions.emplace( // BIP16 exception
            uint256{"0000e803ee215c0684ca0d2f9220594d3f828617972aad66feb2ba51f5e14222"}, SCRIPT_VERIFY_NONE);
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256{"0000e803ee215c0684ca0d2f9220594d3f828617972aad66feb2ba51f5e14222"};
        consensus.BIP65Height = 0; // 00000000007f6655f22f98e72ed80d8b06dc761d5da09df0fa1dc4be4f861eb6
        consensus.BIP66Height = 0; // 000000002104c8c45e99a8853285a3b592602a3ccde2b832481da85e9e4ba182
        consensus.CSVHeight = 6048; // 00000000025e930139bac5c6c31a403776da130831ab85be56578f3fa75369bb
        consensus.SegwitHeight = 6048; // 00000000002b980fcd729daaa248fd9316a5200e9b367f4ff2c42453e84201ca
        consensus.MinBIP9WarningHeight = 8064; // segwit activation height + miner confirmation window
        // WATTx: Enable all EVM upgrades from genesis
        consensus.QIP5Height = 0;
        consensus.QIP6Height = 0;
        consensus.QIP7Height = 0;  // Constantinople (SHR opcode)
        consensus.QIP9Height = 0;
        consensus.nOfflineStakeHeight = 0;
        consensus.nReduceBlocktimeHeight = 0;
        consensus.nMuirGlacierHeight = 0;
        consensus.nLondonHeight = 0;
        consensus.nShanghaiHeight = 0;
        consensus.nCancunHeight = 0;
        consensus.nPectraHeight = 0;
        consensus.powLimit = uint256{"0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.posLimit = uint256{"0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.QIP9PosLimit = uint256{"0000000000001fffffffffffffffffffffffffffffffffffffffffffffffffff"}; // The new POS-limit activated after QIP9
        consensus.RBTPosLimit = uint256{"0000000000003fffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.nPowTargetTimespan = 1200; // 10 blocks at 2min = 20 minutes
        consensus.nPowTargetTimespanV2 = 1200;
        consensus.nRBTPowTargetTimespan = 1200;
        consensus.nPowTargetSpacing = 120; // WATTx testnet: 2 minutes per block (same as mainnet)
        consensus.nRBTPowTargetSpacing = 120;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.enforce_BIP94 = false;
        consensus.fPowNoRetargeting = true;
        consensus.fPoSNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Deployment of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        // Min block number for activation, the number must be divisible by 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 1967616;

        consensus.nMinimumChainWork = uint256{};  // WATTx testnet: no minimum for fresh chain
        consensus.defaultAssumeValid = uint256{};  // WATTx testnet: no assume valid for fresh chain

        pchMessageStart[0] = 0x0d;
        pchMessageStart[1] = 0x22;
        pchMessageStart[2] = 0x15;
        pchMessageStart[3] = 0x06;
        nDefaultPort = 11337;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 11;
        m_assumed_chain_state_size = 1;

        // WATTx Testnet Genesis Block - Fresh chain for immediate sync
        // Message: "WATTx Testnet Launch - Jan 2026 - Fast Sync Testing"
        genesis = CreateTestnetGenesisBlock(1736035200, 0, 0x1f00ffff, 1, 500000000);

        // Mine testnet genesis
        arith_uint256 bnTarget;
        bnTarget.SetCompact(genesis.nBits);
        printf("Mining WATTx TESTNET genesis...\n");
        printf("MerkleRoot: %s\n", genesis.hashMerkleRoot.GetHex().c_str());
        for (genesis.nNonce = 0; genesis.nNonce < 0xFFFFFFFF; genesis.nNonce++) {
            uint256 hash = genesis.GetHash();
            if (UintToArith256(hash) <= bnTarget) {
                printf("TESTNET FOUND! nNonce=%u\n", genesis.nNonce);
                printf("hashGenesisBlock=%s\n", hash.GetHex().c_str());
                break;
            }
            if (genesis.nNonce % 100000 == 0) printf("testnet nonce=%u\n", genesis.nNonce);
        }
        consensus.hashGenesisBlock = genesis.GetHash();

        vFixedSeeds.clear();
        vSeeds.clear();
        // WATTx testnet - isolated mode (no external seeds for now)
        // When ready for public testnet, add: vSeeds.emplace_back("testnet-seed1.wattxchange.app");

        // WATTx testnet addresses start with 'w' (base58 prefix 135)
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,135);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,137);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
        // Dilithium (quantum-resistant) testnet addresses start with 'D' (base58 prefix 30)
        base58Prefixes[DILITHIUM_ADDRESS] = std::vector<unsigned char>(1,30);

        bech32_hrp = "wt"; // WATTx testnet bech32 prefix

        // No fixed seeds - WATTx testnet runs in isolated mode
        // vFixedSeeds = std::vector<uint8_t>(std::begin(chainparams_seed_test), std::end(chainparams_seed_test));

        fDefaultConsistencyChecks = false;
        fMineBlocksOnDemand = false;
        m_is_mockable_chain = false;
        fHasHardwareWalletSupport = true;

        checkpointData = {
            {
                // Will be updated after mining testnet genesis
            }
        };

        m_assumeutxo_data = {
            {}
        };

        chainTxData = ChainTxData{
            .nTime    = 1736035200,
            .tx_count = 0,
            .dTxRate  = 0,
        };

        consensus.nBlocktimeDownscaleFactor = 1; // WATTx testnet: no downscaling
        consensus.nCoinbaseMaturity = 1;  // WATTx testnet: PoW rewards spendable after 1 confirmation
        consensus.nRBTCoinbaseMaturity = 1;
        consensus.nStakeMinConfirmations = 10; // WATTx testnet: Coins need 10 confirmations to stake
        consensus.nSubsidyHalvingIntervalV2 = 1051200; // WATTx testnet: ~4 years at 2min blocks
        consensus.nMinValidatorStake = 20000 * COIN; // 20,000 WATTx minimum (same as mainnet)

        // WATTx Testnet: Same as mainnet (fair launch, no big rewards)
        consensus.nLastPOWBlock = 0x7fffffff;  // Allow indefinite PoW mining until hybrid consensus activation (same as mainnet)
        consensus.nLastBigReward = 0;  // Fair launch - no big rewards (same as mainnet)
        consensus.nMPoSRewardRecipients = 10;
        consensus.nFirstMPoSBlock = consensus.nLastPOWBlock +
                                    consensus.nMPoSRewardRecipients +
                                    consensus.nCoinbaseMaturity;
        consensus.nLastMPoSBlock = 0;   // Disable MPoS, use tiered PoS (same as mainnet)

        consensus.nFixUTXOCacheHFHeight = 0;
        consensus.nEnableHeaderSignatureHeight = 0;
        consensus.nCheckpointSpan = consensus.nCoinbaseMaturity;
        consensus.nRBTCheckpointSpan = consensus.nRBTCoinbaseMaturity;
        consensus.delegationsAddress = uint160(ParseHex("0000000000000000000000000000000000000086")); // Same as mainnet
        consensus.historyStorageAddress = uint160(ParseHex("0000F90827F1C53a10cb7A02335B175320002935")); // EVM block hash history contract address
        consensus.nStakeTimestampMask = 0;  // Allow staking every second
        consensus.nRBTStakeTimestampMask = 0;
    }
};

/**
 * Testnet (v4): public test network which is reset from time to time.
 */
class CTestNet4Params : public CChainParams {
public:
    CTestNet4Params() {
        m_chain_type = ChainType::TESTNET4;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 985500; // qtum halving every 4 years
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 1;
        consensus.MinBIP9WarningHeight = 0;
        consensus.QIP5Height = 0;
        consensus.QIP6Height = 0;
        consensus.QIP7Height = 0;
        consensus.QIP9Height = 0;
        consensus.nOfflineStakeHeight = 1;
        consensus.nReduceBlocktimeHeight = 0;
        consensus.nMuirGlacierHeight = 0;
        consensus.nLondonHeight = 0;
        consensus.nShanghaiHeight = 0;
        consensus.nCancunHeight = 0;
        consensus.nPectraHeight = 0;
        consensus.powLimit = uint256{"0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.posLimit = uint256{"0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.QIP9PosLimit = uint256{"0000000000001fffffffffffffffffffffffffffffffffffffffffffffffffff"}; // The new POS-limit activated after QIP9
        consensus.RBTPosLimit = uint256{"0000000000003fffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.nPowTargetTimespan = 16 * 60; // 16 minutes
        consensus.nPowTargetTimespanV2 = 4000;
        consensus.nRBTPowTargetTimespan = 1000;
        consensus.nPowTargetSpacing = 2 * 64;
        consensus.nRBTPowTargetSpacing = 32;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.enforce_BIP94 = true; // Special difficulty rule for Testnet4 in Bitcoin
        consensus.fPowNoRetargeting = true;
        consensus.fPoSNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Deployment of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        pchMessageStart[0] = 0x1c;
        pchMessageStart[1] = 0x16;
        pchMessageStart[2] = 0x3f;
        pchMessageStart[3] = 0x28;
        nDefaultPort = 43888;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 11;
        m_assumed_chain_state_size = 1;

        // WATTx Signet Genesis Block - Uses mainnet genesis
        genesis = CreateMainnetGenesisBlock(1735430400, 0, 0x1f00ffff, 1, 500000000);

        // Mine signet genesis (finds valid nonce) - same as mainnet but cached separately
        {
            arith_uint256 bnTarget;
            bnTarget.SetCompact(genesis.nBits);
            for (genesis.nNonce = 0; genesis.nNonce < 0xFFFFFFFF; genesis.nNonce++) {
                uint256 hash = genesis.GetHash();
                if (UintToArith256(hash) <= bnTarget) {
                    break;
                }
            }
        }
        consensus.hashGenesisBlock = genesis.GetHash();

        vFixedSeeds.clear();
        vSeeds.clear();
        // WATTx Signet - isolated mode (no external seeds)
        // Do NOT connect to QTUM network

        // WATTx signet addresses start with 'w' (base58 prefix 135)
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,135);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,137);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "ws"; // WATTx signet bech32 prefix

        // No fixed seeds - WATTx signet runs in isolated mode
        // vFixedSeeds = std::vector<uint8_t>(std::begin(chainparams_seed_testnet4), std::end(chainparams_seed_testnet4));

        fDefaultConsistencyChecks = false;
        fMineBlocksOnDemand = false;
        m_is_mockable_chain = false;
        fHasHardwareWalletSupport = true;

        checkpointData = {
            {
                // Will be updated after mining signet genesis with Gapcoin fields
            }
        };

        m_assumeutxo_data = {
            {}
        };

        chainTxData = ChainTxData{
            .nTime    = 1735430400,
            .tx_count = 0,
            .dTxRate  = 0,
        };

        consensus.nBlocktimeDownscaleFactor = 4;
        consensus.nCoinbaseMaturity = 500;
        consensus.nRBTCoinbaseMaturity = consensus.nBlocktimeDownscaleFactor*500;
        consensus.nSubsidyHalvingIntervalV2 = consensus.nBlocktimeDownscaleFactor*985500; // qtum halving every 4 years (nSubsidyHalvingInterval * nBlocktimeDownscaleFactor)
        consensus.nMinValidatorStake = 100000 * COIN; // 100,000 WATTx minimum to stake

        consensus.nLastPOWBlock = 5000;
        consensus.nLastBigReward = 0; // Fair launch - same as mainnet (0.08333333 WATTx per block)
        consensus.nMPoSRewardRecipients = 10;
        consensus.nFirstMPoSBlock = 5000;
        consensus.nLastMPoSBlock = 0;

        consensus.nFixUTXOCacheHFHeight = 0;
        consensus.nEnableHeaderSignatureHeight = 0;
        consensus.nCheckpointSpan = consensus.nCoinbaseMaturity;
        consensus.nRBTCheckpointSpan = consensus.nRBTCoinbaseMaturity;
        consensus.delegationsAddress = uint160(ParseHex("0000000000000000000000000000000000000086")); // Delegations contract for offline staking
        consensus.historyStorageAddress = uint160(ParseHex("0000F90827F1C53a10cb7A02335B175320002935")); // EVM block hash history contract address
        consensus.nStakeTimestampMask = 15;
        consensus.nRBTStakeTimestampMask = 3;
    }
};

/**
 * Signet: test network with an additional consensus parameter (see BIP325).
 */
class SigNetParams : public CChainParams {
public:
    explicit SigNetParams(const SigNetOptions& options)
    {
        std::vector<uint8_t> bin;
        vFixedSeeds.clear();
        vSeeds.clear();

        if (!options.challenge) {
            bin = "51210276aa67f74d27c3dcd4be86ca8375a4d70b1e00f7787451d8445c647a3c099ee7210276aa67f74d27c3dcd4be86ca8375a4d70b1e00f7787451d8445c647a3c099ee752ae"_hex_v_u8;

            consensus.nMinimumChainWork = uint256{};
            consensus.defaultAssumeValid = uint256{};
            m_assumed_blockchain_size = 1;
            m_assumed_chain_state_size = 0;
            chainTxData = ChainTxData{
                // Data from RPC: getchaintxstats 4096 000000895a110f46e59eb82bbc5bfb67fa314656009c295509c21b4999f5180a
                .nTime    = 0,
                .tx_count = 0,
                .dTxRate  = 0,
            };
        } else {
            bin = *options.challenge;
            consensus.nMinimumChainWork = uint256{};
            consensus.defaultAssumeValid = uint256{};
            m_assumed_blockchain_size = 0;
            m_assumed_chain_state_size = 0;
            chainTxData = ChainTxData{
                0,
                0,
                0,
            };
            LogPrintf("Signet with challenge %s\n", HexStr(bin));
        }

        if (options.seeds) {
            vSeeds = *options.seeds;
        }

        m_chain_type = ChainType::SIGNET;
        consensus.signet_blocks = true;
        consensus.signet_challenge.assign(bin.begin(), bin.end());
        consensus.nSubsidyHalvingInterval = 985500;
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 1;
        consensus.QIP5Height = 0;
        consensus.QIP6Height = 0;
        consensus.QIP7Height = 0;
        consensus.QIP9Height = 0;
        consensus.nOfflineStakeHeight = 1;
        consensus.nReduceBlocktimeHeight = 0;
        consensus.nMuirGlacierHeight = 0;
        consensus.nLondonHeight = 0;
        consensus.nShanghaiHeight = 0;
        consensus.nCancunHeight = 0;
        consensus.nPectraHeight = 0;
        consensus.powLimit = uint256{"0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.posLimit = uint256{"0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.QIP9PosLimit = uint256{"0000000000001fffffffffffffffffffffffffffffffffffffffffffffffffff"}; // The new POS-limit activated after QIP9
        consensus.RBTPosLimit = uint256{"0000000000003fffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.nPowTargetTimespan = 16 * 60; // 16 minutes
        consensus.nPowTargetTimespanV2 = 4000;
        consensus.nRBTPowTargetTimespan = 1000;
        consensus.nPowTargetSpacing = 2 * 64;
        consensus.nRBTPowTargetSpacing = 32;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.enforce_BIP94 = false;
        consensus.fPowNoRetargeting = true;
        consensus.fPoSNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1815; // 90% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.MinBIP9WarningHeight = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Activation of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        // message start is defined as the first 4 bytes of the sha256d of the block script
        HashWriter h{};
        h << consensus.signet_challenge;
        uint256 hash = h.GetHash();
        std::copy_n(hash.begin(), 4, pchMessageStart.begin());

        nDefaultPort = 33888;
        nPruneAfterHeight = 1000;

        genesis = CreateSigNetGenesisBlock(1623662135, 7377285, 0x1f00ffff, 1, 378788);
        consensus.hashGenesisBlock = genesis.GetHash();
        // TODO: Generate new genesis block for WATTx regtest
        // assert(consensus.hashGenesisBlock == uint256{"0000e0d4bc95abd1c0fcef0abb2795b6e8525f406262d59dc60cd3c490641347"});
        // TODO: Verify merkle root for WATTx genesis
        // assert(genesis.hashMerkleRoot == uint256{"ed34050eb5909ee535fcb07af292ea55f3d2f291187617b44d3282231405b96d"});

        m_assumeutxo_data = {
            {}
        };

        // WATTx testnet4 addresses start with 'w' (base58 prefix 135)
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,135);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,137);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "w4"; // WATTx testnet4 bech32 prefix

        fDefaultConsistencyChecks = false;
        fMineBlocksOnDemand = false;
        m_is_mockable_chain = false;

        consensus.nBlocktimeDownscaleFactor = 4;
        consensus.nCoinbaseMaturity = 500;
        consensus.nRBTCoinbaseMaturity = consensus.nBlocktimeDownscaleFactor*500;
        consensus.nSubsidyHalvingIntervalV2 = consensus.nBlocktimeDownscaleFactor*985500; // qtum halving every 4 years (nSubsidyHalvingInterval * nBlocktimeDownscaleFactor)
        consensus.nMinValidatorStake = 100000 * COIN; // 100,000 WATTx minimum to stake

        consensus.nLastPOWBlock = 0x7fffffff;
        consensus.nLastBigReward = 0; // Fair launch (0.08333333 WATTx per block)
        consensus.nMPoSRewardRecipients = 10;
        consensus.nFirstMPoSBlock = 5000;
        consensus.nLastMPoSBlock = 0;

        consensus.nFixUTXOCacheHFHeight = 0;
        consensus.nEnableHeaderSignatureHeight = 0;
        consensus.nCheckpointSpan = consensus.nCoinbaseMaturity;
        consensus.nRBTCheckpointSpan = consensus.nRBTCoinbaseMaturity;
        consensus.delegationsAddress = uint160(ParseHex("0000000000000000000000000000000000000086")); // Delegations contract for offline staking
        consensus.historyStorageAddress = uint160(ParseHex("0000F90827F1C53a10cb7A02335B175320002935")); // EVM block hash history contract address
        consensus.nStakeTimestampMask = 15;
        consensus.nRBTStakeTimestampMask = 3;
    }
};

/**
 * Regression test: intended for private networks only. Has minimal difficulty to ensure that
 * blocks can be found instantly.
 */
class CRegTestParams : public CChainParams
{
public:
    explicit CRegTestParams(const RegTestOptions& opts)
    {
        m_chain_type = ChainType::REGTEST;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 985500;
        consensus.BIP34Height = 1; // Always active unless overridden
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1;  // Always active unless overridden
        consensus.BIP66Height = 1;  // Always active unless overridden
        consensus.CSVHeight = 1;    // Always active unless overridden
        consensus.SegwitHeight = 0; // Always active unless overridden
        consensus.MinBIP9WarningHeight = 0;
        consensus.QIP5Height = 0;
        consensus.QIP6Height = 0;
        consensus.QIP7Height = 0;
        consensus.QIP9Height = 0;
        consensus.nOfflineStakeHeight = 1;
        consensus.nReduceBlocktimeHeight = 0;
        consensus.nMuirGlacierHeight = 0;
        consensus.nLondonHeight = 0;
        consensus.nShanghaiHeight = 0;
        consensus.nCancunHeight = 0;
        consensus.nPectraHeight = 0;
        consensus.powLimit = uint256{"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.posLimit = uint256{"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.QIP9PosLimit = uint256{"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}; // The new POS-limit activated after QIP9
        consensus.RBTPosLimit = uint256{"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.nPowTargetTimespan = 16 * 60; // 16 minutes (960 = 832 + 128; multiplier is 832)
        consensus.nPowTargetTimespanV2 = 4000;
        consensus.nRBTPowTargetTimespan = 1000;
        consensus.nPowTargetSpacing = 2 * 64;
        consensus.nRBTPowTargetSpacing = 32;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.enforce_BIP94 = opts.enforce_bip94;
        consensus.fPowNoRetargeting = true;
        consensus.fPoSNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        pchMessageStart[0] = 0xfd;
        pchMessageStart[1] = 0xdd;
        pchMessageStart[2] = 0xc6;
        pchMessageStart[3] = 0xe1;
        nDefaultPort = 23888;
        nPruneAfterHeight = opts.fastprune ? 100 : 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        for (const auto& [dep, height] : opts.activation_heights) {
            switch (dep) {
            case Consensus::BuriedDeployment::DEPLOYMENT_SEGWIT:
                consensus.SegwitHeight = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_HEIGHTINCB:
                consensus.BIP34Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_DERSIG:
                consensus.BIP66Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_CLTV:
                consensus.BIP65Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_CSV:
                consensus.CSVHeight = int{height};
                break;
            }
        }

        for (const auto& [deployment_pos, version_bits_params] : opts.version_bits_parameters) {
            consensus.vDeployments[deployment_pos].nStartTime = version_bits_params.start_time;
            consensus.vDeployments[deployment_pos].nTimeout = version_bits_params.timeout;
            consensus.vDeployments[deployment_pos].min_activation_height = version_bits_params.min_activation_height;
        }

        // WATTx Regtest Genesis - Easy difficulty for testing (uses mainnet message)
        genesis = CreateMainnetGenesisBlock(1735430400, 0, 0x207fffff, 1, 500000000);

        // Mine regtest genesis
        arith_uint256 bnTarget;
        bnTarget.SetCompact(genesis.nBits);
        printf("Mining WATTx REGTEST genesis...\n");
        for (genesis.nNonce = 0; genesis.nNonce < 0xFFFFFFFF; genesis.nNonce++) {
            uint256 hash = genesis.GetHash();
            if (UintToArith256(hash) <= bnTarget) {
                printf("REGTEST FOUND! nNonce=%u\n", genesis.nNonce);
                printf("hashGenesisBlock=%s\n", hash.GetHex().c_str());
                break;
            }
        }
        consensus.hashGenesisBlock = genesis.GetHash();

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();
        vSeeds.emplace_back("dummySeed.invalid.");

        fDefaultConsistencyChecks = true;
        fMineBlocksOnDemand = true;
        m_is_mockable_chain = true;
        fHasHardwareWalletSupport = true;

        checkpointData = {
            {
                // Regtest genesis - hash computed at runtime
            }
        };

        m_assumeutxo_data = {
            {
                // For use by fuzz target src/test/fuzz/utxo_snapshot.cpp
                .height = 200,
                .hash_serialized = AssumeutxoHash{uint256{"4f34d431c3e482f6b0d67b64609ece3964dc8d7976d02ac68dd7c9c1421738f2"}},
                .m_chain_tx_count = 201,
                .blockhash = consteval_ctor(uint256{"5e93653318f294fb5aa339d00bbf8cf1c3515488ad99412c37608b139ea63b27"}),
            },
            {
                // For use by test/functional/feature_assumeutxo.py
                .height = 4099,
                .hash_serialized = AssumeutxoHash{uint256{"73200c9ce4eb500fb90dc57599ed084a1351eb0bf5de133c8a8ed4662e7e8162"}},
                .m_chain_tx_count = 4767,
                .blockhash = consteval_ctor(uint256{"05487442d7c76a7c64070cca8a52742fa7be67566802c55cc4499b15ff8acc0b"}),
            },
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        consensus.nBlocktimeDownscaleFactor = 4;
        consensus.nCoinbaseMaturity = 1;  // WATTx regtest: PoW rewards spendable after 1 confirmation
        consensus.nStakeMinConfirmations = 10; // WATTx regtest: Coins need 10 confirmations to stake
        consensus.nRBTCoinbaseMaturity = 10;  // WATTx regtest: lowered for fast testing
        consensus.nSubsidyHalvingIntervalV2 = consensus.nBlocktimeDownscaleFactor*985500; // qtum halving every 4 years (nSubsidyHalvingInterval * nBlocktimeDownscaleFactor)
        consensus.nMinValidatorStake = 10 * COIN; // Lower for regtest (10 WATTx)

        consensus.nLastPOWBlock = 0x7fffffff;
        consensus.nLastBigReward = 0; // Fair launch (0.08333333 WATTx per block)
        consensus.nMPoSRewardRecipients = 10;
        consensus.nFirstMPoSBlock = 5000;
        consensus.nLastMPoSBlock = 0;

        consensus.nFixUTXOCacheHFHeight=0;
        consensus.nEnableHeaderSignatureHeight = 0;

        consensus.nCheckpointSpan = consensus.nCoinbaseMaturity;
        consensus.nRBTCheckpointSpan = consensus.nRBTCoinbaseMaturity;
        consensus.delegationsAddress = uint160(ParseHex("0000000000000000000000000000000000000086")); // Delegations contract for offline staking
        consensus.historyStorageAddress = uint160(ParseHex("0000F90827F1C53a10cb7A02335B175320002935")); // EVM block hash history contract address
        consensus.nStakeTimestampMask = 15;
        consensus.nRBTStakeTimestampMask = 3;

        // WATTx regtest addresses start with 'w' (base58 prefix 135)
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,135);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,137);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
        // Dilithium (quantum-resistant) regtest addresses start with 'D' (base58 prefix 30)
        base58Prefixes[DILITHIUM_ADDRESS] = std::vector<unsigned char>(1,30);

        bech32_hrp = "wr"; // WATTx regtest bech32 prefix
    }
};

/**
 * Regression network parameters overwrites for unit testing
 */
class CUnitTestParams : public CRegTestParams
{
public:
    explicit CUnitTestParams(const RegTestOptions& opts)
    : CRegTestParams(opts)
    {
        // Activate the BIPs for regtest as in Bitcoin
        consensus.BIP34Height = 100000000; // BIP34 has not activated on regtest (far in the future so block v1 are not rejected in tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = consensus.nBlocktimeDownscaleFactor*500 + 851; // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height = consensus.nBlocktimeDownscaleFactor*500 + 751; // BIP66 activated on regtest (Used in rpc activation tests)
        consensus.QIP6Height = consensus.nBlocktimeDownscaleFactor*500 + 500;
        consensus.QIP7Height = 0; // QIP7 activated on regtest

        // QTUM have 500 blocks of maturity, increased values for regtest in unit tests in order to correspond with it
        consensus.nSubsidyHalvingInterval = 750;
        consensus.nSubsidyHalvingIntervalV2 = consensus.nBlocktimeDownscaleFactor*750;
        consensus.nRuleChangeActivationThreshold = consensus.nBlocktimeDownscaleFactor*558; // 75% for testchains
        consensus.nMinerConfirmationWindow = consensus.nBlocktimeDownscaleFactor*744; // Faster than normal for regtest (744 instead of 2016)

        consensus.nBlocktimeDownscaleFactor = 4;
        consensus.nCoinbaseMaturity = 500;
        consensus.nRBTCoinbaseMaturity = consensus.nBlocktimeDownscaleFactor*500;
        consensus.nMinValidatorStake = 10 * COIN; // Lower for regtest (10 WATTx)

        consensus.nCheckpointSpan = consensus.nCoinbaseMaturity*2; // Increase the check point span for the reorganization tests from 500 to 1000
        consensus.nRBTCheckpointSpan = consensus.nRBTCoinbaseMaturity*2; // Increase the check point span for the reorganization tests from 500 to 1000

        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0;

        m_assumeutxo_data = {
            {
                .height = 2010,
                .hash_serialized = AssumeutxoHash{uint256{"62528c92991cbedf47bdf3f0f5a0ad1e07bce4b2a35500beabe3f87fa5cca44f"}},
                .m_chain_tx_count = 2011,
                .blockhash = consteval_ctor(uint256{"292911929ab59409569a86bae416da0ba697fd7086b107ddd0a8eeaddba91b4d"}),
            }
        };
    }
};

std::unique_ptr<const CChainParams> CChainParams::SigNet(const SigNetOptions& options)
{
    return std::make_unique<const SigNetParams>(options);
}

std::unique_ptr<const CChainParams> CChainParams::RegTest(const RegTestOptions& options)
{
    return std::make_unique<const CRegTestParams>(options);
}

std::unique_ptr<const CChainParams> CChainParams::Main()
{
    return std::make_unique<const CMainParams>();
}

std::unique_ptr<const CChainParams> CChainParams::TestNet()
{
    return std::make_unique<const CTestNetParams>();
}

std::unique_ptr<const CChainParams> CChainParams::TestNet4()
{
    return std::make_unique<const CTestNet4Params>();
}

std::vector<int> CChainParams::GetAvailableSnapshotHeights() const
{
    std::vector<int> heights;
    heights.reserve(m_assumeutxo_data.size());

    for (const auto& data : m_assumeutxo_data) {
        heights.emplace_back(data.height);
    }
    return heights;
}

std::optional<ChainType> GetNetworkForMagic(const MessageStartChars& message)
{
    const auto mainnet_msg = CChainParams::Main()->MessageStart();
    const auto testnet_msg = CChainParams::TestNet()->MessageStart();
    const auto testnet4_msg = CChainParams::TestNet4()->MessageStart();
    const auto regtest_msg = CChainParams::RegTest({})->MessageStart();
    const auto signet_msg = CChainParams::SigNet({})->MessageStart();

    if (std::ranges::equal(message, mainnet_msg)) {
        return ChainType::MAIN;
    } else if (std::ranges::equal(message, testnet_msg)) {
        return ChainType::TESTNET;
    } else if (std::ranges::equal(message, testnet4_msg)) {
        return ChainType::TESTNET4;
    } else if (std::ranges::equal(message, regtest_msg)) {
        return ChainType::REGTEST;
    } else if (std::ranges::equal(message, signet_msg)) {
        return ChainType::SIGNET;
    }
    return std::nullopt;
}

std::unique_ptr<const CChainParams> CChainParams::UnitTest(const RegTestOptions& options)
{
    return std::make_unique<const CUnitTestParams>(options);
}

std::string CChainParams::EVMGenesisInfo() const
{
    dev::eth::EVMConsensus evmConsensus;
    evmConsensus.QIP6Height = consensus.QIP6Height;
    evmConsensus.QIP7Height = consensus.QIP7Height;
    evmConsensus.nMuirGlacierHeight = consensus.nMuirGlacierHeight;
    evmConsensus.nLondonHeight = consensus.nLondonHeight;
    evmConsensus.nShanghaiHeight = consensus.nShanghaiHeight;
    evmConsensus.nCancunHeight = consensus.nCancunHeight;
    evmConsensus.nPectraHeight = consensus.nPectraHeight;
    return dev::eth::genesisInfoQtum(GetEVMNetwork(), evmConsensus);
}

std::string CChainParams::EVMGenesisInfo(int nHeight) const
{
    dev::eth::EVMConsensus evmConsensus(nHeight);
    return dev::eth::genesisInfoQtum(GetEVMNetwork(), evmConsensus);
}

std::string CChainParams::EVMGenesisInfo(const dev::eth::EVMConsensus& evmConsensus) const
{
    return dev::eth::genesisInfoQtum(GetEVMNetwork(), evmConsensus);
}

dev::eth::Network CChainParams::GetEVMNetwork() const
{
    return dev::eth::Network::qtumNetwork;
}

void CChainParams::UpdateOpSenderBlockHeight(int nHeight)
{
    consensus.QIP5Height = nHeight;
}

void CChainParams::UpdateBtcEcrecoverBlockHeight(int nHeight)
{
    consensus.QIP6Height = nHeight;
}

void CChainParams::UpdateConstantinopleBlockHeight(int nHeight)
{
    consensus.QIP7Height = nHeight;
}

void CChainParams::UpdateDifficultyChangeBlockHeight(int nHeight)
{
    consensus.nSubsidyHalvingInterval = 985500; // qtum halving every 4 years
    consensus.nSubsidyHalvingIntervalV2 = consensus.nBlocktimeDownscaleFactor*985500; // qtum halving every 4 years (nSubsidyHalvingInterval * nBlocktimeDownscaleFactor)
    consensus.posLimit = uint256{"00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
    consensus.QIP9PosLimit = uint256{"0000000000001fffffffffffffffffffffffffffffffffffffffffffffffffff"};
    consensus.RBTPosLimit = uint256{"0000000000003fffffffffffffffffffffffffffffffffffffffffffffffffff"};
    consensus.QIP9Height = nHeight;
    consensus.fPowAllowMinDifficultyBlocks = false;
    consensus.fPowNoRetargeting = true;
    consensus.fPoSNoRetargeting = false;
    consensus.nLastPOWBlock = 5000;
    consensus.nMPoSRewardRecipients = 10;
    consensus.nFirstMPoSBlock = consensus.nLastPOWBlock + 
                                consensus.nMPoSRewardRecipients + 
                                consensus.nCoinbaseMaturity;
    consensus.nLastMPoSBlock = 0;
}

void CChainParams::UpdateOfflineStakingBlockHeight(int nHeight)
{
    consensus.nOfflineStakeHeight = nHeight;
}

void CChainParams::UpdateDelegationsAddress(const uint160& address)
{
    consensus.delegationsAddress = address;
}

void CChainParams::UpdateLastMPoSBlockHeight(int nHeight)
{
    consensus.nLastMPoSBlock = nHeight;
}

void CChainParams::UpdateReduceBlocktimeHeight(int nHeight)
{
    consensus.nReduceBlocktimeHeight = nHeight;
}

void CChainParams::UpdatePowAllowMinDifficultyBlocks(bool fValue)
{
    consensus.fPowAllowMinDifficultyBlocks = fValue;
}

void CChainParams::UpdatePowNoRetargeting(bool fValue)
{
    consensus.fPowNoRetargeting = fValue;
}

void CChainParams::UpdatePoSNoRetargeting(bool fValue)
{
    consensus.fPoSNoRetargeting = fValue;
}

void CChainParams::UpdateMuirGlacierHeight(int nHeight)
{
    consensus.nMuirGlacierHeight = nHeight;
}

void CChainParams::UpdateLondonHeight(int nHeight)
{
    consensus.nLondonHeight = nHeight;
}

void CChainParams::UpdateTaprootHeight(int nHeight)
{
    if(nHeight == 0)
    {
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay
    }
    else
    {
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = 0;
        // Min block number for activation, the number must be divisible with 144
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = nHeight;
    }
}

void CChainParams::UpdateShanghaiHeight(int nHeight)
{
    consensus.nShanghaiHeight = nHeight;
}

void CChainParams::UpdateCancunHeight(int nHeight)
{
    consensus.nCancunHeight = nHeight;
}

void CChainParams::UpdatePectraHeight(int nHeight)
{
    consensus.nPectraHeight = nHeight;
}
