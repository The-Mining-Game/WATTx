// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WATTX_PRIVACY_FCMP_CONSENSUS_H
#define WATTX_PRIVACY_FCMP_CONSENSUS_H

/**
 * FCMP Consensus Integration
 *
 * Provides consensus-level validation and state management for FCMP
 * (Full-Chain Membership Proofs) transactions. This integrates with:
 *
 * - Block validation (ConnectBlock/DisconnectBlock)
 * - Mempool validation
 * - Key image tracking (double-spend prevention)
 * - Curve tree state management
 *
 * FCMP works alongside the existing X25X PoW and PoS consensus:
 * - Mining algorithm selection is unaffected
 * - Staking requires transparent UTXOs (not FCMP outputs)
 * - FCMP outputs have separate 10-block maturity for spending
 */

#include <primitives/transaction.h>
#include <primitives/block.h>
#include <privacy/privacy.h>
#include <privacy/fcmp_tx.h>
#include <privacy/curvetree/curve_tree.h>
#include <consensus/validation.h>
#include <consensus/params.h>
#include <dbwrapper.h>
#include <sync.h>

#include <memory>
#include <optional>
#include <set>

class CBlockIndex;
class CCoinsViewCache;

namespace privacy {

//! Master switch for the FCMP confidential amount layer. Default false.
//! See fcmp_consensus.cpp for why this stays off until the builder and
//! end-to-end regtest spends are proven.
extern bool g_fcmp_amount_layer_enabled;

// ============================================================================
// Key Image Database
// ============================================================================

/**
 * @brief Persistent storage for spent key images
 *
 * Key images are the mechanism for preventing double-spends in FCMP.
 * Each FCMP output can only be spent once, identified by its key image.
 */
class CFcmpKeyImageDB
{
public:
    explicit CFcmpKeyImageDB(const fs::path& path, size_t nCacheSize, bool fMemory = false, bool fWipe = false);

    /**
     * @brief Check if a key image has been spent
     * @param keyImage The key image to check
     * @return true if spent, false otherwise
     */
    bool IsSpent(const CKeyImage& keyImage) const;

    /**
     * @brief Mark a key image as spent
     * @param keyImage The key image to mark
     * @param txHash The transaction that spent it
     * @param blockHeight The block height where it was spent
     * @return true on success
     */
    bool MarkSpent(const CKeyImage& keyImage, const uint256& txHash, int blockHeight);

    /**
     * @brief Unmark a key image (for reorg handling)
     * @param keyImage The key image to unmark
     * @return true on success
     */
    bool Unmark(const CKeyImage& keyImage);

    /**
     * @brief Get spending info for a key image
     * @param keyImage The key image to query
     * @param txHash Output: the spending transaction hash
     * @param blockHeight Output: the block height
     * @return true if found
     */
    bool GetSpendingInfo(const CKeyImage& keyImage, uint256& txHash, int& blockHeight) const;

    /**
     * @brief Batch write for efficiency during block connection
     */
    bool WriteBatch(const std::vector<std::pair<CKeyImage, std::pair<uint256, int>>>& spends);

    /**
     * @brief Batch erase for efficiency during block disconnection
     */
    bool EraseBatch(const std::vector<CKeyImage>& keyImages);

    /**
     * @brief Sync to disk
     */
    bool Sync();

private:
    std::unique_ptr<CDBWrapper> m_db;
    mutable RecursiveMutex cs_keyimage;
};

// ============================================================================
// Global FCMP State
// ============================================================================

/**
 * @brief Global FCMP consensus state
 *
 * Manages the curve tree and key image database at the consensus level.
 * Singleton pattern - accessed via GetFcmpState().
 */
class CFcmpConsensusState
{
public:
    CFcmpConsensusState();
    ~CFcmpConsensusState();

    // Initialization
    bool Initialize(const fs::path& datadir, size_t cacheSize = (1 << 23));
    void Shutdown();
    bool IsInitialized() const { return m_initialized; }

    // ========== Curve Tree Access ==========

    /**
     * @brief Get the global curve tree
     */
    std::shared_ptr<curvetree::CurveTree> GetCurveTree() const;

    /**
     * @brief Get current tree root
     */
    ed25519::Point GetTreeRoot() const;

    /**
     * @brief Get tree output count
     */
    uint64_t GetTreeSize() const;

    // ========== Key Image Database ==========

    /**
     * @brief Check if a key image is spent
     */
    bool IsKeyImageSpent(const CKeyImage& keyImage) const;

    /**
     * @brief Get the key image database
     */
    CFcmpKeyImageDB* GetKeyImageDB() { return m_keyImageDB.get(); }

    // ========== Block Processing ==========

    /**
     * @brief Process a block being connected
     * @param block The block being connected
     * @param pindex The block index
     * @return true on success
     */
    bool ConnectBlock(const CBlock& block, const CBlockIndex* pindex);

    /**
     * @brief Process a block being disconnected (reorg)
     * @param block The block being disconnected
     * @param pindex The block index
     * @return true on success
     */
    bool DisconnectBlock(const CBlock& block, const CBlockIndex* pindex);

    // ========== Transaction Validation ==========

    /**
     * @brief Validate FCMP components of a transaction (context-free)
     * @param tx The transaction to validate
     * @param state Validation state for error reporting
     * @return true if valid
     */
    bool CheckFcmpTransaction(const CTransaction& tx, TxValidationState& state) const;

    /**
     * @brief Validate FCMP transaction with full context
     * @param tx The transaction to validate
     * @param state Validation state
     * @param view Coins view for input verification
     * @param nSpendHeight Current spend height
     * @return true if valid
     */
    bool CheckFcmpInputs(const CTransaction& tx, TxValidationState& state,
                         const CCoinsViewCache& view, int nSpendHeight) const;

    // ========== Statistics ==========

    /**
     * @brief Get statistics for logging/RPC
     */
    struct Stats {
        uint64_t treeSize{0};
        uint32_t treeDepth{0};
        uint64_t keyImagesSpent{0};
        int lastBlockHeight{0};
    };
    Stats GetStats() const;

private:
    bool m_initialized{false};
    mutable RecursiveMutex cs_fcmp;

    // Curve tree for membership proofs
    std::shared_ptr<curvetree::CurveTree> m_curveTree GUARDED_BY(cs_fcmp);
    std::shared_ptr<curvetree::ITreeStorage> m_treeStorage;

    // Key image database
    std::unique_ptr<CFcmpKeyImageDB> m_keyImageDB;

    // Track outputs added per block for reorg handling
    std::map<int, uint64_t> m_outputsAddedPerBlock GUARDED_BY(cs_fcmp);

    // Statistics
    uint64_t m_keyImagesSpent{0};
    int m_lastBlockHeight{0};

    /**
     * @brief Extract FCMP outputs from a transaction
     */
    std::vector<curvetree::OutputTuple> ExtractFcmpOutputs(const CTransaction& tx) const;

    /**
     * @brief Extract key images from a transaction
     */
    std::vector<CKeyImage> ExtractKeyImages(const CTransaction& tx) const;
};

// ============================================================================
// Global Access Functions
// ============================================================================

/**
 * @brief Check if FCMP state is available (safe to call GetFcmpState)
 */
bool IsFcmpStateAvailable();

/**
 * @brief Get the global FCMP consensus state
 */
CFcmpConsensusState& GetFcmpState();

/**
 * @brief Initialize FCMP consensus (called during node startup)
 */
bool InitializeFcmpConsensus(const fs::path& datadir);

/**
 * @brief Shutdown FCMP consensus (called during node shutdown)
 */
void ShutdownFcmpConsensus();

// ============================================================================
// Validation Helper Functions
// ============================================================================

/**
 * @brief Check if a transaction contains FCMP inputs
 */
bool HasFcmpInputs(const CTransaction& tx);

/**
 * @brief Check if a transaction contains FCMP outputs
 */
bool HasFcmpOutputs(const CTransaction& tx);

/**
 * @brief Decode FCMP data from a transaction
 * @param tx The transaction
 * @param privTx Output: decoded privacy transaction
 * @return true if FCMP data found and decoded
 */
bool DecodeFcmpTransaction(const CTransaction& tx, CPrivacyTransaction& privTx);

/**
 * @brief Get the FCMP activation height
 * This should match the X25X activation or be set separately
 */
int GetFcmpActivationHeight(const Consensus::Params& params);

/**
 * @brief Check if FCMP is active at a given height
 */
bool IsFcmpActive(int nHeight, const Consensus::Params& params);

/**
 * @brief Get FCMP output maturity (blocks before spendable)
 */
int GetFcmpMaturity(const Consensus::Params& params);

} // namespace privacy

#endif // WATTX_PRIVACY_FCMP_CONSENSUS_H
