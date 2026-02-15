// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WATTX_WALLET_FCMP_WALLET_H
#define WATTX_WALLET_FCMP_WALLET_H

/**
 * FCMP Wallet Manager
 *
 * Manages FCMP (Full-Chain Membership Proofs) transactions for the wallet.
 * This replaces ring signatures with curve tree membership proofs, providing:
 *
 * - Full anonymity set (all outputs ever created)
 * - Smaller proof sizes than large rings
 * - Efficient verification
 *
 * FCMP outputs are tracked separately from standard UTXOs and ring signature
 * outputs. Each FCMP output has:
 * - Leaf index in the curve tree
 * - Ed25519 private key for spending
 * - Blinding factor for commitment
 *
 * The curve tree is maintained globally and updated when new blocks arrive.
 */

#include <privacy/privacy.h>
#include <privacy/fcmp_tx.h>
#include <privacy/ed25519/ed25519_types.h>
#include <privacy/curvetree/curve_tree.h>
#include <wallet/stealth_wallet.h>
#include <policy/feerate.h>
#include <sync.h>

#include <map>
#include <memory>
#include <optional>
#include <vector>

namespace wallet {

class CWallet;

/**
 * @brief FCMP output owned by wallet
 *
 * Contains all information needed to spend an output using FCMP.
 */
struct CFcmpOutputInfo
{
    // Standard output identification
    COutPoint outpoint;

    // Output value
    CAmount amount;

    // Ed25519 private key for this output
    ed25519::Scalar privKey;

    // Blinding factor used in the commitment
    ed25519::Scalar blinding;

    // The output tuple stored in the curve tree
    curvetree::OutputTuple outputTuple;

    // Index of this output in the curve tree (leaf position)
    uint64_t treeLeafIndex;

    // Hash of the key image (for tracking spent status)
    uint256 keyImageHash;

    // Block height when output was confirmed
    int blockHeight;

    // Whether this output has been spent
    bool spent;

    // Whether this output originated from a coinbase/coinstake transaction
    // When true, uses coinbase maturity (100 blocks) instead of FCMP maturity (10 blocks)
    bool isCoinbaseOutput{false};

    // Timestamp when we detected this output
    int64_t nTime;

    CFcmpOutputInfo()
        : amount(0), treeLeafIndex(0), blockHeight(-1), spent(false), isCoinbaseOutput(false), nTime(0) {}

    bool IsSpendable(int currentHeight, int minConfirmations = 10) const {
        if (spent) return false;
        if (blockHeight < 0) return false;
        // Coinbase-originated FCMP outputs require longer maturity (100 blocks)
        int requiredConfs = isCoinbaseOutput ? std::max(minConfirmations, 100) : minConfirmations;
        return (currentHeight - blockHeight) >= requiredConfs;
    }

    SERIALIZE_METHODS(CFcmpOutputInfo, obj) {
        READWRITE(obj.outpoint, obj.amount, obj.privKey, obj.blinding,
                  obj.outputTuple.O, obj.outputTuple.I, obj.outputTuple.C,
                  obj.treeLeafIndex, obj.keyImageHash, obj.blockHeight,
                  obj.spent, obj.isCoinbaseOutput, obj.nTime);
    }
};

/**
 * @brief Result of creating an FCMP transaction
 */
struct CFcmpTransactionResult
{
    // The privacy transaction (FCMP type)
    privacy::CPrivacyTransaction privacyTx;

    // Standard transaction for broadcast (encoded privacy data)
    CTransactionRef standardTx;

    // Key images from this transaction (for tracking)
    std::vector<privacy::CKeyImage> keyImages;

    // Fee paid
    CAmount fee;

    // Success flag
    bool success{false};

    // Error message if failed
    std::string error;

    // Change output info (if any) - must be registered in wallet after commit
    std::optional<CFcmpOutputInfo> changeOutputInfo;
};

/**
 * @brief Result of creating a shield (transparent to FCMP) transaction
 */
struct CFcmpShieldResult
{
    // Standard transaction for broadcast
    CTransactionRef standardTx;

    // Fee paid
    CAmount fee;

    // Leaf index in curve tree for the new output
    uint64_t leafIndex{0};

    // Output tuple stored in curve tree
    curvetree::OutputTuple outputTuple;

    // Private key for the output (needed for spending)
    ed25519::Scalar privKey;

    // Blinding factor
    ed25519::Scalar blinding;

    // Key image hash
    uint256 keyImageHash;

    // Whether the wallet owns the output private key
    bool hasPrivKey{false};

    // Success flag
    bool success{false};

    // Error message if failed
    std::string error;
};

/**
 * @brief Parameters for creating an FCMP transaction
 */
struct CFcmpTransactionParams
{
    // Minimum confirmations for inputs
    int minConfirmations{10};

    // Fee rate (satoshis per vbyte)
    CFeeRate feeRate;

    // Fixed fee (if non-zero, overrides feeRate)
    CAmount fixedFee{0};

    // Subtract fee from amount
    bool subtractFeeFromAmount{false};

    // Message to include in transaction (optional)
    std::vector<uint8_t> txMessage;
};

/**
 * @brief Recipient for FCMP transaction
 *
 * Supports both stealth addresses (full privacy) and regular script
 * destinations (sender-side privacy via deshielding).
 */
struct CFcmpRecipient
{
    // Stealth address to send to (full privacy)
    privacy::CStealthAddress stealthAddress;

    // Regular script destination (sender-side privacy / deshielding)
    CScript scriptPubKey;

    // Amount to send
    CAmount amount;

    // Label (for local tracking)
    std::string label;

    // Whether this recipient uses a stealth address (full privacy)
    // vs regular address (sender-side privacy only)
    bool IsStealthRecipient() const {
        return stealthAddress.IsValid();
    }
};

/**
 * @brief FCMP transaction manager for wallet
 *
 * Handles creation and tracking of FCMP transactions, providing full
 * anonymity by proving membership in the entire output set rather than
 * a small ring of decoys.
 */
class CFcmpWalletManager
{
public:
    explicit CFcmpWalletManager(CWallet* wallet);
    ~CFcmpWalletManager();

    // ========================================================================
    // Transaction Creation
    // ========================================================================

    /**
     * @brief Create an FCMP transaction
     * @param recipients List of recipients with amounts
     * @param params Transaction parameters
     * @return Transaction result with success/error status
     */
    CFcmpTransactionResult CreateFcmpTransaction(
        const std::vector<CFcmpRecipient>& recipients,
        const CFcmpTransactionParams& params = CFcmpTransactionParams());

    /**
     * @brief Estimate fee for an FCMP transaction
     * @param numInputs Number of inputs
     * @param numOutputs Number of outputs
     * @param feeRate Fee rate
     * @return Estimated fee
     */
    CAmount EstimateFee(
        size_t numInputs,
        size_t numOutputs,
        const CFeeRate& feeRate) const;

    /**
     * @brief Create a shield transaction (transparent to FCMP)
     * @param recipient Stealth address to shield to
     * @param amount Amount to shield
     * @param minConfirmations Minimum confirmations for inputs
     * @return Shield result with success/error status
     */
    CFcmpShieldResult CreateShieldTransaction(
        const privacy::CStealthAddress& recipient,
        CAmount amount,
        int minConfirmations = 1);

    // ========================================================================
    // Output Management
    // ========================================================================

    /**
     * @brief Get all FCMP outputs
     * @param includeSpent Include spent outputs
     * @return Vector of FCMP outputs
     */
    std::vector<CFcmpOutputInfo> GetFcmpOutputs(bool includeSpent = false) const;

    /**
     * @brief Get spendable FCMP outputs
     * @param minConfirmations Minimum confirmations required
     * @return Vector of spendable outputs
     */
    std::vector<CFcmpOutputInfo> GetSpendableFcmpOutputs(int minConfirmations = 10) const;

    /**
     * @brief Add an FCMP output to tracking
     * @param output Output info to add
     * @return true if added successfully
     */
    bool AddFcmpOutput(const CFcmpOutputInfo& output);

    /** Update block height for an existing output when its transaction is confirmed */
    bool UpdateFcmpOutputBlockHeight(const COutPoint& outpoint, int blockHeight);

    /**
     * @brief Mark an FCMP output as spent
     * @param outpoint Output to mark
     * @param spendingTxHash Hash of spending transaction
     * @return true if marked successfully
     */
    bool MarkFcmpOutputSpent(const COutPoint& outpoint, const uint256& spendingTxHash);

    /**
     * @brief Check if we own an output
     * @param outpoint Output to check
     * @return true if we own this output
     */
    bool HaveFcmpOutput(const COutPoint& outpoint) const;

    /**
     * @brief Get output info
     * @param outpoint Output to get
     * @return Output info or nullopt if not found
     */
    std::optional<CFcmpOutputInfo> GetFcmpOutput(const COutPoint& outpoint) const;

    // ========================================================================
    // Key Image Management
    // ========================================================================

    /**
     * @brief Check if a key image is spent (from our outputs)
     * @param keyImage Key image to check
     * @return true if spent
     */
    bool IsKeyImageSpent(const privacy::CKeyImage& keyImage) const;

    /**
     * @brief Generate key image for an output
     * @param privKey Private key
     * @param outputPoint Output point O
     * @return Key image
     */
    privacy::CKeyImage GenerateKeyImage(
        const ed25519::Scalar& privKey,
        const ed25519::Point& outputPoint) const;

    // ========================================================================
    // Balance Queries
    // ========================================================================

    /**
     * @brief Get total FCMP balance
     * @return Total balance of all FCMP outputs
     */
    CAmount GetFcmpBalance() const;

    /**
     * @brief Get spendable FCMP balance
     * @param minConfirmations Minimum confirmations
     * @return Balance of spendable outputs
     */
    CAmount GetSpendableFcmpBalance(int minConfirmations = 10) const;

    /**
     * @brief Get pending FCMP balance (unconfirmed)
     * @return Balance of unconfirmed outputs
     */
    CAmount GetPendingFcmpBalance() const;

    // ========================================================================
    // Curve Tree Access
    // ========================================================================

    /**
     * @brief Get the global curve tree
     * @return Shared pointer to curve tree
     */
    std::shared_ptr<curvetree::CurveTree> GetCurveTree() const;

    /**
     * @brief Set the curve tree (called during initialization)
     * @param tree Curve tree instance
     */
    void SetCurveTree(std::shared_ptr<curvetree::CurveTree> tree);

    /**
     * @brief Get current tree root
     * @return Tree root point
     */
    ed25519::Point GetTreeRoot() const;

    // ========================================================================
    // Transaction Scanning
    // ========================================================================

    /**
     * @brief Scan a transaction for FCMP outputs belonging to us
     * @param tx Transaction to scan
     * @param blockHeight Block height (-1 for unconfirmed)
     * @return Number of outputs found
     */
    int ScanTransactionForFcmpOutputs(
        const CTransaction& tx,
        int blockHeight = -1);

    /**
     * @brief Scan a block for FCMP outputs
     * @param block Block to scan
     * @param blockHeight Block height
     * @return Number of outputs found
     */
    int ScanBlockForFcmpOutputs(
        const CBlock& block,
        int blockHeight);

    // ========================================================================
    // Persistence
    // ========================================================================

    /**
     * @brief Load FCMP data from wallet database
     * @return true if loaded successfully
     */
    bool Load();

    /**
     * @brief Save FCMP data to wallet database
     * @return true if saved successfully
     */
    bool Save();

    // ========================================================================
    // Auto-Shielding
    // ========================================================================

    /**
     * @brief Auto-shield transparent funds to FCMP
     *
     * Called after block processing. If the wallet has transparent balance
     * above the minimum threshold, automatically creates a shield transaction.
     * Skipped during IBD and when a shield is already pending.
     */
    void AutoShield();

    // ========================================================================
    // Utility
    // ========================================================================

    /**
     * @brief Get current block height
     */
    int GetCurrentHeight() const;

    /**
     * @brief Create output tuple from stealth address derivation
     * @param stealthAddr Recipient stealth address
     * @param amount Amount to send
     * @param blinding Output: blinding factor used
     * @param privKey Output: private key (if we're the recipient)
     * @return Output tuple for curve tree
     */
    curvetree::OutputTuple CreateOutputTuple(
        const privacy::CStealthAddress& stealthAddr,
        CAmount amount,
        ed25519::Scalar& blinding,
        std::optional<ed25519::Scalar>& privKey) const;

private:
    CWallet* m_wallet;
    mutable RecursiveMutex cs_fcmp;

    // FCMP outputs owned by wallet (outpoint -> info)
    std::map<COutPoint, CFcmpOutputInfo> m_fcmpOutputs GUARDED_BY(cs_fcmp);

    // Key images we've generated (hash -> outpoint)
    std::map<uint256, COutPoint> m_keyImages GUARDED_BY(cs_fcmp);

    // Key images we've seen spent (hash -> spending tx)
    std::map<uint256, uint256> m_spentKeyImages GUARDED_BY(cs_fcmp);

    // Global curve tree (shared with consensus)
    std::shared_ptr<curvetree::CurveTree> m_curveTree;

    // Auto-shield state
    bool m_autoShieldPending GUARDED_BY(cs_fcmp) = false;

    /**
     * @brief Select inputs for transaction
     * @param targetAmount Amount needed
     * @param selectedInputs Output: selected inputs
     * @param inputTotal Output: total input value
     * @param minConfirmations Minimum confirmations
     * @return true if selection successful
     */
    bool SelectInputs(
        CAmount targetAmount,
        std::vector<CFcmpOutputInfo>& selectedInputs,
        CAmount& inputTotal,
        int minConfirmations) EXCLUSIVE_LOCKS_REQUIRED(cs_fcmp);

    /**
     * @brief Build FCMP input from output
     * @param output Output to spend
     * @param messageHash Transaction message hash
     * @return FCMP input or nullopt on error
     */
    std::optional<privacy::CFcmpInput> BuildFcmpInput(
        const CFcmpOutputInfo& output,
        const uint256& messageHash) EXCLUSIVE_LOCKS_REQUIRED(cs_fcmp);

    /**
     * @brief Compute transaction message hash
     * @param inputs Selected inputs
     * @param recipients Output recipients
     * @param fee Transaction fee
     * @return Message hash
     */
    uint256 ComputeMessageHash(
        const std::vector<CFcmpOutputInfo>& inputs,
        const std::vector<CFcmpRecipient>& recipients,
        CAmount fee) const;
};

} // namespace wallet

#endif // WATTX_WALLET_FCMP_WALLET_H
