// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WATTX_PRIVACY_PRIVACY_H
#define WATTX_PRIVACY_PRIVACY_H

/**
 * WATTx Privacy Module
 *
 * Implements Monero-style privacy features for the UTXO layer:
 *
 * 1. STEALTH ADDRESSES (stealth.h)
 *    - One-time addresses for each transaction output
 *    - Sender creates unique address, only recipient can spend
 *    - View keys allow auditing without spending capability
 *
 * 2. RING SIGNATURES (ring_signature.h)
 *    - Hide sender among decoy outputs
 *    - Key images prevent double-spending
 *    - MLSAG for multiple inputs
 *
 * 3. CONFIDENTIAL TRANSACTIONS (confidential.h)
 *    - Pedersen commitments hide amounts
 *    - Homomorphic: inputs == outputs + fee
 *    - Bulletproofs for efficient range proofs
 *
 * TRANSACTION TYPES:
 *
 * Type 0: Standard (legacy Bitcoin-style)
 *   - Transparent inputs and outputs
 *   - Public amounts
 *   - Standard signatures
 *
 * Type 1: Stealth-only
 *   - Stealth addresses for outputs
 *   - Public amounts
 *   - Standard signatures
 *
 * Type 2: Ring-only
 *   - Standard addresses
 *   - Ring signatures hide sender
 *   - Public amounts
 *
 * Type 3: Confidential-only
 *   - Standard addresses
 *   - Hidden amounts with commitments
 *   - Range proofs
 *
 * Type 4: Full Privacy (RingCT)
 *   - Stealth addresses
 *   - Ring signatures
 *   - Confidential amounts
 *   - Key images
 *   - Range proofs
 */

#include <privacy/stealth.h>
#include <privacy/ring_signature.h>
#include <privacy/confidential.h>
#include <privacy/fcmp_tx.h>

#include <primitives/transaction.h>
#include <script/script.h>
#include <uint256.h>

#include <vector>
#include <optional>

namespace privacy {

/**
 * @brief Privacy transaction types
 */
// Windows headers define TRANSPARENT as a macro - undefine it
#ifdef TRANSPARENT
#undef TRANSPARENT
#endif

enum class PrivacyType : uint8_t
{
    TRANSPARENT = 0,    // Standard Bitcoin-style
    STEALTH = 1,        // Stealth addresses only
    RING = 2,           // Ring signatures only
    CONFIDENTIAL = 3,   // Confidential amounts only
    RINGCT = 4,         // Full privacy (ring + confidential + stealth)
    FCMP = 5,           // Full-Chain Membership Proofs (next-gen privacy)
};

/**
 * @brief Privacy input - replaces standard CTxIn for private transactions
 */
struct CPrivacyInput
{
    // Ring of potential outputs (for ring signature)
    CRing ring;

    // Key image (prevents double-spend)
    CKeyImage keyImage;

    // Ring signature or MLSAG component
    // (Full signature stored at transaction level for efficiency)

    // Commitment to the input amount (for RingCT)
    CPedersenCommitment commitment;

    PrivacyType GetType() const {
        if (!ring.IsValid()) return PrivacyType::TRANSPARENT;
        if (commitment.IsNull()) return PrivacyType::RING;
        return PrivacyType::RINGCT;
    }

    SERIALIZE_METHODS(CPrivacyInput, obj) {
        READWRITE(obj.ring, obj.keyImage, obj.commitment);
    }
};

/**
 * @brief Privacy output - replaces standard CTxOut for private transactions
 */
struct CPrivacyOutput
{
    // One-time stealth output data
    CStealthOutput stealthOutput;

    // Confidential output (commitment + range proof)
    CConfidentialOutput confidentialOutput;

    // Standard script (for Type 0-2)
    CScript scriptPubKey;

    // Explicit amount (for non-confidential types)
    CAmount nValue{0};

    PrivacyType GetType() const {
        if (confidentialOutput.IsValid() && stealthOutput.oneTimePubKey.IsValid()) {
            return PrivacyType::RINGCT;
        }
        if (confidentialOutput.IsValid()) {
            return PrivacyType::CONFIDENTIAL;
        }
        if (stealthOutput.oneTimePubKey.IsValid()) {
            return PrivacyType::STEALTH;
        }
        return PrivacyType::TRANSPARENT;
    }

    SERIALIZE_METHODS(CPrivacyOutput, obj) {
        READWRITE(obj.stealthOutput, obj.confidentialOutput, obj.scriptPubKey, obj.nValue);
    }
};

/**
 * @brief Privacy transaction wrapper
 */
class CPrivacyTransaction
{
public:
    // Transaction version (includes privacy flags)
    uint32_t nVersion{2};

    // Privacy type
    PrivacyType privacyType{PrivacyType::TRANSPARENT};

    // Privacy inputs
    std::vector<CPrivacyInput> privacyInputs;

    // Privacy outputs
    std::vector<CPrivacyOutput> privacyOutputs;

    // MLSAG signature (covers all inputs) - for RingCT
    CMLSAGSignature mlsagSig;

    // FCMP inputs (for FCMP privacy type)
    std::vector<CFcmpInput> fcmpInputs;

    // FCMP aggregated signature (optional, for batched proofs)
    CFcmpAggregatedSig fcmpAggSig;

    // Aggregated range proof (covers all outputs)
    CRangeProof aggregatedRangeProof;

    // Transaction fee (explicit for RingCT, derived otherwise)
    CAmount nFee{0};

    // Lock time
    uint32_t nLockTime{0};

    CPrivacyTransaction() = default;

    /**
     * @brief Convert to standard transaction for broadcast
     */
    CTransaction ToTransaction() const;

    /**
     * @brief Parse from standard transaction
     */
    static std::optional<CPrivacyTransaction> FromTransaction(const CTransaction& tx);

    /**
     * @brief Get the transaction hash
     */
    uint256 GetHash() const;

    /**
     * @brief Verify the transaction is valid
     */
    bool Verify() const;

    /**
     * @brief Verify FCMP-specific transaction components
     */
    bool VerifyFcmp() const;

    /** Self-check for wallet-created FCMP transactions (skips FFI proof verification) */
    bool VerifyFcmpSelfCheck() const;

    template <typename Stream>
    void Serialize(Stream& s) const {
        s << nVersion;
        s << static_cast<uint8_t>(privacyType);
        s << privacyInputs << privacyOutputs;

        // Serialize based on privacy type
        if (privacyType == PrivacyType::FCMP) {
            s << fcmpInputs << fcmpAggSig;
        } else {
            s << mlsagSig;
        }

        s << aggregatedRangeProof << nFee << nLockTime;
    }

    template <typename Stream>
    void Unserialize(Stream& s) {
        s >> nVersion;
        uint8_t type;
        s >> type;
        privacyType = static_cast<PrivacyType>(type);
        s >> privacyInputs >> privacyOutputs;

        // Deserialize based on privacy type
        if (privacyType == PrivacyType::FCMP) {
            s >> fcmpInputs >> fcmpAggSig;
        } else {
            s >> mlsagSig;
        }

        s >> aggregatedRangeProof >> nFee >> nLockTime;
    }
};

/**
 * @brief Builder for creating privacy transactions
 */
class CPrivacyTransactionBuilder
{
public:
    CPrivacyTransactionBuilder(PrivacyType type = PrivacyType::RINGCT);

    /**
     * @brief Add an input to spend
     * @param outpoint The output to spend
     * @param privKey The private key
     * @param amount The input amount
     * @param blindingFactor The blinding factor (for RingCT)
     */
    bool AddInput(
        const COutPoint& outpoint,
        const CKey& privKey,
        CAmount amount,
        const CBlindingFactor& blindingFactor = CBlindingFactor());

    /**
     * @brief Add a stealth output
     * @param stealthAddr Recipient's stealth address
     * @param amount Amount to send
     */
    bool AddOutput(
        const CStealthAddress& stealthAddr,
        CAmount amount);

    /**
     * @brief Add a standard output (for transparent or mixed)
     * @param scriptPubKey Output script
     * @param amount Amount
     */
    bool AddOutput(
        const CScript& scriptPubKey,
        CAmount amount);

    /**
     * @brief Set transaction fee
     */
    void SetFee(CAmount fee);

    /**
     * @brief Set ring size for inputs
     */
    void SetRingSize(size_t size);

    /**
     * @brief Build the final transaction
     */
    std::optional<CPrivacyTransaction> Build();

private:
    PrivacyType m_type;
    std::vector<std::tuple<COutPoint, CKey, CAmount, CBlindingFactor>> m_inputs;
    std::vector<std::tuple<CStealthAddress, CAmount>> m_stealthOutputs;
    std::vector<std::tuple<CScript, CAmount>> m_standardOutputs;
    CAmount m_fee{0};
    size_t m_ringSize{11}; // Default ring size (like Monero)
};

/**
 * @brief Check if a key image has been used (double-spend detection)
 */
bool IsKeyImageSpent(const CKeyImage& keyImage);

/**
 * @brief Record a key image as spent
 */
bool MarkKeyImageSpent(const CKeyImage& keyImage, const uint256& txHash);

/**
 * @brief Get minimum ring size for current chain height
 */
size_t GetMinRingSize(int height);

/**
 * @brief Get default ring size for current chain height
 */
size_t GetDefaultRingSize(int height);

} // namespace privacy

#endif // WATTX_PRIVACY_PRIVACY_H
