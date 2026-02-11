// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WATTX_WALLET_PRIVACY_WALLET_H
#define WATTX_WALLET_PRIVACY_WALLET_H

#include <privacy/privacy.h>
#include <privacy/ring_signature.h>
#include <privacy/confidential.h>
#include <wallet/stealth_wallet.h>
#include <key.h>
#include <sync.h>

#include <map>
#include <memory>
#include <optional>
#include <vector>

namespace wallet {

class CWallet;

/**
 * @brief Privacy output owned by wallet
 */
struct CPrivacyOutputInfo
{
    COutPoint outpoint;
    CAmount amount;
    CKey privKey;                       // Private key to spend this output
    privacy::CBlindingFactor blinding;  // Blinding factor for commitment
    privacy::CPedersenCommitment commitment;
    uint256 keyImageHash;               // Hash of key image (for tracking)
    int blockHeight;
    bool spent;

    SERIALIZE_METHODS(CPrivacyOutputInfo, obj) {
        READWRITE(obj.outpoint, obj.amount, obj.commitment, obj.keyImageHash,
                  obj.blockHeight, obj.spent);
    }
};

/**
 * @brief Result of creating a privacy transaction
 */
struct CPrivacyTransactionResult
{
    privacy::CPrivacyTransaction privacyTx;
    CTransactionRef standardTx;  // Use ref since CTransaction is immutable
    std::vector<privacy::CKeyImage> keyImages;  // For tracking
    bool success{false};
    std::string error;
};

/**
 * @brief Parameters for creating a privacy transaction
 */
struct CPrivacyTransactionParams
{
    privacy::PrivacyType type{privacy::PrivacyType::RINGCT};
    size_t ringSize{11};
    CAmount fee{0};
    bool subtractFeeFromAmount{false};
};

/**
 * @brief Privacy transaction manager for wallet
 *
 * Handles creation and tracking of ring signature and confidential transactions.
 */
class CPrivacyWalletManager
{
public:
    CPrivacyWalletManager(CWallet* wallet);
    ~CPrivacyWalletManager();

    //! Create a privacy transaction
    CPrivacyTransactionResult CreatePrivacyTransaction(
        const std::vector<std::pair<privacy::CStealthAddress, CAmount>>& recipients,
        const CPrivacyTransactionParams& params);

    //! Create a ring signature for spending an output
    bool CreateRingSignatureForOutput(
        const CPrivacyOutputInfo& output,
        size_t ringSize,
        privacy::CRing& ring,
        privacy::CKeyImage& keyImage);

    //! Select decoys for ring signature
    bool SelectDecoys(
        const COutPoint& realOutput,
        size_t count,
        std::vector<privacy::CRingMember>& decoys);

    //! Get all privacy outputs
    std::vector<CPrivacyOutputInfo> GetPrivacyOutputs(bool includeSpent = false) const;

    //! Get spendable privacy outputs
    std::vector<CPrivacyOutputInfo> GetSpendablePrivacyOutputs() const;

    //! Add a privacy output to tracking
    bool AddPrivacyOutput(const CPrivacyOutputInfo& output);

    //! Mark a privacy output as spent
    bool MarkPrivacyOutputSpent(const COutPoint& outpoint, const uint256& spendingTx);

    //! Check if a key image is spent (from our outputs)
    bool IsKeyImageSpent(const privacy::CKeyImage& keyImage) const;

    //! Get total privacy balance
    CAmount GetPrivacyBalance() const;

    //! Get spendable privacy balance
    CAmount GetSpendablePrivacyBalance() const;

    //! Convert a standard output to privacy output (for wallet)
    bool ConvertToPrivacyOutput(
        const COutPoint& outpoint,
        const CKey& privKey,
        CAmount amount,
        CPrivacyOutputInfo& output);

    //! Generate key image for an output
    privacy::CKeyImage GenerateKeyImage(const CKey& privKey) const;

    //! Load from wallet
    bool Load();

    //! Save to wallet
    bool Save();

private:
    CWallet* m_wallet;
    mutable RecursiveMutex cs_privacy;

    // Privacy outputs owned by wallet (outpoint -> info)
    std::map<COutPoint, CPrivacyOutputInfo> m_privacyOutputs GUARDED_BY(cs_privacy);

    // Key images we've generated (hash -> outpoint)
    std::map<uint256, COutPoint> m_keyImages GUARDED_BY(cs_privacy);

    //! Select inputs for transaction
    bool SelectInputs(
        CAmount targetAmount,
        std::vector<CPrivacyOutputInfo>& selectedInputs,
        CAmount& inputTotal);

    //! Build ring for an input
    bool BuildInputRing(
        const CPrivacyOutputInfo& input,
        size_t ringSize,
        privacy::CPrivacyInput& privacyInput);
};

/**
 * @brief Helper to create standard transaction from privacy transaction
 */
CTransaction ConvertPrivacyToStandard(const privacy::CPrivacyTransaction& privTx);

/**
 * @brief Encode privacy transaction data into OP_RETURN
 */
CScript EncodePrivacyData(const privacy::CPrivacyTransaction& privTx);

} // namespace wallet

#endif // WATTX_WALLET_PRIVACY_WALLET_H
