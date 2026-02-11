// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WATTX_WALLET_STEALTH_WALLET_H
#define WATTX_WALLET_STEALTH_WALLET_H

#include <privacy/stealth.h>
#include <key.h>
#include <pubkey.h>
#include <sync.h>
#include <uint256.h>
#include <primitives/transaction.h>
#include <wallet/walletdb.h>

#include <map>
#include <memory>
#include <optional>
#include <set>
#include <vector>

namespace wallet {

class CWallet;

/**
 * @brief Stored stealth address with associated keys
 */
struct CStealthAddressData
{
    privacy::CStealthAddress address;
    CKey scanPrivKey;       // Private scan key for detecting payments
    CKey spendPrivKey;      // Private spend key for spending
    std::string label;       // User-assigned label
    int64_t nCreateTime;    // Creation timestamp

    bool IsValid() const { return address.IsValid() && scanPrivKey.IsValid(); }

    // Serialization
    SERIALIZE_METHODS(CStealthAddressData, obj) {
        READWRITE(obj.address, obj.label, obj.nCreateTime);
        // Keys are stored separately (encrypted)
    }
};

/**
 * @brief Received stealth payment
 */
struct CStealthPayment
{
    uint256 txid;                   // Transaction hash
    uint32_t nOutput;               // Output index
    CAmount nValue;                 // Amount received
    CPubKey oneTimePubKey;          // One-time public key
    CKey derivedPrivKey;            // Derived private key for spending
    uint256 stealthAddressHash;     // Hash of stealth address that received this
    int blockHeight;                // Block height (-1 for mempool)
    bool spent;                     // Whether output has been spent

    COutPoint GetOutpoint() const { return COutPoint(Txid::FromUint256(txid), nOutput); }

    SERIALIZE_METHODS(CStealthPayment, obj) {
        READWRITE(obj.txid, obj.nOutput, obj.nValue, obj.oneTimePubKey,
                  obj.stealthAddressHash, obj.blockHeight, obj.spent);
        // derivedPrivKey stored separately (encrypted)
    }
};

/**
 * @brief Stealth address manager for wallet
 *
 * Manages stealth addresses and detects incoming payments.
 * Uses the DKSAP (Dual-Key Stealth Address Protocol) from privacy/stealth.h
 */
class CStealthAddressManager
{
public:
    CStealthAddressManager(CWallet* wallet);
    ~CStealthAddressManager();

    //! Generate a new stealth address
    bool GenerateStealthAddress(const std::string& label, CStealthAddressData& addressData);

    //! Import a stealth address from keys
    bool ImportStealthAddress(const CKey& scanKey, const CKey& spendKey,
                               const std::string& label, CStealthAddressData& addressData);

    //! Get all stealth addresses
    std::vector<CStealthAddressData> GetStealthAddresses() const;

    //! Get stealth address by label
    std::optional<CStealthAddressData> GetStealthAddressByLabel(const std::string& label) const;

    //! Get stealth address by hash
    std::optional<CStealthAddressData> GetStealthAddressByHash(const uint256& hash) const;

    //! Scan a transaction for stealth payments to our addresses
    std::vector<CStealthPayment> ScanTransactionForPayments(const CTransaction& tx);

    //! Scan a block for stealth payments
    std::vector<CStealthPayment> ScanBlockForPayments(const CBlock& block, int height);

    //! Get all received stealth payments
    std::vector<CStealthPayment> GetStealthPayments(bool includeSpent = false) const;

    //! Get unspent stealth outputs
    std::vector<CStealthPayment> GetUnspentStealthOutputs() const;

    //! Mark a stealth payment as spent
    bool MarkSpent(const COutPoint& outpoint, const uint256& spendingTx);

    //! Get total stealth balance
    CAmount GetStealthBalance() const;

    //! Get spendable stealth balance
    CAmount GetSpendableStealthBalance() const;

    //! Create a stealth output for sending
    bool CreateStealthOutput(const privacy::CStealthAddress& recipientAddress,
                             CAmount amount,
                             CTxOut& txout,
                             privacy::CStealthOutput& stealthData);

    //! Get private key for spending a stealth output
    std::optional<CKey> GetPrivateKeyForOutput(const COutPoint& outpoint) const;

    //! Load from wallet database
    bool LoadFromDB();

    //! Save to wallet database
    bool SaveToDB();

    //! Check if we have stealth addresses
    bool HasStealthAddresses() const;

    //! Get the number of stealth addresses
    size_t GetStealthAddressCount() const;

private:
    CWallet* m_wallet;
    mutable RecursiveMutex cs_stealth;

    // Stealth addresses owned by this wallet (hash -> data)
    std::map<uint256, CStealthAddressData> m_stealthAddresses GUARDED_BY(cs_stealth);

    // Received stealth payments (outpoint -> payment)
    std::map<COutPoint, CStealthPayment> m_payments GUARDED_BY(cs_stealth);

    // Derived private keys for payments (outpoint -> key)
    std::map<COutPoint, CKey> m_paymentKeys GUARDED_BY(cs_stealth);

    //! Try to detect stealth payments in a transaction (full DKSAP protocol)
    std::vector<CStealthPayment> TryDetectPayments(
        const CTransaction& tx,
        int blockHeight);

    //! Compute hash of stealth address for indexing
    static uint256 HashStealthAddress(const privacy::CStealthAddress& addr);
};

/**
 * @brief Write stealth address to wallet database
 */
class StealthAddressDB
{
public:
    static bool WriteStealthAddress(WalletBatch& batch, const CStealthAddressData& addressData);
    static bool ReadStealthAddresses(WalletDatabase& db, std::map<uint256, CStealthAddressData>& addresses);
    static bool WriteStealthPayment(WalletBatch& batch, const CStealthPayment& payment);
    static bool ReadStealthPayments(WalletDatabase& db, std::map<COutPoint, CStealthPayment>& payments);
    static bool WriteStealthKey(WalletBatch& batch, const COutPoint& outpoint, const CKey& key);
    static bool ReadStealthKey(WalletDatabase& db, const COutPoint& outpoint, CKey& key);
};

} // namespace wallet

#endif // WATTX_WALLET_STEALTH_WALLET_H
