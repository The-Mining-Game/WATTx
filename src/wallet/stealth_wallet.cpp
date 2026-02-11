// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/stealth_wallet.h>
#include <wallet/wallet.h>
#include <hash.h>
#include <logging.h>
#include <script/script.h>
#include <script/solver.h>
#include <key_io.h>
#include <random.h>
#include <streams.h>
#include <util/fs.h>

#include <fstream>

namespace wallet {

CStealthAddressManager::CStealthAddressManager(CWallet* wallet)
    : m_wallet(wallet)
{
}

CStealthAddressManager::~CStealthAddressManager() = default;

bool CStealthAddressManager::GenerateStealthAddress(const std::string& label,
                                                      CStealthAddressData& addressData)
{
    LOCK(cs_stealth);

    // Generate new random keys
    CKey scanKey, spendKey;
    scanKey.MakeNewKey(true);
    spendKey.MakeNewKey(true);

    // Create stealth address
    addressData.address = privacy::CStealthAddress(scanKey.GetPubKey(), spendKey.GetPubKey());
    addressData.scanPrivKey = scanKey;
    addressData.spendPrivKey = spendKey;
    addressData.label = label;
    addressData.nCreateTime = GetTime();

    if (!addressData.IsValid()) {
        return false;
    }

    // Store in memory
    uint256 addrHash = HashStealthAddress(addressData.address);
    m_stealthAddresses[addrHash] = addressData;

    // Persist immediately
    WalletBatch batch(m_wallet->GetDatabase());
    StealthAddressDB::WriteStealthAddress(batch, addressData);

    LogPrintf("Generated new stealth address: %s (label: %s)\n",
              addressData.address.ToString(), label);
    return true;
}

bool CStealthAddressManager::ImportStealthAddress(const CKey& scanKey, const CKey& spendKey,
                                                    const std::string& label,
                                                    CStealthAddressData& addressData)
{
    LOCK(cs_stealth);

    // Create stealth address from keys
    addressData.address = privacy::CStealthAddress(scanKey.GetPubKey(), spendKey.GetPubKey());
    addressData.scanPrivKey = scanKey;
    addressData.spendPrivKey = spendKey;
    addressData.label = label;
    addressData.nCreateTime = GetTime();

    if (!addressData.IsValid()) {
        return false;
    }

    // Check if already exists
    uint256 addrHash = HashStealthAddress(addressData.address);
    if (m_stealthAddresses.count(addrHash)) {
        LogPrintf("Stealth address already exists: %s\n", addressData.address.ToString());
        return false;
    }

    m_stealthAddresses[addrHash] = addressData;

    // Persist immediately
    WalletBatch batch(m_wallet->GetDatabase());
    StealthAddressDB::WriteStealthAddress(batch, addressData);

    LogPrintf("Imported stealth address: %s (label: %s)\n",
              addressData.address.ToString(), label);
    return true;
}

std::vector<CStealthAddressData> CStealthAddressManager::GetStealthAddresses() const
{
    LOCK(cs_stealth);
    std::vector<CStealthAddressData> result;
    result.reserve(m_stealthAddresses.size());
    for (const auto& [hash, data] : m_stealthAddresses) {
        result.push_back(data);
    }
    return result;
}

std::optional<CStealthAddressData> CStealthAddressManager::GetStealthAddressByLabel(
    const std::string& label) const
{
    LOCK(cs_stealth);
    for (const auto& [hash, data] : m_stealthAddresses) {
        if (data.label == label) {
            return data;
        }
    }
    return std::nullopt;
}

std::optional<CStealthAddressData> CStealthAddressManager::GetStealthAddressByHash(
    const uint256& hash) const
{
    LOCK(cs_stealth);
    auto it = m_stealthAddresses.find(hash);
    if (it != m_stealthAddresses.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<CStealthPayment> CStealthAddressManager::TryDetectPayments(
    const CTransaction& tx,
    int blockHeight)
{
    std::vector<CStealthPayment> found;
    uint256 txid = tx.GetHash();

    // Step 1: Find ephemeral pubkey R from OP_RETURN outputs with "WTXS" marker
    CPubKey ephemeralPubKey;
    bool hasEphemeral = false;

    for (const auto& txout : tx.vout) {
        if (!txout.scriptPubKey.IsUnspendable()) continue;

        // Parse OP_RETURN data
        CScript::const_iterator it = txout.scriptPubKey.begin();
        opcodetype opcode;
        std::vector<unsigned char> data;

        // Skip OP_RETURN
        if (!txout.scriptPubKey.GetOp(it, opcode) || opcode != OP_RETURN) continue;
        if (!txout.scriptPubKey.GetOp(it, opcode, data)) continue;

        // Check for "WTXS" stealth marker (4 bytes) + compressed pubkey (33 bytes)
        if (data.size() >= 37 &&
            data[0] == 'W' && data[1] == 'T' && data[2] == 'X' && data[3] == 'S') {
            std::vector<unsigned char> pubkeyData(data.begin() + 4, data.begin() + 37);
            CPubKey candidate(pubkeyData);
            if (candidate.IsFullyValid()) {
                ephemeralPubKey = candidate;
                hasEphemeral = true;
                break;
            }
        }
    }

    if (!hasEphemeral) return found;

    // Step 2: For each non-OP_RETURN output, try to match against our stealth addresses
    for (uint32_t i = 0; i < tx.vout.size(); i++) {
        const CTxOut& txout = tx.vout[i];
        if (txout.scriptPubKey.IsUnspendable()) continue;

        // Extract pubkey from output
        std::vector<std::vector<unsigned char>> solutions;
        TxoutType type = Solver(txout.scriptPubKey, solutions);

        CPubKey outputPubKey;
        if (type == TxoutType::PUBKEY && solutions.size() >= 1) {
            outputPubKey = CPubKey(solutions[0]);
        } else {
            continue;
        }

        if (!outputPubKey.IsFullyValid()) continue;

        // Step 3: Try each stealth address using proper DKSAP protocol
        for (const auto& [addrHash, addrData] : m_stealthAddresses) {
            // Build a CStealthOutput from the ephemeral data and output pubkey
            privacy::CStealthOutput stealthOut;
            stealthOut.oneTimePubKey = outputPubKey;
            stealthOut.ephemeral = privacy::CEphemeralData(ephemeralPubKey, 0);
            stealthOut.outputIndex = i;

            // Compute view tag for fast filtering
            // S = scan_privkey * R (ECDH shared secret)
            // view_tag = first byte of H(S)
            uint8_t viewTag = privacy::ComputeViewTag(
                CPubKey()); // Compute from ephemeral - ScanStealthOutput does full check

            // Use ScanStealthOutput which implements proper DKSAP:
            // 1. S = scan_privkey * R
            // 2. P' = spend_pubkey + H(S, outputIndex)*G
            // 3. Check P' == outputPubKey
            // 4. If match, derive spending key = spend_privkey + H(S, outputIndex)
            CKey derivedKey;
            if (privacy::ScanStealthOutput(stealthOut, addrData.scanPrivKey,
                                            addrData.address.spendPubKey, derivedKey)) {
                // Verify the derived key matches the output
                if (derivedKey.GetPubKey() == outputPubKey) {
                    CStealthPayment payment;
                    payment.txid = txid;
                    payment.nOutput = i;
                    payment.nValue = txout.nValue;
                    payment.oneTimePubKey = outputPubKey;
                    payment.derivedPrivKey = derivedKey;
                    payment.stealthAddressHash = addrHash;
                    payment.blockHeight = blockHeight;
                    payment.spent = false;

                    LogPrintf("Detected stealth payment: %s:%d, amount=%d, to address=%s\n",
                              txid.ToString(), i, txout.nValue, addrData.address.ToString());
                    found.push_back(payment);
                    break; // One address match per output
                }
            }
        }
    }

    return found;
}

std::vector<CStealthPayment> CStealthAddressManager::ScanTransactionForPayments(
    const CTransaction& tx)
{
    LOCK(cs_stealth);

    if (m_stealthAddresses.empty()) {
        return {};
    }

    auto payments = TryDetectPayments(tx, -1);

    for (auto& payment : payments) {
        COutPoint outpoint = payment.GetOutpoint();

        // Check if we already have this payment
        if (m_payments.find(outpoint) == m_payments.end()) {
            m_payments[outpoint] = payment;
            m_paymentKeys[outpoint] = payment.derivedPrivKey;

            // Persist immediately
            WalletBatch batch(m_wallet->GetDatabase());
            StealthAddressDB::WriteStealthPayment(batch, payment);

            // Persist the derived key (serialized)
            std::vector<unsigned char> keyData(UCharCast(payment.derivedPrivKey.begin()), UCharCast(payment.derivedPrivKey.end()));
            StealthAddressDB::WriteStealthKey(batch, outpoint, payment.derivedPrivKey);
        }
    }

    return payments;
}

std::vector<CStealthPayment> CStealthAddressManager::ScanBlockForPayments(
    const CBlock& block, int height)
{
    LOCK(cs_stealth);
    std::vector<CStealthPayment> allPayments;

    if (m_stealthAddresses.empty()) {
        return allPayments;
    }

    WalletBatch batch(m_wallet->GetDatabase());

    for (const auto& tx : block.vtx) {
        auto payments = TryDetectPayments(*tx, height);

        for (auto& payment : payments) {
            COutPoint outpoint = payment.GetOutpoint();

            // Update height if we already have it from mempool
            auto it = m_payments.find(outpoint);
            if (it != m_payments.end()) {
                it->second.blockHeight = height;
                StealthAddressDB::WriteStealthPayment(batch, it->second);
            } else {
                m_payments[outpoint] = payment;
                m_paymentKeys[outpoint] = payment.derivedPrivKey;
                StealthAddressDB::WriteStealthPayment(batch, payment);
                StealthAddressDB::WriteStealthKey(batch, outpoint, payment.derivedPrivKey);
            }

            allPayments.push_back(payment);
        }
    }

    return allPayments;
}

std::vector<CStealthPayment> CStealthAddressManager::GetStealthPayments(bool includeSpent) const
{
    LOCK(cs_stealth);
    std::vector<CStealthPayment> result;
    for (const auto& [outpoint, payment] : m_payments) {
        if (includeSpent || !payment.spent) {
            result.push_back(payment);
        }
    }
    return result;
}

std::vector<CStealthPayment> CStealthAddressManager::GetUnspentStealthOutputs() const
{
    LOCK(cs_stealth);
    std::vector<CStealthPayment> result;
    for (const auto& [outpoint, payment] : m_payments) {
        if (!payment.spent) {
            result.push_back(payment);
        }
    }
    return result;
}

bool CStealthAddressManager::MarkSpent(const COutPoint& outpoint, const uint256& spendingTx)
{
    LOCK(cs_stealth);
    auto it = m_payments.find(outpoint);
    if (it == m_payments.end()) {
        return false;
    }

    it->second.spent = true;

    LogPrintf("Marked stealth output as spent: %s:%d in tx %s\n",
              outpoint.hash.ToString(), outpoint.n, spendingTx.ToString());
    return true;
}

CAmount CStealthAddressManager::GetStealthBalance() const
{
    LOCK(cs_stealth);
    CAmount total = 0;
    for (const auto& [outpoint, payment] : m_payments) {
        if (!payment.spent) {
            total += payment.nValue;
        }
    }
    return total;
}

CAmount CStealthAddressManager::GetSpendableStealthBalance() const
{
    LOCK(cs_stealth);
    CAmount total = 0;
    for (const auto& [outpoint, payment] : m_payments) {
        if (!payment.spent && payment.blockHeight > 0) {
            // Confirmed payments only
            total += payment.nValue;
        }
    }
    return total;
}

bool CStealthAddressManager::CreateStealthOutput(
    const privacy::CStealthAddress& recipientAddress,
    CAmount amount,
    CTxOut& txout,
    privacy::CStealthOutput& stealthData)
{
    // Generate ephemeral key for this payment
    CKey ephemeralKey;
    ephemeralKey.MakeNewKey(true);

    // Generate the stealth destination
    if (!privacy::GenerateStealthDestination(recipientAddress, ephemeralKey, stealthData)) {
        LogPrintf("Failed to generate stealth destination\n");
        return false;
    }

    // Create P2PK output with the one-time public key
    txout.scriptPubKey = GetScriptForRawPubKey(stealthData.oneTimePubKey);
    txout.nValue = amount;

    LogPrintf("Created stealth output: pubkey=%s, amount=%d\n",
              HexStr(stealthData.oneTimePubKey), amount);
    return true;
}

std::optional<CKey> CStealthAddressManager::GetPrivateKeyForOutput(const COutPoint& outpoint) const
{
    LOCK(cs_stealth);
    auto it = m_paymentKeys.find(outpoint);
    if (it != m_paymentKeys.end()) {
        return it->second;
    }
    return std::nullopt;
}

bool CStealthAddressManager::LoadFromDB()
{
    LOCK(cs_stealth);

    // Load stealth addresses
    if (!StealthAddressDB::ReadStealthAddresses(m_wallet->GetDatabase(), m_stealthAddresses)) {
        LogPrintf("Warning: Failed to load stealth addresses from DB\n");
        return false;
    }

    // Load stealth payments
    if (!StealthAddressDB::ReadStealthPayments(m_wallet->GetDatabase(), m_payments)) {
        LogPrintf("Warning: Failed to load stealth payments from DB\n");
        return false;
    }

    // Load derived keys for each payment
    for (const auto& [outpoint, payment] : m_payments) {
        CKey key;
        if (StealthAddressDB::ReadStealthKey(m_wallet->GetDatabase(), outpoint, key)) {
            m_paymentKeys[outpoint] = key;
        }
    }

    LogPrintf("Stealth address manager: loaded %d addresses, %d payments\n",
              m_stealthAddresses.size(), m_payments.size());
    return true;
}

bool CStealthAddressManager::SaveToDB()
{
    LOCK(cs_stealth);

    WalletBatch batch(m_wallet->GetDatabase());

    // Save all stealth addresses
    for (const auto& [hash, data] : m_stealthAddresses) {
        if (!StealthAddressDB::WriteStealthAddress(batch, data)) {
            LogPrintf("Error: Failed to save stealth address to DB\n");
            return false;
        }
    }

    // Save all payments
    for (const auto& [outpoint, payment] : m_payments) {
        if (!StealthAddressDB::WriteStealthPayment(batch, payment)) {
            LogPrintf("Error: Failed to save stealth payment to DB\n");
            return false;
        }
    }

    // Save derived keys
    for (const auto& [outpoint, key] : m_paymentKeys) {
        if (!StealthAddressDB::WriteStealthKey(batch, outpoint, key)) {
            LogPrintf("Error: Failed to save stealth key to DB\n");
            return false;
        }
    }

    LogPrintf("Stealth address manager: saved %d addresses, %d payments\n",
              m_stealthAddresses.size(), m_payments.size());
    return true;
}

bool CStealthAddressManager::HasStealthAddresses() const
{
    LOCK(cs_stealth);
    return !m_stealthAddresses.empty();
}

size_t CStealthAddressManager::GetStealthAddressCount() const
{
    LOCK(cs_stealth);
    return m_stealthAddresses.size();
}

uint256 CStealthAddressManager::HashStealthAddress(const privacy::CStealthAddress& addr)
{
    HashWriter hasher;
    hasher << addr.scanPubKey << addr.spendPubKey;
    return hasher.GetHash();
}

//
// StealthAddressDB Implementation
//

bool StealthAddressDB::WriteStealthAddress(WalletBatch& batch, const CStealthAddressData& addressData)
{
    // Compute hash for keying
    HashWriter hasher;
    hasher << addressData.address.scanPubKey << addressData.address.spendPubKey;
    uint256 hash = hasher.GetHash();
    return batch.WriteStealthAddress(hash, addressData);
}

bool StealthAddressDB::ReadStealthAddresses(WalletDatabase& db,
                                             std::map<uint256, CStealthAddressData>& addresses)
{
    addresses.clear();

    WalletBatch batch(db, false);

    DataStream prefix;
    prefix << DBKeys::STEALTH_ADDR;

    std::unique_ptr<DatabaseCursor> cursor = batch.GetBatch().GetNewPrefixCursor(prefix);
    if (!cursor) return false;

    DataStream ssKey, ssValue;
    while (true) {
        DatabaseCursor::Status status = cursor->Next(ssKey, ssValue);
        if (status == DatabaseCursor::Status::DONE) break;
        if (status == DatabaseCursor::Status::FAIL) return false;

        std::string type;
        ssKey >> type;
        uint256 hash;
        ssKey >> hash;

        CStealthAddressData data;
        ssValue >> data;
        addresses[hash] = data;
    }

    return true;
}

bool StealthAddressDB::WriteStealthPayment(WalletBatch& batch, const CStealthPayment& payment)
{
    COutPoint outpoint = payment.GetOutpoint();
    return batch.WriteStealthPayment(outpoint, payment);
}

bool StealthAddressDB::ReadStealthPayments(WalletDatabase& db,
                                            std::map<COutPoint, CStealthPayment>& payments)
{
    payments.clear();

    WalletBatch batch(db, false);

    DataStream prefix;
    prefix << DBKeys::STEALTH_PAYMENT;

    std::unique_ptr<DatabaseCursor> cursor = batch.GetBatch().GetNewPrefixCursor(prefix);
    if (!cursor) return false;

    DataStream ssKey, ssValue;
    while (true) {
        DatabaseCursor::Status status = cursor->Next(ssKey, ssValue);
        if (status == DatabaseCursor::Status::DONE) break;
        if (status == DatabaseCursor::Status::FAIL) return false;

        std::string type;
        ssKey >> type;
        Txid hash;
        uint32_t n;
        ssKey >> hash;
        ssKey >> n;

        CStealthPayment payment;
        ssValue >> payment;
        payments[COutPoint(hash, n)] = payment;
    }

    return true;
}

bool StealthAddressDB::WriteStealthKey(WalletBatch& batch, const COutPoint& outpoint, const CKey& key)
{
    // Serialize key as raw bytes
    std::vector<unsigned char> keyData(UCharCast(key.begin()), UCharCast(key.end()));
    return batch.WriteStealthKey(outpoint, keyData);
}

bool StealthAddressDB::ReadStealthKey(WalletDatabase& db, const COutPoint& outpoint, CKey& key)
{
    WalletBatch batch(db, false);
    std::vector<unsigned char> keyData;
    if (!batch.ReadStealthKey(outpoint, keyData)) {
        return false;
    }

    // Reconstruct CKey from raw bytes
    if (keyData.size() != 32) return false;
    key.Set(keyData.begin(), keyData.end(), true);
    return key.IsValid();
}

} // namespace wallet
