// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <privacy/consensus.h>
#include <hash.h>
#include <logging.h>
#include <script/script.h>
#include <util/fs.h>

#include <algorithm>

namespace privacy {

//
// Activation Check
//

bool IsPrivacyActive(int nHeight, const Consensus::Params& params)
{
    return params.IsPrivacyActive(nHeight);
}

// Global key image database
static std::shared_ptr<CKeyImageDB> g_keyImageDB;
static std::mutex g_keyImageDBMutex;

// DB key prefix
static constexpr uint8_t DB_KEYIMAGE = 'k';

//
// CKeyImageDB Implementation
//

CKeyImageDB::CKeyImageDB(const fs::path& path, size_t nCacheSize, bool fMemory, bool fWipe)
{
    m_db = std::make_unique<CDBWrapper>(DBParams{
        .path = path,
        .cache_bytes = nCacheSize,
        .memory_only = fMemory,
        .wipe_data = fWipe
    });
}

bool CKeyImageDB::IsSpent(const CKeyImage& keyImage) const
{
    LOCK(cs_db);
    if (!keyImage.IsValid()) return false;
    uint256 keyImageHash = keyImage.GetHash();
    return m_db->Exists(std::make_pair(DB_KEYIMAGE, keyImageHash));
}

bool CKeyImageDB::GetEntry(const CKeyImage& keyImage, CKeyImageEntry& entry) const
{
    LOCK(cs_db);
    if (!keyImage.IsValid()) return false;
    uint256 keyImageHash = keyImage.GetHash();
    return m_db->Read(std::make_pair(DB_KEYIMAGE, keyImageHash), entry);
}

bool CKeyImageDB::MarkSpent(const CKeyImage& keyImage, const uint256& txHash, int blockHeight)
{
    LOCK(cs_db);
    if (!keyImage.IsValid()) return false;

    CKeyImageEntry entry;
    entry.txHash = txHash;
    entry.blockHeight = blockHeight;

    uint256 keyImageHash = keyImage.GetHash();
    return m_db->Write(std::make_pair(DB_KEYIMAGE, keyImageHash), entry);
}

bool CKeyImageDB::UnmarkSpent(const CKeyImage& keyImage)
{
    LOCK(cs_db);
    if (!keyImage.IsValid()) return false;
    uint256 keyImageHash = keyImage.GetHash();
    return m_db->Erase(std::make_pair(DB_KEYIMAGE, keyImageHash));
}

bool CKeyImageDB::WriteKeyImages(const std::vector<std::pair<CKeyImage, CKeyImageEntry>>& entries)
{
    LOCK(cs_db);
    CDBBatch batch(*m_db);

    for (const auto& [keyImage, entry] : entries) {
        if (!keyImage.IsValid()) continue;
        uint256 keyImageHash = keyImage.GetHash();
        batch.Write(std::make_pair(DB_KEYIMAGE, keyImageHash), entry);
    }

    return m_db->WriteBatch(batch);
}

bool CKeyImageDB::EraseKeyImages(const std::vector<CKeyImage>& keyImages)
{
    LOCK(cs_db);
    CDBBatch batch(*m_db);

    for (const auto& keyImage : keyImages) {
        if (!keyImage.IsValid()) continue;
        uint256 keyImageHash = keyImage.GetHash();
        batch.Erase(std::make_pair(DB_KEYIMAGE, keyImageHash));
    }

    return m_db->WriteBatch(batch);
}

bool CKeyImageDB::Sync()
{
    LOCK(cs_db);
    CDBBatch batch(*m_db);
    return m_db->WriteBatch(batch, true);  // fSync = true
}

//
// Validation Functions
//

std::string PrivacyValidationResultToString(PrivacyValidationResult result)
{
    switch (result) {
        case PrivacyValidationResult::VALID:
            return "valid";
        case PrivacyValidationResult::INVALID_KEY_IMAGE_SPENT:
            return "key-image-spent";
        case PrivacyValidationResult::INVALID_KEY_IMAGE_FORMAT:
            return "invalid-key-image-format";
        case PrivacyValidationResult::INVALID_RING_SIZE:
            return "invalid-ring-size";
        case PrivacyValidationResult::INVALID_RING_SIGNATURE:
            return "invalid-ring-signature";
        case PrivacyValidationResult::INVALID_MLSAG_SIGNATURE:
            return "invalid-mlsag-signature";
        case PrivacyValidationResult::INVALID_COMMITMENT_BALANCE:
            return "invalid-commitment-balance";
        case PrivacyValidationResult::INVALID_RANGE_PROOF:
            return "invalid-range-proof";
        case PrivacyValidationResult::INVALID_STEALTH_OUTPUT:
            return "invalid-stealth-output";
        case PrivacyValidationResult::INVALID_DECOY_SELECTION:
            return "invalid-decoy-selection";
        case PrivacyValidationResult::INVALID_MIXED_TYPES:
            return "invalid-mixed-privacy-types";
        case PrivacyValidationResult::ERROR_INTERNAL:
            return "internal-error";
        default:
            return "unknown";
    }
}

bool CheckPrivacyTransaction(
    const CPrivacyTransaction& tx,
    TxValidationState& state,
    int height)
{
    // Check for empty inputs/outputs
    if (tx.privacyInputs.empty()) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "privacy-no-inputs");
    }
    if (tx.privacyOutputs.empty()) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "privacy-no-outputs");
    }

    // Get minimum ring size for this height
    size_t minRingSize = GetMinRingSize(height);
    size_t maxRingSize = 64;  // Maximum to prevent DoS

    // Check each input
    for (size_t i = 0; i < tx.privacyInputs.size(); i++) {
        const CPrivacyInput& input = tx.privacyInputs[i];

        // For ring signature types, verify key image format
        if (tx.privacyType == PrivacyType::RING || tx.privacyType == PrivacyType::RINGCT) {
            if (!input.keyImage.IsValid()) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS,
                    "privacy-invalid-key-image",
                    strprintf("Input %d has invalid key image", i));
            }

            // Check ring size
            if (!input.ring.IsValid()) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS,
                    "privacy-invalid-ring",
                    strprintf("Input %d has invalid ring", i));
            }

            size_t ringSize = input.ring.members.size();
            if (ringSize < minRingSize) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS,
                    "privacy-ring-too-small",
                    strprintf("Input %d ring size %d < min %d", i, ringSize, minRingSize));
            }
            if (ringSize > maxRingSize) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS,
                    "privacy-ring-too-large",
                    strprintf("Input %d ring size %d > max %d", i, ringSize, maxRingSize));
            }

            // Check all ring members have valid public keys
            for (size_t j = 0; j < ringSize; j++) {
                if (!input.ring.members[j].pubKey.IsValid()) {
                    return state.Invalid(TxValidationResult::TX_CONSENSUS,
                        "privacy-invalid-ring-member",
                        strprintf("Input %d ring member %d has invalid pubkey", i, j));
                }
            }
        }

        // For confidential types, verify commitment format
        if (tx.privacyType == PrivacyType::CONFIDENTIAL || tx.privacyType == PrivacyType::RINGCT) {
            if (!input.commitment.IsValid()) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS,
                    "privacy-invalid-input-commitment",
                    strprintf("Input %d has invalid commitment", i));
            }
        }
    }

    // Check outputs
    for (size_t i = 0; i < tx.privacyOutputs.size(); i++) {
        const CPrivacyOutput& output = tx.privacyOutputs[i];

        // For stealth outputs, verify format
        if (tx.privacyType == PrivacyType::STEALTH || tx.privacyType == PrivacyType::RINGCT) {
            if (output.stealthOutput.oneTimePubKey.IsValid()) {
                // One-time pubkey must be valid if present
                if (!output.stealthOutput.oneTimePubKey.IsFullyValid()) {
                    return state.Invalid(TxValidationResult::TX_CONSENSUS,
                        "privacy-invalid-stealth-pubkey",
                        strprintf("Output %d has invalid one-time pubkey", i));
                }
            }
        }

        // For confidential outputs, verify commitment and range proof
        if (tx.privacyType == PrivacyType::CONFIDENTIAL || tx.privacyType == PrivacyType::RINGCT) {
            if (output.confidentialOutput.IsValid()) {
                if (!output.confidentialOutput.commitment.IsValid()) {
                    return state.Invalid(TxValidationResult::TX_CONSENSUS,
                        "privacy-invalid-output-commitment",
                        strprintf("Output %d has invalid commitment", i));
                }
            }
        }

        // Non-confidential outputs must have valid amount
        if (tx.privacyType == PrivacyType::TRANSPARENT ||
            tx.privacyType == PrivacyType::STEALTH ||
            tx.privacyType == PrivacyType::RING) {
            if (output.nValue < 0 || output.nValue > MAX_MONEY) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS,
                    "privacy-invalid-amount",
                    strprintf("Output %d has invalid amount", i));
            }
        }
    }

    // Check for duplicate key images within transaction
    if (tx.privacyType == PrivacyType::RING || tx.privacyType == PrivacyType::RINGCT) {
        std::set<uint256> keyImageHashes;
        for (const auto& input : tx.privacyInputs) {
            uint256 kiHash = input.keyImage.GetHash();
            if (!keyImageHashes.insert(kiHash).second) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS,
                    "privacy-duplicate-key-image");
            }
        }
    }

    // Verify fee is reasonable (non-negative)
    if (tx.nFee < 0) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "privacy-negative-fee");
    }

    return true;
}

bool ContextualCheckPrivacyTransaction(
    const CPrivacyTransaction& tx,
    const CKeyImageDB& keyImageDB,
    TxValidationState& state,
    int height)
{
    // First do contextless checks
    if (!CheckPrivacyTransaction(tx, state, height)) {
        return false;
    }

    // Check key images are not spent
    if (tx.privacyType == PrivacyType::RING || tx.privacyType == PrivacyType::RINGCT) {
        for (size_t i = 0; i < tx.privacyInputs.size(); i++) {
            const CKeyImage& keyImage = tx.privacyInputs[i].keyImage;
            if (keyImageDB.IsSpent(keyImage)) {
                CKeyImageEntry entry;
                keyImageDB.GetEntry(keyImage, entry);
                return state.Invalid(TxValidationResult::TX_CONSENSUS,
                    "privacy-key-image-spent",
                    strprintf("Key image for input %d already spent in tx %s",
                              i, entry.txHash.ToString()));
            }
        }

        // Verify MLSAG signature
        if (tx.privacyInputs.size() > 0 && tx.mlsagSig.IsValid()) {
            uint256 txHash = tx.GetHash();
            if (!VerifyMLSAGSignature(txHash, tx.mlsagSig)) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS,
                    "privacy-invalid-mlsag");
            }
        }
    }

    // Verify commitment balance for confidential transactions
    if (tx.privacyType == PrivacyType::CONFIDENTIAL || tx.privacyType == PrivacyType::RINGCT) {
        std::vector<CPedersenCommitment> inputCommitments;
        std::vector<CPedersenCommitment> outputCommitments;

        for (const auto& input : tx.privacyInputs) {
            if (input.commitment.IsValid()) {
                inputCommitments.push_back(input.commitment);
            }
        }

        for (const auto& output : tx.privacyOutputs) {
            if (output.confidentialOutput.IsValid()) {
                outputCommitments.push_back(output.confidentialOutput.commitment);
            }
        }

        if (!inputCommitments.empty() && !outputCommitments.empty()) {
            // Note: Fee commitment would need to be added for proper balance
            if (!VerifyCommitmentBalance(inputCommitments, outputCommitments)) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS,
                    "privacy-commitment-imbalance");
            }
        }

        // Verify range proofs. SECURITY: mandatory when confidential outputs exist;
        // the prior `&& tx.aggregatedRangeProof.IsValid()` gate let an attacker skip
        // the check by omitting the proof (inflation path). Now absent/invalid fails.
        if (!outputCommitments.empty()) {
            if (!VerifyAggregatedRangeProof(outputCommitments, tx.aggregatedRangeProof)) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS,
                    "privacy-invalid-range-proof");
            }
        }
    }

    return true;
}

bool CheckKeyImageNotSpent(
    const CKeyImage& keyImage,
    const CKeyImageDB& keyImageDB,
    TxValidationState& state)
{
    if (!keyImage.IsValid()) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "invalid-key-image-format");
    }

    if (keyImageDB.IsSpent(keyImage)) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "key-image-spent");
    }

    return true;
}

bool CheckRingSize(
    const CRing& ring,
    int height,
    TxValidationState& state)
{
    size_t minSize = GetMinRingSize(height);
    size_t maxSize = 64;

    if (!ring.IsValid()) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "invalid-ring");
    }

    if (ring.members.size() < minSize) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "ring-too-small");
    }

    if (ring.members.size() > maxSize) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "ring-too-large");
    }

    return true;
}

bool CheckRingMembers(
    const CRing& ring,
    TxValidationState& state)
{
    for (size_t i = 0; i < ring.members.size(); i++) {
        const CRingMember& member = ring.members[i];

        // Check outpoint is valid
        if (member.outpoint.IsNull()) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS,
                "invalid-ring-member-outpoint",
                strprintf("Ring member %d has null outpoint", i));
        }

        // Check pubkey is valid
        if (!member.pubKey.IsValid() || !member.pubKey.IsFullyValid()) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS,
                "invalid-ring-member-pubkey",
                strprintf("Ring member %d has invalid pubkey", i));
        }
    }

    // Check for duplicate outpoints
    std::set<COutPoint> outpoints;
    for (const auto& member : ring.members) {
        if (!outpoints.insert(member.outpoint).second) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS,
                "duplicate-ring-member");
        }
    }

    return true;
}

bool ConnectPrivacyTransaction(
    const CPrivacyTransaction& tx,
    CKeyImageDB& keyImageDB,
    const uint256& txHash,
    int blockHeight)
{
    if (tx.privacyType != PrivacyType::RING && tx.privacyType != PrivacyType::RINGCT) {
        return true;  // No key images to track
    }

    std::vector<std::pair<CKeyImage, CKeyImageEntry>> entries;
    entries.reserve(tx.privacyInputs.size());

    for (const auto& input : tx.privacyInputs) {
        if (!input.keyImage.IsValid()) continue;

        CKeyImageEntry entry;
        entry.txHash = txHash;
        entry.blockHeight = blockHeight;
        entries.emplace_back(input.keyImage, entry);
    }

    if (entries.empty()) return true;

    if (!keyImageDB.WriteKeyImages(entries)) {
        LogPrintf("ERROR: Failed to write key images for tx %s\n", txHash.ToString());
        return false;
    }

    LogDebug(BCLog::PRIVACY, "Connected %d key images for tx %s at height %d\n",
             entries.size(), txHash.ToString(), blockHeight);
    return true;
}

bool DisconnectPrivacyTransaction(
    const CPrivacyTransaction& tx,
    CKeyImageDB& keyImageDB)
{
    if (tx.privacyType != PrivacyType::RING && tx.privacyType != PrivacyType::RINGCT) {
        return true;  // No key images to untrack
    }

    std::vector<CKeyImage> keyImages;
    keyImages.reserve(tx.privacyInputs.size());

    for (const auto& input : tx.privacyInputs) {
        if (!input.keyImage.IsValid()) continue;
        keyImages.push_back(input.keyImage);
    }

    if (keyImages.empty()) return true;

    if (!keyImageDB.EraseKeyImages(keyImages)) {
        LogPrintf("ERROR: Failed to erase key images during disconnect\n");
        return false;
    }

    LogDebug(BCLog::PRIVACY, "Disconnected %d key images\n", keyImages.size());
    return true;
}

//
// Global Functions
//

bool InitializeKeyImageDB(const fs::path& datadir)
{
    std::lock_guard<std::mutex> lock(g_keyImageDBMutex);

    fs::path dbPath = datadir / "keyimages";

    g_keyImageDB = std::make_shared<CKeyImageDB>(
        dbPath,
        1 << 20,  // 1MB cache
        false,    // not memory-only
        false     // don't wipe
    );

    LogPrintf("Key image database initialized at %s\n", fs::PathToString(dbPath));
    return true;
}

void ShutdownKeyImageDB()
{
    std::lock_guard<std::mutex> lock(g_keyImageDBMutex);

    if (g_keyImageDB) {
        g_keyImageDB->Sync();
        g_keyImageDB.reset();
    }

    LogPrintf("Key image database shutdown\n");
}

std::shared_ptr<CKeyImageDB> GetKeyImageDB()
{
    std::lock_guard<std::mutex> lock(g_keyImageDBMutex);
    return g_keyImageDB;
}

bool HasPrivacyData(const CTransaction& tx)
{
    // Check for privacy markers in transaction
    // Privacy transactions are identified by:
    // 1. Special version flag (version & 0x8000)
    // 2. OP_RETURN output with privacy prefix

    // Version flag check
    if (tx.version & 0x8000) {
        return true;
    }

    // Check for OP_RETURN with privacy prefix
    static const std::vector<unsigned char> PRIVACY_PREFIX = {'W', 'T', 'X', 'P'};

    for (const auto& out : tx.vout) {
        if (out.scriptPubKey.size() >= 5 && out.scriptPubKey[0] == OP_RETURN) {
            // Check for privacy prefix after OP_RETURN
            std::vector<unsigned char> data(out.scriptPubKey.begin() + 1, out.scriptPubKey.end());
            if (data.size() >= PRIVACY_PREFIX.size()) {
                // Handle OP_PUSHDATA prefix
                size_t offset = 0;
                if (data[0] <= 75) {
                    offset = 1;
                } else if (data[0] == OP_PUSHDATA1 && data.size() > 1) {
                    offset = 2;
                } else if (data[0] == OP_PUSHDATA2 && data.size() > 2) {
                    offset = 3;
                }

                if (data.size() >= offset + PRIVACY_PREFIX.size()) {
                    bool match = true;
                    for (size_t i = 0; i < PRIVACY_PREFIX.size(); i++) {
                        if (data[offset + i] != PRIVACY_PREFIX[i]) {
                            match = false;
                            break;
                        }
                    }
                    if (match) return true;
                }
            }
        }
    }

    return false;
}

std::optional<CPrivacyTransaction> ExtractPrivacyTransaction(const CTransaction& tx)
{
    if (!HasPrivacyData(tx)) {
        return std::nullopt;
    }

    // Find the OP_RETURN output with privacy data
    for (const auto& out : tx.vout) {
        if (out.scriptPubKey.size() < 5 || out.scriptPubKey[0] != OP_RETURN) {
            continue;
        }

        // Extract data after OP_RETURN
        std::vector<unsigned char> data(out.scriptPubKey.begin() + 1, out.scriptPubKey.end());

        // Parse pushdata
        size_t offset = 0;
        size_t dataLen = 0;
        if (data[0] <= 75) {
            dataLen = data[0];
            offset = 1;
        } else if (data[0] == OP_PUSHDATA1 && data.size() > 1) {
            dataLen = data[1];
            offset = 2;
        } else if (data[0] == OP_PUSHDATA2 && data.size() > 2) {
            dataLen = data[1] | (data[2] << 8);
            offset = 3;
        } else {
            continue;
        }

        if (data.size() < offset + dataLen) {
            continue;
        }

        // Check privacy prefix
        static const std::vector<unsigned char> PRIVACY_PREFIX = {'W', 'T', 'X', 'P'};
        if (dataLen < PRIVACY_PREFIX.size()) {
            continue;
        }

        bool match = true;
        for (size_t i = 0; i < PRIVACY_PREFIX.size(); i++) {
            if (data[offset + i] != PRIVACY_PREFIX[i]) {
                match = false;
                break;
            }
        }

        if (!match) continue;

        // Deserialize privacy transaction after prefix
        try {
            DataStream stream(std::vector<uint8_t>(
                data.begin() + offset + PRIVACY_PREFIX.size(),
                data.begin() + offset + dataLen));

            CPrivacyTransaction privTx;
            stream >> privTx;
            return privTx;
        } catch (const std::exception& e) {
            LogDebug(BCLog::PRIVACY, "Failed to deserialize privacy transaction: %s\n", e.what());
            continue;
        }
    }

    return std::nullopt;
}

} // namespace privacy
