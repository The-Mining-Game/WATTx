// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <privacy/fcmp_consensus.h>
#include <privacy/fcmp_tx.h>
#include <privacy/confidential.h>
#include <bpplus_api.h>             // wattx_bpplus::verify — sound ed25519 BP+ range proofs
#include <privacy/ed25519/pedersen.h>
#include <privacy/curvetree/tree_db.h>
#include <chain.h>
#include <logging.h>
#include <hash.h>
#include <streams.h>
#include <common/system.h>
#include <util/fs.h>
#include <util/time.h>

#include <cstring>

namespace privacy {

// ============================================================================
// Key Image Database Implementation
// ============================================================================

// Database keys
static constexpr uint8_t DB_KEY_IMAGE = 'K';
static constexpr uint8_t DB_SPENT_COUNT = 'S';

// Serializable structure for key image spend info
struct KeyImageSpendInfo {
    uint256 txHash;
    int32_t blockHeight;

    SERIALIZE_METHODS(KeyImageSpendInfo, obj) {
        READWRITE(obj.txHash, obj.blockHeight);
    }
};

CFcmpKeyImageDB::CFcmpKeyImageDB(const fs::path& path, size_t nCacheSize, bool fMemory, bool fWipe)
{
    m_db = std::make_unique<CDBWrapper>(DBParams{
        .path = path,
        .cache_bytes = nCacheSize,
        .memory_only = fMemory,
        .wipe_data = fWipe
    });
}

bool CFcmpKeyImageDB::IsSpent(const CKeyImage& keyImage) const
{
    LOCK(cs_keyimage);
    uint256 hash = keyImage.GetHash();
    return m_db->Exists(std::make_pair(DB_KEY_IMAGE, hash));
}

bool CFcmpKeyImageDB::MarkSpent(const CKeyImage& keyImage, const uint256& txHash, int blockHeight)
{
    LOCK(cs_keyimage);
    uint256 hash = keyImage.GetHash();

    // Store: keyImage hash -> (txHash, blockHeight)
    KeyImageSpendInfo info{txHash, blockHeight};
    return m_db->Write(std::make_pair(DB_KEY_IMAGE, hash), info);
}

bool CFcmpKeyImageDB::Unmark(const CKeyImage& keyImage)
{
    LOCK(cs_keyimage);
    uint256 hash = keyImage.GetHash();
    return m_db->Erase(std::make_pair(DB_KEY_IMAGE, hash));
}

bool CFcmpKeyImageDB::GetSpendingInfo(const CKeyImage& keyImage, uint256& txHash, int& blockHeight) const
{
    LOCK(cs_keyimage);
    uint256 hash = keyImage.GetHash();

    KeyImageSpendInfo info;
    if (!m_db->Read(std::make_pair(DB_KEY_IMAGE, hash), info)) {
        return false;
    }

    txHash = info.txHash;
    blockHeight = info.blockHeight;
    return true;
}

bool CFcmpKeyImageDB::WriteBatch(const std::vector<std::pair<CKeyImage, std::pair<uint256, int>>>& spends)
{
    LOCK(cs_keyimage);
    CDBBatch batch(*m_db);

    for (const auto& [keyImage, spendInfo] : spends) {
        uint256 hash = keyImage.GetHash();
        KeyImageSpendInfo info{spendInfo.first, spendInfo.second};
        batch.Write(std::make_pair(DB_KEY_IMAGE, hash), info);
    }

    return m_db->WriteBatch(batch);
}

bool CFcmpKeyImageDB::EraseBatch(const std::vector<CKeyImage>& keyImages)
{
    LOCK(cs_keyimage);
    CDBBatch batch(*m_db);

    for (const auto& keyImage : keyImages) {
        uint256 hash = keyImage.GetHash();
        batch.Erase(std::make_pair(DB_KEY_IMAGE, hash));
    }

    return m_db->WriteBatch(batch);
}

bool CFcmpKeyImageDB::Sync()
{
    // CDBWrapper syncs automatically on batch writes
    return true;
}

// ============================================================================
// FCMP Consensus State Implementation
// ============================================================================

// Global singleton
static std::unique_ptr<CFcmpConsensusState> g_fcmpState;

CFcmpConsensusState::CFcmpConsensusState() = default;
CFcmpConsensusState::~CFcmpConsensusState() = default;

bool CFcmpConsensusState::Initialize(const fs::path& datadir, size_t cacheSize)
{
    LOCK(cs_fcmp);

    if (m_initialized) {
        return true;
    }

    try {
        // Initialize key image database
        fs::path keyImagePath = datadir / "fcmp" / "keyimages";
        fs::create_directories(keyImagePath);
        m_keyImageDB = std::make_unique<CFcmpKeyImageDB>(keyImagePath, cacheSize / 2);

        // Initialize curve tree with persistent LevelDB storage
        fs::path treeDbPath = datadir / "fcmp" / "curvetree";
        fs::create_directories(treeDbPath);
        m_treeStorage = std::make_shared<curvetree::LevelDBTreeStorage>(treeDbPath);
        m_curveTree = std::make_shared<curvetree::CurveTree>(m_treeStorage);

        m_initialized = true;

        LogPrintf("FCMP: Consensus state initialized. Tree size: %lu outputs\n",
                  m_curveTree->GetOutputCount());

        return true;
    } catch (const std::exception& e) {
        LogPrintf("FCMP: Failed to initialize consensus state: %s\n", e.what());
        return false;
    }
}

void CFcmpConsensusState::Shutdown()
{
    LOCK(cs_fcmp);

    if (!m_initialized) return;

    // Sync databases
    if (m_keyImageDB) {
        m_keyImageDB->Sync();
    }

    // Clear state
    m_curveTree.reset();
    m_treeStorage.reset();
    m_keyImageDB.reset();
    m_initialized = false;

    LogPrintf("FCMP: Consensus state shutdown complete\n");
}

std::shared_ptr<curvetree::CurveTree> CFcmpConsensusState::GetCurveTree() const
{
    LOCK(cs_fcmp);
    return m_curveTree;
}

ed25519::Point CFcmpConsensusState::GetTreeRoot() const
{
    LOCK(cs_fcmp);
    if (!m_curveTree) {
        return ed25519::Point::Identity();
    }
    return m_curveTree->GetRoot();
}

uint64_t CFcmpConsensusState::GetTreeSize() const
{
    LOCK(cs_fcmp);
    if (!m_curveTree) return 0;
    return m_curveTree->GetOutputCount();
}

bool CFcmpConsensusState::IsKeyImageSpent(const CKeyImage& keyImage) const
{
    if (!m_keyImageDB) return false;
    return m_keyImageDB->IsSpent(keyImage);
}

bool CFcmpConsensusState::ConnectBlock(const CBlock& block, const CBlockIndex* pindex)
{
    LOCK(cs_fcmp);

    if (!m_initialized) {
        return true; // FCMP not active yet
    }

    int height = pindex->nHeight;
    uint64_t outputsAdded = 0;

    // Collect key images to mark spent
    std::vector<std::pair<CKeyImage, std::pair<uint256, int>>> keyImagesToMark;

    // Collect outputs to add to tree
    std::vector<curvetree::OutputTuple> outputsToAdd;

    for (const auto& tx : block.vtx) {
        // Extract FCMP outputs
        auto outputs = ExtractFcmpOutputs(*tx);
        for (auto& output : outputs) {
            outputsToAdd.push_back(std::move(output));
            outputsAdded++;
        }

        // Extract key images from FCMP inputs
        auto keyImages = ExtractKeyImages(*tx);
        for (const auto& ki : keyImages) {
            keyImagesToMark.emplace_back(ki, std::make_pair(tx->GetHash(), height));
        }
    }

    // Add outputs to curve tree
    if (!outputsToAdd.empty()) {
        m_curveTree->AddOutputs(outputsToAdd);
    }

    // Mark key images as spent
    if (!keyImagesToMark.empty()) {
        if (!m_keyImageDB->WriteBatch(keyImagesToMark)) {
            LogPrintf("FCMP: Failed to write key images for block %d\n", height);
            return false;
        }
        m_keyImagesSpent += keyImagesToMark.size();
    }

    // Track for reorg handling
    m_outputsAddedPerBlock[height] = outputsAdded;
    m_lastBlockHeight = height;

    if (outputsAdded > 0 || !keyImagesToMark.empty()) {
        LogPrintf("FCMP: Block %d connected. Added %lu outputs, spent %lu key images. Tree size: %lu\n",
                  height, outputsAdded, keyImagesToMark.size(), m_curveTree->GetOutputCount());
    }

    return true;
}

bool CFcmpConsensusState::DisconnectBlock(const CBlock& block, const CBlockIndex* pindex)
{
    LOCK(cs_fcmp);

    if (!m_initialized) {
        return true;
    }

    int height = pindex->nHeight;

    // Collect key images to unmark
    std::vector<CKeyImage> keyImagesToUnmark;

    for (const auto& tx : block.vtx) {
        auto keyImages = ExtractKeyImages(*tx);
        for (const auto& ki : keyImages) {
            keyImagesToUnmark.push_back(ki);
        }
    }

    // Unmark key images
    if (!keyImagesToUnmark.empty()) {
        if (!m_keyImageDB->EraseBatch(keyImagesToUnmark)) {
            LogPrintf("FCMP: Failed to erase key images for block %d\n", height);
            return false;
        }
        m_keyImagesSpent -= keyImagesToUnmark.size();
    }

    // Remove outputs from curve tree
    auto it = m_outputsAddedPerBlock.find(height);
    if (it != m_outputsAddedPerBlock.end() && it->second > 0) {
        if (!m_curveTree->RemoveLastN(it->second)) {
            LogPrintf("FCMP: Failed to remove %lu outputs from curve tree for block %d\n",
                      it->second, height);
            return false;
        }
        LogPrintf("FCMP: Block %d disconnected. Removed %lu outputs. Tree size: %lu\n",
                  height, it->second, m_curveTree->GetOutputCount());
        m_outputsAddedPerBlock.erase(it);
    }

    if (height <= m_lastBlockHeight) {
        m_lastBlockHeight = height - 1;
    }

    return true;
}

bool CFcmpConsensusState::CheckFcmpTransaction(const CTransaction& tx, TxValidationState& state) const
{
    // Decode FCMP data from transaction
    CPrivacyTransaction privTx;
    if (!DecodeFcmpTransaction(tx, privTx)) {
        // Not an FCMP transaction, skip
        return true;
    }

    // SECURITY — FAIL-CLOSED: the FCMP amount layer is not curve-coherent. Input
    // pseudo-outputs are ed25519 Pedersen commitments (fcmp_tx.cpp builds them with
    // an "Ed25519 prefix") while output commitments are secp256k1 (CreateCommitment).
    // Value conservation CANNOT be soundly verified across two different curves, so a
    // shielded output could carry unbacked value (DASH/Particl/Ghost-class inflation).
    // Until the amount layer is unified on ed25519 (ed25519 commitments + Bulletproofs+
    // range proofs; the balance + membership checks are already ed25519), reject any
    // FCMP transaction that creates confidential outputs. No shielded value can be
    // minted. Re-enable by removing this guard once the coherent ed25519 amount layer
    // and its range-proof verifier are wired and tested end-to-end.
    if (!privTx.privacyOutputs.empty()) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS,
                             "fcmp-amount-layer-disabled",
                             "FCMP confidential outputs are disabled pending a curve-coherent, "
                             "range-proven amount layer (anti-inflation fail-closed)");
    }

    // Check FCMP inputs
    for (const auto& input : privTx.fcmpInputs) {
        // 1. Key image must be valid (non-empty)
        if (input.keyImage.IsNull()) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                 "fcmp-keyimage-null",
                                 "FCMP input has null key image");
        }

        // 2. Input tuple points must be valid
        if (!input.inputTuple.O_tilde.IsValid() ||
            !input.inputTuple.I_tilde.IsValid() ||
            !input.inputTuple.C_tilde.IsValid()) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                 "fcmp-input-invalid-points",
                                 "FCMP input has invalid curve points");
        }

        // 3. Membership proof must be present
        if (input.membershipProof.proofData.empty()) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                 "fcmp-proof-empty",
                                 "FCMP input has empty membership proof");
        }

        // 4. Pseudo-output must be valid
        if (!input.pseudoOutput.IsValid()) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                 "fcmp-pseudo-output-invalid",
                                 "FCMP input has invalid pseudo-output");
        }
    }

    // Check for duplicate key images within transaction
    std::set<uint256> seenKeyImages;
    for (const auto& input : privTx.fcmpInputs) {
        uint256 kiHash = input.keyImage.GetHash();
        if (!seenKeyImages.insert(kiHash).second) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                 "fcmp-duplicate-keyimage",
                                 "Duplicate key image in transaction");
        }
    }

    return true;
}

bool CFcmpConsensusState::CheckFcmpInputs(const CTransaction& tx, TxValidationState& state,
                                          const CCoinsViewCache& view, int nSpendHeight) const
{
    LOCK(cs_fcmp);

    if (!m_initialized) {
        // FCMP not initialized - reject FCMP transactions
        CPrivacyTransaction privTx;
        if (DecodeFcmpTransaction(tx, privTx) && !privTx.fcmpInputs.empty()) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                 "fcmp-not-active",
                                 "FCMP transactions not yet active");
        }
        return true;
    }

    CPrivacyTransaction privTx;
    if (!DecodeFcmpTransaction(tx, privTx)) {
        return true; // Not an FCMP transaction
    }

    // Get current tree root for verification
    ed25519::Point treeRoot = m_curveTree->GetRoot();

    // Compute message hash for signature verification
    HashWriter hasher{};
    hasher << tx.GetHash();
    uint256 messageHash = hasher.GetHash();

    // Verify each FCMP input
    for (const auto& input : privTx.fcmpInputs) {
        // 1. Check key image not already spent
        if (IsKeyImageSpent(input.keyImage)) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                 "fcmp-keyimage-spent",
                                 "FCMP key image already spent");
        }

        // 2. Verify membership proof matches current tree root
        if (input.membershipProof.treeRoot.data != treeRoot.data) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                 "fcmp-proof-stale-root",
                                 "FCMP proof uses stale tree root");
        }

        // 3. Verify the full FCMP input (proof + signature)
        if (!VerifyFcmpInput(input, treeRoot, messageHash)) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                 "fcmp-verification-failed",
                                 "FCMP input verification failed");
        }
    }

    // 4. SECURITY — every confidential output MUST carry a valid ed25519 Bulletproofs+
    // range proof over its commitment. The homomorphic balance check (step 5) only
    // proves the commitments SUM correctly; without a range proof an output can commit
    // to an out-of-range (negative / >2^64 wraparound) value that still balances and
    // mints on redemption (the Particl/Ghost/DASH inflation-bug class). Verified by the
    // ported Monero BP+ (libwattx_bpplus): the proof must verify AND commit to exactly
    // this output's commitment (enforced internally via the 8*V == C cofactor match).
    std::vector<CPedersenCommitment> outputCommitments;
    for (const auto& output : privTx.privacyOutputs) {
        const std::vector<unsigned char>& cdata = output.confidentialOutput.commitment.data;
        const std::vector<unsigned char>& pdata = output.confidentialOutput.rangeProof.data;
        // 32-byte compressed ed25519 commitment (drop a 33-byte length/type prefix).
        const uint8_t* c32 = cdata.data();
        if (cdata.size() == 33) c32 = cdata.data() + 1;
        else if (cdata.size() != 32) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                 "fcmp-bad-commitment",
                                 "FCMP output commitment is not a 32-byte ed25519 point");
        }
        if (!wattx_bpplus::verify(c32, 1, pdata.data(), pdata.size())) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                 "fcmp-rangeproof-invalid",
                                 "FCMP output Bulletproofs+ range proof missing or invalid");
        }
        outputCommitments.push_back(output.confidentialOutput.commitment);
    }

    // 5. Verify balance (sum of pseudo-outputs = sum of outputs + fee)
    if (!VerifyFcmpBalance(privTx.fcmpInputs, outputCommitments, privTx.nFee)) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS,
                             "fcmp-balance-invalid",
                             "FCMP transaction balance verification failed");
    }

    return true;
}

CFcmpConsensusState::Stats CFcmpConsensusState::GetStats() const
{
    LOCK(cs_fcmp);

    Stats stats;
    if (m_curveTree) {
        stats.treeSize = m_curveTree->GetOutputCount();
        stats.treeDepth = m_curveTree->GetDepth();
    }
    stats.keyImagesSpent = m_keyImagesSpent;
    stats.lastBlockHeight = m_lastBlockHeight;

    return stats;
}

std::vector<curvetree::OutputTuple> CFcmpConsensusState::ExtractFcmpOutputs(const CTransaction& tx) const
{
    std::vector<curvetree::OutputTuple> outputs;

    // Check transaction for FCMP output data
    // FCMP outputs are encoded in OP_RETURN outputs or special script types
    for (size_t i = 0; i < tx.vout.size(); i++) {
        const CTxOut& out = tx.vout[i];

        // Look for FCMP output marker in script
        // Format: OP_RETURN OP_PUSHDATA1 <len> <FCMP_MARKER:4> <O:32> <I:32> <C:32>
        // Total: 1 + 1 + 1 + 4 + 96 = 103 bytes
        if (out.scriptPubKey.size() >= 103 && out.scriptPubKey[0] == OP_RETURN) {
            // Find the FCMP marker "FCMP" (0x46434D50)
            // After OP_RETURN, there's a push opcode:
            //   - For data < 76 bytes: single byte length at [1], data starts at [2]
            //   - For data 76-255 bytes: OP_PUSHDATA1 at [1], length at [2], data starts at [3]
            size_t dataOffset = 0;
            if (out.scriptPubKey[1] == 0x4c) { // OP_PUSHDATA1
                dataOffset = 3;
            } else if (out.scriptPubKey[1] < 0x4c) { // Direct push
                dataOffset = 2;
            } else {
                continue; // Unexpected encoding
            }

            if (out.scriptPubKey.size() < dataOffset + 100) continue; // Not enough data

            // Check for FCMP marker
            if (out.scriptPubKey[dataOffset] == 0x46 && out.scriptPubKey[dataOffset+1] == 0x43 &&
                out.scriptPubKey[dataOffset+2] == 0x4D && out.scriptPubKey[dataOffset+3] == 0x50) {

                curvetree::OutputTuple tuple;
                // Extract O, I, C points (32 bytes each)
                const uint8_t* data = out.scriptPubKey.data() + dataOffset + 4;
                std::memcpy(tuple.O.data.data(), data, 32);
                std::memcpy(tuple.I.data.data(), data + 32, 32);
                std::memcpy(tuple.C.data.data(), data + 64, 32);

                // Validate points
                if (tuple.O.IsValid() && tuple.I.IsValid() && tuple.C.IsValid()) {
                    outputs.push_back(tuple);
                }
            }
        }
    }

    return outputs;
}

std::vector<CKeyImage> CFcmpConsensusState::ExtractKeyImages(const CTransaction& tx) const
{
    std::vector<CKeyImage> keyImages;

    // Decode FCMP transaction and extract key images
    CPrivacyTransaction privTx;
    if (DecodeFcmpTransaction(tx, privTx)) {
        for (const auto& input : privTx.fcmpInputs) {
            keyImages.push_back(input.keyImage);
        }
    }

    return keyImages;
}

// ============================================================================
// Global Access Functions
// ============================================================================

bool IsFcmpStateAvailable()
{
    return g_fcmpState != nullptr;
}

CFcmpConsensusState& GetFcmpState()
{
    assert(g_fcmpState);
    return *g_fcmpState;
}

bool InitializeFcmpConsensus(const fs::path& datadir)
{
    g_fcmpState = std::make_unique<CFcmpConsensusState>();
    return g_fcmpState->Initialize(datadir);
}

void ShutdownFcmpConsensus()
{
    if (g_fcmpState) {
        g_fcmpState->Shutdown();
        g_fcmpState.reset();
    }
}

// ============================================================================
// Validation Helper Functions
// ============================================================================

bool HasFcmpInputs(const CTransaction& tx)
{
    // Check witness stack for FCMP marker bytes 0x46434D50 ("FCMP")
    if (!tx.HasWitness()) {
        return false;
    }

    for (const auto& vin : tx.vin) {
        for (const auto& item : vin.scriptWitness.stack) {
            if (item.size() >= 4 &&
                item[0] == 0x46 && item[1] == 0x43 &&
                item[2] == 0x4D && item[3] == 0x50) {
                return true;
            }
        }
    }

    return false;
}

bool HasFcmpOutputs(const CTransaction& tx)
{
    for (const auto& out : tx.vout) {
        if (out.scriptPubKey.size() >= 102 && out.scriptPubKey[0] == OP_RETURN) {
            if (out.scriptPubKey[2] == 0x46 && out.scriptPubKey[3] == 0x43 &&
                out.scriptPubKey[4] == 0x4D && out.scriptPubKey[5] == 0x50) {
                return true;
            }
        }
    }
    return false;
}

bool DecodeFcmpTransaction(const CTransaction& tx, CPrivacyTransaction& privTx)
{
    // Try to decode FCMP data from transaction
    // FCMP data can be in:
    // 1. Witness data (preferred)
    // 2. OP_RETURN outputs
    // 3. Special transaction version

    // For now, check witness for FCMP serialized data
    if (tx.HasWitness()) {
        for (size_t i = 0; i < tx.vin.size(); i++) {
            const auto& witness = tx.vin[i].scriptWitness;
            if (witness.stack.size() > 0) {
                // Look for FCMP marker in witness stack
                for (const auto& item : witness.stack) {
                    if (item.size() >= 4 &&
                        item[0] == 0x46 && item[1] == 0x43 &&
                        item[2] == 0x4D && item[3] == 0x50) {

                        // Try to deserialize
                        try {
                            SpanReader sr{item};
                            sr.ignore(4); // Skip marker
                            sr >> privTx;
                            return true;
                        } catch (...) {
                            continue;
                        }
                    }
                }
            }
        }
    }

    return false;
}

int GetFcmpActivationHeight(const Consensus::Params& params)
{
    return params.nFcmpActivationHeight;
}

bool IsFcmpActive(int nHeight, const Consensus::Params& params)
{
    return params.IsFcmpActive(nHeight);
}

int GetFcmpMaturity(const Consensus::Params& params)
{
    return params.nFcmpMaturity;
}

} // namespace privacy
