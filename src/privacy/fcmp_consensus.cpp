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
#include <coins.h>
#include <util/moneystr.h>
#include <logging.h>
#include <hash.h>
#include <streams.h>
#include <common/system.h>
#include <util/fs.h>
#include <util/time.h>

#include <cstring>

namespace privacy {

// Master switch for the FCMP confidential AMOUNT layer (commitments + range
// proofs + balance). Default OFF: on mainnet nothing changes until this is
// deliberately enabled, and `tree_size == 0` means no shielded output has ever
// existed, so there is no legacy state to be compatible with.
//
// Turn on with -fcmpamountlayer (regtest/testnet) once the transaction builder
// balances blinding factors. Enabling it before end-to-end spends verify is how
// an inflation bug reaches production.
bool g_fcmp_amount_layer_enabled = false;

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
        // A note may only enter the tree from a transaction that PAID for it.
        //
        // Previously this added a leaf for ANY OP_RETURN carrying the "FCMP"
        // marker, with no value check and no cost: anyone could publish a
        // commitment to any amount and have consensus accept it as a shielded
        // note. That is unlimited inflation the moment the spend path works.
        //
        // A note-bearing OP_RETURN is still the ENCODING of a leaf, but the leaf
        // is only created when the containing transaction backed it by paying
        // into the shielded pool -- i.e. it created a pool output. The value
        // conservation itself is checked in CheckFcmpInputs, which runs against
        // the coins view before we get here; this is the structural gate that
        // stops a free-standing OP_RETURN from ever reaching the tree.
        const bool backed = CreatesPool(*tx);

        auto outputs = ExtractFcmpOutputs(*tx);
        if (!outputs.empty() && !backed) {
            LogPrintf("FCMP: block %d tx %s carries %lu note(s) with no pool "
                      "output backing them - ignored\n",
                      height, tx->GetHash().ToString(), outputs.size());
            outputs.clear();
        }
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
    // Confidential outputs are verified in ONE group (ed25519) by
    // confidential_ed25519.cpp: every output carries an audited Bulletproofs+
    // range proof bound to its own commitment, and the values must conserve.
    //
    // NOTE: g_fcmp_amount_layer_enabled is still false by default. The checks
    // below are complete and unit-tested, but the amount layer stays OFF until
    // the transaction builder balances blinding factors and end-to-end regtest
    // spends pass -- until then no confidential output can be created, exactly
    // as before. Flipping this on without that is how inflation ships.
    if (!privTx.privacyOutputs.empty()) {
        if (!g_fcmp_amount_layer_enabled) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                 "fcmp-amount-layer-disabled",
                                 "FCMP confidential outputs are disabled pending a curve-coherent, "
                                 "range-proven amount layer (anti-inflation fail-closed)");
        }

        std::vector<CPedersenCommitment> outputCommitments;
        for (const auto& out : privTx.privacyOutputs) {
            const CConfidentialOutput& co = out.confidentialOutput;

            // A purely transparent output inside an FCMP transaction carries no
            // commitment and no proof; it is covered by the explicit nValue.
            if (co.commitment.IsNull() && co.rangeProof.data.empty()) {
                continue;
            }

            if (!co.commitment.IsValid()) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                     "fcmp-output-commitment-invalid",
                                     "FCMP confidential output has an invalid commitment");
            }

            // A per-output proof is optional; the builder emits ONE aggregated
            // proof covering every commitment (smaller, and what BP+ is for).
            // If a per-output proof is present it must still be valid -- an
            // unverifiable blob is never allowed to ride along.
            if (!co.rangeProof.data.empty() && !VerifyRangeProof(co.commitment, co.rangeProof)) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                     "fcmp-output-rangeproof-invalid",
                                     "FCMP confidential output has an invalid range proof");
            }

            outputCommitments.push_back(co.commitment);
        }

        // Fail closed: every confidential output must be covered by the
        // aggregated range proof. Without it an output could hide a wrapped or
        // negative value and mint supply out of nothing.
        if (!outputCommitments.empty()) {
            if (!VerifyAggregatedRangeProof(outputCommitments, privTx.aggregatedRangeProof)) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                     "fcmp-aggregated-rangeproof-invalid",
                                     "FCMP confidential outputs are not covered by a valid "
                                     "aggregated range proof");
            }
        }

        if (!outputCommitments.empty()) {
            // Value conservation: sum(input pseudo-outputs) == sum(outputs) + fee.
            std::vector<CPedersenCommitment> inputCommitments;
            inputCommitments.reserve(privTx.fcmpInputs.size());
            for (const auto& input : privTx.fcmpInputs) {
                if (!input.pseudoOutput.IsValid()) {
                    return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                         "fcmp-pseudo-output-invalid",
                                         "FCMP input has invalid pseudo-output");
                }
                inputCommitments.push_back(input.pseudoOutput);
            }

            if (inputCommitments.empty()) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                     "fcmp-outputs-without-inputs",
                                     "FCMP confidential outputs with no shielded inputs to fund them");
            }

            // The fee is public, so its commitment has zero blinding and every
            // verifier recomputes it identically.
            //
            // A zero fee contributes 0*H + 0*G = the identity point, which is
            // the additive neutral element -- there is simply no term to add,
            // and constructing it would produce a point that IsValid() rejects.
            CPedersenCommitment feeCommitment;
            const CPedersenCommitment* feePtr = nullptr;
            if (privTx.nFee < 0) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                     "fcmp-fee-negative",
                                     "FCMP transaction has a negative fee");
            }
            if (privTx.nFee > 0) {
                if (!CreatePublicValueCommitment(privTx.nFee, feeCommitment)) {
                    return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                         "fcmp-fee-commitment-failed",
                                         "FCMP transaction has an unrepresentable fee");
                }
                feePtr = &feeCommitment;
            }

            if (!VerifyCommitmentBalance(inputCommitments, outputCommitments, feePtr)) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                     "fcmp-amount-imbalance",
                                     "FCMP transaction inputs do not balance outputs plus fee");
            }
        }
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

    // RULE P1 -- a transaction that touches the shielded pool MUST carry a valid
    // FCMP payload, and one that carries a payload MUST touch the pool.
    //
    // This is what makes the pool script safe to leave anyone-can-spend at the
    // script level. It must be checked BEFORE the decode-and-skip below: a decode
    // failure on a pool-spending transaction is a REJECTION, never a "not an FCMP
    // transaction, carry on". The old behaviour -- decode fails, return true --
    // meant a malformed payload silently bypassed every check in this function.
    const bool spends_pool = SpendsPool(tx, view);
    const bool creates_pool = CreatesPool(tx);
    const bool touches_pool = spends_pool || creates_pool;

    CPrivacyTransaction privTx;
    const bool has_payload = DecodeFcmpTransaction(tx, privTx);

    if (touches_pool && !has_payload) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS,
                             "fcmp-pool-without-payload",
                             "transaction touches the shielded pool without a valid FCMP payload");
    }
    if (has_payload && !touches_pool) {
        // A payload with no pool involvement has no value backing it: its outputs
        // would be notes nobody paid for.
        return state.Invalid(TxValidationResult::TX_CONSENSUS,
                             "fcmp-payload-without-pool",
                             "FCMP payload on a transaction that does not touch the shielded pool");
    }
    if (!has_payload) {
        return true; // Not an FCMP transaction, and it does not touch the pool
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

    // 4. SECURITY — every confidential output MUST be covered by a valid ed25519
    // Bulletproofs+ range proof. The balance check (step 6) only proves the
    // commitments SUM correctly; without a range proof an output can commit to an
    // out-of-range (negative / >2^64 wraparound) value that still balances and mints
    // on redemption (the Particl/Ghost/DASH inflation-bug class).
    //
    // The builder emits ONE aggregated proof over all output commitments, which is
    // what BP+ is for and is smaller than one proof per output. Verification goes
    // through VerifyAggregatedRangeProof, which validates the 0x0E commitment tag and
    // strips the proof's 0x02 version byte -- the previous code passed the version
    // byte through to wattx_bpplus::verify, so a correctly-formed proof could never
    // verify, and demanded a per-output proof on every privacyOutput, which made a
    // transparent output inside an FCMP transaction impossible to express.
    std::vector<CPedersenCommitment> outputCommitments;
    for (const auto& output : privTx.privacyOutputs) {
        const CConfidentialOutput& co = output.confidentialOutput;

        // A transparent output inside an FCMP transaction (a deshield recipient, or
        // transparent change) carries no commitment and no proof; its value is
        // explicit in nValue and covered by the transparent conservation rules.
        if (co.commitment.IsNull() && co.rangeProof.data.empty()) {
            continue;
        }

        if (!co.commitment.IsValid()) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                 "fcmp-bad-commitment",
                                 "FCMP confidential output has an invalid commitment");
        }

        // A per-output proof is optional, but an unverifiable blob never rides along.
        if (!co.rangeProof.data.empty() && !VerifyRangeProof(co.commitment, co.rangeProof)) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                 "fcmp-output-rangeproof-invalid",
                                 "FCMP confidential output has an invalid range proof");
        }

        outputCommitments.push_back(co.commitment);
    }

    if (!outputCommitments.empty()) {
        if (!VerifyAggregatedRangeProof(outputCommitments, privTx.aggregatedRangeProof)) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                 "fcmp-aggregated-rangeproof-invalid",
                                 "FCMP confidential outputs are not covered by a valid "
                                 "aggregated range proof");
        }
    }

    // 5. Compute the pool delta -- the net transparent value the shielded set gained.
    // Read from the transaction and the coins view, so the sender declares nothing
    // and can lie about nothing.
    CAmount poolDelta = 0;
    if (!ComputePoolDelta(tx, view, poolDelta)) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS,
                             "fcmp-pool-delta-unavailable",
                             "could not compute the shielded pool delta");
    }

    // 6. THE LEDGER INVARIANT:  sum(pseudo-outputs) + delta*H == sum(output commitments)
    //
    // Pinning the shielded value change to delta is what ties the shielded set to
    // real coin: delta is transparent value that Consensus::CheckTxInputs has already
    // conserved, so shielded value cannot be created here, only moved.
    //
    // The fee needs no term of its own. A fee paid out of the pool simply makes delta
    // more negative, and the miner collects it through the ordinary sum(vin)-sum(vout)
    // path -- which is why privTx.nFee is NOT trusted or used in this check.
    if (privTx.fcmpInputs.empty() && outputCommitments.empty()) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS,
                             "fcmp-nothing-to-balance",
                             "FCMP transaction touches the pool with no shielded inputs or outputs");
    }

    std::vector<CPedersenCommitment> inputCommitments;
    inputCommitments.reserve(privTx.fcmpInputs.size());
    for (const auto& input : privTx.fcmpInputs) {
        if (!input.pseudoOutput.IsValid()) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS,
                                 "fcmp-pseudo-output-invalid",
                                 "FCMP input has an invalid pseudo-output");
        }
        inputCommitments.push_back(input.pseudoOutput);
    }

    if (!VerifyPoolBalance(inputCommitments, outputCommitments, poolDelta)) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS,
                             "fcmp-amount-imbalance",
                             strprintf("FCMP shielded value does not balance the pool delta "
                                       "(%d in, %d out, delta=%s)",
                                       inputCommitments.size(), outputCommitments.size(),
                                       FormatMoney(poolDelta)));
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

// ============================================================================
// Shielded Pool (value backing)
// ============================================================================

const CScript& GetShieldedPoolScript()
{
    // Witness program, version 16 (as-yet unassigned), 32-byte domain-separated
    // program. Unassigned witness versions are anyone-can-spend to nodes that do
    // not know the rule, which is what lets this deploy as a softfork; Rule P1 is
    // what actually protects the funds.
    //
    // The program is a fixed constant, NOT a hash of anything transaction-specific:
    // there is exactly one pool, and every node must recognise it byte-for-byte
    // without needing any context to derive it.
    static const CScript pool_script = [] {
        const std::string tag = "WATTx FCMP shielded pool v1";
        const uint256 program = Hash(std::span<const unsigned char>(
            reinterpret_cast<const unsigned char*>(tag.data()), tag.size()));
        CScript s;
        s << OP_16 << std::vector<unsigned char>(program.begin(), program.end());
        return s;
    }();
    return pool_script;
}

bool IsPoolScript(const CScript& scriptPubKey)
{
    return scriptPubKey == GetShieldedPoolScript();
}

bool CreatesPool(const CTransaction& tx)
{
    for (const auto& out : tx.vout) {
        if (IsPoolScript(out.scriptPubKey)) return true;
    }
    return false;
}

bool SpendsPool(const CTransaction& tx, const CCoinsViewCache& view)
{
    if (tx.IsCoinBase()) return false;
    for (const auto& in : tx.vin) {
        const Coin& coin = view.AccessCoin(in.prevout);
        // A missing coin cannot be classified. Report "does not spend the pool"
        // and let the ordinary missing-inputs machinery reject the transaction;
        // claiming otherwise here would turn an unavailable UTXO into an FCMP
        // rule violation and produce a misleading rejection reason.
        if (coin.IsSpent()) continue;
        if (IsPoolScript(coin.out.scriptPubKey)) return true;
    }
    return false;
}

bool ComputePoolDelta(const CTransaction& tx, const CCoinsViewCache& view, CAmount& delta)
{
    CAmount created = 0;
    for (const auto& out : tx.vout) {
        if (!IsPoolScript(out.scriptPubKey)) continue;
        // Every value here is already MoneyRange-checked by CheckTransaction, but
        // this function must be safe to call in any order relative to that, and a
        // silent overflow would forge pool value.
        if (out.nValue < 0 || out.nValue > MAX_MONEY) return false;
        created += out.nValue;
        if (created > MAX_MONEY) return false;
    }

    CAmount spent = 0;
    if (!tx.IsCoinBase()) {
        for (const auto& in : tx.vin) {
            const Coin& coin = view.AccessCoin(in.prevout);
            if (coin.IsSpent()) return false; // caller must supply every input coin
            if (!IsPoolScript(coin.out.scriptPubKey)) continue;
            if (coin.out.nValue < 0 || coin.out.nValue > MAX_MONEY) return false;
            spent += coin.out.nValue;
            if (spent > MAX_MONEY) return false;
        }
    }

    delta = created - spent;
    return true;
}

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
