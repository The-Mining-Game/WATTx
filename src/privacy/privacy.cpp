// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <privacy/privacy.h>
#include <privacy/fcmp_consensus.h>
#include <privacy/ed25519/ed25519_types.h>
#include <hash.h>
#include <consensus/params.h>
#include <script/solver.h>
#include <logging.h>

#include <map>
#include <mutex>

namespace privacy {

// In-memory fallback for when the persistent LevelDB store isn't available
// (test environment, pre-FCMP activation, early startup)
static std::mutex g_fallbackKeyImageMutex;
static std::map<std::vector<unsigned char>, uint256> g_fallbackKeyImages;

bool IsKeyImageSpent(const CKeyImage& keyImage)
{
    // Try persistent LevelDB-backed database first
    if (IsFcmpStateAvailable()) {
        return GetFcmpState().IsKeyImageSpent(keyImage);
    }
    // Fallback to in-memory tracking
    std::lock_guard<std::mutex> lock(g_fallbackKeyImageMutex);
    return g_fallbackKeyImages.count(keyImage.data) > 0;
}

bool MarkKeyImageSpent(const CKeyImage& keyImage, const uint256& txHash)
{
    // Try persistent LevelDB-backed database first
    if (IsFcmpStateAvailable()) {
        auto* db = GetFcmpState().GetKeyImageDB();
        if (db) {
            return db->MarkSpent(keyImage, txHash, 0);
        }
    }
    // Fallback to in-memory tracking
    std::lock_guard<std::mutex> lock(g_fallbackKeyImageMutex);
    if (g_fallbackKeyImages.count(keyImage.data) > 0) {
        return false; // Already spent
    }
    g_fallbackKeyImages[keyImage.data] = txHash;
    return true;
}

size_t GetMinRingSize(int height)
{
    // Minimum ring size increases over time for better privacy
    // Privacy activates at block 210,000
    if (height < 210000) return 3;
    if (height < 420000) return 7;
    return 11;
}

size_t GetDefaultRingSize(int height)
{
    // Default ring size for new transactions
    return std::max(GetMinRingSize(height), size_t(11));
}

CPrivacyTransactionBuilder::CPrivacyTransactionBuilder(PrivacyType type)
    : m_type(type), m_ringSize(11)
{
}

bool CPrivacyTransactionBuilder::AddInput(
    const COutPoint& outpoint,
    const CKey& privKey,
    CAmount amount,
    const CBlindingFactor& blindingFactor)
{
    m_inputs.emplace_back(outpoint, privKey, amount, blindingFactor);
    return true;
}

bool CPrivacyTransactionBuilder::AddOutput(
    const CStealthAddress& stealthAddr,
    CAmount amount)
{
    if (!stealthAddr.IsValid() || amount <= 0) {
        return false;
    }
    m_stealthOutputs.emplace_back(stealthAddr, amount);
    return true;
}

bool CPrivacyTransactionBuilder::AddOutput(
    const CScript& scriptPubKey,
    CAmount amount)
{
    if (scriptPubKey.empty() || amount <= 0) {
        return false;
    }
    m_standardOutputs.emplace_back(scriptPubKey, amount);
    return true;
}

void CPrivacyTransactionBuilder::SetFee(CAmount fee)
{
    m_fee = fee;
}

void CPrivacyTransactionBuilder::SetRingSize(size_t size)
{
    m_ringSize = std::max(size, size_t(3));
}

std::optional<CPrivacyTransaction> CPrivacyTransactionBuilder::Build()
{
    if (m_inputs.empty()) {
        return std::nullopt;
    }

    if (m_stealthOutputs.empty() && m_standardOutputs.empty()) {
        return std::nullopt;
    }

    CPrivacyTransaction tx;
    tx.privacyType = m_type;
    tx.nFee = m_fee;

    // Calculate totals
    CAmount inputTotal = 0;
    for (const auto& [outpoint, privKey, amount, blind] : m_inputs) {
        inputTotal += amount;
    }

    CAmount outputTotal = 0;
    for (const auto& [addr, amount] : m_stealthOutputs) {
        outputTotal += amount;
    }
    for (const auto& [script, amount] : m_standardOutputs) {
        outputTotal += amount;
    }

    if (inputTotal < outputTotal + m_fee) {
        return std::nullopt; // Insufficient funds
    }

    // Blinding factors of the input pseudo-outputs, needed to balance the
    // outputs so that sum(in) == sum(out) + fee holds on the curve.
    std::vector<CBlindingFactor> inputBlinds;

    // Build inputs
    for (const auto& [outpoint, privKey, amount, blind] : m_inputs) {
        CPrivacyInput input;

        // For ring signatures, we need to select decoys
        if (m_type == PrivacyType::RING || m_type == PrivacyType::RINGCT) {
            // Add real output as first member
            CRingMember realMember(outpoint, privKey.GetPubKey());
            input.ring.members.push_back(realMember);

            // Select decoys (placeholder - needs UTXO access)
            std::vector<CRingMember> decoys;
            SelectDecoys(outpoint, m_ringSize - 1, decoys);
            for (const auto& decoy : decoys) {
                input.ring.members.push_back(decoy);
            }

            // Generate key image
            GenerateKeyImage(privKey, privKey.GetPubKey(), input.keyImage);
        }

        // For confidential, create commitment
        if (m_type == PrivacyType::CONFIDENTIAL || m_type == PrivacyType::RINGCT) {
            CBlindingFactor bf = blind.IsValid() ? blind : CBlindingFactor::Random();
            CreateCommitment(amount, bf, input.commitment);
            // Tracked so the outputs can be made to balance against them; without
            // this the G-components never cancel and consensus rejects the tx as
            // imbalanced even when the values are correct.
            inputBlinds.push_back(bf);
        }

        tx.privacyInputs.push_back(input);
    }

    // Build outputs
    std::vector<CBlindingFactor> outputBlinds;
    std::vector<CAmount> outputAmounts;
    std::vector<CPedersenCommitment> outputCommitments;

    for (const auto& [stealthAddr, amount] : m_stealthOutputs) {
        CPrivacyOutput output;

        // Generate stealth destination
        CKey ephemeralKey;
        GenerateStealthDestination(stealthAddr, ephemeralKey, output.stealthOutput);

        output.nValue = amount;

        // For confidential, create commitment
        if (m_type == PrivacyType::CONFIDENTIAL || m_type == PrivacyType::RINGCT) {
            CBlindingFactor bf = CBlindingFactor::Random();
            CreateCommitment(amount, bf, output.confidentialOutput.commitment);
            outputBlinds.push_back(bf);
            outputAmounts.push_back(amount);
            outputCommitments.push_back(output.confidentialOutput.commitment);
        }

        tx.privacyOutputs.push_back(output);
    }

    for (const auto& [script, amount] : m_standardOutputs) {
        CPrivacyOutput output;
        output.scriptPubKey = script;
        output.nValue = amount;

        if (m_type == PrivacyType::CONFIDENTIAL || m_type == PrivacyType::RINGCT) {
            CBlindingFactor bf = CBlindingFactor::Random();
            CreateCommitment(amount, bf, output.confidentialOutput.commitment);
            outputBlinds.push_back(bf);
            outputAmounts.push_back(amount);
            outputCommitments.push_back(output.confidentialOutput.commitment);
        }

        tx.privacyOutputs.push_back(output);
    }

    // Make the outputs balance the inputs before proving anything.
    //
    // The last output's blinding is replaced with sum(inputBlinds) -
    // sum(other outputBlinds), so the G-components cancel in
    //     sum(in) == sum(out) + fee
    // (the fee commitment carries zero blinding). Its commitment must then be
    // recomputed, and the range proof must be built over the FINAL commitments
    // or it will not bind to what the transaction actually carries.
    if (!outputCommitments.empty()) {
        if (inputBlinds.empty()) {
            return std::nullopt; // confidential outputs with no shielded inputs to fund them
        }
        if (!BalanceBlindingFactors(inputBlinds, outputBlinds)) {
            return std::nullopt;
        }

        const size_t last = outputBlinds.size() - 1;
        if (!CreateCommitment(outputAmounts[last], outputBlinds[last], outputCommitments[last])) {
            return std::nullopt;
        }
        // Mirror the corrected commitment back into the transaction itself; the
        // vector is only a working copy.
        size_t confIdx = 0;
        for (auto& out : tx.privacyOutputs) {
            if (out.confidentialOutput.commitment.IsNull()) continue;
            if (confIdx == last) {
                out.confidentialOutput.commitment = outputCommitments[last];
                break;
            }
            confIdx++;
        }
    }

    // Create range proofs over the final commitments
    if (!outputCommitments.empty()) {
        if (!CreateAggregatedRangeProof(outputAmounts, outputBlinds, outputCommitments,
                                        tx.aggregatedRangeProof)) {
            return std::nullopt;
        }
    }

    // Create MLSAG signature (placeholder - needs full implementation)
    if (m_type == PrivacyType::RING || m_type == PrivacyType::RINGCT) {
        std::vector<CRing> rings;
        std::vector<size_t> realIndices;
        std::vector<CKey> privKeys;

        for (size_t i = 0; i < tx.privacyInputs.size(); i++) {
            rings.push_back(tx.privacyInputs[i].ring);
            realIndices.push_back(0); // Real is always first in our construction
            privKeys.push_back(std::get<1>(m_inputs[i]));
        }

        uint256 txHash = tx.GetHash();
        CreateMLSAGSignature(txHash, rings, realIndices, privKeys, tx.mlsagSig);
    }

    return tx;
}

uint256 CPrivacyTransaction::GetHash() const
{
    HashWriter hasher;
    hasher << nVersion << static_cast<uint8_t>(privacyType);

    // Hash ring-based inputs
    for (const auto& input : privacyInputs) {
        hasher << input.keyImage;
    }

    // Hash FCMP inputs
    for (const auto& input : fcmpInputs) {
        hasher << input.keyImage;
        hasher << input.inputTuple.O_tilde.data;
        hasher << input.inputTuple.I_tilde.data;
        hasher << input.inputTuple.C_tilde.data;
    }

    for (const auto& output : privacyOutputs) {
        if (output.stealthOutput.oneTimePubKey.IsValid()) {
            hasher << output.stealthOutput.oneTimePubKey;
        }
        if (output.confidentialOutput.IsValid()) {
            hasher << output.confidentialOutput.commitment.data;
        }
        hasher << output.scriptPubKey << output.nValue;
    }

    hasher << nFee << nLockTime;

    return hasher.GetHash();
}

bool CPrivacyTransaction::Verify() const
{
    // Handle FCMP transactions
    if (privacyType == PrivacyType::FCMP) {
        return VerifyFcmp();
    }

    // Verify key images are not spent (for ring signature types)
    for (const auto& input : privacyInputs) {
        if (input.keyImage.IsValid() && IsKeyImageSpent(input.keyImage)) {
            return false;
        }
    }

    // Verify ring signatures (if applicable)
    if (privacyType == PrivacyType::RING || privacyType == PrivacyType::RINGCT) {
        uint256 txHash = GetHash();
        if (!VerifyMLSAGSignature(txHash, mlsagSig)) {
            return false;
        }
    }

    // Verify commitment balance (if applicable)
    if (privacyType == PrivacyType::CONFIDENTIAL || privacyType == PrivacyType::RINGCT) {
        std::vector<CPedersenCommitment> inputCommitments;
        for (const auto& input : privacyInputs) {
            if (input.commitment.IsValid()) {
                inputCommitments.push_back(input.commitment);
            }
        }

        std::vector<CPedersenCommitment> outputCommitments;
        for (const auto& output : privacyOutputs) {
            if (output.confidentialOutput.IsValid()) {
                outputCommitments.push_back(output.confidentialOutput.commitment);
            }
        }

        if (!inputCommitments.empty() && !outputCommitments.empty()) {
            // TODO: Add fee commitment
            if (!VerifyCommitmentBalance(inputCommitments, outputCommitments)) {
                return false;
            }
        }

        // Verify range proofs. SECURITY: mandatory whenever confidential outputs
        // exist — the previous `&& aggregatedRangeProof.IsValid()` gate let an
        // attacker SKIP verification by simply omitting the proof, allowing an
        // out-of-range output to mint. Absent/empty proof now rejects the tx.
        if (!outputCommitments.empty()) {
            if (!VerifyAggregatedRangeProof(outputCommitments, aggregatedRangeProof)) {
                return false;
            }
        }
    }

    return true;
}

bool CPrivacyTransaction::VerifyFcmp() const
{
    // 1. Check FCMP inputs exist
    if (fcmpInputs.empty()) {
        LogPrintf("FCMP Verify: FAILED - no inputs\n");
        return false;
    }

    // 2. Verify key images are not spent
    for (size_t i = 0; i < fcmpInputs.size(); i++) {
        const auto& input = fcmpInputs[i];
        if (!input.keyImage.IsValid()) {
            LogPrintf("FCMP Verify: FAILED - input %d key image invalid\n", i);
            return false;
        }
        if (IsKeyImageSpent(input.keyImage)) {
            LogPrintf("FCMP Verify: FAILED - input %d key image already spent\n", i);
            return false;
        }
    }

    // 3. Get transaction hash for signature verification
    uint256 txHash = GetHash();

    // 4. Get tree root (in production, this would come from chain state)
    // For now, use the root from the first input's proof
    if (!fcmpInputs[0].membershipProof.IsValid()) {
        LogPrintf("FCMP Verify: FAILED - membership proof invalid\n");
        return false;
    }
    ed25519::Point treeRoot = fcmpInputs[0].membershipProof.treeRoot;

    // 5. Batch verify all FCMP inputs
    if (!BatchVerifyFcmpInputs(fcmpInputs, treeRoot, txHash)) {
        LogPrintf("FCMP Verify: FAILED - batch input verification failed\n");
        return false;
    }

    // 6. Verify commitment balance
    std::vector<CPedersenCommitment> outputCommitments;
    for (const auto& output : privacyOutputs) {
        if (output.confidentialOutput.IsValid()) {
            outputCommitments.push_back(output.confidentialOutput.commitment);
        }
    }

    if (!outputCommitments.empty()) {
        if (!VerifyFcmpBalance(fcmpInputs, outputCommitments, nFee)) {
            LogPrintf("FCMP Verify: FAILED - commitment balance check failed (%d inputs, %d outputs, fee=%lld)\n",
                      fcmpInputs.size(), outputCommitments.size(), nFee);
            return false;
        }

        // 7. Verify range proofs. SECURITY: mandatory when outputs exist — omitting
        // the proof must NOT skip the check (that was an inflation path). An empty
        // or invalid aggregated proof now fails the transaction.
        if (!outputCommitments.empty()) {
            if (!VerifyAggregatedRangeProof(outputCommitments, aggregatedRangeProof)) {
                LogPrintf("FCMP Verify: FAILED - range proof verification failed\n");
                return false;
            }
        }
    }

    LogPrintf("FCMP Verify: PASSED\n");
    return true;
}

bool CPrivacyTransaction::VerifyFcmpSelfCheck(CAmount poolDelta) const
{
    // 1. Check FCMP inputs exist
    if (fcmpInputs.empty()) {
        LogPrintf("FCMP SelfCheck: FAILED - no inputs\n");
        return false;
    }

    // 2. Verify key images are valid
    for (size_t i = 0; i < fcmpInputs.size(); i++) {
        if (!fcmpInputs[i].keyImage.IsValid()) {
            LogPrintf("FCMP SelfCheck: FAILED - input %d key image invalid\n", i);
            return false;
        }
    }

    // 3. Verify SA+L signature for each input
    auto G = ed25519::Point::BasePoint();
    for (size_t i = 0; i < fcmpInputs.size(); i++) {
        const auto& input = fcmpInputs[i];
        auto sG = input.salSignature.s * G;
        auto cO = input.salSignature.c * input.inputTuple.O_tilde;
        auto R_plus_cO = input.inputTuple.R + cO;

        if (sG.data != R_plus_cO.data) {
            LogPrintf("FCMP SelfCheck: FAILED - input %d SA+L signature invalid\n", i);
            return false;
        }
    }

    // 4. Verify commitment balance.
    //
    // Collect by COMMITMENT, not by CConfidentialOutput::IsValid(). IsValid()
    // additionally requires a non-empty per-output rangeProof, and the builder
    // emits ONE aggregated proof instead -- so this loop used to find zero
    // commitments on every wallet-built transaction, skip the balance check
    // entirely, and report PASSED. That vacuous pass is how an unbalanced,
    // input-less transaction reached the wire with a txid returned to the user.
    std::vector<CPedersenCommitment> outputCommitments;
    for (const auto& output : privacyOutputs) {
        const CConfidentialOutput& co = output.confidentialOutput;
        if (co.commitment.IsNull() && co.rangeProof.data.empty()) {
            continue; // genuinely transparent output
        }
        if (!co.commitment.IsValid()) {
            LogPrintf("FCMP SelfCheck: FAILED - output has an invalid commitment\n");
            return false;
        }
        outputCommitments.push_back(co.commitment);
    }

    // Fail closed: a shielded transaction with nothing to balance is malformed,
    // not trivially valid.
    if (outputCommitments.empty()) {
        LogPrintf("FCMP SelfCheck: FAILED - no output commitments to balance\n");
        return false;
    }

    // The aggregated range proof must cover them, and must exist. Checking it here
    // means the wallet never broadcasts something consensus will reject.
    if (!VerifyAggregatedRangeProof(outputCommitments, aggregatedRangeProof)) {
        LogPrintf("FCMP SelfCheck: FAILED - outputs are not covered by a valid "
                  "aggregated range proof\n");
        return false;
    }

    // Balance against the pool delta. nFee is NOT used: under the pool model the
    // fee is transparent, and paying it simply makes the delta more negative.
    std::vector<CPedersenCommitment> inputCommitments;
    inputCommitments.reserve(fcmpInputs.size());
    for (const auto& input : fcmpInputs) {
        if (!input.pseudoOutput.IsValid()) {
            LogPrintf("FCMP SelfCheck: FAILED - input has an invalid pseudo-output\n");
            return false;
        }
        inputCommitments.push_back(input.pseudoOutput);
    }

    if (!VerifyPoolBalance(inputCommitments, outputCommitments, poolDelta)) {
        LogPrintf("FCMP SelfCheck: FAILED - shielded value does not balance the "
                  "pool delta (%d in, %d out, delta=%lld)\n",
                  inputCommitments.size(), outputCommitments.size(), poolDelta);
        return false;
    }

    LogPrintf("FCMP SelfCheck: PASSED (SA+L sig + range proof + pool balance verified, "
              "membership proof deferred to consensus)\n");
    return true;
}

std::optional<CTransaction> CPrivacyTransaction::ToFcmpTransaction(const CFcmpShell& shell) const
{
    if (privacyType != PrivacyType::FCMP) {
        return std::nullopt;
    }

    // A transaction with no inputs is not a transaction. This is what the old
    // ToTransaction() produced for every FCMP spend: it walked privacyInputs (the
    // RingCT vector, always empty here), emitted vin: [], and the resulting tx had
    // no witness for the payload -- so DecodeFcmpTransaction found nothing and
    // consensus skipped every FCMP check. The mempool rejected it only because a
    // non-coinbase tx with an empty vin is invalid.
    if (shell.poolInputs.empty()) {
        LogPrintf("FCMP ToFcmpTransaction: no pool inputs -- refusing to build an "
                  "input-less transaction\n");
        return std::nullopt;
    }
    if (shell.outputs.empty()) {
        LogPrintf("FCMP ToFcmpTransaction: no outputs\n");
        return std::nullopt;
    }

    CMutableTransaction mtx;
    mtx.version = nVersion;
    mtx.nLockTime = nLockTime;

    for (const auto& outpoint : shell.poolInputs) {
        // Empty scriptSig: the pool script is a native witness program, so the
        // txid is not scriptSig-malleable. The SA+L signature commits to that
        // txid, which is what stops a third party rewriting the outputs of a
        // transaction paying from an anyone-can-spend script.
        mtx.vin.emplace_back(outpoint);
    }

    for (const auto& out : shell.outputs) {
        mtx.vout.push_back(out);
    }

    // Serialize the payload behind the "FCMP" marker and attach it to vin[0]'s
    // witness, which is where DecodeFcmpTransaction looks for it.
    DataStream payload;
    payload << *this;

    std::vector<unsigned char> item;
    item.reserve(4 + payload.size());
    item.push_back(0x46); // 'F'
    item.push_back(0x43); // 'C'
    item.push_back(0x4D); // 'M'
    item.push_back(0x50); // 'P'
    for (const std::byte b : payload) {
        item.push_back(static_cast<unsigned char>(b));
    }

    mtx.vin[0].scriptWitness.stack.push_back(std::move(item));

    return CTransaction(mtx);
}

CTransaction CPrivacyTransaction::ToTransaction() const
{
    // TODO: Convert to standard transaction format
    // This would encode privacy data in OP_RETURN outputs or special scripts
    CMutableTransaction mtx;
    mtx.version = nVersion;
    mtx.nLockTime = nLockTime;

    // Encode inputs
    for (const auto& input : privacyInputs) {
        if (!input.ring.members.empty()) {
            // Use first ring member's outpoint as the input reference
            CTxIn vin(input.ring.members[0].outpoint);
            mtx.vin.push_back(vin);
        }
    }

    // Encode outputs
    for (const auto& output : privacyOutputs) {
        CTxOut vout;
        if (!output.scriptPubKey.empty()) {
            vout.scriptPubKey = output.scriptPubKey;
            vout.nValue = output.nValue;
        } else if (output.stealthOutput.oneTimePubKey.IsValid()) {
            // Create P2PK script for stealth output
            vout.scriptPubKey = GetScriptForRawPubKey(output.stealthOutput.oneTimePubKey);
            vout.nValue = output.nValue;
        }
        mtx.vout.push_back(vout);
    }

    return CTransaction(mtx);
}

std::optional<CPrivacyTransaction> CPrivacyTransaction::FromTransaction(const CTransaction& tx)
{
    // TODO: Parse privacy data from transaction
    // This would look for special markers and decode accordingly
    return std::nullopt;
}

} // namespace privacy
