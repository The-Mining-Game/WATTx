// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/privacy_wallet.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>
#include <hash.h>
#include <logging.h>
#include <script/script.h>
#include <script/solver.h>
#include <random.h>
#include <util/strencodings.h>

namespace wallet {

CPrivacyWalletManager::CPrivacyWalletManager(CWallet* wallet)
    : m_wallet(wallet)
{
}

CPrivacyWalletManager::~CPrivacyWalletManager() = default;

CPrivacyTransactionResult CPrivacyWalletManager::CreatePrivacyTransaction(
    const std::vector<std::pair<privacy::CStealthAddress, CAmount>>& recipients,
    const CPrivacyTransactionParams& params)
{
    LOCK(cs_privacy);
    CPrivacyTransactionResult result;

    if (recipients.empty()) {
        result.error = "No recipients specified";
        return result;
    }

    // Calculate total output amount
    CAmount totalOutput = 0;
    for (const auto& [addr, amount] : recipients) {
        if (!addr.IsValid()) {
            result.error = "Invalid recipient stealth address";
            return result;
        }
        if (amount <= 0) {
            result.error = "Invalid output amount";
            return result;
        }
        totalOutput += amount;
    }

    // Add fee
    CAmount totalRequired = totalOutput + params.fee;

    // Select inputs
    std::vector<CPrivacyOutputInfo> selectedInputs;
    CAmount inputTotal = 0;
    if (!SelectInputs(totalRequired, selectedInputs, inputTotal)) {
        result.error = "Insufficient privacy funds";
        return result;
    }

    if (selectedInputs.empty()) {
        result.error = "No spendable privacy outputs available";
        return result;
    }

    // Build privacy transaction
    privacy::CPrivacyTransactionBuilder builder(params.type);
    builder.SetFee(params.fee);
    builder.SetRingSize(params.ringSize);

    // Add inputs
    for (const auto& input : selectedInputs) {
        builder.AddInput(input.outpoint, input.privKey, input.amount, input.blinding);
    }

    // Add outputs
    for (const auto& [addr, amount] : recipients) {
        builder.AddOutput(addr, amount);
    }

    // Add change output if needed
    CAmount change = inputTotal - totalOutput - params.fee;
    if (change > 0) {
        // Create change output to our own stealth address
        auto* stealthMgr = m_wallet->GetStealthAddressManager();
        if (stealthMgr && stealthMgr->HasStealthAddresses()) {
            auto addresses = stealthMgr->GetStealthAddresses();
            if (!addresses.empty()) {
                builder.AddOutput(addresses[0].address, change);
            }
        } else if (!recipients.empty()) {
            // Fallback: use first recipient address (should not happen in practice)
            builder.AddOutput(recipients[0].first, change);
        }
    }

    // Build the transaction
    auto privTxOpt = builder.Build();
    if (!privTxOpt) {
        result.error = "Failed to build privacy transaction";
        return result;
    }

    result.privacyTx = *privTxOpt;

    // Convert to standard transaction
    result.standardTx = MakeTransactionRef(result.privacyTx.ToTransaction());

    // Extract key images for tracking
    for (const auto& input : result.privacyTx.privacyInputs) {
        if (input.keyImage.IsValid()) {
            result.keyImages.push_back(input.keyImage);
        }
    }

    result.success = true;
    LogPrintf("Created privacy transaction with %d inputs, %d outputs\n",
              selectedInputs.size(), recipients.size());

    return result;
}

bool CPrivacyWalletManager::CreateRingSignatureForOutput(
    const CPrivacyOutputInfo& output,
    size_t ringSize,
    privacy::CRing& ring,
    privacy::CKeyImage& keyImage)
{
    LOCK(cs_privacy);

    // Select decoys
    std::vector<privacy::CRingMember> decoys;
    if (!SelectDecoys(output.outpoint, ringSize - 1, decoys)) {
        LogPrintf("Failed to select decoys for ring signature\n");
        return false;
    }

    // Build ring with real output at random position
    ring.members.clear();

    // Add real output
    privacy::CRingMember realMember(output.outpoint, output.privKey.GetPubKey());
    ring.members.push_back(realMember);

    // Add decoys
    for (const auto& decoy : decoys) {
        ring.members.push_back(decoy);
    }

    // Shuffle ring (real is at index 0, we'll track this)
    // In production, would properly shuffle and track real index

    // Generate key image
    privacy::GenerateKeyImage(output.privKey, output.privKey.GetPubKey(), keyImage);

    return true;
}

bool CPrivacyWalletManager::SelectDecoys(
    const COutPoint& realOutput,
    size_t count,
    std::vector<privacy::CRingMember>& decoys)
{
    decoys.clear();

    // Use the global decoy provider
    auto provider = privacy::GetDecoyProvider();
    if (!provider) {
        LogPrintf("No decoy provider available\n");
        return false;
    }

    // Get random decoy candidates
    std::vector<privacy::CDecoyCandidate> candidates;
    size_t fetched = provider->GetRandomOutputs(count, 0, provider->GetHeight(), candidates);

    if (fetched < count) {
        LogPrintf("Could only fetch %d of %d requested decoys\n", fetched, count);
        // Continue with what we have if at least some were found
        if (fetched == 0) {
            return false;
        }
    }

    // Convert candidates to ring members, excluding real output
    for (const auto& candidate : candidates) {
        if (candidate.outpoint == realOutput) {
            continue;  // Skip if this is our real output
        }
        decoys.emplace_back(candidate.outpoint, candidate.pubKey);
    }

    return !decoys.empty();
}

std::vector<CPrivacyOutputInfo> CPrivacyWalletManager::GetPrivacyOutputs(bool includeSpent) const
{
    LOCK(cs_privacy);
    std::vector<CPrivacyOutputInfo> result;
    for (const auto& [outpoint, info] : m_privacyOutputs) {
        if (includeSpent || !info.spent) {
            result.push_back(info);
        }
    }
    return result;
}

std::vector<CPrivacyOutputInfo> CPrivacyWalletManager::GetSpendablePrivacyOutputs() const
{
    LOCK(cs_privacy);
    std::vector<CPrivacyOutputInfo> result;
    for (const auto& [outpoint, info] : m_privacyOutputs) {
        if (!info.spent && info.blockHeight > 0) {
            result.push_back(info);
        }
    }
    return result;
}

bool CPrivacyWalletManager::AddPrivacyOutput(const CPrivacyOutputInfo& output)
{
    LOCK(cs_privacy);

    if (m_privacyOutputs.count(output.outpoint)) {
        return false;  // Already exists
    }

    m_privacyOutputs[output.outpoint] = output;

    // Track key image
    if (!output.keyImageHash.IsNull()) {
        m_keyImages[output.keyImageHash] = output.outpoint;
    }

    // Persist immediately
    WalletBatch batch(m_wallet->GetDatabase());
    batch.WritePrivacyOutput(output.outpoint, output);
    if (!output.keyImageHash.IsNull()) {
        batch.WritePrivacyKeyImage(output.keyImageHash, output.outpoint);
    }

    LogPrintf("Added privacy output: %s:%d, amount=%d\n",
              output.outpoint.hash.ToString(), output.outpoint.n, output.amount);
    return true;
}

bool CPrivacyWalletManager::MarkPrivacyOutputSpent(const COutPoint& outpoint, const uint256& spendingTx)
{
    LOCK(cs_privacy);
    auto it = m_privacyOutputs.find(outpoint);
    if (it == m_privacyOutputs.end()) {
        return false;
    }

    it->second.spent = true;

    // Persist change
    WalletBatch batch(m_wallet->GetDatabase());
    batch.WritePrivacyOutput(outpoint, it->second);

    LogPrintf("Marked privacy output as spent: %s:%d in tx %s\n",
              outpoint.hash.ToString(), outpoint.n, spendingTx.ToString());
    return true;
}

bool CPrivacyWalletManager::IsKeyImageSpent(const privacy::CKeyImage& keyImage) const
{
    LOCK(cs_privacy);
    uint256 hash = keyImage.GetHash();
    auto it = m_keyImages.find(hash);
    if (it == m_keyImages.end()) {
        return false;
    }

    auto outputIt = m_privacyOutputs.find(it->second);
    if (outputIt == m_privacyOutputs.end()) {
        return false;
    }

    return outputIt->second.spent;
}

CAmount CPrivacyWalletManager::GetPrivacyBalance() const
{
    LOCK(cs_privacy);
    CAmount total = 0;
    for (const auto& [outpoint, info] : m_privacyOutputs) {
        if (!info.spent) {
            total += info.amount;
        }
    }
    return total;
}

CAmount CPrivacyWalletManager::GetSpendablePrivacyBalance() const
{
    LOCK(cs_privacy);
    CAmount total = 0;
    for (const auto& [outpoint, info] : m_privacyOutputs) {
        if (!info.spent && info.blockHeight > 0) {
            total += info.amount;
        }
    }
    return total;
}

bool CPrivacyWalletManager::ConvertToPrivacyOutput(
    const COutPoint& outpoint,
    const CKey& privKey,
    CAmount amount,
    CPrivacyOutputInfo& output)
{
    output.outpoint = outpoint;
    output.amount = amount;
    output.privKey = privKey;
    output.blockHeight = -1;  // Will be updated when confirmed
    output.spent = false;

    // Generate random blinding factor
    output.blinding = privacy::CBlindingFactor::Random();

    // Create commitment
    if (!privacy::CreateCommitment(amount, output.blinding, output.commitment)) {
        LogPrintf("Failed to create commitment for privacy output\n");
        return false;
    }

    // Generate key image and store hash
    privacy::CKeyImage keyImage;
    privacy::GenerateKeyImage(privKey, privKey.GetPubKey(), keyImage);
    output.keyImageHash = keyImage.GetHash();

    return true;
}

privacy::CKeyImage CPrivacyWalletManager::GenerateKeyImage(const CKey& privKey) const
{
    privacy::CKeyImage keyImage;
    privacy::GenerateKeyImage(privKey, privKey.GetPubKey(), keyImage);
    return keyImage;
}

bool CPrivacyWalletManager::Load()
{
    LOCK(cs_privacy);

    WalletBatch batch(m_wallet->GetDatabase(), false);

    // Load privacy outputs via prefix cursor
    {
        DataStream prefix;
        prefix << DBKeys::PRIVACY_OUTPUT;
        auto cursor = batch.GetBatch().GetNewPrefixCursor(prefix);
        if (cursor) {
            DataStream ssKey, ssValue;
            while (cursor->Next(ssKey, ssValue) == DatabaseCursor::Status::MORE) {
                std::string type;
                ssKey >> type;
                Txid hash;
                uint32_t n;
                ssKey >> hash;
                ssKey >> n;

                CPrivacyOutputInfo info;
                ssValue >> info;
                info.outpoint = COutPoint(hash, n);
                m_privacyOutputs[info.outpoint] = info;

                // Rebuild key image index from loaded outputs
                if (!info.keyImageHash.IsNull()) {
                    m_keyImages[info.keyImageHash] = info.outpoint;
                }
            }
        }
    }

    LogPrintf("Privacy wallet manager: loaded %d outputs, %d key images\n",
              m_privacyOutputs.size(), m_keyImages.size());
    return true;
}

bool CPrivacyWalletManager::Save()
{
    LOCK(cs_privacy);

    WalletBatch batch(m_wallet->GetDatabase());

    // Save all privacy outputs
    for (const auto& [outpoint, info] : m_privacyOutputs) {
        if (!batch.WritePrivacyOutput(outpoint, info)) {
            LogPrintf("Error: Failed to save privacy output to DB\n");
            return false;
        }
    }

    // Save key image mappings
    for (const auto& [hash, outpoint] : m_keyImages) {
        if (!batch.WritePrivacyKeyImage(hash, outpoint)) {
            LogPrintf("Error: Failed to save privacy key image to DB\n");
            return false;
        }
    }

    LogPrintf("Privacy wallet manager: saved %d outputs\n", m_privacyOutputs.size());
    return true;
}

bool CPrivacyWalletManager::SelectInputs(
    CAmount targetAmount,
    std::vector<CPrivacyOutputInfo>& selectedInputs,
    CAmount& inputTotal)
{
    LOCK(cs_privacy);
    selectedInputs.clear();
    inputTotal = 0;

    // Simple selection: use largest outputs first
    std::vector<std::pair<CAmount, COutPoint>> sortedOutputs;
    for (const auto& [outpoint, info] : m_privacyOutputs) {
        if (!info.spent && info.blockHeight > 0) {
            sortedOutputs.emplace_back(info.amount, outpoint);
        }
    }

    // Sort by amount descending
    std::sort(sortedOutputs.begin(), sortedOutputs.end(),
              [](const auto& a, const auto& b) { return a.first > b.first; });

    // Select outputs until target is met
    for (const auto& [amount, outpoint] : sortedOutputs) {
        if (inputTotal >= targetAmount) {
            break;
        }

        auto it = m_privacyOutputs.find(outpoint);
        if (it != m_privacyOutputs.end()) {
            selectedInputs.push_back(it->second);
            inputTotal += amount;
        }
    }

    return inputTotal >= targetAmount;
}

bool CPrivacyWalletManager::BuildInputRing(
    const CPrivacyOutputInfo& input,
    size_t ringSize,
    privacy::CPrivacyInput& privacyInput)
{
    // Select decoys
    std::vector<privacy::CRingMember> decoys;
    if (!SelectDecoys(input.outpoint, ringSize - 1, decoys)) {
        return false;
    }

    // Build ring
    privacyInput.ring.members.clear();

    // Add real output at position 0 (will be shuffled by signature creation)
    privacy::CRingMember realMember(input.outpoint, input.privKey.GetPubKey());
    privacyInput.ring.members.push_back(realMember);

    // Add decoys
    for (const auto& decoy : decoys) {
        privacyInput.ring.members.push_back(decoy);
    }

    // Generate key image
    privacy::GenerateKeyImage(input.privKey, input.privKey.GetPubKey(), privacyInput.keyImage);

    // Set commitment if RingCT
    privacyInput.commitment = input.commitment;

    return true;
}

//
// Helper Functions
//

CTransaction ConvertPrivacyToStandard(const privacy::CPrivacyTransaction& privTx)
{
    return privTx.ToTransaction();
}

CScript EncodePrivacyData(const privacy::CPrivacyTransaction& privTx)
{
    // Create OP_RETURN with privacy prefix and serialized data
    std::vector<unsigned char> data;

    // Privacy prefix: "WTXP"
    data.push_back('W');
    data.push_back('T');
    data.push_back('X');
    data.push_back('P');

    // Serialize privacy transaction
    DataStream ss;
    ss << privTx;

    // Append serialized data (convert std::byte to unsigned char)
    for (auto b : ss) {
        data.push_back(static_cast<unsigned char>(b));
    }

    // Create OP_RETURN script
    CScript script;
    script << OP_RETURN << data;

    return script;
}

} // namespace wallet
