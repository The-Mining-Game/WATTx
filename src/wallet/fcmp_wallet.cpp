// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/fcmp_wallet.h>
#include <wallet/coincontrol.h>
#include <wallet/receive.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>
#include <privacy/fcmp/fcmp_wrapper.h>
#include <privacy/ed25519/pedersen.h>
#include <privacy/stealth.h>
#include <hash.h>
#include <logging.h>
#include <script/script.h>
#include <util/moneystr.h>
#include <util/time.h>

#include <algorithm>

namespace wallet {

// ============================================================================
// Constructor / Destructor
// ============================================================================

CFcmpWalletManager::CFcmpWalletManager(CWallet* wallet)
    : m_wallet(wallet)
{
    // Curve tree will be set separately during initialization
}

CFcmpWalletManager::~CFcmpWalletManager() = default;

// ============================================================================
// Transaction Creation
// ============================================================================

CFcmpTransactionResult CFcmpWalletManager::CreateFcmpTransaction(
    const std::vector<CFcmpRecipient>& recipients,
    const CFcmpTransactionParams& params)
{
    CFcmpTransactionResult result;
    result.success = false;

    LOCK(cs_fcmp);

    // Validate recipients
    if (recipients.empty()) {
        result.error = "No recipients specified";
        return result;
    }

    // Calculate total output amount
    CAmount totalOutput = 0;
    for (const auto& recipient : recipients) {
        if (recipient.amount <= 0) {
            result.error = "Invalid recipient amount";
            return result;
        }
        totalOutput += recipient.amount;
    }

    // Estimate fee if not fixed
    CAmount fee = params.fixedFee;
    if (fee == 0) {
        // Estimate based on typical FCMP transaction size
        fee = EstimateFee(2, recipients.size() + 1, params.feeRate);
    }

    // Calculate target amount
    CAmount targetAmount = totalOutput + fee;
    if (params.subtractFeeFromAmount && recipients.size() == 1) {
        targetAmount = totalOutput;
    }

    // Select inputs
    std::vector<CFcmpOutputInfo> selectedInputs;
    CAmount inputTotal = 0;
    if (!SelectInputs(targetAmount, selectedInputs, inputTotal, params.minConfirmations)) {
        result.error = "Insufficient FCMP funds";
        return result;
    }

    // Verify we have enough
    if (inputTotal < targetAmount) {
        result.error = "Selected inputs insufficient for amount + fee";
        return result;
    }

    // Adjust fee if subtracting from amount
    if (params.subtractFeeFromAmount && recipients.size() == 1) {
        // Don't change - fee comes from output
    }

    // Compute message hash for signatures
    uint256 messageHash = ComputeMessageHash(selectedInputs, recipients, fee);

    // Check we have a curve tree
    if (!m_curveTree) {
        result.error = "Curve tree not initialized";
        return result;
    }

    // Build privacy transaction
    result.privacyTx.privacyType = privacy::PrivacyType::FCMP;
    result.privacyTx.nFee = fee;
    result.fee = fee;

    // Build FCMP inputs
    for (const auto& input : selectedInputs) {
        auto fcmpInput = BuildFcmpInput(input, messageHash);
        if (!fcmpInput) {
            result.error = "Failed to build FCMP input";
            return result;
        }

        result.privacyTx.fcmpInputs.push_back(*fcmpInput);
        result.keyImages.push_back(fcmpInput->keyImage);
    }

    // Build outputs
    CAmount changeAmount = inputTotal - totalOutput - fee;

    for (size_t i = 0; i < recipients.size(); ++i) {
        const auto& recipient = recipients[i];
        CAmount outputAmount = recipient.amount;

        // Subtract fee from first output if requested
        if (params.subtractFeeFromAmount && i == 0) {
            outputAmount -= fee;
            if (outputAmount <= 0) {
                result.error = "Amount too small after fee subtraction";
                return result;
            }
        }

        // Create output
        privacy::CPrivacyOutput privOutput;

        if (recipient.IsStealthRecipient()) {
            // Full privacy: stealth address output with hidden amount
            CKey ephemeralKey;
            ephemeralKey.MakeNewKey(true);
            privacy::GenerateStealthDestination(
                recipient.stealthAddress,
                ephemeralKey,
                privOutput.stealthOutput
            );

            // Create commitment for confidential amount
            ed25519::Scalar blinding = ed25519::Scalar::Random();
            auto commitment = ed25519::PedersenCommitment::CommitAmount(
                static_cast<uint64_t>(outputAmount),
                blinding
            );

            privOutput.confidentialOutput.commitment.data.resize(33);
            privOutput.confidentialOutput.commitment.data[0] = 0x02;
            std::memcpy(
                privOutput.confidentialOutput.commitment.data.data() + 1,
                commitment.GetPoint().data.data(),
                32
            );
        } else {
            // Deshielding: regular script output (sender privacy preserved,
            // recipient receives to a standard address with visible amount)
            privOutput.scriptPubKey = recipient.scriptPubKey;
        }

        privOutput.nValue = outputAmount;
        result.privacyTx.privacyOutputs.push_back(privOutput);
    }

    // Add change output if needed
    if (changeAmount > 0) {
        // Get our own stealth address for change
        auto* stealthMgr = m_wallet->GetStealthAddressManager();
        privacy::CStealthAddress changeAddr;
        bool haveChangeAddr = false;

        if (stealthMgr && stealthMgr->HasStealthAddresses()) {
            auto addresses = stealthMgr->GetStealthAddresses();
            if (!addresses.empty()) {
                changeAddr = addresses[0].address;
                haveChangeAddr = true;
            }
        }

        // Generate stealth destination for change
        privacy::CPrivacyOutput changeOutput;
        ed25519::Scalar changeBlinding = ed25519::Scalar::Random();

        if (haveChangeAddr) {
            CKey changeEphemeral;
            changeEphemeral.MakeNewKey(true);
            privacy::GenerateStealthDestination(
                changeAddr,
                changeEphemeral,
                changeOutput.stealthOutput
            );
        }

        auto changeCommitment = ed25519::PedersenCommitment::CommitAmount(
            static_cast<uint64_t>(changeAmount),
            changeBlinding
        );

        changeOutput.confidentialOutput.commitment.data.resize(33);
        changeOutput.confidentialOutput.commitment.data[0] = 0x02;
        std::memcpy(
            changeOutput.confidentialOutput.commitment.data.data() + 1,
            changeCommitment.GetPoint().data.data(),
            32
        );
        changeOutput.nValue = changeAmount;

        result.privacyTx.privacyOutputs.push_back(changeOutput);

        // Track change output as our own FCMP output
        if (haveChangeAddr) {
            CFcmpOutputInfo changeInfo;
            changeInfo.amount = changeAmount;
            changeInfo.blinding = changeBlinding;
            changeInfo.blockHeight = -1;
            changeInfo.spent = false;
            changeInfo.nTime = GetTime();

            // Derive key for change using stealth protocol
            std::optional<ed25519::Scalar> changePk;
            changeInfo.outputTuple = CreateOutputTuple(changeAddr, changeAmount, changeInfo.blinding, changePk);
            if (changePk) {
                changeInfo.privKey = *changePk;
            }

            auto changeKI = GenerateKeyImage(changeInfo.privKey, changeInfo.outputTuple.O);
            changeInfo.keyImageHash = changeKI.GetHash();
            // Store in result - caller adds to wallet after tx commit
            result.changeOutputInfo = changeInfo;
        }
    }

    // Self-verify the transaction (SA+L signature, balance)
    // Note: FCMP proof FFI verification is skipped during creation as the proof
    // will be validated by consensus when the transaction is included in a block.
    // The SA+L signature and commitment balance are verified here.
    if (!result.privacyTx.VerifyFcmpSelfCheck()) {
        result.error = "Transaction self-check failed";
        return result;
    }

    // Convert to standard transaction for broadcast
    result.standardTx = MakeTransactionRef(result.privacyTx.ToTransaction());

    result.success = true;
    return result;
}

CAmount CFcmpWalletManager::EstimateFee(
    size_t numInputs,
    size_t numOutputs,
    const CFeeRate& feeRate) const
{
    // FCMP proof is approximately:
    // - Per input: ~2KB (membership proof + SA+L signature)
    // - Per output: ~100 bytes (commitment + encrypted data)
    // - Base overhead: ~100 bytes

    size_t estimatedSize = 100 +
                          numInputs * 2048 +
                          numOutputs * 100;

    return feeRate.GetFee(estimatedSize);
}

// ============================================================================
// Auto-Shielding
// ============================================================================

void CFcmpWalletManager::AutoShield()
{
    // Minimum transparent balance to trigger auto-shield (1 WATTx)
    static constexpr CAmount AUTO_SHIELD_MIN = 100000000;

    LOCK(cs_fcmp);

    // Skip if already shielding
    if (m_autoShieldPending) return;

    // Skip during IBD
    if (m_wallet->chain().isInitialBlockDownload()) return;

    // Skip if wallet is locked
    if (m_wallet->IsLocked()) return;

    // Check transparent balance
    Balance bal = GetBalance(*m_wallet, /*min_depth=*/1);
    CAmount transparentBalance = bal.m_mine_trusted;

    if (transparentBalance < AUTO_SHIELD_MIN) return;

    // Get or generate a stealth address for shielding
    auto* stealthMgr = m_wallet->GetStealthAddressManager();
    if (!stealthMgr) return;

    privacy::CStealthAddress shieldAddr;
    if (stealthMgr->HasStealthAddresses()) {
        auto addresses = stealthMgr->GetStealthAddresses();
        if (!addresses.empty()) {
            shieldAddr = addresses[0].address;
        }
    }

    if (!shieldAddr.IsValid()) {
        CStealthAddressData newAddr;
        if (!stealthMgr->GenerateStealthAddress("auto_shield", newAddr)) return;
        shieldAddr = newAddr.address;
    }

    m_autoShieldPending = true;

    // Create shield template to get the OP_RETURN script and cryptographic material
    auto result = CreateShieldTransaction(shieldAddr, transparentBalance - 1000, /*minConfirmations=*/1);

    if (result.success) {
        // Extract OP_RETURN script from template
        CScript opReturnScript;
        for (const auto& txout : result.standardTx->vout) {
            if (txout.scriptPubKey.size() > 0 && txout.scriptPubKey[0] == OP_RETURN) {
                opReturnScript = txout.scriptPubKey;
                break;
            }
        }

        if (!opReturnScript.empty()) {
            // Build a proper transaction with inputs via wallet coin selection
            CRecipient opReturnRecipient{CNoDestination{opReturnScript}, 0, false};

            // Get a wallet address for the shielded value output
            auto destResult = m_wallet->GetNewDestination(OutputType::BECH32, "auto_shield");
            if (destResult) {
                CRecipient shieldRecipient{*destResult, transparentBalance - 1000, true /* subtract fee */};

                std::vector<CRecipient> recipients;
                recipients.push_back(shieldRecipient);
                recipients.push_back(opReturnRecipient);

                CCoinControl coinControl;
                coinControl.m_min_depth = 1;

                auto txResult = CreateTransaction(*m_wallet, recipients, std::nullopt, coinControl, true);

                if (txResult) {
                    // Commit the properly-formed transaction
                    mapValue_t mapValue;
                    mapValue["comment"] = "Auto-shield to FCMP";
                    m_wallet->CommitTransaction(txResult->tx, std::move(mapValue), {});

                    // Register the FCMP output with the correct txid and output index
                    if (result.hasPrivKey) {
                        // Find the OP_RETURN output index in the committed TX
                        int opReturnVout = -1;
                        for (size_t vi = 0; vi < txResult->tx->vout.size(); vi++) {
                            if (txResult->tx->vout[vi].scriptPubKey.size() > 0 &&
                                txResult->tx->vout[vi].scriptPubKey[0] == OP_RETURN) {
                                opReturnVout = vi;
                                break;
                            }
                        }

                        CFcmpOutputInfo outputInfo;
                        outputInfo.outpoint = COutPoint(txResult->tx->GetHash(), opReturnVout >= 0 ? opReturnVout : 0);
                        outputInfo.amount = transparentBalance - 1000 - txResult->fee;
                        outputInfo.privKey = result.privKey;
                        outputInfo.blinding = result.blinding;
                        outputInfo.outputTuple = result.outputTuple;
                        outputInfo.keyImageHash = result.keyImageHash;
                        outputInfo.blockHeight = -1;
                        outputInfo.spent = false;
                        outputInfo.nTime = GetTime();
                        AddFcmpOutput(outputInfo);
                    }

                    LogPrintf("Auto-shield: %s WATTx shielded to FCMP (txid=%s)\n",
                              FormatMoney(transparentBalance - 1000), txResult->tx->GetHash().GetHex());
                } else {
                    LogPrintf("Auto-shield: Failed to create transaction: %s\n",
                              util::ErrorString(txResult).original);
                }
            }
        }
    }

    m_autoShieldPending = false;
}

CFcmpShieldResult CFcmpWalletManager::CreateShieldTransaction(
    const privacy::CStealthAddress& recipient,
    CAmount amount,
    int minConfirmations)
{
    CFcmpShieldResult result;
    result.success = false;

    LOCK(cs_fcmp);

    if (amount <= 0) {
        result.error = "Invalid amount";
        return result;
    }

    // Estimate fee for shielding transaction
    // Shield txs are simpler: transparent inputs -> FCMP output in OP_RETURN
    CAmount fee = 1000; // 0.00001 WATTx minimum fee

    // Create a standard transaction that:
    // 1. Spends transparent inputs
    // 2. Has an OP_RETURN output with FCMP output data (O, I, C)
    // 3. May have change output back to wallet

    // Generate output tuple for curve tree
    ed25519::Scalar blinding = ed25519::Scalar::Random();
    std::optional<ed25519::Scalar> privKey;
    curvetree::OutputTuple outputTuple = CreateOutputTuple(recipient, amount, blinding, privKey);

    // Create the OP_RETURN script with FCMP output marker
    // Format: OP_RETURN <FCMP_MARKER> <O:32> <I:32> <C:32>
    CScript opReturnScript;
    opReturnScript << OP_RETURN;

    std::vector<uint8_t> fcmpData;
    fcmpData.reserve(4 + 96); // marker + 3 points

    // FCMP marker "FCMP"
    fcmpData.push_back(0x46); // 'F'
    fcmpData.push_back(0x43); // 'C'
    fcmpData.push_back(0x4D); // 'M'
    fcmpData.push_back(0x50); // 'P'

    // Add O, I, C points
    fcmpData.insert(fcmpData.end(), outputTuple.O.data.begin(), outputTuple.O.data.end());
    fcmpData.insert(fcmpData.end(), outputTuple.I.data.begin(), outputTuple.I.data.end());
    fcmpData.insert(fcmpData.end(), outputTuple.C.data.begin(), outputTuple.C.data.end());

    opReturnScript << fcmpData;

    // Build the transaction
    CMutableTransaction mtx;
    mtx.version = 2;

    // Add OP_RETURN output (FCMP data)
    mtx.vout.push_back(CTxOut(0, opReturnScript));

    // The wallet will add inputs and change output
    // For now, return a template that the wallet can complete

    result.standardTx = MakeTransactionRef(std::move(mtx));
    result.fee = fee;

    // Store output info in result for caller to persist after TX confirmation
    result.outputTuple = outputTuple;
    result.blinding = blinding;

    if (privKey) {
        result.hasPrivKey = true;
        result.privKey = *privKey;

        auto keyImage = GenerateKeyImage(*privKey, outputTuple.O);
        result.keyImageHash = keyImage.GetHash();

        if (m_curveTree) {
            result.leafIndex = m_curveTree->GetOutputCount();
        }
    }

    result.success = true;
    return result;
}

// ============================================================================
// Output Management
// ============================================================================

std::vector<CFcmpOutputInfo> CFcmpWalletManager::GetFcmpOutputs(bool includeSpent) const
{
    LOCK(cs_fcmp);

    std::vector<CFcmpOutputInfo> outputs;
    outputs.reserve(m_fcmpOutputs.size());

    for (const auto& [outpoint, info] : m_fcmpOutputs) {
        if (includeSpent || !info.spent) {
            outputs.push_back(info);
        }
    }

    return outputs;
}

std::vector<CFcmpOutputInfo> CFcmpWalletManager::GetSpendableFcmpOutputs(int minConfirmations) const
{
    LOCK(cs_fcmp);

    int currentHeight = GetCurrentHeight();
    std::vector<CFcmpOutputInfo> outputs;

    for (const auto& [outpoint, info] : m_fcmpOutputs) {
        if (info.IsSpendable(currentHeight, minConfirmations)) {
            outputs.push_back(info);
        }
    }

    // Sort by amount (largest first for efficient selection)
    std::sort(outputs.begin(), outputs.end(),
        [](const CFcmpOutputInfo& a, const CFcmpOutputInfo& b) {
            return a.amount > b.amount;
        });

    return outputs;
}

bool CFcmpWalletManager::UpdateFcmpOutputBlockHeight(const COutPoint& outpoint, int blockHeight)
{
    LOCK(cs_fcmp);

    auto it = m_fcmpOutputs.find(outpoint);
    if (it == m_fcmpOutputs.end()) {
        return false;
    }

    if (it->second.blockHeight != blockHeight) {
        it->second.blockHeight = blockHeight;
        WalletBatch batch(m_wallet->GetDatabase());
        batch.WriteFcmpOutput(outpoint, it->second);
        LogPrintf("FCMP: Updated output %s blockHeight to %d\n", outpoint.ToString(), blockHeight);
    }
    return true;
}

bool CFcmpWalletManager::AddFcmpOutput(const CFcmpOutputInfo& output)
{
    LOCK(cs_fcmp);

    if (m_fcmpOutputs.count(output.outpoint)) {
        return false; // Already exists
    }

    m_fcmpOutputs[output.outpoint] = output;

    // Track key image
    if (!output.keyImageHash.IsNull()) {
        m_keyImages[output.keyImageHash] = output.outpoint;
    }

    // Persist immediately
    WalletBatch batch(m_wallet->GetDatabase());
    batch.WriteFcmpOutput(output.outpoint, output);
    if (!output.keyImageHash.IsNull()) {
        batch.WriteFcmpKeyImage(output.keyImageHash, output.outpoint);
    }

    LogPrintf("FCMP: Added output %s: %d satoshis at leaf %lu\n",
              output.outpoint.ToString(), output.amount, output.treeLeafIndex);

    return true;
}

bool CFcmpWalletManager::MarkFcmpOutputSpent(const COutPoint& outpoint, const uint256& spendingTxHash)
{
    LOCK(cs_fcmp);

    auto it = m_fcmpOutputs.find(outpoint);
    if (it == m_fcmpOutputs.end()) {
        return false;
    }

    it->second.spent = true;

    // Track the spending
    if (!it->second.keyImageHash.IsNull()) {
        m_spentKeyImages[it->second.keyImageHash] = spendingTxHash;
    }

    // Persist changes
    WalletBatch batch(m_wallet->GetDatabase());
    batch.WriteFcmpOutput(outpoint, it->second);
    if (!it->second.keyImageHash.IsNull()) {
        batch.WriteFcmpSpentKeyImage(it->second.keyImageHash, spendingTxHash);
    }

    LogPrintf("FCMP: Marked output %s as spent in tx %s\n",
              outpoint.ToString(), spendingTxHash.ToString());

    return true;
}

bool CFcmpWalletManager::HaveFcmpOutput(const COutPoint& outpoint) const
{
    LOCK(cs_fcmp);
    return m_fcmpOutputs.count(outpoint) > 0;
}

std::optional<CFcmpOutputInfo> CFcmpWalletManager::GetFcmpOutput(const COutPoint& outpoint) const
{
    LOCK(cs_fcmp);

    auto it = m_fcmpOutputs.find(outpoint);
    if (it == m_fcmpOutputs.end()) {
        return std::nullopt;
    }

    return it->second;
}

// ============================================================================
// Key Image Management
// ============================================================================

bool CFcmpWalletManager::IsKeyImageSpent(const privacy::CKeyImage& keyImage) const
{
    LOCK(cs_fcmp);

    uint256 hash = keyImage.GetHash();
    return m_spentKeyImages.count(hash) > 0;
}

privacy::CKeyImage CFcmpWalletManager::GenerateKeyImage(
    const ed25519::Scalar& privKey,
    const ed25519::Point& outputPoint) const
{
    // Compute Hp(O) - hash of output to point
    std::vector<uint8_t> toHash(outputPoint.data.begin(), outputPoint.data.end());
    auto Hp = ed25519::Point::HashToPoint(toHash);

    // Key image I = x * Hp(O)
    auto I = privKey * Hp;

    // Convert to CKeyImage format
    privacy::CKeyImage keyImage;
    keyImage.data.resize(33);
    keyImage.data[0] = 0x02; // Ed25519 prefix
    std::memcpy(keyImage.data.data() + 1, I.data.data(), 32);

    return keyImage;
}

// ============================================================================
// Balance Queries
// ============================================================================

CAmount CFcmpWalletManager::GetFcmpBalance() const
{
    LOCK(cs_fcmp);

    CAmount total = 0;
    for (const auto& [outpoint, info] : m_fcmpOutputs) {
        if (!info.spent) {
            total += info.amount;
        }
    }

    return total;
}

CAmount CFcmpWalletManager::GetSpendableFcmpBalance(int minConfirmations) const
{
    LOCK(cs_fcmp);

    int currentHeight = GetCurrentHeight();
    CAmount total = 0;

    for (const auto& [outpoint, info] : m_fcmpOutputs) {
        if (info.IsSpendable(currentHeight, minConfirmations)) {
            total += info.amount;
        }
    }

    return total;
}

CAmount CFcmpWalletManager::GetPendingFcmpBalance() const
{
    LOCK(cs_fcmp);

    CAmount total = 0;
    for (const auto& [outpoint, info] : m_fcmpOutputs) {
        if (!info.spent && info.blockHeight < 0) {
            total += info.amount;
        }
    }

    return total;
}

// ============================================================================
// Curve Tree Access
// ============================================================================

std::shared_ptr<curvetree::CurveTree> CFcmpWalletManager::GetCurveTree() const
{
    LOCK(cs_fcmp);
    return m_curveTree;
}

void CFcmpWalletManager::SetCurveTree(std::shared_ptr<curvetree::CurveTree> tree)
{
    LOCK(cs_fcmp);
    m_curveTree = std::move(tree);
}

ed25519::Point CFcmpWalletManager::GetTreeRoot() const
{
    LOCK(cs_fcmp);

    if (!m_curveTree) {
        return ed25519::Point::Identity();
    }

    return m_curveTree->GetRoot();
}

// ============================================================================
// Transaction Scanning
// ============================================================================

int CFcmpWalletManager::ScanTransactionForFcmpOutputs(
    const CTransaction& tx,
    int blockHeight)
{
    LOCK(cs_fcmp);

    int found = 0;
    uint256 txid = tx.GetHash();

    // Check if this is a coinbase/coinstake transaction (for maturity tracking)
    bool isCoinbaseTx = tx.IsCoinBase() || tx.IsCoinStake();

    // Get the stealth address manager to check ownership
    auto* stealthMgr = m_wallet->GetStealthAddressManager();
    if (!stealthMgr || !stealthMgr->HasStealthAddresses()) {
        return 0;
    }

    auto stealthAddresses = stealthMgr->GetStealthAddresses();

    // Look for OP_RETURN outputs with "FCMP" marker containing (O, I, C) tuples
    for (uint32_t i = 0; i < tx.vout.size(); i++) {
        const CTxOut& txout = tx.vout[i];
        if (!txout.scriptPubKey.IsUnspendable()) continue;

        // Parse OP_RETURN data
        CScript::const_iterator it = txout.scriptPubKey.begin();
        opcodetype opcode;
        std::vector<unsigned char> data;

        if (!txout.scriptPubKey.GetOp(it, opcode) || opcode != OP_RETURN) continue;
        if (!txout.scriptPubKey.GetOp(it, opcode, data)) continue;

        // Check for "FCMP" marker (4 bytes) + O(32) + I(32) + C(32) = 100 bytes minimum
        if (data.size() < 100) continue;
        if (data[0] != 'F' || data[1] != 'C' || data[2] != 'M' || data[3] != 'P') continue;

        LogDebug(BCLog::PRIVACY, "FCMP scan: found FCMP marker in tx %s vout %d (data size=%zu, isCoinbase=%s)\n",
                  txid.ToString().substr(0,8), i, data.size(), isCoinbaseTx ? "true" : "false");

        // Extract O, I, C points
        ed25519::Point O, I, C;
        std::memcpy(O.data.data(), data.data() + 4, 32);
        std::memcpy(I.data.data(), data.data() + 36, 32);
        std::memcpy(C.data.data(), data.data() + 68, 32);

        // Check if ephemeral key R is appended (for stealth detection)
        CPubKey ephemeralPubKey;
        if (data.size() >= 133) {
            // R is a 33-byte compressed pubkey after O,I,C
            std::vector<unsigned char> rData(data.begin() + 100, data.begin() + 133);
            CPubKey candidate(rData);
            if (candidate.IsFullyValid()) {
                ephemeralPubKey = candidate;
            }
        }

        // Try to detect ownership via stealth address scanning
        if (!ephemeralPubKey.IsValid()) {
            continue;
        }

        LogDebug(BCLog::PRIVACY, "FCMP scan: checking %zu stealth addresses for ownership of tx %s vout %d\n",
                  stealthAddresses.size(), txid.ToString().substr(0,8), i);

        for (const auto& addrData : stealthAddresses) {
            // For FCMP outputs, bypass ScanStealthOutput (which checks view tags)
            // and use DeriveStealthSpendingKey directly. The OP_RETURN format
            // doesn't include view tags, so we verify ownership by checking that
            // the derived key produces the correct O point.
            CKey derivedKey;
            bool deriveResult = privacy::DeriveStealthSpendingKey(
                addrData.scanPrivKey, addrData.spendPrivKey,
                ephemeralPubKey, i, derivedKey);

            if (!deriveResult || !derivedKey.IsValid()) {
                continue;
            }

            // Verify the derived key matches the O point in the OP_RETURN
            // O = Hash(oneTimePubKey) * G where oneTimePubKey = derivedKey.GetPubKey()
            CPubKey oneTimePubKey = derivedKey.GetPubKey();
            std::vector<uint8_t> verifyPubKeyBytes(oneTimePubKey.begin(), oneTimePubKey.end());
            uint256 verifyKeyHash = Hash(verifyPubKeyBytes);
            ed25519::Scalar verifyScalar = ed25519::Scalar::FromBytesModOrder(
                std::vector<uint8_t>(verifyKeyHash.begin(), verifyKeyHash.end()));
            ed25519::Point verifyO = verifyScalar * ed25519::Point::BasePoint();

            bool scanResult = (verifyO == O);
            LogDebug(BCLog::PRIVACY, "FCMP scan: O point match=%s for tx %s vout %d\n",
                      scanResult ? "yes" : "no", txid.ToString().substr(0,8), i);
            if (scanResult) {
                // We own this output! Create FCMP output record
                CFcmpOutputInfo outputInfo;
                outputInfo.outpoint = COutPoint(Txid::FromUint256(txid), i);
                outputInfo.amount = txout.nValue; // For shielding txs, amount is in the transparent input
                outputInfo.outputTuple.O = O;
                outputInfo.outputTuple.I = I;
                outputInfo.outputTuple.C = C;
                outputInfo.blockHeight = blockHeight;
                outputInfo.spent = false;
                outputInfo.isCoinbaseOutput = isCoinbaseTx;
                outputInfo.nTime = GetTime();

                // Derive Ed25519 private key from the one-time public key
                // This MUST match the miner's derivation in CreateFcmpRewardOutput:
                //   O = Hash(oneTimePubKey) * G
                // The scanner derives the spending key, then gets the public key from it
                // to use the same hash input as the miner.
                CPubKey oneTimePubKey = derivedKey.GetPubKey();
                std::vector<uint8_t> pubKeyBytes(oneTimePubKey.begin(), oneTimePubKey.end());
                uint256 keyHash = Hash(pubKeyBytes);
                outputInfo.privKey = ed25519::Scalar::FromBytesModOrder(
                    std::vector<uint8_t>(keyHash.begin(), keyHash.end()));

                // Derive blinding factor deterministically from the one-time public key
                // This MUST match the miner's derivation in CreateFcmpRewardOutput
                std::vector<uint8_t> blindingInput(pubKeyBytes.begin(), pubKeyBytes.end());
                blindingInput.push_back(0x42); // domain separator for blinding derivation
                uint256 blindingHash = Hash(blindingInput);
                outputInfo.blinding = ed25519::Scalar::FromBytesModOrder(
                    std::vector<uint8_t>(blindingHash.begin(), blindingHash.end()));

                // Compute key image hash
                auto keyImage = GenerateKeyImage(outputInfo.privKey, O);
                outputInfo.keyImageHash = keyImage.GetHash();

                // Assign tree leaf index
                if (m_curveTree) {
                    outputInfo.treeLeafIndex = m_curveTree->GetOutputCount();
                }

                // Add to tracked outputs
                if (AddFcmpOutput(outputInfo)) {
                    // Persist immediately
                    WalletBatch batch(m_wallet->GetDatabase());
                    batch.WriteFcmpOutput(outputInfo.outpoint, outputInfo);
                    batch.WriteFcmpKeyImage(outputInfo.keyImageHash, outputInfo.outpoint);
                    found++;
                }

                break; // One match per OP_RETURN
            }
        }
    }

    return found;
}

int CFcmpWalletManager::ScanBlockForFcmpOutputs(
    const CBlock& block,
    int blockHeight)
{
    LOCK(cs_fcmp);

    // Update blockHeight for any outputs we already track that are in this block
    for (const auto& tx : block.vtx) {
        uint256 txid = tx->GetHash();
        for (auto& [outpoint, info] : m_fcmpOutputs) {
            if (outpoint.hash == txid && info.blockHeight < 0) {
                info.blockHeight = blockHeight;
                WalletBatch batch(m_wallet->GetDatabase());
                batch.WriteFcmpOutput(outpoint, info);
                LogPrintf("FCMP: Confirmed output %s at height %d\n", outpoint.ToString(), blockHeight);
            }
        }
    }

    int found = 0;
    for (const auto& tx : block.vtx) {
        found += ScanTransactionForFcmpOutputs(*tx, blockHeight);
    }
    return found;
}

// ============================================================================
// Persistence
// ============================================================================

bool CFcmpWalletManager::Load()
{
    LOCK(cs_fcmp);

    WalletBatch batch(m_wallet->GetDatabase(), false);

    // Load FCMP outputs via prefix cursor
    {
        DataStream prefix;
        prefix << DBKeys::FCMP_OUTPUT;
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

                CFcmpOutputInfo info;
                ssValue >> info;
                info.outpoint = COutPoint(hash, n);
                m_fcmpOutputs[info.outpoint] = info;

                // Rebuild key image index
                if (!info.keyImageHash.IsNull()) {
                    m_keyImages[info.keyImageHash] = info.outpoint;
                }
            }
        }
    }

    // Load spent key images
    {
        DataStream prefix;
        prefix << DBKeys::FCMP_SPENT_KI;
        auto cursor = batch.GetBatch().GetNewPrefixCursor(prefix);
        if (cursor) {
            DataStream ssKey, ssValue;
            while (cursor->Next(ssKey, ssValue) == DatabaseCursor::Status::MORE) {
                std::string type;
                ssKey >> type;
                uint256 kiHash;
                ssKey >> kiHash;

                uint256 txHash;
                ssValue >> txHash;
                m_spentKeyImages[kiHash] = txHash;
            }
        }
    }

    LogPrintf("FCMP wallet manager: loaded %d outputs, %d spent key images\n",
              m_fcmpOutputs.size(), m_spentKeyImages.size());
    return true;
}

bool CFcmpWalletManager::Save()
{
    LOCK(cs_fcmp);

    WalletBatch batch(m_wallet->GetDatabase());

    // Save all FCMP outputs
    for (const auto& [outpoint, info] : m_fcmpOutputs) {
        if (!batch.WriteFcmpOutput(outpoint, info)) {
            LogPrintf("Error: Failed to save FCMP output to DB\n");
            return false;
        }
    }

    // Save key image mappings
    for (const auto& [hash, outpoint] : m_keyImages) {
        if (!batch.WriteFcmpKeyImage(hash, outpoint)) {
            LogPrintf("Error: Failed to save FCMP key image to DB\n");
            return false;
        }
    }

    // Save spent key images
    for (const auto& [hash, txHash] : m_spentKeyImages) {
        if (!batch.WriteFcmpSpentKeyImage(hash, txHash)) {
            LogPrintf("Error: Failed to save FCMP spent key image to DB\n");
            return false;
        }
    }

    LogPrintf("FCMP wallet manager: saved %d outputs\n", m_fcmpOutputs.size());
    return true;
}

// ============================================================================
// Utility
// ============================================================================

int CFcmpWalletManager::GetCurrentHeight() const
{
    if (!m_wallet) return 0;

    LOCK(m_wallet->cs_wallet);
    return m_wallet->GetLastBlockHeight();
}

curvetree::OutputTuple CFcmpWalletManager::CreateOutputTuple(
    const privacy::CStealthAddress& stealthAddr,
    CAmount amount,
    ed25519::Scalar& blinding,
    std::optional<ed25519::Scalar>& privKey) const
{
    curvetree::OutputTuple tuple;

    // Generate ephemeral key for DKSAP
    CKey ephemeralKey;
    ephemeralKey.MakeNewKey(true);

    // Generate stealth destination using DKSAP protocol
    privacy::CStealthOutput stealthOut;
    if (!privacy::GenerateStealthDestination(stealthAddr, ephemeralKey, stealthOut)) {
        // Fallback: use random key if stealth derivation fails
        LogPrintf("FCMP CreateOutputTuple: GenerateStealthDestination FAILED - using random key (output will NOT be spendable!)\n");
        auto kp = ed25519::KeyPair::Generate();
        tuple.O = kp.public_key;
        privKey = std::nullopt;
    } else {
        // Default: derive O from the stealth output public key (non-owned case)
        std::vector<uint8_t> pubKeyBytes(stealthOut.oneTimePubKey.begin(), stealthOut.oneTimePubKey.end());
        uint256 keyHash = Hash(pubKeyBytes);
        ed25519::Scalar outputScalar = ed25519::Scalar::FromBytesModOrder(
            std::vector<uint8_t>(keyHash.begin(), keyHash.end()));
        tuple.O = outputScalar * ed25519::Point::BasePoint();

        // Check if we own this stealth address to store private key
        auto* stealthMgr = m_wallet->GetStealthAddressManager();
        if (stealthMgr) {
            auto stealthAddresses = stealthMgr->GetStealthAddresses();
            for (const auto& addrData : stealthAddresses) {
                if (addrData.address.scanPubKey == stealthAddr.scanPubKey &&
                    addrData.address.spendPubKey == stealthAddr.spendPubKey) {
                    // We own this address - derive spending key to verify ownership
                    CKey derivedKey;
                    if (privacy::DeriveStealthSpendingKey(addrData.scanPrivKey, addrData.spendPrivKey,
                                                          ephemeralKey.GetPubKey(), 0, derivedKey)) {
                        // Derive privKey from the one-time public key (same as miner derivation)
                        // This ensures privKey * G == O (the outputScalar computed above)
                        // Both sides hash the same oneTimePubKey bytes to produce the same scalar.
                        privKey = outputScalar;
                        LogPrintf("FCMP CreateOutputTuple: derived spending key, O = privKey*G\n");
                    } else {
                        LogPrintf("FCMP CreateOutputTuple: DeriveStealthSpendingKey FAILED\n");
                    }
                    break;
                }
            }
        }
    }

    // I = Hp(O) - key image point
    std::vector<uint8_t> toHash(tuple.O.data.begin(), tuple.O.data.end());
    tuple.I = ed25519::Point::HashToPoint(toHash);

    // C = amount*H + blinding*G (Pedersen commitment)
    // Derive blinding deterministically from the one-time public key
    // This MUST match the derivation in CreateFcmpRewardOutput (miner) and
    // ScanTransactionForFcmpOutputs (scanner) so all three agree on C.
    if (!stealthOut.oneTimePubKey.IsValid()) {
        // Fallback if no valid stealth output
        blinding = ed25519::Scalar::Random();
    } else {
        std::vector<uint8_t> blindingInput(stealthOut.oneTimePubKey.begin(), stealthOut.oneTimePubKey.end());
        blindingInput.push_back(0x42); // domain separator for blinding derivation
        uint256 blindingHash = Hash(blindingInput);
        blinding = ed25519::Scalar::FromBytesModOrder(
            std::vector<uint8_t>(blindingHash.begin(), blindingHash.end()));
    }
    auto commitment = ed25519::PedersenCommitment::CommitAmount(
        static_cast<uint64_t>(amount),
        blinding
    );
    tuple.C = commitment.GetPoint();

    return tuple;
}

// ============================================================================
// Private Methods
// ============================================================================

bool CFcmpWalletManager::SelectInputs(
    CAmount targetAmount,
    std::vector<CFcmpOutputInfo>& selectedInputs,
    CAmount& inputTotal,
    int minConfirmations)
{
    AssertLockHeld(cs_fcmp);

    selectedInputs.clear();
    inputTotal = 0;

    // Get spendable outputs sorted by amount (largest first)
    auto spendable = GetSpendableFcmpOutputs(minConfirmations);

    // Simple selection: take largest outputs until we have enough
    for (const auto& output : spendable) {
        selectedInputs.push_back(output);
        inputTotal += output.amount;

        if (inputTotal >= targetAmount) {
            return true;
        }
    }

    // Not enough funds
    return false;
}

std::optional<privacy::CFcmpInput> CFcmpWalletManager::BuildFcmpInput(
    const CFcmpOutputInfo& output,
    const uint256& messageHash)
{
    AssertLockHeld(cs_fcmp);

    if (!m_curveTree) {
        return std::nullopt;
    }

    privacy::CFcmpInput fcmpInput;

    // Generate key image
    fcmpInput.keyImage = GenerateKeyImage(output.privKey, output.outputTuple.O);

    // Re-randomize input
    ed25519::Scalar rerandomizer = ed25519::Scalar::Random();

    auto G = ed25519::Point::BasePoint();
    auto H = ed25519::PedersenGenerators::Default().H();

    // O_tilde = O + r*G
    auto rG = rerandomizer * G;
    fcmpInput.inputTuple.O_tilde = output.outputTuple.O + rG;

    // I_tilde = I (cannot re-randomize key image)
    fcmpInput.inputTuple.I_tilde = output.outputTuple.I;

    // R = r*G
    fcmpInput.inputTuple.R = rG;

    // C_tilde = C + r*H
    auto rH = rerandomizer * H;
    fcmpInput.inputTuple.C_tilde = output.outputTuple.C + rH;

    // Generate membership proof
    auto branch = m_curveTree->GetBranch(output.treeLeafIndex);
    if (!branch) {
        LogPrintf("FCMP: Failed to get branch for leaf %lu\n",
                  output.treeLeafIndex);
        return std::nullopt;
    }

    try {
        privacy::fcmp::FcmpContext ctx;
        privacy::fcmp::FcmpProver prover(m_curveTree);
        auto proofBytes = prover.GenerateProof(
            output.outputTuple, output.treeLeafIndex,
            output.privKey, rerandomizer
        );
        fcmpInput.membershipProof = privacy::CFcmpProof(
            std::move(proofBytes),
            m_curveTree->GetRoot()
        );
    } catch (const std::exception& e) {
        LogPrintf("FCMP: Proof generation failed: %s\n", e.what());
        return std::nullopt;
    }

    // Generate SA+L signature
    // c = H(R || I_tilde || O_tilde || message)
    HashWriter sigHasher{};
    sigHasher << fcmpInput.inputTuple.R.data;
    sigHasher << fcmpInput.inputTuple.I_tilde.data;
    sigHasher << fcmpInput.inputTuple.O_tilde.data;
    sigHasher << messageHash;
    uint256 challengeHash = sigHasher.GetHash();

    fcmpInput.salSignature.c = ed25519::Scalar::FromBytesModOrder(
        std::vector<uint8_t>(challengeHash.begin(), challengeHash.end())
    );

    // s = r + c*(x + r), where O_tilde = (x+r)*G
    auto xPlusR = output.privKey + rerandomizer;
    auto cxr = fcmpInput.salSignature.c * xPlusR;
    fcmpInput.salSignature.s = rerandomizer + cxr;

    // Create pseudo-output commitment
    auto pseudoCommitment = ed25519::PedersenCommitment::CommitAmount(
        static_cast<uint64_t>(output.amount),
        output.blinding
    );
    fcmpInput.pseudoOutput.data.resize(33);
    fcmpInput.pseudoOutput.data[0] = 0x02;
    std::memcpy(
        fcmpInput.pseudoOutput.data.data() + 1,
        pseudoCommitment.GetPoint().data.data(),
        32
    );

    return fcmpInput;
}

uint256 CFcmpWalletManager::ComputeMessageHash(
    const std::vector<CFcmpOutputInfo>& inputs,
    const std::vector<CFcmpRecipient>& recipients,
    CAmount fee) const
{
    HashWriter hasher{};

    // Hash inputs
    for (const auto& input : inputs) {
        hasher << input.outpoint;
        hasher << input.amount;
        hasher << input.treeLeafIndex;
    }

    // Hash outputs
    for (const auto& recipient : recipients) {
        hasher << recipient.amount;
        // Hash stealth address components
        hasher << recipient.stealthAddress.scanPubKey;
        hasher << recipient.stealthAddress.spendPubKey;
    }

    hasher << fee;

    return hasher.GetHash();
}

} // namespace wallet
