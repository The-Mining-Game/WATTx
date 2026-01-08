// Copyright (c) 2024 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/server.h>
#include <rpc/util.h>
#include <wallet/rpc/util.h>
#include <wallet/wallet.h>
#include <wallet/spend.h>
#include <wallet/receive.h>
#include <wallet/scriptpubkeyman.h>
#include <validators/validatordb.h>
#include <validators/delegation.h>
#include <chainparams.h>
#include <key_io.h>
#include <util/moneystr.h>
#include <node/context.h>
#include <core_io.h>

#include <univalue.h>

using namespace validators;

namespace wallet {

// Helper to parse hex string to CKeyID
static CKeyID ParseValidatorKeyID(const std::string& hexStr) {
    std::vector<unsigned char> data = ParseHex(hexStr);
    if (data.size() != 20) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid key ID (must be 40 hex characters)");
    }
    uint160 hash;
    memcpy(hash.begin(), data.data(), 20);
    return CKeyID(hash);
}

// Helper to get public key from wallet (works with both legacy and descriptor wallets)
static bool GetPubKeyFromWallet(const CWallet& wallet, const CKeyID& keyId, CPubKey& pubkey) {
    PKHash pkhash(keyId);
    return wallet.GetPubKey(pkhash, pubkey);
}

// Helper to get private key from wallet (works with both legacy and descriptor wallets)
static bool GetKeyFromWallet(const CWallet& wallet, const CKeyID& keyId, CKey& key) {
    // First try legacy wallet
    LegacyScriptPubKeyMan* legacy_spk = wallet.GetLegacyScriptPubKeyMan();
    if (legacy_spk && legacy_spk->GetKey(keyId, key)) {
        return true;
    }

    // For descriptor wallets, first get the pubkey, then use it to get the signing provider
    CPubKey pubkey;
    if (!GetPubKeyFromWallet(wallet, keyId, pubkey)) {
        return false;
    }

    // Iterate through script pub key managers and try to get private key
    CScript script = GetScriptForDestination(PKHash(keyId));
    std::set<ScriptPubKeyMan*> spk_mans = wallet.GetScriptPubKeyMans(script);
    for (auto* spk_man : spk_mans) {
        DescriptorScriptPubKeyMan* desc_spk = dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man);
        if (desc_spk) {
            // Use the public GetSigningProvider(pubkey) which includes private keys
            std::unique_ptr<FlatSigningProvider> keys = desc_spk->GetSigningProvider(pubkey);
            if (keys && keys->GetKey(keyId, key)) {
                return true;
            }
        }
    }
    return false;
}

RPCHelpMan registervalidator()
{
    return RPCHelpMan{"registervalidator",
        "\nRegister this wallet as a validator for staking.\n"
        "Requires the wallet to have at least the minimum validator stake.\n",
        {
            {"fee_rate", RPCArg::Type::NUM, RPCArg::Default{DEFAULT_POOL_FEE}, "Pool fee rate in basis points (100 = 1%, max 10000 = 100%)"},
            {"name", RPCArg::Type::STR, RPCArg::Default{""}, "Optional validator name (max 64 characters)"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "validatorId", "The validator's public key ID"},
                {RPCResult::Type::STR_AMOUNT, "stake", "Stake amount"},
                {RPCResult::Type::NUM, "feeRate", "Pool fee rate in basis points"},
                {RPCResult::Type::STR, "name", "Validator name"},
                {RPCResult::Type::STR, "status", "Registration status"},
            }
        },
        RPCExamples{
            HelpExampleCli("registervalidator", "")
            + HelpExampleCli("registervalidator", "500 \"MyValidator\"")
            + HelpExampleRpc("registervalidator", "500, \"MyValidator\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            if (!g_validator_db) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Validator database not initialized");
            }

            EnsureWalletIsUnlocked(*pwallet);

            // Get fee rate
            int64_t feeRate = DEFAULT_POOL_FEE;
            if (!request.params[0].isNull()) {
                feeRate = request.params[0].getInt<int64_t>();
            }

            if (feeRate < MIN_POOL_FEE || feeRate > MAX_POOL_FEE) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("Fee rate must be between %d and %d basis points", MIN_POOL_FEE, MAX_POOL_FEE));
            }

            // Get validator name
            std::string validatorName;
            if (!request.params[1].isNull()) {
                validatorName = request.params[1].get_str();
                if (validatorName.size() > MAX_VALIDATOR_NAME) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                        strprintf("Validator name too long (max %d characters)", MAX_VALIDATOR_NAME));
                }
            }

            const Consensus::Params& consensusParams = Params().GetConsensus();

            // Get stake weight to check if we meet minimum
            LOCK(pwallet->cs_wallet);

            CAmount nStakeWeight = pwallet->GetStakeWeight();
            if (nStakeWeight < consensusParams.nMinValidatorStake) {
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                    strprintf("Insufficient stake. Have %s, need %s WATTx minimum",
                              FormatMoney(nStakeWeight), FormatMoney(consensusParams.nMinValidatorStake)));
            }

            // Get a staking address from the wallet
            auto destResult = pwallet->GetNewDestination(OutputType::LEGACY, "");
            if (!destResult) {
                throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, util::ErrorString(destResult).original);
            }
            CTxDestination stakeDest = *destResult;

            // Get the key ID
            const PKHash* pkhash = std::get_if<PKHash>(&stakeDest);
            if (!pkhash) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to get valid staking address");
            }
            CKeyID validatorKeyId = ToKeyID(*pkhash);

            // Get the public key (works with both legacy and descriptor wallets)
            CPubKey pubkey;
            if (!GetPubKeyFromWallet(*pwallet, validatorKeyId, pubkey)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to get public key for validator registration");
            }

            // Create validator entry
            ValidatorEntry entry;
            entry.validatorId = validatorKeyId;
            entry.validatorPubKey = pubkey;
            entry.stakeAmount = nStakeWeight;
            entry.poolFeeRate = feeRate;
            entry.registrationHeight = pwallet->chain().getHeight().value_or(0);
            entry.status = ValidatorStatus::PENDING;
            entry.validatorName = validatorName;

            // Register the validator
            if (!g_validator_db->RegisterValidator(entry)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to register validator (may already be registered)");
            }

            // Return result
            UniValue result(UniValue::VOBJ);
            result.pushKV("validatorId", validatorKeyId.ToString());
            result.pushKV("stake", ValueFromAmount(nStakeWeight));
            result.pushKV("feeRate", feeRate);
            result.pushKV("name", validatorName);
            result.pushKV("status", "pending");

            return result;
        },
    };
}

RPCHelpMan setvalidatorpoolfee()
{
    return RPCHelpMan{"setvalidatorpoolfee",
        "\nUpdate the pool fee rate for this validator.\n",
        {
            {"fee_rate", RPCArg::Type::NUM, RPCArg::Optional::NO, "New pool fee rate in basis points (100 = 1%, max 10000 = 100%)"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "validatorId", "The validator's public key ID"},
                {RPCResult::Type::NUM, "oldFeeRate", "Previous fee rate"},
                {RPCResult::Type::NUM, "newFeeRate", "New fee rate"},
            }
        },
        RPCExamples{
            HelpExampleCli("setvalidatorpoolfee", "500")
            + HelpExampleRpc("setvalidatorpoolfee", "500")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            if (!g_validator_db) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Validator database not initialized");
            }

            EnsureWalletIsUnlocked(*pwallet);

            int64_t newFeeRate = request.params[0].getInt<int64_t>();
            if (newFeeRate < MIN_POOL_FEE || newFeeRate > MAX_POOL_FEE) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("Fee rate must be between %d and %d basis points", MIN_POOL_FEE, MAX_POOL_FEE));
            }

            LOCK(pwallet->cs_wallet);

            // Find our validator by checking wallet addresses
            CKeyID validatorId;
            int64_t oldFeeRate = 0;
            bool found = false;

            for (const auto& [dest, label] : pwallet->m_address_book) {
                const PKHash* pkhash = std::get_if<PKHash>(&dest);
                if (!pkhash) continue;

                CKeyID keyId = ToKeyID(*pkhash);
                const ValidatorEntry* validator = g_validator_db->GetValidator(keyId);
                if (validator) {
                    validatorId = keyId;
                    oldFeeRate = validator->poolFeeRate;
                    found = true;
                    break;
                }
            }

            if (!found) {
                throw JSONRPCError(RPC_WALLET_ERROR, "No validator registration found for this wallet");
            }

            // Create and process update
            ValidatorUpdate update;
            update.validatorId = validatorId;
            update.updateType = ValidatorUpdateType::UPDATE_FEE;
            update.newValue = newFeeRate;
            update.updateHeight = pwallet->chain().getHeight().value_or(0);

            // Get key and sign (works with both legacy and descriptor wallets)
            CKey key;
            if (!GetKeyFromWallet(*pwallet, validatorId, key)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to get validator key for signing");
            }

            if (!update.Sign(key)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign update");
            }

            if (!g_validator_db->ProcessUpdate(update)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to process fee update");
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("validatorId", validatorId.ToString());
            result.pushKV("oldFeeRate", oldFeeRate);
            result.pushKV("newFeeRate", newFeeRate);

            return result;
        },
    };
}

RPCHelpMan delegatestake()
{
    return RPCHelpMan{"delegatestake",
        "\nDelegate stake to a validator.\n"
        "Minimum delegation amount is 1,000 WATTx.\n",
        {
            {"validatorId", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The validator's public key ID to delegate to"},
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO, "Amount to delegate in WATTx"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "delegationId", "Unique delegation ID"},
                {RPCResult::Type::STR, "delegatorId", "Your public key ID"},
                {RPCResult::Type::STR, "validatorId", "Validator's public key ID"},
                {RPCResult::Type::STR_AMOUNT, "amount", "Amount delegated"},
                {RPCResult::Type::STR, "validatorName", "Validator's name"},
                {RPCResult::Type::NUM, "validatorFee", "Validator's fee rate"},
            }
        },
        RPCExamples{
            HelpExampleCli("delegatestake", "\"0123456789abcdef0123456789abcdef01234567\" 10000")
            + HelpExampleRpc("delegatestake", "\"0123456789abcdef0123456789abcdef01234567\", 10000")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            if (!g_validator_db || !g_delegation_db) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Validator/delegation database not initialized");
            }

            EnsureWalletIsUnlocked(*pwallet);

            // Parse validator ID
            CKeyID validatorId = ParseValidatorKeyID(request.params[0].get_str());

            // Check validator exists
            const ValidatorEntry* validator = g_validator_db->GetValidator(validatorId);
            if (!validator) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Validator not found");
            }

            if (validator->status != ValidatorStatus::ACTIVE && validator->status != ValidatorStatus::PENDING) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Validator is not accepting delegations");
            }

            // Parse amount
            CAmount amount = AmountFromValue(request.params[1]);
            if (amount < MIN_DELEGATION_AMOUNT) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("Minimum delegation is %s WATTx", FormatMoney(MIN_DELEGATION_AMOUNT)));
            }

            LOCK(pwallet->cs_wallet);

            // Get available balance
            CAmount nBalance = GetBalance(*pwallet).m_mine_trusted;
            if (nBalance < amount) {
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                    strprintf("Insufficient funds. Have %s, need %s WATTx",
                              FormatMoney(nBalance), FormatMoney(amount)));
            }

            // Get a delegation address
            auto destResult = pwallet->GetNewDestination(OutputType::LEGACY, "delegation");
            if (!destResult) {
                throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, util::ErrorString(destResult).original);
            }
            CTxDestination delegateDest = *destResult;

            const PKHash* pkhash = std::get_if<PKHash>(&delegateDest);
            if (!pkhash) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to get valid delegation address");
            }
            CKeyID delegatorId = ToKeyID(*pkhash);

            // Get the public key and private key (works with both wallet types)
            CPubKey pubkey;
            CKey key;
            if (!GetPubKeyFromWallet(*pwallet, delegatorId, pubkey)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to get public key for delegation");
            }
            if (!GetKeyFromWallet(*pwallet, delegatorId, key)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to get private key for signing delegation");
            }

            // Create delegation request
            DelegationRequest delegationReq;
            delegationReq.delegatorId = delegatorId;
            delegationReq.delegatorPubKey = pubkey;
            delegationReq.validatorId = validatorId;
            delegationReq.amount = amount;
            delegationReq.height = pwallet->chain().getHeight().value_or(0);

            if (!delegationReq.Sign(key)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign delegation request");
            }

            // For now, use a null outpoint (in production, this would be a real UTXO)
            COutPoint delegationOutpoint;

            if (!g_delegation_db->ProcessDelegation(delegationReq, delegationOutpoint)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to process delegation");
            }

            // Create delegation entry to get ID
            DelegationEntry entry;
            entry.delegatorId = delegatorId;
            entry.validatorId = validatorId;
            entry.amount = amount;
            entry.delegationHeight = delegationReq.height;

            UniValue result(UniValue::VOBJ);
            result.pushKV("delegationId", entry.GetDelegationId().ToString());
            result.pushKV("delegatorId", delegatorId.ToString());
            result.pushKV("validatorId", validatorId.ToString());
            result.pushKV("amount", ValueFromAmount(amount));
            result.pushKV("validatorName", validator->validatorName);
            result.pushKV("validatorFee", validator->poolFeeRate);

            return result;
        },
    };
}

RPCHelpMan undelegatestake()
{
    return RPCHelpMan{"undelegatestake",
        "\nUndelegate stake from a validator.\n"
        "Stake will be returned after the unbonding period.\n",
        {
            {"validatorId", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The validator's public key ID"},
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Default{0}, "Amount to undelegate (0 = all)"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "validatorId", "Validator's public key ID"},
                {RPCResult::Type::STR_AMOUNT, "undelegatedAmount", "Amount being undelegated"},
                {RPCResult::Type::NUM, "unbondingBlocks", "Blocks until funds are available"},
            }
        },
        RPCExamples{
            HelpExampleCli("undelegatestake", "\"0123456789abcdef0123456789abcdef01234567\"")
            + HelpExampleCli("undelegatestake", "\"0123456789abcdef0123456789abcdef01234567\" 5000")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            if (!g_delegation_db) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Delegation database not initialized");
            }

            EnsureWalletIsUnlocked(*pwallet);

            // Parse validator ID
            CKeyID validatorId = ParseValidatorKeyID(request.params[0].get_str());

            // Parse amount (0 = all)
            CAmount amount = 0;
            if (!request.params[1].isNull()) {
                amount = AmountFromValue(request.params[1]);
            }

            LOCK(pwallet->cs_wallet);

            // Find our delegation to this validator
            CKeyID delegatorId;
            CAmount delegatedAmount = 0;
            bool found = false;

            for (const auto& [dest, label] : pwallet->m_address_book) {
                const PKHash* pkhash = std::get_if<PKHash>(&dest);
                if (!pkhash) continue;

                CKeyID keyId = ToKeyID(*pkhash);
                auto delegations = g_delegation_db->GetDelegationsForDelegator(keyId);

                for (const auto& d : delegations) {
                    if (d.validatorId == validatorId && d.IsActive()) {
                        delegatorId = keyId;
                        delegatedAmount = d.amount;
                        found = true;
                        break;
                    }
                }
                if (found) break;
            }

            if (!found) {
                throw JSONRPCError(RPC_WALLET_ERROR, "No active delegation found to this validator");
            }

            // If amount is 0, undelegate all
            CAmount undelegateAmount = (amount == 0) ? delegatedAmount : amount;
            if (undelegateAmount > delegatedAmount) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    strprintf("Cannot undelegate more than delegated (%s WATTx)", FormatMoney(delegatedAmount)));
            }

            // Create undelegation request
            UndelegationRequest undelegateReq;
            undelegateReq.delegatorId = delegatorId;
            undelegateReq.validatorId = validatorId;
            undelegateReq.amount = undelegateAmount;
            undelegateReq.height = pwallet->chain().getHeight().value_or(0);

            // Get key and sign (works with both legacy and descriptor wallets)
            CKey key;
            if (!GetKeyFromWallet(*pwallet, delegatorId, key)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to get delegation key");
            }

            if (!undelegateReq.Sign(key)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign undelegation request");
            }

            if (!g_delegation_db->ProcessUndelegation(undelegateReq)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to process undelegation");
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("validatorId", validatorId.ToString());
            result.pushKV("undelegatedAmount", ValueFromAmount(undelegateAmount));
            result.pushKV("unbondingBlocks", DELEGATION_UNBONDING_PERIOD);

            return result;
        },
    };
}

RPCHelpMan claimrewards()
{
    return RPCHelpMan{"claimrewards",
        "\nClaim pending delegation rewards.\n",
        {
            {"validatorId", RPCArg::Type::STR_HEX, RPCArg::Default{""}, "Specific validator to claim from (empty = all)"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_AMOUNT, "claimed", "Total rewards claimed"},
                {RPCResult::Type::NUM, "delegationsCount", "Number of delegations claimed from"},
            }
        },
        RPCExamples{
            HelpExampleCli("claimrewards", "")
            + HelpExampleCli("claimrewards", "\"0123456789abcdef0123456789abcdef01234567\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            if (!g_delegation_db) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Delegation database not initialized");
            }

            EnsureWalletIsUnlocked(*pwallet);

            // Parse optional validator ID
            CKeyID specificValidatorId;
            if (!request.params[0].isNull() && !request.params[0].get_str().empty()) {
                specificValidatorId = ParseValidatorKeyID(request.params[0].get_str());
            }

            LOCK(pwallet->cs_wallet);

            CAmount totalClaimed = 0;
            int claimedCount = 0;

            // Find all our delegations and claim rewards
            for (const auto& [dest, label] : pwallet->m_address_book) {
                const PKHash* pkhash = std::get_if<PKHash>(&dest);
                if (!pkhash) continue;

                CKeyID keyId = ToKeyID(*pkhash);
                auto delegations = g_delegation_db->GetDelegationsForDelegator(keyId);

                for (const auto& d : delegations) {
                    if (!d.IsActive() || d.pendingRewards == 0) continue;

                    // If specific validator requested, skip others
                    if (!specificValidatorId.IsNull() && d.validatorId != specificValidatorId) {
                        continue;
                    }

                    // Create claim request
                    RewardClaimRequest claimReq;
                    claimReq.delegatorId = keyId;
                    claimReq.validatorId = d.validatorId;
                    claimReq.height = pwallet->chain().getHeight().value_or(0);

                    // Get key and sign (works with both legacy and descriptor wallets)
                    CKey key;
                    if (!GetKeyFromWallet(*pwallet, keyId, key)) {
                        continue; // Skip if we can't sign
                    }

                    if (!claimReq.Sign(key)) {
                        continue;
                    }

                    CAmount claimed = g_delegation_db->ProcessRewardClaim(claimReq);
                    if (claimed > 0) {
                        totalClaimed += claimed;
                        claimedCount++;
                    }
                }
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("claimed", ValueFromAmount(totalClaimed));
            result.pushKV("delegationsCount", claimedCount);

            return result;
        },
    };
}

RPCHelpMan getmydelegations()
{
    return RPCHelpMan{"getmydelegations",
        "\nList all delegations from this wallet.\n",
        {},
        RPCResult{
            RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR, "delegationId", "Unique delegation ID"},
                    {RPCResult::Type::STR, "validatorId", "Validator's public key ID"},
                    {RPCResult::Type::STR, "validatorName", "Validator's name"},
                    {RPCResult::Type::STR_AMOUNT, "amount", "Amount delegated"},
                    {RPCResult::Type::STR_AMOUNT, "pendingRewards", "Unclaimed rewards"},
                    {RPCResult::Type::STR, "status", "Delegation status"},
                    {RPCResult::Type::NUM, "validatorFee", "Validator's fee rate"},
                }},
            }
        },
        RPCExamples{
            HelpExampleCli("getmydelegations", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            if (!g_delegation_db || !g_validator_db) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Delegation database not initialized");
            }

            LOCK(pwallet->cs_wallet);

            UniValue result(UniValue::VARR);

            for (const auto& [dest, label] : pwallet->m_address_book) {
                const PKHash* pkhash = std::get_if<PKHash>(&dest);
                if (!pkhash) continue;

                CKeyID keyId = ToKeyID(*pkhash);
                auto delegations = g_delegation_db->GetDelegationsForDelegator(keyId);

                for (const auto& d : delegations) {
                    UniValue entry(UniValue::VOBJ);
                    entry.pushKV("delegationId", d.GetDelegationId().ToString());
                    entry.pushKV("validatorId", d.validatorId.ToString());

                    // Get validator name
                    const ValidatorEntry* validator = g_validator_db->GetValidator(d.validatorId);
                    if (validator) {
                        entry.pushKV("validatorName", validator->validatorName);
                        entry.pushKV("validatorFee", validator->poolFeeRate);
                    } else {
                        entry.pushKV("validatorName", "");
                        entry.pushKV("validatorFee", 0);
                    }

                    entry.pushKV("amount", ValueFromAmount(d.amount));
                    entry.pushKV("pendingRewards", ValueFromAmount(d.pendingRewards));
                    entry.pushKV("status", DelegationStatusToString(d.status));

                    result.push_back(entry);
                }
            }

            return result;
        },
    };
}

RPCHelpMan getmyvalidator()
{
    return RPCHelpMan{"getmyvalidator",
        "\nGet this wallet's validator registration info.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "validatorId", "Validator's public key ID"},
                {RPCResult::Type::STR_AMOUNT, "stake", "Self-stake amount"},
                {RPCResult::Type::STR_AMOUNT, "delegated", "Total delegated to us"},
                {RPCResult::Type::STR_AMOUNT, "totalStake", "Total stake (self + delegated)"},
                {RPCResult::Type::NUM, "feeRate", "Pool fee rate in basis points"},
                {RPCResult::Type::STR, "name", "Validator name"},
                {RPCResult::Type::STR, "status", "Validator status"},
                {RPCResult::Type::NUM, "delegatorCount", "Number of delegators"},
            }
        },
        RPCExamples{
            HelpExampleCli("getmyvalidator", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::shared_ptr<CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            if (!g_validator_db) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Validator database not initialized");
            }

            LOCK(pwallet->cs_wallet);

            // Find our validator
            for (const auto& [dest, label] : pwallet->m_address_book) {
                const PKHash* pkhash = std::get_if<PKHash>(&dest);
                if (!pkhash) continue;

                CKeyID keyId = ToKeyID(*pkhash);
                const ValidatorEntry* validator = g_validator_db->GetValidator(keyId);
                if (validator) {
                    UniValue result(UniValue::VOBJ);
                    result.pushKV("validatorId", validator->validatorId.ToString());
                    result.pushKV("stake", ValueFromAmount(validator->stakeAmount));
                    result.pushKV("delegated", ValueFromAmount(validator->totalDelegated));
                    result.pushKV("totalStake", ValueFromAmount(validator->GetTotalStake()));
                    result.pushKV("feeRate", validator->poolFeeRate);
                    result.pushKV("name", validator->validatorName);
                    result.pushKV("status", ValidatorStatusToString(validator->status));
                    result.pushKV("delegatorCount", validator->delegatorCount);

                    return result;
                }
            }

            throw JSONRPCError(RPC_WALLET_ERROR, "No validator registration found for this wallet");
        },
    };
}

Span<const CRPCCommand> GetValidatorWalletRPCCommands()
{
    static const CRPCCommand commands[]{
        {"wallet", &registervalidator},
        {"wallet", &setvalidatorpoolfee},
        {"wallet", &delegatestake},
        {"wallet", &undelegatestake},
        {"wallet", &claimrewards},
        {"wallet", &getmydelegations},
        {"wallet", &getmyvalidator},
    };
    return commands;
}

} // namespace wallet
