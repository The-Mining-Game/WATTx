// Copyright (c) 2024 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <validators/validatordb.h>
#include <validators/delegation.h>
#include <trust/trustscore.h>
#include <trust/heartbeat_net.h>
#include <chainparams.h>
#include <core_io.h>
#include <univalue.h>
#include <key_io.h>
#include <util/strencodings.h>

namespace {
// Helper function to parse hex string to CKeyID
CKeyID ParseKeyID(const std::string& hexStr) {
    std::vector<unsigned char> data = ParseHex(hexStr);
    if (data.size() == 20) {
        return CKeyID(uint160(data));
    }
    return CKeyID();
}
} // anonymous namespace

using namespace validators;

static RPCHelpMan listvalidators()
{
    return RPCHelpMan{"listvalidators",
        "\nList all registered validators.\n",
        {
            {"minFee", RPCArg::Type::NUM, RPCArg::Default{-1}, "Filter validators with fee at or below this rate (basis points, 100 = 1%)"},
            {"activeOnly", RPCArg::Type::BOOL, RPCArg::Default{true}, "Only show active validators"},
        },
        RPCResult{
            RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR, "validatorId", "Validator public key ID"},
                    {RPCResult::Type::STR_AMOUNT, "stake", "Self-stake amount"},
                    {RPCResult::Type::STR_AMOUNT, "delegated", "Total delegated amount"},
                    {RPCResult::Type::STR_AMOUNT, "totalStake", "Total stake (self + delegated)"},
                    {RPCResult::Type::NUM, "feeRate", "Pool fee rate in basis points"},
                    {RPCResult::Type::STR, "name", "Validator name"},
                    {RPCResult::Type::STR, "status", "Validator status"},
                    {RPCResult::Type::NUM, "delegatorCount", "Number of delegators"},
                    {RPCResult::Type::STR, "trustTier", "Trust tier (if available)"},
                    {RPCResult::Type::NUM, "uptimePercent", "Uptime percentage * 10"},
                }},
            }
        },
        RPCExamples{
            HelpExampleCli("listvalidators", "")
            + HelpExampleCli("listvalidators", "500 true")
            + HelpExampleRpc("listvalidators", "500, true")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            if (!g_validator_db) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Validator database not initialized");
            }

            int64_t maxFee = -1;
            if (!request.params[0].isNull()) {
                maxFee = request.params[0].getInt<int64_t>();
            }

            bool activeOnly = true;
            if (!request.params[1].isNull()) {
                activeOnly = request.params[1].get_bool();
            }

            std::vector<ValidatorEntry> validators;
            if (maxFee >= 0) {
                validators = g_validator_db->GetValidatorsByMaxFee(maxFee);
            } else if (activeOnly) {
                validators = g_validator_db->GetActiveValidators();
            } else {
                validators = g_validator_db->GetValidatorsByStake();
            }

            UniValue result(UniValue::VARR);
            for (const auto& v : validators) {
                UniValue entry(UniValue::VOBJ);
                entry.pushKV("validatorId", v.validatorId.ToString());
                entry.pushKV("stake", ValueFromAmount(v.stakeAmount));
                entry.pushKV("delegated", ValueFromAmount(v.totalDelegated));
                entry.pushKV("totalStake", ValueFromAmount(v.GetTotalStake()));
                entry.pushKV("feeRate", v.poolFeeRate);
                entry.pushKV("name", v.validatorName);
                entry.pushKV("status", ValidatorStatusToString(v.status));
                entry.pushKV("delegatorCount", v.delegatorCount);

                // Get trust info if available
                if (trust::g_heartbeat_manager) {
                    const trust::TrustScoreManager* trustManager = trust::g_heartbeat_manager->GetTrustManager();
                    if (trustManager) {
                        const trust::ValidatorInfo* info = trustManager->GetValidator(v.validatorId);
                        if (info) {
                            entry.pushKV("trustTier", trust::TrustTierToString(info->GetTrustTier(Params().GetConsensus())));
                            entry.pushKV("uptimePercent", info->GetUptimePercentage());
                        }
                    }
                }

                result.push_back(entry);
            }

            return result;
        },
    };
}

static RPCHelpMan getvalidator()
{
    return RPCHelpMan{"getvalidator",
        "\nGet information about a specific validator.\n",
        {
            {"validatorId", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The validator's public key ID"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "validatorId", "Validator public key ID"},
                {RPCResult::Type::STR_AMOUNT, "stake", "Self-stake amount"},
                {RPCResult::Type::STR_AMOUNT, "delegated", "Total delegated amount"},
                {RPCResult::Type::STR_AMOUNT, "totalStake", "Total stake (self + delegated)"},
                {RPCResult::Type::NUM, "feeRate", "Pool fee rate in basis points"},
                {RPCResult::Type::STR, "name", "Validator name"},
                {RPCResult::Type::STR, "status", "Validator status"},
                {RPCResult::Type::NUM, "registrationHeight", "Block height when registered"},
                {RPCResult::Type::NUM, "delegatorCount", "Number of delegators"},
                {RPCResult::Type::STR, "trustTier", "Trust tier"},
                {RPCResult::Type::NUM, "uptimePercent", "Uptime percentage * 10"},
                {RPCResult::Type::NUM, "rewardMultiplier", "Reward multiplier (100 = 1x)"},
            }
        },
        RPCExamples{
            HelpExampleCli("getvalidator", "\"0123456789abcdef...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            if (!g_validator_db) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Validator database not initialized");
            }

            std::string idStr = request.params[0].get_str();
            CKeyID validatorId = ParseKeyID(idStr);

            const ValidatorEntry* v = g_validator_db->GetValidator(validatorId);
            if (!v) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Validator not found");
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("validatorId", v->validatorId.ToString());
            result.pushKV("stake", ValueFromAmount(v->stakeAmount));
            result.pushKV("delegated", ValueFromAmount(v->totalDelegated));
            result.pushKV("totalStake", ValueFromAmount(v->GetTotalStake()));
            result.pushKV("feeRate", v->poolFeeRate);
            result.pushKV("name", v->validatorName);
            result.pushKV("status", ValidatorStatusToString(v->status));
            result.pushKV("registrationHeight", v->registrationHeight);
            result.pushKV("delegatorCount", v->delegatorCount);

            // Get trust info
            if (trust::g_heartbeat_manager) {
                const trust::TrustScoreManager* trustManager = trust::g_heartbeat_manager->GetTrustManager();
                if (trustManager) {
                    const trust::ValidatorInfo* info = trustManager->GetValidator(validatorId);
                    if (info) {
                        trust::TrustTier tier = info->GetTrustTier(Params().GetConsensus());
                        result.pushKV("trustTier", trust::TrustTierToString(tier));
                        result.pushKV("uptimePercent", info->GetUptimePercentage());
                        result.pushKV("rewardMultiplier", info->GetRewardMultiplier(Params().GetConsensus()));
                    }
                }
            }

            return result;
        },
    };
}

static RPCHelpMan getvalidatorstats()
{
    return RPCHelpMan{"getvalidatorstats",
        "\nGet overall validator network statistics.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "totalValidators", "Total registered validators"},
                {RPCResult::Type::NUM, "activeValidators", "Currently active validators"},
                {RPCResult::Type::STR_AMOUNT, "totalStaked", "Total amount staked"},
                {RPCResult::Type::STR_AMOUNT, "totalDelegated", "Total amount delegated"},
                {RPCResult::Type::NUM, "totalDelegations", "Total delegation count"},
                {RPCResult::Type::NUM, "bronzeCount", "Validators at Bronze tier"},
                {RPCResult::Type::NUM, "silverCount", "Validators at Silver tier"},
                {RPCResult::Type::NUM, "goldCount", "Validators at Gold tier"},
                {RPCResult::Type::NUM, "platinumCount", "Validators at Platinum tier"},
            }
        },
        RPCExamples{
            HelpExampleCli("getvalidatorstats", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            if (!g_validator_db) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Validator database not initialized");
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("totalValidators", (int64_t)g_validator_db->GetValidatorCount());
            result.pushKV("activeValidators", (int64_t)g_validator_db->GetActiveValidatorCount());

            CAmount totalStaked = 0;
            CAmount totalDelegated = 0;
            int bronzeCount = 0, silverCount = 0, goldCount = 0, platinumCount = 0;

            auto validators = g_validator_db->GetActiveValidators();
            for (const auto& v : validators) {
                totalStaked += v.stakeAmount;
                totalDelegated += v.totalDelegated;

                if (trust::g_heartbeat_manager) {
                    const trust::TrustScoreManager* trustManager = trust::g_heartbeat_manager->GetTrustManager();
                    if (trustManager) {
                        const trust::ValidatorInfo* info = trustManager->GetValidator(v.validatorId);
                        if (info) {
                            trust::TrustTier tier = info->GetTrustTier(Params().GetConsensus());
                            switch (tier) {
                                case trust::TrustTier::BRONZE: bronzeCount++; break;
                                case trust::TrustTier::SILVER: silverCount++; break;
                                case trust::TrustTier::GOLD: goldCount++; break;
                                case trust::TrustTier::PLATINUM: platinumCount++; break;
                                default: break;
                            }
                        }
                    }
                }
            }

            result.pushKV("totalStaked", ValueFromAmount(totalStaked));
            result.pushKV("totalDelegated", ValueFromAmount(totalDelegated));

            if (g_delegation_db) {
                result.pushKV("totalDelegations", (int64_t)g_delegation_db->GetActiveDelegationCount());
            } else {
                result.pushKV("totalDelegations", 0);
            }

            result.pushKV("bronzeCount", bronzeCount);
            result.pushKV("silverCount", silverCount);
            result.pushKV("goldCount", goldCount);
            result.pushKV("platinumCount", platinumCount);

            return result;
        },
    };
}

static RPCHelpMan listdelegations()
{
    return RPCHelpMan{"listdelegations",
        "\nList delegations for a delegator or validator.\n",
        {
            {"keyId", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The delegator or validator public key ID"},
            {"type", RPCArg::Type::STR, RPCArg::Default{"delegator"}, "Query type: 'delegator' or 'validator'"},
        },
        RPCResult{
            RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR, "delegationId", "Unique delegation ID"},
                    {RPCResult::Type::STR, "delegatorId", "Delegator public key ID"},
                    {RPCResult::Type::STR, "validatorId", "Validator public key ID"},
                    {RPCResult::Type::STR_AMOUNT, "amount", "Delegated amount"},
                    {RPCResult::Type::STR, "status", "Delegation status"},
                    {RPCResult::Type::STR_AMOUNT, "pendingRewards", "Unclaimed rewards"},
                }},
            }
        },
        RPCExamples{
            HelpExampleCli("listdelegations", "\"0123456789abcdef...\" delegator")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            if (!g_delegation_db) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Delegation database not initialized");
            }

            std::string idStr = request.params[0].get_str();
            CKeyID keyId = ParseKeyID(idStr);

            std::string queryType = "delegator";
            if (!request.params[1].isNull()) {
                queryType = request.params[1].get_str();
            }

            std::vector<DelegationEntry> delegations;
            if (queryType == "validator") {
                delegations = g_delegation_db->GetDelegationsForValidator(keyId);
            } else {
                delegations = g_delegation_db->GetDelegationsForDelegator(keyId);
            }

            UniValue result(UniValue::VARR);
            for (const auto& d : delegations) {
                UniValue entry(UniValue::VOBJ);
                entry.pushKV("delegationId", d.GetDelegationId().ToString());
                entry.pushKV("delegatorId", d.delegatorId.ToString());
                entry.pushKV("validatorId", d.validatorId.ToString());
                entry.pushKV("amount", ValueFromAmount(d.amount));
                entry.pushKV("status", DelegationStatusToString(d.status));
                entry.pushKV("pendingRewards", ValueFromAmount(d.pendingRewards));
                result.push_back(entry);
            }

            return result;
        },
    };
}

static RPCHelpMan getpendingrewards()
{
    return RPCHelpMan{"getpendingrewards",
        "\nGet pending rewards for a delegator.\n",
        {
            {"delegatorId", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The delegator's public key ID"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_AMOUNT, "pendingRewards", "Total pending rewards"},
            }
        },
        RPCExamples{
            HelpExampleCli("getpendingrewards", "\"0123456789abcdef...\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            if (!g_delegation_db) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Delegation database not initialized");
            }

            std::string idStr = request.params[0].get_str();
            CKeyID delegatorId = ParseKeyID(idStr);

            CAmount pending = g_delegation_db->GetPendingRewardsForDelegator(delegatorId);

            UniValue result(UniValue::VOBJ);
            result.pushKV("pendingRewards", ValueFromAmount(pending));

            return result;
        },
    };
}

static RPCHelpMan gettrusttierinfo()
{
    return RPCHelpMan{"gettrusttierinfo",
        "\nGet trust tier thresholds and multipliers.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::OBJ, "thresholds", "Uptime thresholds for each tier",
                {
                    {RPCResult::Type::NUM, "bronze", "Bronze tier threshold (x10, e.g., 950 = 95.0%)"},
                    {RPCResult::Type::NUM, "silver", "Silver tier threshold"},
                    {RPCResult::Type::NUM, "gold", "Gold tier threshold"},
                    {RPCResult::Type::NUM, "platinum", "Platinum tier threshold"},
                }},
                {RPCResult::Type::OBJ, "multipliers", "Reward multipliers for each tier",
                {
                    {RPCResult::Type::NUM, "bronze", "Bronze tier multiplier (100 = 1.0x)"},
                    {RPCResult::Type::NUM, "silver", "Silver tier multiplier"},
                    {RPCResult::Type::NUM, "gold", "Gold tier multiplier"},
                    {RPCResult::Type::NUM, "platinum", "Platinum tier multiplier"},
                }},
                {RPCResult::Type::STR_AMOUNT, "minValidatorStake", "Minimum stake to be a validator"},
                {RPCResult::Type::NUM, "heartbeatInterval", "Blocks between heartbeats"},
            }
        },
        RPCExamples{
            HelpExampleCli("gettrusttierinfo", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            const Consensus::Params& params = Params().GetConsensus();

            UniValue thresholds(UniValue::VOBJ);
            thresholds.pushKV("bronze", params.nBronzeUptimeThreshold);
            thresholds.pushKV("silver", params.nSilverUptimeThreshold);
            thresholds.pushKV("gold", params.nGoldUptimeThreshold);
            thresholds.pushKV("platinum", params.nPlatinumUptimeThreshold);

            UniValue multipliers(UniValue::VOBJ);
            multipliers.pushKV("bronze", params.nBronzeRewardMultiplier);
            multipliers.pushKV("silver", params.nSilverRewardMultiplier);
            multipliers.pushKV("gold", params.nGoldRewardMultiplier);
            multipliers.pushKV("platinum", params.nPlatinumRewardMultiplier);

            UniValue result(UniValue::VOBJ);
            result.pushKV("thresholds", thresholds);
            result.pushKV("multipliers", multipliers);
            result.pushKV("minValidatorStake", ValueFromAmount(params.nMinValidatorStake));
            result.pushKV("heartbeatInterval", params.nHeartbeatInterval);

            return result;
        },
    };
}

void RegisterValidatorRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"validators", &listvalidators},
        {"validators", &getvalidator},
        {"validators", &getvalidatorstats},
        {"validators", &listdelegations},
        {"validators", &getpendingrewards},
        {"validators", &gettrusttierinfo},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
