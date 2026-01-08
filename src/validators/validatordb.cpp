// Copyright (c) 2024 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <validators/validatordb.h>
#include <hash.h>
#include <logging.h>

#include <algorithm>

namespace validators {

// Global instance
std::unique_ptr<ValidatorDB> g_validator_db;

void InitValidatorDB(const Consensus::Params& params) {
    g_validator_db = std::make_unique<ValidatorDB>(params);
    LogPrintf("ValidatorDB: Initialized validator database\n");
}

void ShutdownValidatorDB() {
    g_validator_db.reset();
    LogPrintf("ValidatorDB: Shut down validator database\n");
}

std::string ValidatorStatusToString(ValidatorStatus status) {
    switch (status) {
        case ValidatorStatus::PENDING: return "pending";
        case ValidatorStatus::ACTIVE: return "active";
        case ValidatorStatus::INACTIVE: return "inactive";
        case ValidatorStatus::JAILED: return "jailed";
        case ValidatorStatus::UNBONDING: return "unbonding";
        default: return "unknown";
    }
}

// ValidatorEntry implementation

bool ValidatorEntry::MeetsMinimumStake(const Consensus::Params& params) const {
    return GetTotalStake() >= params.nMinValidatorStake;
}

bool ValidatorEntry::IsEligibleForStaking(const Consensus::Params& params, int currentHeight) const {
    // Must be active status
    if (status != ValidatorStatus::ACTIVE) {
        return false;
    }

    // Must meet minimum stake
    if (!MeetsMinimumStake(params)) {
        return false;
    }

    // Must have passed maturity period (2000 blocks like QTUM)
    if (currentHeight - registrationHeight < 2000) {
        return false;
    }

    return true;
}

CAmount ValidatorEntry::CalculateValidatorReward(CAmount blockReward) const {
    if (totalDelegated == 0) {
        // No delegators, validator gets full reward
        return blockReward;
    }

    // Calculate validator's portion:
    // 1. Validator gets their stake's proportional share
    // 2. Plus pool fee on delegators' share

    CAmount totalStake = GetTotalStake();
    if (totalStake == 0) return 0;

    // Validator's stake share
    CAmount validatorStakeShare = (blockReward * stakeAmount) / totalStake;

    // Delegators' total share (before fee)
    CAmount delegatorsShare = blockReward - validatorStakeShare;

    // Pool fee taken from delegators' share
    CAmount poolFee = (delegatorsShare * poolFeeRate) / 10000;

    return validatorStakeShare + poolFee;
}

CAmount ValidatorEntry::CalculateDelegatorsReward(CAmount blockReward) const {
    if (totalDelegated == 0) {
        return 0;
    }

    CAmount totalStake = GetTotalStake();
    if (totalStake == 0) return 0;

    // Delegators' stake share (proportional)
    CAmount delegatorsShare = (blockReward * totalDelegated) / totalStake;

    // Subtract pool fee
    CAmount poolFee = (delegatorsShare * poolFeeRate) / 10000;

    return delegatorsShare - poolFee;
}

// ValidatorUpdate implementation

uint256 ValidatorUpdate::GetHash() const {
    HashWriter ss{};
    ss << validatorId;
    ss << static_cast<uint8_t>(updateType);
    ss << newValue;
    ss << newName;
    ss << updateHeight;
    return ss.GetHash();
}

bool ValidatorUpdate::Sign(const CKey& key) {
    uint256 hash = GetHash();
    return key.Sign(hash, signature);
}

bool ValidatorUpdate::Verify(const CPubKey& pubkey) const {
    uint256 hash = GetHash();
    return pubkey.Verify(hash, signature);
}

// ValidatorDB implementation

ValidatorDB::ValidatorDB(const Consensus::Params& params)
    : consensusParams(params), currentHeight(0) {}

bool ValidatorDB::RegisterValidator(const ValidatorEntry& entry) {
    LOCK(cs_validators);

    // Check if already registered
    if (validators.count(entry.validatorId) > 0) {
        LogPrintf("ValidatorDB: Validator %s already registered\n",
                  entry.validatorId.ToString());
        return false;
    }

    // Validate pool fee rate
    if (entry.poolFeeRate < MIN_POOL_FEE || entry.poolFeeRate > MAX_POOL_FEE) {
        LogPrintf("ValidatorDB: Invalid pool fee rate %lld\n", entry.poolFeeRate);
        return false;
    }

    // Validate minimum stake
    if (entry.stakeAmount < consensusParams.nMinValidatorStake) {
        LogPrintf("ValidatorDB: Stake %lld below minimum %lld\n",
                  entry.stakeAmount, consensusParams.nMinValidatorStake);
        return false;
    }

    // Validate name length
    if (entry.validatorName.size() > MAX_VALIDATOR_NAME) {
        LogPrintf("ValidatorDB: Validator name too long (%zu > %zu)\n",
                  entry.validatorName.size(), MAX_VALIDATOR_NAME);
        return false;
    }

    // Add to database
    validators[entry.validatorId] = entry;

    // Add to outpoint index
    if (!entry.stakeOutpoint.IsNull()) {
        outpointIndex[entry.stakeOutpoint] = entry.validatorId;
    }

    LogPrintf("ValidatorDB: Registered validator %s with stake %lld and fee %lld bps\n",
              entry.validatorId.ToString(), entry.stakeAmount, entry.poolFeeRate);

    return true;
}

bool ValidatorDB::ProcessUpdate(const ValidatorUpdate& update) {
    LOCK(cs_validators);

    auto it = validators.find(update.validatorId);
    if (it == validators.end()) {
        LogPrintf("ValidatorDB: Cannot update unknown validator %s\n",
                  update.validatorId.ToString());
        return false;
    }

    ValidatorEntry& entry = it->second;

    // Verify signature
    if (!update.Verify(entry.validatorPubKey)) {
        LogPrintf("ValidatorDB: Invalid signature on validator update\n");
        return false;
    }

    switch (update.updateType) {
        case ValidatorUpdateType::UPDATE_FEE:
            if (update.newValue < MIN_POOL_FEE || update.newValue > MAX_POOL_FEE) {
                LogPrintf("ValidatorDB: Invalid pool fee rate %lld\n", update.newValue);
                return false;
            }
            entry.poolFeeRate = update.newValue;
            LogPrintf("ValidatorDB: Updated validator %s fee to %lld bps\n",
                      entry.validatorId.ToString(), entry.poolFeeRate);
            break;

        case ValidatorUpdateType::UPDATE_NAME:
            if (update.newName.size() > MAX_VALIDATOR_NAME) {
                return false;
            }
            entry.validatorName = update.newName;
            LogPrintf("ValidatorDB: Updated validator %s name to '%s'\n",
                      entry.validatorId.ToString(), entry.validatorName);
            break;

        case ValidatorUpdateType::DEACTIVATE:
            entry.status = ValidatorStatus::UNBONDING;
            LogPrintf("ValidatorDB: Validator %s deactivating (unbonding)\n",
                      entry.validatorId.ToString());
            break;

        case ValidatorUpdateType::REACTIVATE:
            if (entry.status == ValidatorStatus::JAILED) {
                if (currentHeight < entry.jailReleaseHeight) {
                    LogPrintf("ValidatorDB: Cannot reactivate jailed validator %s until height %d\n",
                              entry.validatorId.ToString(), entry.jailReleaseHeight);
                    return false;
                }
            }
            if (entry.status == ValidatorStatus::INACTIVE ||
                entry.status == ValidatorStatus::JAILED) {
                entry.status = ValidatorStatus::ACTIVE;
                LogPrintf("ValidatorDB: Validator %s reactivated\n",
                          entry.validatorId.ToString());
            }
            break;

        case ValidatorUpdateType::INCREASE_STAKE:
            entry.stakeAmount += update.newValue;
            LogPrintf("ValidatorDB: Validator %s increased stake by %lld to %lld\n",
                      entry.validatorId.ToString(), update.newValue, entry.stakeAmount);
            break;

        case ValidatorUpdateType::DECREASE_STAKE:
            if (update.newValue > entry.stakeAmount) {
                return false;
            }
            if (entry.stakeAmount - update.newValue < consensusParams.nMinValidatorStake) {
                LogPrintf("ValidatorDB: Cannot reduce stake below minimum\n");
                return false;
            }
            entry.stakeAmount -= update.newValue;
            LogPrintf("ValidatorDB: Validator %s decreased stake by %lld to %lld\n",
                      entry.validatorId.ToString(), update.newValue, entry.stakeAmount);
            break;
    }

    return true;
}

bool ValidatorDB::UpdateStakeOutpoint(const CKeyID& validatorId, const COutPoint& newOutpoint) {
    LOCK(cs_validators);

    auto it = validators.find(validatorId);
    if (it == validators.end()) {
        return false;
    }

    // Remove old outpoint from index
    if (!it->second.stakeOutpoint.IsNull()) {
        outpointIndex.erase(it->second.stakeOutpoint);
    }

    // Update outpoint
    it->second.stakeOutpoint = newOutpoint;

    // Add new outpoint to index
    if (!newOutpoint.IsNull()) {
        outpointIndex[newOutpoint] = validatorId;
    }

    return true;
}

const ValidatorEntry* ValidatorDB::GetValidator(const CKeyID& validatorId) const {
    LOCK(cs_validators);
    auto it = validators.find(validatorId);
    if (it == validators.end()) {
        return nullptr;
    }
    return &it->second;
}

const ValidatorEntry* ValidatorDB::GetValidatorByOutpoint(const COutPoint& outpoint) const {
    LOCK(cs_validators);
    auto it = outpointIndex.find(outpoint);
    if (it == outpointIndex.end()) {
        return nullptr;
    }
    auto vit = validators.find(it->second);
    if (vit == validators.end()) {
        return nullptr;
    }
    return &vit->second;
}

bool ValidatorDB::IsValidatorStake(const COutPoint& outpoint) const {
    LOCK(cs_validators);
    return outpointIndex.count(outpoint) > 0;
}

std::vector<ValidatorEntry> ValidatorDB::GetActiveValidators() const {
    LOCK(cs_validators);
    std::vector<ValidatorEntry> result;
    for (const auto& [id, entry] : validators) {
        if (entry.status == ValidatorStatus::ACTIVE) {
            result.push_back(entry);
        }
    }
    return result;
}

std::vector<ValidatorEntry> ValidatorDB::GetValidatorsByStake() const {
    LOCK(cs_validators);
    std::vector<ValidatorEntry> result;
    for (const auto& [id, entry] : validators) {
        if (entry.status == ValidatorStatus::ACTIVE) {
            result.push_back(entry);
        }
    }
    std::sort(result.begin(), result.end(),
              [](const ValidatorEntry& a, const ValidatorEntry& b) {
                  return a.GetTotalStake() > b.GetTotalStake();
              });
    return result;
}

std::vector<ValidatorEntry> ValidatorDB::GetValidatorsByMaxFee(int64_t maxFeeRate) const {
    LOCK(cs_validators);
    std::vector<ValidatorEntry> result;
    for (const auto& [id, entry] : validators) {
        if (entry.status == ValidatorStatus::ACTIVE && entry.poolFeeRate <= maxFeeRate) {
            result.push_back(entry);
        }
    }
    std::sort(result.begin(), result.end(),
              [](const ValidatorEntry& a, const ValidatorEntry& b) {
                  return a.poolFeeRate < b.poolFeeRate;
              });
    return result;
}

bool ValidatorDB::SetValidatorStatus(const CKeyID& validatorId, ValidatorStatus status) {
    LOCK(cs_validators);
    auto it = validators.find(validatorId);
    if (it == validators.end()) {
        return false;
    }
    it->second.status = status;
    if (status == ValidatorStatus::ACTIVE) {
        it->second.lastActiveHeight = currentHeight;
    }
    return true;
}

bool ValidatorDB::JailValidator(const CKeyID& validatorId, int jailBlocks) {
    LOCK(cs_validators);
    auto it = validators.find(validatorId);
    if (it == validators.end()) {
        return false;
    }
    it->second.status = ValidatorStatus::JAILED;
    it->second.jailReleaseHeight = currentHeight + jailBlocks;
    LogPrintf("ValidatorDB: Jailed validator %s until height %d\n",
              validatorId.ToString(), it->second.jailReleaseHeight);
    return true;
}

bool ValidatorDB::UnjailValidator(const CKeyID& validatorId) {
    LOCK(cs_validators);
    auto it = validators.find(validatorId);
    if (it == validators.end()) {
        return false;
    }
    if (it->second.status != ValidatorStatus::JAILED) {
        return false;
    }
    if (currentHeight < it->second.jailReleaseHeight) {
        LogPrintf("ValidatorDB: Cannot unjail validator %s until height %d (current: %d)\n",
                  validatorId.ToString(), it->second.jailReleaseHeight, currentHeight);
        return false;
    }
    it->second.status = ValidatorStatus::ACTIVE;
    it->second.jailReleaseHeight = 0;
    LogPrintf("ValidatorDB: Unjailed validator %s\n", validatorId.ToString());
    return true;
}

size_t ValidatorDB::GetValidatorCount() const {
    LOCK(cs_validators);
    return validators.size();
}

size_t ValidatorDB::GetActiveValidatorCount() const {
    LOCK(cs_validators);
    size_t count = 0;
    for (const auto& [id, entry] : validators) {
        if (entry.status == ValidatorStatus::ACTIVE) {
            count++;
        }
    }
    return count;
}

bool ValidatorDB::AddDelegation(const CKeyID& validatorId, CAmount amount) {
    LOCK(cs_validators);
    auto it = validators.find(validatorId);
    if (it == validators.end()) {
        return false;
    }
    it->second.totalDelegated += amount;
    it->second.delegatorCount++;
    LogPrintf("ValidatorDB: Added delegation of %lld to validator %s (total: %lld, delegators: %d)\n",
              amount, validatorId.ToString(), it->second.totalDelegated, it->second.delegatorCount);
    return true;
}

bool ValidatorDB::RemoveDelegation(const CKeyID& validatorId, CAmount amount) {
    LOCK(cs_validators);
    auto it = validators.find(validatorId);
    if (it == validators.end()) {
        return false;
    }
    if (amount > it->second.totalDelegated) {
        return false;
    }
    it->second.totalDelegated -= amount;
    if (it->second.delegatorCount > 0) {
        it->second.delegatorCount--;
    }
    LogPrintf("ValidatorDB: Removed delegation of %lld from validator %s (total: %lld, delegators: %d)\n",
              amount, validatorId.ToString(), it->second.totalDelegated, it->second.delegatorCount);
    return true;
}

void ValidatorDB::ProcessBlock(int height) {
    LOCK(cs_validators);
    currentHeight = height;

    // Process unbonding validators
    for (auto& [id, entry] : validators) {
        // Check if unbonding period is complete
        if (entry.status == ValidatorStatus::UNBONDING) {
            if (height - entry.lastActiveHeight >= UNBONDING_PERIOD) {
                entry.status = ValidatorStatus::INACTIVE;
                LogPrintf("ValidatorDB: Validator %s unbonding complete, now inactive\n",
                          id.ToString());
            }
        }

        // Auto-unjail if jail period expired (validator still needs to reactivate)
        if (entry.status == ValidatorStatus::JAILED &&
            height >= entry.jailReleaseHeight) {
            // Don't auto-unjail, but log that they can now unjail
            LogPrintf("ValidatorDB: Validator %s jail period expired, can now unjail\n",
                      id.ToString());
        }
    }
}

} // namespace validators
