// Copyright (c) 2024 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <validators/delegation.h>
#include <validators/validatordb.h>
#include <hash.h>
#include <logging.h>

#include <algorithm>

namespace validators {

// Global instance
std::unique_ptr<DelegationDB> g_delegation_db;

void InitDelegationDB(const Consensus::Params& params) {
    g_delegation_db = std::make_unique<DelegationDB>(params);
    LogPrintf("DelegationDB: Initialized delegation database\n");
}

void ShutdownDelegationDB() {
    g_delegation_db.reset();
    LogPrintf("DelegationDB: Shut down delegation database\n");
}

std::string DelegationStatusToString(DelegationStatus status) {
    switch (status) {
        case DelegationStatus::PENDING: return "pending";
        case DelegationStatus::ACTIVE: return "active";
        case DelegationStatus::UNBONDING: return "unbonding";
        case DelegationStatus::WITHDRAWN: return "withdrawn";
        default: return "unknown";
    }
}

// DelegationEntry implementation

uint256 DelegationEntry::GetDelegationId() const {
    HashWriter ss{};
    ss << delegatorId;
    ss << validatorId;
    ss << delegationHeight;
    return ss.GetHash();
}

// DelegationRequest implementation

uint256 DelegationRequest::GetHash() const {
    HashWriter ss{};
    ss << delegatorId;
    ss << delegatorPubKey;
    ss << validatorId;
    ss << amount;
    ss << height;
    return ss.GetHash();
}

bool DelegationRequest::Sign(const CKey& key) {
    uint256 hash = GetHash();
    return key.Sign(hash, signature);
}

bool DelegationRequest::Verify() const {
    uint256 hash = GetHash();
    return delegatorPubKey.Verify(hash, signature);
}

// UndelegationRequest implementation

uint256 UndelegationRequest::GetHash() const {
    HashWriter ss{};
    ss << delegatorId;
    ss << validatorId;
    ss << amount;
    ss << height;
    return ss.GetHash();
}

bool UndelegationRequest::Sign(const CKey& key) {
    uint256 hash = GetHash();
    return key.Sign(hash, signature);
}

bool UndelegationRequest::Verify(const CPubKey& pubkey) const {
    uint256 hash = GetHash();
    return pubkey.Verify(hash, signature);
}

// RewardClaimRequest implementation

uint256 RewardClaimRequest::GetHash() const {
    HashWriter ss{};
    ss << delegatorId;
    ss << validatorId;
    ss << height;
    return ss.GetHash();
}

bool RewardClaimRequest::Sign(const CKey& key) {
    uint256 hash = GetHash();
    return key.Sign(hash, signature);
}

bool RewardClaimRequest::Verify(const CPubKey& pubkey) const {
    uint256 hash = GetHash();
    return pubkey.Verify(hash, signature);
}

// DelegationDB implementation

DelegationDB::DelegationDB(const Consensus::Params& params)
    : consensusParams(params), currentHeight(0) {}

bool DelegationDB::ProcessDelegation(const DelegationRequest& request, const COutPoint& outpoint) {
    LOCK(cs_delegations);

    // Verify signature
    if (!request.Verify()) {
        LogPrintf("DelegationDB: Invalid delegation request signature\n");
        return false;
    }

    // Check minimum delegation amount
    if (request.amount < MIN_DELEGATION_AMOUNT) {
        LogPrintf("DelegationDB: Delegation amount %lld below minimum %lld\n",
                  request.amount, MIN_DELEGATION_AMOUNT);
        return false;
    }

    // Check if validator exists and is active
    if (g_validator_db) {
        const ValidatorEntry* validator = g_validator_db->GetValidator(request.validatorId);
        if (!validator) {
            LogPrintf("DelegationDB: Cannot delegate to unknown validator %s\n",
                      request.validatorId.ToString());
            return false;
        }
        if (validator->status != ValidatorStatus::ACTIVE) {
            LogPrintf("DelegationDB: Cannot delegate to inactive validator %s\n",
                      request.validatorId.ToString());
            return false;
        }
    }

    // Create delegation entry
    DelegationEntry entry;
    entry.delegatorId = request.delegatorId;
    entry.validatorId = request.validatorId;
    entry.amount = request.amount;
    entry.delegationHeight = request.height;
    entry.lastRewardHeight = request.height;
    entry.status = DelegationStatus::PENDING;
    entry.delegationOutpoint = outpoint;
    entry.unbondingStartHeight = 0;
    entry.pendingRewards = 0;

    uint256 delegationId = entry.GetDelegationId();

    // Check for duplicate
    if (delegations.count(delegationId) > 0) {
        LogPrintf("DelegationDB: Duplicate delegation ID %s\n", delegationId.ToString());
        return false;
    }

    // Add to database
    delegations[delegationId] = entry;

    // Update indexes
    delegatorIndex[entry.delegatorId].push_back(delegationId);
    validatorIndex[entry.validatorId].push_back(delegationId);
    if (!outpoint.IsNull()) {
        outpointIndex[outpoint] = delegationId;
    }

    // Update validator's delegated amount
    if (g_validator_db) {
        g_validator_db->AddDelegation(request.validatorId, request.amount);
    }

    LogPrintf("DelegationDB: Created delegation %s: %lld WATTx from %s to validator %s\n",
              delegationId.ToString().substr(0, 16), request.amount / 100000000,
              request.delegatorId.ToString(), request.validatorId.ToString());

    return true;
}

bool DelegationDB::ProcessUndelegation(const UndelegationRequest& request) {
    LOCK(cs_delegations);

    // Find delegations from this delegator to this validator
    auto it = delegatorIndex.find(request.delegatorId);
    if (it == delegatorIndex.end()) {
        LogPrintf("DelegationDB: No delegations found for delegator %s\n",
                  request.delegatorId.ToString());
        return false;
    }

    CAmount remainingToUndelegate = request.amount;
    bool anyUndelegated = false;

    for (const auto& delegationId : it->second) {
        auto delIt = delegations.find(delegationId);
        if (delIt == delegations.end()) continue;

        DelegationEntry& entry = delIt->second;

        // Only process active delegations to the specified validator
        if (entry.validatorId != request.validatorId) continue;
        if (entry.status != DelegationStatus::ACTIVE) continue;

        CAmount toUndelegate;
        if (request.amount == 0) {
            // Undelegate all
            toUndelegate = entry.amount;
        } else if (remainingToUndelegate >= entry.amount) {
            toUndelegate = entry.amount;
            remainingToUndelegate -= entry.amount;
        } else {
            toUndelegate = remainingToUndelegate;
            remainingToUndelegate = 0;
        }

        // Start unbonding
        entry.status = DelegationStatus::UNBONDING;
        entry.unbondingStartHeight = currentHeight;

        // Update validator's delegated amount
        if (g_validator_db) {
            g_validator_db->RemoveDelegation(request.validatorId, toUndelegate);
        }

        LogPrintf("DelegationDB: Started unbonding delegation %s: %lld WATTx\n",
                  delegationId.ToString().substr(0, 16), toUndelegate / 100000000);

        anyUndelegated = true;

        if (remainingToUndelegate == 0) break;
    }

    return anyUndelegated;
}

CAmount DelegationDB::ProcessRewardClaim(const RewardClaimRequest& request) {
    LOCK(cs_delegations);

    CAmount totalClaimed = 0;

    // Find delegations for this delegator
    auto it = delegatorIndex.find(request.delegatorId);
    if (it == delegatorIndex.end()) {
        return 0;
    }

    for (const auto& delegationId : it->second) {
        auto delIt = delegations.find(delegationId);
        if (delIt == delegations.end()) continue;

        DelegationEntry& entry = delIt->second;

        // If specific validator requested, filter
        if (!request.validatorId.IsNull() && entry.validatorId != request.validatorId) {
            continue;
        }

        // Claim pending rewards
        if (entry.pendingRewards > 0) {
            totalClaimed += entry.pendingRewards;
            entry.pendingRewards = 0;
            entry.lastRewardHeight = currentHeight;
        }
    }

    if (totalClaimed > 0) {
        LogPrintf("DelegationDB: Claimed %lld rewards for delegator %s\n",
                  totalClaimed / 100000000, request.delegatorId.ToString());
    }

    return totalClaimed;
}

const DelegationEntry* DelegationDB::GetDelegation(const uint256& delegationId) const {
    LOCK(cs_delegations);
    auto it = delegations.find(delegationId);
    if (it == delegations.end()) {
        return nullptr;
    }
    return &it->second;
}

const DelegationEntry* DelegationDB::GetDelegationByOutpoint(const COutPoint& outpoint) const {
    LOCK(cs_delegations);
    auto it = outpointIndex.find(outpoint);
    if (it == outpointIndex.end()) {
        return nullptr;
    }
    auto delIt = delegations.find(it->second);
    if (delIt == delegations.end()) {
        return nullptr;
    }
    return &delIt->second;
}

std::vector<DelegationEntry> DelegationDB::GetDelegationsForDelegator(const CKeyID& delegatorId) const {
    LOCK(cs_delegations);
    std::vector<DelegationEntry> result;

    auto it = delegatorIndex.find(delegatorId);
    if (it == delegatorIndex.end()) {
        return result;
    }

    for (const auto& delegationId : it->second) {
        auto delIt = delegations.find(delegationId);
        if (delIt != delegations.end()) {
            result.push_back(delIt->second);
        }
    }

    return result;
}

std::vector<DelegationEntry> DelegationDB::GetDelegationsForValidator(const CKeyID& validatorId) const {
    LOCK(cs_delegations);
    std::vector<DelegationEntry> result;

    auto it = validatorIndex.find(validatorId);
    if (it == validatorIndex.end()) {
        return result;
    }

    for (const auto& delegationId : it->second) {
        auto delIt = delegations.find(delegationId);
        if (delIt != delegations.end()) {
            result.push_back(delIt->second);
        }
    }

    return result;
}

CAmount DelegationDB::GetTotalDelegationForValidator(const CKeyID& validatorId) const {
    LOCK(cs_delegations);
    CAmount total = 0;

    auto it = validatorIndex.find(validatorId);
    if (it == validatorIndex.end()) {
        return total;
    }

    for (const auto& delegationId : it->second) {
        auto delIt = delegations.find(delegationId);
        if (delIt != delegations.end() && delIt->second.status == DelegationStatus::ACTIVE) {
            total += delIt->second.amount;
        }
    }

    return total;
}

CAmount DelegationDB::GetPendingRewardsForDelegator(const CKeyID& delegatorId) const {
    LOCK(cs_delegations);
    CAmount total = 0;

    auto it = delegatorIndex.find(delegatorId);
    if (it == delegatorIndex.end()) {
        return total;
    }

    for (const auto& delegationId : it->second) {
        auto delIt = delegations.find(delegationId);
        if (delIt != delegations.end()) {
            total += delIt->second.pendingRewards;
        }
    }

    return total;
}

bool DelegationDB::AddRewards(const uint256& delegationId, CAmount rewards) {
    LOCK(cs_delegations);
    auto it = delegations.find(delegationId);
    if (it == delegations.end()) {
        return false;
    }
    it->second.pendingRewards += rewards;
    return true;
}

bool DelegationDB::DistributeBlockReward(const CKeyID& validatorId, CAmount delegatorsShare) {
    LOCK(cs_delegations);

    if (delegatorsShare == 0) {
        return true;
    }

    // Get total active delegation for this validator
    CAmount totalDelegation = GetTotalDelegationForValidator(validatorId);
    if (totalDelegation == 0) {
        return true;
    }

    // Distribute proportionally to each delegator
    auto it = validatorIndex.find(validatorId);
    if (it == validatorIndex.end()) {
        return true;
    }

    for (const auto& delegationId : it->second) {
        auto delIt = delegations.find(delegationId);
        if (delIt == delegations.end()) continue;

        DelegationEntry& entry = delIt->second;
        if (entry.status != DelegationStatus::ACTIVE) continue;

        // Calculate proportional share
        CAmount share = (delegatorsShare * entry.amount) / totalDelegation;
        if (share > 0) {
            entry.pendingRewards += share;
        }
    }

    LogPrintf("DelegationDB: Distributed %lld to delegators of validator %s\n",
              delegatorsShare, validatorId.ToString());

    return true;
}

bool DelegationDB::SetDelegationStatus(const uint256& delegationId, DelegationStatus status) {
    LOCK(cs_delegations);
    auto it = delegations.find(delegationId);
    if (it == delegations.end()) {
        return false;
    }
    it->second.status = status;
    return true;
}

bool DelegationDB::IsDelegation(const COutPoint& outpoint) const {
    LOCK(cs_delegations);
    return outpointIndex.count(outpoint) > 0;
}

bool DelegationDB::UpdateDelegationOutpoint(const uint256& delegationId, const COutPoint& newOutpoint) {
    LOCK(cs_delegations);
    auto it = delegations.find(delegationId);
    if (it == delegations.end()) {
        return false;
    }

    // Remove old outpoint from index
    if (!it->second.delegationOutpoint.IsNull()) {
        outpointIndex.erase(it->second.delegationOutpoint);
    }

    // Update outpoint
    it->second.delegationOutpoint = newOutpoint;

    // Add new outpoint to index
    if (!newOutpoint.IsNull()) {
        outpointIndex[newOutpoint] = delegationId;
    }

    return true;
}

void DelegationDB::ProcessBlock(int height) {
    LOCK(cs_delegations);
    currentHeight = height;

    for (auto& [id, entry] : delegations) {
        // Activate pending delegations after maturity
        if (entry.status == DelegationStatus::PENDING) {
            if (height - entry.delegationHeight >= DELEGATION_MATURITY) {
                entry.status = DelegationStatus::ACTIVE;
                LogPrintf("DelegationDB: Delegation %s is now active\n",
                          id.ToString().substr(0, 16));
            }
        }

        // Complete unbonding
        if (entry.status == DelegationStatus::UNBONDING) {
            if (height - entry.unbondingStartHeight >= DELEGATION_UNBONDING_PERIOD) {
                entry.status = DelegationStatus::WITHDRAWN;
                LogPrintf("DelegationDB: Delegation %s unbonding complete\n",
                          id.ToString().substr(0, 16));
            }
        }
    }
}

size_t DelegationDB::GetActiveDelegationCount() const {
    LOCK(cs_delegations);
    size_t count = 0;
    for (const auto& [id, entry] : delegations) {
        if (entry.status == DelegationStatus::ACTIVE) {
            count++;
        }
    }
    return count;
}

size_t DelegationDB::GetDelegatorCountForValidator(const CKeyID& validatorId) const {
    LOCK(cs_delegations);
    std::set<CKeyID> uniqueDelegators;

    auto it = validatorIndex.find(validatorId);
    if (it == validatorIndex.end()) {
        return 0;
    }

    for (const auto& delegationId : it->second) {
        auto delIt = delegations.find(delegationId);
        if (delIt != delegations.end() && delIt->second.status == DelegationStatus::ACTIVE) {
            uniqueDelegators.insert(delIt->second.delegatorId);
        }
    }

    return uniqueDelegators.size();
}

} // namespace validators
