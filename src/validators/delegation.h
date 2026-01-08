// Copyright (c) 2024 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WATTX_VALIDATORS_DELEGATION_H
#define WATTX_VALIDATORS_DELEGATION_H

#include <consensus/params.h>
#include <key.h>
#include <pubkey.h>
#include <uint256.h>
#include <serialize.h>
#include <sync.h>
#include <primitives/transaction.h>

#include <cstdint>
#include <map>
#include <memory>
#include <vector>

namespace validators {

/**
 * Delegation status
 */
enum class DelegationStatus : uint8_t {
    PENDING = 0,      // Delegation pending (maturity)
    ACTIVE = 1,       // Active delegation
    UNBONDING = 2,    // Unbonding (waiting to withdraw)
    WITHDRAWN = 3     // Fully withdrawn
};

/**
 * Convert delegation status to string
 */
std::string DelegationStatusToString(DelegationStatus status);

/**
 * A single delegation entry
 */
class DelegationEntry {
public:
    CKeyID delegatorId;           // Delegator's public key ID
    CKeyID validatorId;           // Validator receiving the delegation
    CAmount amount;               // Amount delegated in satoshis
    int delegationHeight;         // Block height when delegation was created
    int lastRewardHeight;         // Last height rewards were claimed
    DelegationStatus status;      // Current delegation status
    COutPoint delegationOutpoint; // UTXO holding the delegated stake
    int unbondingStartHeight;     // Height when unbonding started
    CAmount pendingRewards;       // Accumulated unclaimed rewards

    DelegationEntry() : amount(0), delegationHeight(0), lastRewardHeight(0),
                        status(DelegationStatus::PENDING), unbondingStartHeight(0),
                        pendingRewards(0) {}

    SERIALIZE_METHODS(DelegationEntry, obj) {
        READWRITE(obj.delegatorId, obj.validatorId, obj.amount,
                  obj.delegationHeight, obj.lastRewardHeight,
                  Using<CustomUintFormatter<1>>(obj.status),
                  obj.delegationOutpoint, obj.unbondingStartHeight,
                  obj.pendingRewards);
    }

    /**
     * Check if delegation is active and earning rewards
     */
    bool IsActive() const { return status == DelegationStatus::ACTIVE; }

    /**
     * Get the unique delegation ID (hash of delegator + validator + height)
     */
    uint256 GetDelegationId() const;
};

/**
 * Delegation request for creating new delegation
 */
class DelegationRequest {
public:
    CKeyID delegatorId;
    CPubKey delegatorPubKey;
    CKeyID validatorId;
    CAmount amount;
    int height;
    std::vector<unsigned char> signature;

    DelegationRequest() : amount(0), height(0) {}

    SERIALIZE_METHODS(DelegationRequest, obj) {
        READWRITE(obj.delegatorId, obj.delegatorPubKey, obj.validatorId,
                  obj.amount, obj.height, obj.signature);
    }

    /**
     * Get hash for signing
     */
    uint256 GetHash() const;

    /**
     * Sign the request
     */
    bool Sign(const CKey& key);

    /**
     * Verify the signature
     */
    bool Verify() const;
};

/**
 * Undelegation request for withdrawing stake
 */
class UndelegationRequest {
public:
    CKeyID delegatorId;
    CKeyID validatorId;
    CAmount amount;           // Amount to undelegate (0 = all)
    int height;
    std::vector<unsigned char> signature;

    UndelegationRequest() : amount(0), height(0) {}

    SERIALIZE_METHODS(UndelegationRequest, obj) {
        READWRITE(obj.delegatorId, obj.validatorId, obj.amount,
                  obj.height, obj.signature);
    }

    /**
     * Get hash for signing
     */
    uint256 GetHash() const;

    /**
     * Sign the request
     */
    bool Sign(const CKey& key);

    /**
     * Verify the signature
     */
    bool Verify(const CPubKey& pubkey) const;
};

/**
 * Reward claim request
 */
class RewardClaimRequest {
public:
    CKeyID delegatorId;
    CKeyID validatorId;        // Specific validator, or empty for all
    int height;
    std::vector<unsigned char> signature;

    RewardClaimRequest() : height(0) {}

    SERIALIZE_METHODS(RewardClaimRequest, obj) {
        READWRITE(obj.delegatorId, obj.validatorId, obj.height, obj.signature);
    }

    /**
     * Get hash for signing
     */
    uint256 GetHash() const;

    /**
     * Sign the request
     */
    bool Sign(const CKey& key);

    /**
     * Verify the signature
     */
    bool Verify(const CPubKey& pubkey) const;
};

/**
 * Delegation database manager
 * Handles delegation, undelegation, and reward distribution
 */
class DelegationDB {
private:
    mutable Mutex cs_delegations;

    // Delegations indexed by delegation ID
    std::map<uint256, DelegationEntry> delegations;

    // Index: delegator -> list of delegation IDs
    std::map<CKeyID, std::vector<uint256>> delegatorIndex;

    // Index: validator -> list of delegation IDs
    std::map<CKeyID, std::vector<uint256>> validatorIndex;

    // Index: outpoint -> delegation ID
    std::map<COutPoint, uint256> outpointIndex;

    const Consensus::Params& consensusParams;
    int currentHeight;

public:
    explicit DelegationDB(const Consensus::Params& params);

    /**
     * Process a new delegation request
     */
    bool ProcessDelegation(const DelegationRequest& request, const COutPoint& outpoint);

    /**
     * Process an undelegation request
     */
    bool ProcessUndelegation(const UndelegationRequest& request);

    /**
     * Process a reward claim
     */
    CAmount ProcessRewardClaim(const RewardClaimRequest& request);

    /**
     * Get delegation by ID
     */
    const DelegationEntry* GetDelegation(const uint256& delegationId) const;

    /**
     * Get delegation by outpoint
     */
    const DelegationEntry* GetDelegationByOutpoint(const COutPoint& outpoint) const;

    /**
     * Get all delegations for a delegator
     */
    std::vector<DelegationEntry> GetDelegationsForDelegator(const CKeyID& delegatorId) const;

    /**
     * Get all delegations for a validator
     */
    std::vector<DelegationEntry> GetDelegationsForValidator(const CKeyID& validatorId) const;

    /**
     * Get total delegation amount for a validator
     */
    CAmount GetTotalDelegationForValidator(const CKeyID& validatorId) const;

    /**
     * Get total pending rewards for a delegator
     */
    CAmount GetPendingRewardsForDelegator(const CKeyID& delegatorId) const;

    /**
     * Add rewards to a delegation
     */
    bool AddRewards(const uint256& delegationId, CAmount rewards);

    /**
     * Distribute block reward to delegators of a validator
     * Called when a validator produces a block
     */
    bool DistributeBlockReward(const CKeyID& validatorId, CAmount delegatorsShare);

    /**
     * Update delegation status
     */
    bool SetDelegationStatus(const uint256& delegationId, DelegationStatus status);

    /**
     * Check if an outpoint is a delegation
     */
    bool IsDelegation(const COutPoint& outpoint) const;

    /**
     * Update delegation outpoint after UTXO moves
     */
    bool UpdateDelegationOutpoint(const uint256& delegationId, const COutPoint& newOutpoint);

    /**
     * Set current block height
     */
    void SetHeight(int height) { currentHeight = height; }

    /**
     * Process block (handle unbonding completions, etc.)
     */
    void ProcessBlock(int height);

    /**
     * Get count of active delegations
     */
    size_t GetActiveDelegationCount() const;

    /**
     * Get count of delegators for a validator
     */
    size_t GetDelegatorCountForValidator(const CKeyID& validatorId) const;

    /**
     * Serialize delegations to stream (for persistence)
     */
    template<typename Stream>
    void Serialize(Stream& s) const {
        LOCK(cs_delegations);
        s << delegations;
    }

    /**
     * Deserialize delegations from stream
     */
    template<typename Stream>
    void Unserialize(Stream& s) {
        LOCK(cs_delegations);
        s >> delegations;
        // Rebuild indexes
        delegatorIndex.clear();
        validatorIndex.clear();
        outpointIndex.clear();
        for (const auto& [id, entry] : delegations) {
            delegatorIndex[entry.delegatorId].push_back(id);
            validatorIndex[entry.validatorId].push_back(id);
            if (!entry.delegationOutpoint.IsNull()) {
                outpointIndex[entry.delegationOutpoint] = id;
            }
        }
    }
};

// Constants
static constexpr CAmount MIN_DELEGATION_AMOUNT = 1000LL * 100000000LL; // 1,000 WATTx minimum
static constexpr int DELEGATION_MATURITY = 500;                    // 500 blocks maturity
static constexpr int DELEGATION_UNBONDING_PERIOD = 259200;         // ~3 days at 1s blocks

/**
 * Global delegation database instance
 */
extern std::unique_ptr<DelegationDB> g_delegation_db;

/**
 * Initialize delegation database
 */
void InitDelegationDB(const Consensus::Params& params);

/**
 * Shutdown delegation database
 */
void ShutdownDelegationDB();

} // namespace validators

#endif // WATTX_VALIDATORS_DELEGATION_H
