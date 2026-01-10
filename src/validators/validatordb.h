// Copyright (c) 2024 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WATTX_VALIDATORS_VALIDATORDB_H
#define WATTX_VALIDATORS_VALIDATORDB_H

#include <consensus/params.h>
#include <dbwrapper.h>
#include <key.h>
#include <pubkey.h>
#include <uint256.h>
#include <serialize.h>
#include <sync.h>
#include <primitives/transaction.h>
#include <util/fs.h>

#include <cstdint>
#include <map>
#include <string>
#include <vector>
#include <memory>

namespace validators {

/**
 * Validator status enumeration
 */
enum class ValidatorStatus : uint8_t {
    PENDING = 0,      // Registration pending (maturity)
    ACTIVE = 1,       // Active and eligible for staking
    INACTIVE = 2,     // Voluntarily deactivated
    JAILED = 3,       // Jailed due to misbehavior/downtime
    UNBONDING = 4     // In unbonding period after deactivation
};

/**
 * Convert validator status to string
 */
std::string ValidatorStatusToString(ValidatorStatus status);

/**
 * Validator entry stored in the database
 */
class ValidatorEntry {
public:
    CKeyID validatorId;             // Validator's public key ID
    CPubKey validatorPubKey;        // Validator's full public key
    CAmount stakeAmount;            // Self-stake amount in satoshis
    int64_t poolFeeRate;            // Pool fee rate in basis points (100 = 1%)
    int registrationHeight;         // Block height when validator registered
    int lastActiveHeight;           // Last block height when validator was active
    ValidatorStatus status;         // Current validator status
    std::string validatorName;      // Optional validator name/alias (max 64 chars)
    COutPoint stakeOutpoint;        // UTXO holding the validator's stake
    int jailReleaseHeight;          // Height at which validator can be unjailed
    int64_t totalDelegated;         // Total amount delegated to this validator
    int delegatorCount;             // Number of delegators

    ValidatorEntry() : stakeAmount(0), poolFeeRate(0), registrationHeight(0),
                       lastActiveHeight(0), status(ValidatorStatus::PENDING),
                       jailReleaseHeight(0), totalDelegated(0), delegatorCount(0) {}

    SERIALIZE_METHODS(ValidatorEntry, obj) {
        READWRITE(obj.validatorId, obj.validatorPubKey, obj.stakeAmount,
                  obj.poolFeeRate, obj.registrationHeight, obj.lastActiveHeight);
        // Handle enum serialization manually
        uint8_t status_byte;
        SER_WRITE(obj, status_byte = static_cast<uint8_t>(obj.status));
        READWRITE(status_byte);
        SER_READ(obj, obj.status = static_cast<ValidatorStatus>(status_byte));
        READWRITE(obj.validatorName, obj.stakeOutpoint, obj.jailReleaseHeight,
                  obj.totalDelegated, obj.delegatorCount);
    }

    /**
     * Get total stake (self + delegated)
     */
    CAmount GetTotalStake() const { return stakeAmount + totalDelegated; }

    /**
     * Check if validator is active
     */
    bool IsActive() const { return status == ValidatorStatus::ACTIVE; }

    /**
     * Check if validator meets minimum stake requirement
     */
    bool MeetsMinimumStake(const Consensus::Params& params) const;

    /**
     * Check if validator is eligible for staking
     */
    bool IsEligibleForStaking(const Consensus::Params& params, int currentHeight) const;

    /**
     * Calculate validator's share of block reward
     * Returns amount in satoshis
     */
    CAmount CalculateValidatorReward(CAmount blockReward) const;

    /**
     * Calculate delegators' total share of block reward
     */
    CAmount CalculateDelegatorsReward(CAmount blockReward) const;
};

/**
 * Validator update types for modification transactions
 */
enum class ValidatorUpdateType : uint8_t {
    UPDATE_FEE = 1,           // Update pool fee rate
    UPDATE_NAME = 2,          // Update validator name
    DEACTIVATE = 3,           // Voluntarily deactivate
    REACTIVATE = 4,           // Reactivate after deactivation
    INCREASE_STAKE = 5,       // Add more stake
    DECREASE_STAKE = 6        // Reduce stake (triggers unbonding)
};

/**
 * Validator update entry
 */
class ValidatorUpdate {
public:
    CKeyID validatorId;
    ValidatorUpdateType updateType;
    int64_t newValue;           // New fee rate or stake delta
    std::string newName;        // New name (for UPDATE_NAME)
    int updateHeight;           // Block height of update
    std::vector<unsigned char> signature;

    ValidatorUpdate() : updateType(ValidatorUpdateType::UPDATE_FEE),
                        newValue(0), updateHeight(0) {}

    SERIALIZE_METHODS(ValidatorUpdate, obj) {
        READWRITE(obj.validatorId);
        uint8_t type_byte;
        SER_WRITE(obj, type_byte = static_cast<uint8_t>(obj.updateType));
        READWRITE(type_byte);
        SER_READ(obj, obj.updateType = static_cast<ValidatorUpdateType>(type_byte));
        READWRITE(obj.newValue, obj.newName, obj.updateHeight, obj.signature);
    }

    /**
     * Get hash for signing
     */
    uint256 GetHash() const;

    /**
     * Sign the update
     */
    bool Sign(const CKey& key);

    /**
     * Verify the signature
     */
    bool Verify(const CPubKey& pubkey) const;
};

/**
 * Validator database manager
 * Handles registration, updates, and queries for validators
 * Uses LevelDB for persistent storage
 */
class ValidatorDB {
private:
    mutable Mutex cs_validators;
    std::map<CKeyID, ValidatorEntry> validators;
    const Consensus::Params& consensusParams;
    int currentHeight;

    // Index by stake outpoint for quick lookup
    std::map<COutPoint, CKeyID> outpointIndex;

    // LevelDB persistence
    std::unique_ptr<CDBWrapper> m_db;

    // Database keys
    static constexpr uint8_t DB_VALIDATOR = 'v';
    static constexpr uint8_t DB_METADATA = 'm';

    // Internal persistence methods
    bool WriteValidatorToDB(const ValidatorEntry& entry);
    bool EraseValidatorFromDB(const CKeyID& validatorId);
    bool LoadFromDB();

public:
    ValidatorDB(const Consensus::Params& params, const fs::path& path, size_t cache_size = 1 << 20, bool memory_only = false);

    /**
     * Register a new validator
     */
    bool RegisterValidator(const ValidatorEntry& entry);

    /**
     * Process a validator update
     */
    bool ProcessUpdate(const ValidatorUpdate& update);

    /**
     * Update validator's stake UTXO after it moves
     */
    bool UpdateStakeOutpoint(const CKeyID& validatorId, const COutPoint& newOutpoint);

    /**
     * Get validator by ID
     */
    const ValidatorEntry* GetValidator(const CKeyID& validatorId) const;

    /**
     * Get validator by stake outpoint
     */
    const ValidatorEntry* GetValidatorByOutpoint(const COutPoint& outpoint) const;

    /**
     * Check if a UTXO is a validator stake
     */
    bool IsValidatorStake(const COutPoint& outpoint) const;

    /**
     * Get all active validators
     */
    std::vector<ValidatorEntry> GetActiveValidators() const;

    /**
     * Get validators sorted by total stake (descending)
     */
    std::vector<ValidatorEntry> GetValidatorsByStake() const;

    /**
     * Get validators with pool fee at or below given rate
     */
    std::vector<ValidatorEntry> GetValidatorsByMaxFee(int64_t maxFeeRate) const;

    /**
     * Update validator status
     */
    bool SetValidatorStatus(const CKeyID& validatorId, ValidatorStatus status);

    /**
     * Jail a validator for misbehavior
     */
    bool JailValidator(const CKeyID& validatorId, int jailBlocks);

    /**
     * Unjail a validator (if jail period has expired)
     */
    bool UnjailValidator(const CKeyID& validatorId);

    /**
     * Set current block height
     */
    void SetHeight(int height) { currentHeight = height; }

    /**
     * Get total validator count
     */
    size_t GetValidatorCount() const;

    /**
     * Get active validator count
     */
    size_t GetActiveValidatorCount() const;

    /**
     * Add delegated stake to a validator
     */
    bool AddDelegation(const CKeyID& validatorId, CAmount amount);

    /**
     * Remove delegated stake from a validator
     */
    bool RemoveDelegation(const CKeyID& validatorId, CAmount amount);

    /**
     * Process block (update heights, check jails, etc.)
     */
    void ProcessBlock(int height);

    /**
     * Serialize validators to stream (for persistence)
     */
    template<typename Stream>
    void Serialize(Stream& s) const {
        LOCK(cs_validators);
        s << validators;
    }

    /**
     * Deserialize validators from stream
     */
    template<typename Stream>
    void Unserialize(Stream& s) {
        LOCK(cs_validators);
        s >> validators;
        // Rebuild outpoint index
        outpointIndex.clear();
        for (const auto& [id, entry] : validators) {
            if (!entry.stakeOutpoint.IsNull()) {
                outpointIndex[entry.stakeOutpoint] = id;
            }
        }
    }
};

// Constants
static constexpr int64_t MIN_POOL_FEE = 0;        // 0%
static constexpr int64_t MAX_POOL_FEE = 10000;    // 100%
static constexpr int64_t DEFAULT_POOL_FEE = 1000; // 10%
static constexpr size_t MAX_VALIDATOR_NAME = 64;
static constexpr int DEFAULT_JAIL_BLOCKS = 86400; // ~1 day at 1s blocks
static constexpr int UNBONDING_PERIOD = 259200;   // ~3 days at 1s blocks

/**
 * Global validator database instance
 */
extern std::unique_ptr<ValidatorDB> g_validator_db;

/**
 * Initialize validator database with persistence
 * @param params Consensus parameters
 * @param path Data directory for LevelDB storage
 * @param cache_size LevelDB cache size in bytes
 */
void InitValidatorDB(const Consensus::Params& params, const fs::path& path, size_t cache_size = 1 << 20);

/**
 * Shutdown validator database (flushes to disk)
 */
void ShutdownValidatorDB();

} // namespace validators

#endif // WATTX_VALIDATORS_VALIDATORDB_H
