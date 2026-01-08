// Copyright (c) 2024 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WATTX_TRUST_HEARTBEAT_NET_H
#define WATTX_TRUST_HEARTBEAT_NET_H

#include <trust/trustscore.h>
#include <net.h>
#include <protocol.h>
#include <sync.h>
#include <uint256.h>
#include <key.h>

#include <atomic>
#include <memory>
#include <set>

class CChainState;
class CConnman;

namespace trust {

/**
 * Network message for validator registration announcement
 */
class ValidatorRegistration {
public:
    CPubKey validatorPubKey;
    int64_t stakeAmount;
    int64_t poolFeeRate;  // Basis points (100 = 1%)
    int registrationHeight;
    std::vector<unsigned char> signature;

    ValidatorRegistration() : stakeAmount(0), poolFeeRate(0), registrationHeight(0) {}

    SERIALIZE_METHODS(ValidatorRegistration, obj) {
        READWRITE(obj.validatorPubKey, obj.stakeAmount, obj.poolFeeRate,
                  obj.registrationHeight, obj.signature);
    }

    uint256 GetHash() const;
    bool Sign(const CKey& key);
    bool Verify() const;
};

/**
 * Network message containing list of validators
 */
class ValidatorList {
public:
    std::vector<ValidatorInfo> validators;

    SERIALIZE_METHODS(ValidatorList, obj) {
        READWRITE(obj.validators);
    }
};

/**
 * Heartbeat network manager - handles broadcasting and receiving heartbeats
 */
class HeartbeatManager {
private:
    mutable Mutex cs_heartbeat;

    // Our validator key (if we are a validator)
    std::unique_ptr<CKey> m_validator_key GUARDED_BY(cs_heartbeat);
    bool m_is_validator GUARDED_BY(cs_heartbeat){false};

    // Trust score manager reference
    TrustScoreManager& m_trust_manager;

    // Consensus params
    const Consensus::Params& m_consensus_params;

    // Recently seen heartbeats (to prevent replay)
    std::set<uint256> m_seen_heartbeats GUARDED_BY(cs_heartbeat);
    static constexpr size_t MAX_SEEN_HEARTBEATS = 10000;

    // Last heartbeat height we broadcast
    int m_last_heartbeat_height GUARDED_BY(cs_heartbeat){0};

    // Connection manager for broadcasting
    CConnman* m_connman{nullptr};

public:
    HeartbeatManager(TrustScoreManager& trustManager, const Consensus::Params& params);

    /**
     * Set this node as a validator with the given key
     */
    void SetValidatorKey(const CKey& key);

    /**
     * Check if this node is configured as a validator
     */
    bool IsValidator() const;

    /**
     * Get our validator public key ID
     */
    CKeyID GetValidatorId() const;

    /**
     * Set the connection manager for broadcasting
     */
    void SetConnman(CConnman* connman) { m_connman = connman; }

    /**
     * Check if we should broadcast a heartbeat at this height
     */
    bool ShouldBroadcastHeartbeat(int currentHeight) const;

    /**
     * Create and broadcast a heartbeat for the current block
     */
    bool BroadcastHeartbeat(int blockHeight, const uint256& blockHash);

    /**
     * Process a received heartbeat message
     * Returns true if the heartbeat was valid and new
     */
    bool ProcessHeartbeat(const Heartbeat& heartbeat, NodeId from);

    /**
     * Process a validator registration message
     */
    bool ProcessValidatorRegistration(const ValidatorRegistration& reg, NodeId from);

    /**
     * Create a validator registration message for this node
     */
    bool CreateRegistration(int64_t stakeAmount, int64_t poolFeeRate,
                           int height, ValidatorRegistration& regOut);

    /**
     * Get list of active validators for responding to getvalidators
     */
    ValidatorList GetValidatorList() const;

    /**
     * Process received validator list
     */
    void ProcessValidatorList(const ValidatorList& list);

    /**
     * Update heartbeat expectations at new block height
     */
    void OnNewBlock(int height);

    /**
     * Clean up old seen heartbeats to prevent memory growth
     */
    void CleanupSeenHeartbeats();

    /**
     * Get statistics for logging/RPC
     */
    struct Stats {
        bool isValidator;
        int lastHeartbeatHeight;
        size_t seenHeartbeats;
        int activeValidators;
    };
    Stats GetStats() const;

    /**
     * Get reference to trust manager for RPC queries
     */
    TrustScoreManager* GetTrustManager() { return &m_trust_manager; }
    const TrustScoreManager* GetTrustManager() const { return &m_trust_manager; }
};

/**
 * Global heartbeat manager instance
 */
extern std::unique_ptr<HeartbeatManager> g_heartbeat_manager;

/**
 * Initialize the heartbeat manager
 */
void InitHeartbeatManager(TrustScoreManager& trustManager, const Consensus::Params& params);

/**
 * Shutdown the heartbeat manager
 */
void ShutdownHeartbeatManager();

} // namespace trust

#endif // WATTX_TRUST_HEARTBEAT_NET_H
