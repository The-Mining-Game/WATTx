// Copyright (c) 2024 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WATTX_TRUST_TRUSTSCORE_H
#define WATTX_TRUST_TRUSTSCORE_H

#include <consensus/params.h>
#include <key.h>
#include <pubkey.h>
#include <uint256.h>
#include <serialize.h>
#include <netaddress.h>
#include <netbase.h>
#include <sync.h>

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace trust {

/**
 * Trust tier levels for WATTx validators
 */
enum class TrustTier : uint8_t {
    NONE = 0,      // Below minimum requirements
    BRONZE = 1,    // 95%+ uptime
    SILVER = 2,    // 97%+ uptime
    GOLD = 3,      // 99%+ uptime
    PLATINUM = 4   // 99.9%+ uptime
};

/**
 * Get the string name for a trust tier
 */
std::string TrustTierToString(TrustTier tier);

/**
 * Validator information including trust score and uptime
 */
class ValidatorInfo {
public:
    CKeyID validatorId;           // Validator's public key ID
    int64_t stakeAmount;          // Amount staked in satoshis
    int64_t poolFeeRate;          // Pool fee rate in basis points (100 = 1%)
    int registrationHeight;       // Block height when validator registered
    int lastHeartbeatHeight;      // Last heartbeat block height
    int heartbeatsExpected;       // Total heartbeats expected since registration
    int heartbeatsReceived;       // Total heartbeats actually received
    bool isActive;                // Whether validator is currently active

    // WATTx: IP-based trust tracking
    CService lastKnownAddress;    // Last known IP:port of the validator
    int64_t lastCheckInTime;      // Unix timestamp of last check-in
    int consecutiveCheckIns;      // Consecutive successful check-ins
    int missedCheckIns;           // Total missed check-ins

    ValidatorInfo() : stakeAmount(0), poolFeeRate(0), registrationHeight(0),
                      lastHeartbeatHeight(0), heartbeatsExpected(0),
                      heartbeatsReceived(0), isActive(false),
                      lastCheckInTime(0), consecutiveCheckIns(0), missedCheckIns(0) {}

    // Custom serialization to handle CService without requiring SerParams
    template<typename Stream>
    void Serialize(Stream& s) const {
        ::Serialize(s, validatorId);
        ::Serialize(s, stakeAmount);
        ::Serialize(s, poolFeeRate);
        ::Serialize(s, registrationHeight);
        ::Serialize(s, lastHeartbeatHeight);
        ::Serialize(s, heartbeatsExpected);
        ::Serialize(s, heartbeatsReceived);
        ::Serialize(s, isActive);
        // Serialize CService as string
        std::string addrStr = lastKnownAddress.ToStringAddrPort();
        ::Serialize(s, addrStr);
        ::Serialize(s, lastCheckInTime);
        ::Serialize(s, consecutiveCheckIns);
        ::Serialize(s, missedCheckIns);
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        ::Unserialize(s, validatorId);
        ::Unserialize(s, stakeAmount);
        ::Unserialize(s, poolFeeRate);
        ::Unserialize(s, registrationHeight);
        ::Unserialize(s, lastHeartbeatHeight);
        ::Unserialize(s, heartbeatsExpected);
        ::Unserialize(s, heartbeatsReceived);
        ::Unserialize(s, isActive);
        // Deserialize address string and parse
        std::string addrStr;
        ::Unserialize(s, addrStr);
        if (!addrStr.empty()) {
            lastKnownAddress = LookupNumeric(addrStr, 18888);
        }
        ::Unserialize(s, lastCheckInTime);
        ::Unserialize(s, consecutiveCheckIns);
        ::Unserialize(s, missedCheckIns);
    }

    /**
     * Get the validator's IP address as string
     */
    std::string GetIPAddress() const;

    /**
     * Calculate uptime percentage (multiplied by 10 for precision)
     * Returns value like 950 for 95.0%
     */
    int GetUptimePercentage() const;

    /**
     * Determine trust tier based on uptime
     */
    TrustTier GetTrustTier(const Consensus::Params& params) const;

    /**
     * Get reward multiplier based on trust tier (percentage, 100 = 1.0x)
     */
    int GetRewardMultiplier(const Consensus::Params& params) const;

    /**
     * Check if validator meets minimum stake requirement
     */
    bool MeetsMinimumStake(const Consensus::Params& params) const;

    /**
     * Check if validator is eligible for staking
     */
    bool IsEligibleForStaking(const Consensus::Params& params) const;
};

/**
 * Heartbeat message broadcasted by validators
 * WATTx: Includes IP address for trust scoring and peer discovery
 */
class Heartbeat {
public:
    CKeyID validatorId;           // Validator's public key ID
    int blockHeight;              // Block height at which heartbeat was created
    uint256 blockHash;            // Hash of the block at blockHeight
    int64_t timestamp;            // Unix timestamp
    CService nodeAddress;         // WATTx: Node's IP address and port for peer discovery
    uint16_t nodePort;            // WATTx: Node's listening port
    std::vector<unsigned char> signature;  // Signature proving validator identity

    Heartbeat() : blockHeight(0), timestamp(0), nodePort(18888) {}

    // Custom serialization to handle CService without requiring SerParams
    template<typename Stream>
    void Serialize(Stream& s) const {
        ::Serialize(s, validatorId);
        ::Serialize(s, blockHeight);
        ::Serialize(s, blockHash);
        ::Serialize(s, timestamp);
        // Serialize CService as string to avoid params requirement
        std::string addrStr = nodeAddress.ToStringAddrPort();
        ::Serialize(s, addrStr);
        ::Serialize(s, nodePort);
        ::Serialize(s, signature);
    }

    template<typename Stream>
    void Unserialize(Stream& s) {
        ::Unserialize(s, validatorId);
        ::Unserialize(s, blockHeight);
        ::Unserialize(s, blockHash);
        ::Unserialize(s, timestamp);
        // Deserialize address string and parse
        std::string addrStr;
        ::Unserialize(s, addrStr);
        if (!addrStr.empty()) {
            nodeAddress = LookupNumeric(addrStr, 18888);
        }
        ::Unserialize(s, nodePort);
        ::Unserialize(s, signature);
    }

    /**
     * Get the hash of this heartbeat for signing
     */
    uint256 GetHash() const;

    /**
     * Sign the heartbeat with the validator's private key
     */
    bool Sign(const CKey& key);

    /**
     * Verify the heartbeat signature
     */
    bool Verify(const CPubKey& pubkey) const;

    /**
     * Get the node address as a string for addnode command
     */
    std::string GetNodeAddressString() const;
};

/**
 * Trust score manager - handles validator registration, heartbeat tracking, and tier calculation
 */
class TrustScoreManager {
private:
    std::map<CKeyID, ValidatorInfo> validators;
    const Consensus::Params& consensusParams;
    int currentHeight;

public:
    explicit TrustScoreManager(const Consensus::Params& params);

    /**
     * Register a new validator
     */
    bool RegisterValidator(const CKeyID& validatorId, int64_t stakeAmount,
                          int64_t poolFeeRate, int height);

    /**
     * Update validator stake amount
     */
    bool UpdateStake(const CKeyID& validatorId, int64_t newStakeAmount);

    /**
     * Update validator pool fee rate
     */
    bool UpdatePoolFee(const CKeyID& validatorId, int64_t newFeeRate);

    /**
     * Process a heartbeat from a validator
     */
    bool ProcessHeartbeat(const Heartbeat& heartbeat, int height);

    /**
     * Update expected heartbeats for all validators at new block height
     */
    void UpdateHeartbeatExpectations(int height);

    /**
     * Get validator info by ID
     */
    const ValidatorInfo* GetValidator(const CKeyID& validatorId) const;

    /**
     * Get trust tier for a validator
     */
    TrustTier GetValidatorTier(const CKeyID& validatorId) const;

    /**
     * Get reward multiplier for a validator
     */
    int GetValidatorRewardMultiplier(const CKeyID& validatorId) const;

    /**
     * Check if a validator is eligible to stake
     */
    bool IsValidatorEligible(const CKeyID& validatorId) const;

    /**
     * Get all active validators
     */
    std::vector<ValidatorInfo> GetActiveValidators() const;

    /**
     * Get validators by tier
     */
    std::vector<ValidatorInfo> GetValidatorsByTier(TrustTier tier) const;

    /**
     * Deactivate a validator
     */
    bool DeactivateValidator(const CKeyID& validatorId);

    /**
     * Set current block height for calculations
     */
    void SetHeight(int height) { currentHeight = height; }

    //////////////////////////////////////////////////
    // WATTx IP-Based Trust & Peer Discovery
    //////////////////////////////////////////////////

    /**
     * Update validator's IP address from heartbeat check-in
     */
    bool UpdateValidatorAddress(const CKeyID& validatorId, const CService& address, int64_t timestamp);

    /**
     * Get all known validator addresses for peer discovery
     */
    std::vector<CService> GetValidatorAddresses() const;

    /**
     * Get addresses of validators with minimum trust tier
     */
    std::vector<CService> GetTrustedValidatorAddresses(TrustTier minTier) const;

    /**
     * Check if an IP address belongs to a registered validator
     */
    bool IsValidatorAddress(const CService& address) const;

    /**
     * Get validator ID from IP address (if known)
     */
    CKeyID GetValidatorIdByAddress(const CService& address) const;

    /**
     * Record a missed check-in for validators that didn't report
     */
    void RecordMissedCheckIns(int currentHeight);
};

/**
 * Auto-peer discovery manager for WATTx
 * Handles automatic peer connections from validator heartbeats
 */
class PeerDiscoveryManager {
private:
    std::set<CService> knownValidatorPeers;
    std::set<CService> pendingAdditions;
    std::string configFilePath;
    mutable Mutex cs_peers;

public:
    PeerDiscoveryManager();

    /**
     * Set the path to the config file for persisting peers
     */
    void SetConfigPath(const std::string& path);

    /**
     * Process a new validator address from heartbeat
     * Returns true if this is a new peer to add
     */
    bool ProcessValidatorAddress(const CService& address, const CKeyID& validatorId);

    /**
     * Get list of peers pending addition via addnode
     */
    std::vector<CService> GetPendingPeers();

    /**
     * Mark a peer as successfully added
     */
    void MarkPeerAdded(const CService& address);

    /**
     * Save known validator peers to config file
     */
    bool SavePeersToConfig();

    /**
     * Load known validator peers from config file
     */
    bool LoadPeersFromConfig();

    /**
     * Get the addnode command string for a peer
     */
    static std::string GetAddNodeCommand(const CService& address);

    /**
     * Check if we already know about this peer
     */
    bool IsKnownPeer(const CService& address) const;

    /**
     * Get count of known validator peers
     */
    size_t GetKnownPeerCount() const;
};

/**
 * Global peer discovery manager instance
 */
extern std::unique_ptr<PeerDiscoveryManager> g_peer_discovery;

/**
 * Initialize peer discovery manager
 */
void InitPeerDiscovery(const std::string& dataDir);

/**
 * Shutdown peer discovery manager
 */
void ShutdownPeerDiscovery();

} // namespace trust

#endif // WATTX_TRUST_TRUSTSCORE_H
