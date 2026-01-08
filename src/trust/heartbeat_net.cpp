// Copyright (c) 2024 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <trust/heartbeat_net.h>
#include <hash.h>
#include <logging.h>
#include <net.h>
#include <util/time.h>

namespace trust {

// Global instance
std::unique_ptr<HeartbeatManager> g_heartbeat_manager;

void InitHeartbeatManager(TrustScoreManager& trustManager, const Consensus::Params& params) {
    g_heartbeat_manager = std::make_unique<HeartbeatManager>(trustManager, params);
}

void ShutdownHeartbeatManager() {
    g_heartbeat_manager.reset();
}

// ValidatorRegistration implementation

uint256 ValidatorRegistration::GetHash() const {
    HashWriter ss{};
    ss << validatorPubKey;
    ss << stakeAmount;
    ss << poolFeeRate;
    ss << registrationHeight;
    return ss.GetHash();
}

bool ValidatorRegistration::Sign(const CKey& key) {
    uint256 hash = GetHash();
    return key.Sign(hash, signature);
}

bool ValidatorRegistration::Verify() const {
    uint256 hash = GetHash();
    return validatorPubKey.Verify(hash, signature);
}

// HeartbeatManager implementation

HeartbeatManager::HeartbeatManager(TrustScoreManager& trustManager, const Consensus::Params& params)
    : m_trust_manager(trustManager), m_consensus_params(params) {}

void HeartbeatManager::SetValidatorKey(const CKey& key) {
    LOCK(cs_heartbeat);
    m_validator_key = std::make_unique<CKey>(key);
    m_is_validator = true;
    LogPrintf("HeartbeatManager: Configured as validator with pubkey %s\n",
              HexStr(key.GetPubKey()));
}

bool HeartbeatManager::IsValidator() const {
    LOCK(cs_heartbeat);
    return m_is_validator && m_validator_key != nullptr;
}

CKeyID HeartbeatManager::GetValidatorId() const {
    LOCK(cs_heartbeat);
    if (!m_validator_key) {
        return CKeyID();
    }
    return m_validator_key->GetPubKey().GetID();
}

bool HeartbeatManager::ShouldBroadcastHeartbeat(int currentHeight) const {
    LOCK(cs_heartbeat);
    if (!m_is_validator || !m_validator_key) {
        return false;
    }

    // Check if enough blocks have passed since last heartbeat
    int interval = m_consensus_params.nHeartbeatInterval;
    if (currentHeight - m_last_heartbeat_height < interval) {
        return false;
    }

    // Check if we're at a heartbeat boundary
    return (currentHeight % interval) == 0;
}

bool HeartbeatManager::BroadcastHeartbeat(int blockHeight, const uint256& blockHash) {
    LOCK(cs_heartbeat);

    if (!m_is_validator || !m_validator_key) {
        return false;
    }

    // Create heartbeat
    Heartbeat hb;
    hb.validatorId = m_validator_key->GetPubKey().GetID();
    hb.blockHeight = blockHeight;
    hb.blockHash = blockHash;
    hb.timestamp = GetTime();

    // WATTx: Include our IP address for peer discovery
    // TODO: Get local address from connman when networking is fully integrated
    hb.nodePort = 18888; // Default WATTx port

    // Sign it (signature includes IP address)
    if (!hb.Sign(*m_validator_key)) {
        LogPrintf("HeartbeatManager: Failed to sign heartbeat\n");
        return false;
    }

    // Record that we've seen our own heartbeat
    m_seen_heartbeats.insert(hb.GetHash());

    // Update last broadcast height
    m_last_heartbeat_height = blockHeight;

    // TODO: Broadcast to network via net_processing when fully integrated
    // The heartbeat message will be relayed via the P2P protocol

    LogPrintf("HeartbeatManager: Broadcast heartbeat at height %d from %s\n",
              blockHeight, hb.GetNodeAddressString());
    return true;
}

bool HeartbeatManager::ProcessHeartbeat(const Heartbeat& heartbeat, NodeId from) {
    LOCK(cs_heartbeat);

    // Check if we've already seen this heartbeat
    uint256 hbHash = heartbeat.GetHash();
    if (m_seen_heartbeats.count(hbHash) > 0) {
        return false; // Already processed
    }

    // Add to seen set
    m_seen_heartbeats.insert(hbHash);

    // Clean up if too many
    if (m_seen_heartbeats.size() > MAX_SEEN_HEARTBEATS) {
        CleanupSeenHeartbeats();
    }

    // Process the heartbeat in the trust manager
    if (!m_trust_manager.ProcessHeartbeat(heartbeat, heartbeat.blockHeight)) {
        LogPrintf("HeartbeatManager: Failed to process heartbeat from validator\n");
        return false;
    }

    // WATTx: Process IP address for trust scoring and peer discovery
    if (heartbeat.nodeAddress.IsValid()) {
        // Update validator's address in trust manager
        m_trust_manager.UpdateValidatorAddress(heartbeat.validatorId,
                                               heartbeat.nodeAddress,
                                               heartbeat.timestamp);

        // Trigger auto-peer discovery - add new validator peers automatically
        if (g_peer_discovery && g_peer_discovery->ProcessValidatorAddress(
                heartbeat.nodeAddress, heartbeat.validatorId)) {

            // New peer discovered - add it automatically via addnode
            if (m_connman) {
                LogPrintf("HeartbeatManager: Auto-adding validator peer %s\n",
                          heartbeat.nodeAddress.ToStringAddrPort());

                // Add the node (equivalent to addnode "ip:port" add)
                AddedNodeParams params;
                params.m_added_node = heartbeat.nodeAddress.ToStringAddrPort();
                params.m_use_v2transport = true;
                m_connman->AddNode(params);

                // Mark as added so we don't try again
                g_peer_discovery->MarkPeerAdded(heartbeat.nodeAddress);
            }
        }
    }

    // TODO: Relay to other peers via net_processing when fully integrated

    LogPrintf("HeartbeatManager: Processed heartbeat from validator at height %d (IP: %s)\n",
              heartbeat.blockHeight, heartbeat.GetNodeAddressString());
    return true;
}

bool HeartbeatManager::ProcessValidatorRegistration(const ValidatorRegistration& reg, NodeId from) {
    // Verify signature
    if (!reg.Verify()) {
        LogPrintf("HeartbeatManager: Invalid validator registration signature\n");
        return false;
    }

    // Verify stake amount meets minimum
    if (reg.stakeAmount < m_consensus_params.nMinValidatorStake) {
        LogPrintf("HeartbeatManager: Validator stake %lld below minimum %lld\n",
                  reg.stakeAmount, m_consensus_params.nMinValidatorStake);
        return false;
    }

    // Register with trust manager
    CKeyID validatorId = reg.validatorPubKey.GetID();
    if (!m_trust_manager.RegisterValidator(validatorId, reg.stakeAmount,
                                           reg.poolFeeRate, reg.registrationHeight)) {
        LogPrintf("HeartbeatManager: Failed to register validator\n");
        return false;
    }

    // TODO: Relay to other peers via net_processing when fully integrated

    LogPrintf("HeartbeatManager: Registered validator with stake %lld\n", reg.stakeAmount);
    return true;
}

bool HeartbeatManager::CreateRegistration(int64_t stakeAmount, int64_t poolFeeRate,
                                          int height, ValidatorRegistration& regOut) {
    LOCK(cs_heartbeat);

    if (!m_is_validator || !m_validator_key) {
        return false;
    }

    regOut.validatorPubKey = m_validator_key->GetPubKey();
    regOut.stakeAmount = stakeAmount;
    regOut.poolFeeRate = poolFeeRate;
    regOut.registrationHeight = height;

    if (!regOut.Sign(*m_validator_key)) {
        return false;
    }

    return true;
}

ValidatorList HeartbeatManager::GetValidatorList() const {
    ValidatorList list;
    list.validators = m_trust_manager.GetActiveValidators();
    return list;
}

void HeartbeatManager::ProcessValidatorList(const ValidatorList& list) {
    // Process each validator in the list
    // This is used for initial sync when connecting to the network
    for (const auto& info : list.validators) {
        if (info.isActive && info.MeetsMinimumStake(m_consensus_params)) {
            // Re-register the validator if we don't know about them
            const ValidatorInfo* existing = m_trust_manager.GetValidator(info.validatorId);
            if (!existing) {
                m_trust_manager.RegisterValidator(info.validatorId, info.stakeAmount,
                                                  info.poolFeeRate, info.registrationHeight);
            }
        }
    }
}

void HeartbeatManager::OnNewBlock(int height) {
    // Update heartbeat expectations in trust manager
    m_trust_manager.UpdateHeartbeatExpectations(height);
    m_trust_manager.SetHeight(height);

    // Check if we should broadcast a heartbeat
    if (ShouldBroadcastHeartbeat(height)) {
        // Note: We need the block hash here - this would be called from validation
        // with the actual block hash
        LogPrintf("HeartbeatManager: Time to broadcast heartbeat at height %d\n", height);
    }
}

void HeartbeatManager::CleanupSeenHeartbeats() {
    LOCK(cs_heartbeat);
    // Simple cleanup: just clear half when we hit the limit
    // In production, would want time-based expiry
    if (m_seen_heartbeats.size() > MAX_SEEN_HEARTBEATS / 2) {
        auto it = m_seen_heartbeats.begin();
        std::advance(it, m_seen_heartbeats.size() / 2);
        m_seen_heartbeats.erase(m_seen_heartbeats.begin(), it);
    }
}

HeartbeatManager::Stats HeartbeatManager::GetStats() const {
    LOCK(cs_heartbeat);
    Stats stats;
    stats.isValidator = m_is_validator;
    stats.lastHeartbeatHeight = m_last_heartbeat_height;
    stats.seenHeartbeats = m_seen_heartbeats.size();
    stats.activeValidators = m_trust_manager.GetActiveValidators().size();
    return stats;
}

} // namespace trust
