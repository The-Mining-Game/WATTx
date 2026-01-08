// Copyright (c) 2024 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <trust/trustscore.h>
#include <hash.h>
#include <logging.h>
#include <netbase.h>
#include <util/time.h>
#include <fstream>
#include <sstream>

namespace trust {

// Global peer discovery manager
std::unique_ptr<PeerDiscoveryManager> g_peer_discovery;

void InitPeerDiscovery(const std::string& dataDir) {
    g_peer_discovery = std::make_unique<PeerDiscoveryManager>();
    g_peer_discovery->SetConfigPath(dataDir + "/validator_peers.conf");
    g_peer_discovery->LoadPeersFromConfig();
    LogPrintf("PeerDiscovery: Initialized with %d known peers\n", g_peer_discovery->GetKnownPeerCount());
}

void ShutdownPeerDiscovery() {
    if (g_peer_discovery) {
        g_peer_discovery->SavePeersToConfig();
    }
    g_peer_discovery.reset();
}

std::string TrustTierToString(TrustTier tier) {
    switch (tier) {
        case TrustTier::NONE:     return "NONE";
        case TrustTier::BRONZE:   return "BRONZE";
        case TrustTier::SILVER:   return "SILVER";
        case TrustTier::GOLD:     return "GOLD";
        case TrustTier::PLATINUM: return "PLATINUM";
        default:                  return "UNKNOWN";
    }
}

// ValidatorInfo implementation

int ValidatorInfo::GetUptimePercentage() const {
    if (heartbeatsExpected == 0) {
        return 1000; // 100% if no heartbeats expected yet
    }
    return (heartbeatsReceived * 1000) / heartbeatsExpected;
}

TrustTier ValidatorInfo::GetTrustTier(const Consensus::Params& params) const {
    if (!isActive || stakeAmount < params.nMinValidatorStake) {
        return TrustTier::NONE;
    }

    int uptime = GetUptimePercentage();

    if (uptime >= params.nPlatinumUptimeThreshold) {
        return TrustTier::PLATINUM;
    } else if (uptime >= params.nGoldUptimeThreshold) {
        return TrustTier::GOLD;
    } else if (uptime >= params.nSilverUptimeThreshold) {
        return TrustTier::SILVER;
    } else if (uptime >= params.nBronzeUptimeThreshold) {
        return TrustTier::BRONZE;
    }

    return TrustTier::NONE;
}

int ValidatorInfo::GetRewardMultiplier(const Consensus::Params& params) const {
    TrustTier tier = GetTrustTier(params);

    switch (tier) {
        case TrustTier::PLATINUM: return params.nPlatinumRewardMultiplier;
        case TrustTier::GOLD:     return params.nGoldRewardMultiplier;
        case TrustTier::SILVER:   return params.nSilverRewardMultiplier;
        case TrustTier::BRONZE:   return params.nBronzeRewardMultiplier;
        default:                  return 0; // No reward if not eligible
    }
}

bool ValidatorInfo::MeetsMinimumStake(const Consensus::Params& params) const {
    return stakeAmount >= params.nMinValidatorStake;
}

bool ValidatorInfo::IsEligibleForStaking(const Consensus::Params& params) const {
    if (!isActive) return false;
    if (!MeetsMinimumStake(params)) return false;
    if (GetTrustTier(params) == TrustTier::NONE) return false;
    return true;
}

std::string ValidatorInfo::GetIPAddress() const {
    if (!lastKnownAddress.IsValid()) {
        return "";
    }
    return lastKnownAddress.ToStringAddr();
}

// Heartbeat implementation

uint256 Heartbeat::GetHash() const {
    HashWriter ss{};
    ss << validatorId;
    ss << blockHeight;
    ss << blockHash;
    ss << timestamp;
    // Use string representation for hashing since CService serialization
    // requires version parameters not available with HashWriter
    std::string addrStr = nodeAddress.ToStringAddrPort();
    ss << addrStr;
    ss << nodePort;
    return ss.GetHash();
}

std::string Heartbeat::GetNodeAddressString() const {
    if (!nodeAddress.IsValid()) {
        return "";
    }
    return nodeAddress.ToStringAddrPort();
}

bool Heartbeat::Sign(const CKey& key) {
    uint256 hash = GetHash();
    return key.Sign(hash, signature);
}

bool Heartbeat::Verify(const CPubKey& pubkey) const {
    uint256 hash = GetHash();
    return pubkey.Verify(hash, signature);
}

// TrustScoreManager implementation

TrustScoreManager::TrustScoreManager(const Consensus::Params& params)
    : consensusParams(params), currentHeight(0) {}

bool TrustScoreManager::RegisterValidator(const CKeyID& validatorId,
                                          int64_t stakeAmount,
                                          int64_t poolFeeRate,
                                          int height) {
    // Check minimum stake
    if (stakeAmount < consensusParams.nMinValidatorStake) {
        LogPrintf("TrustScoreManager: Validator registration failed - insufficient stake %lld < %lld\n",
                  stakeAmount, consensusParams.nMinValidatorStake);
        return false;
    }

    // Check if already registered
    if (validators.find(validatorId) != validators.end()) {
        LogPrintf("TrustScoreManager: Validator already registered\n");
        return false;
    }

    // Validate pool fee rate (0-10000 basis points = 0-100%)
    if (poolFeeRate < 0 || poolFeeRate > 10000) {
        LogPrintf("TrustScoreManager: Invalid pool fee rate %lld\n", poolFeeRate);
        return false;
    }

    ValidatorInfo info;
    info.validatorId = validatorId;
    info.stakeAmount = stakeAmount;
    info.poolFeeRate = poolFeeRate;
    info.registrationHeight = height;
    info.lastHeartbeatHeight = height;
    info.heartbeatsExpected = 0;
    info.heartbeatsReceived = 0;
    info.isActive = true;

    validators[validatorId] = info;

    LogPrintf("TrustScoreManager: Registered validator with stake %lld, fee rate %lld bps\n",
              stakeAmount, poolFeeRate);
    return true;
}

bool TrustScoreManager::UpdateStake(const CKeyID& validatorId, int64_t newStakeAmount) {
    auto it = validators.find(validatorId);
    if (it == validators.end()) {
        return false;
    }

    it->second.stakeAmount = newStakeAmount;

    // Deactivate if below minimum
    if (newStakeAmount < consensusParams.nMinValidatorStake) {
        it->second.isActive = false;
        LogPrintf("TrustScoreManager: Validator deactivated - stake below minimum\n");
    }

    return true;
}

bool TrustScoreManager::UpdatePoolFee(const CKeyID& validatorId, int64_t newFeeRate) {
    auto it = validators.find(validatorId);
    if (it == validators.end()) {
        return false;
    }

    if (newFeeRate < 0 || newFeeRate > 10000) {
        return false;
    }

    it->second.poolFeeRate = newFeeRate;
    return true;
}

bool TrustScoreManager::ProcessHeartbeat(const Heartbeat& heartbeat, int height) {
    auto it = validators.find(heartbeat.validatorId);
    if (it == validators.end()) {
        LogPrintf("TrustScoreManager: Heartbeat from unknown validator\n");
        return false;
    }

    if (!it->second.isActive) {
        LogPrintf("TrustScoreManager: Heartbeat from inactive validator\n");
        return false;
    }

    // Check heartbeat is for current window
    int expectedInterval = consensusParams.nHeartbeatInterval;
    int lastHeartbeat = it->second.lastHeartbeatHeight;

    if (height < lastHeartbeat + expectedInterval) {
        // Too early for next heartbeat
        return false;
    }

    // Record heartbeat
    it->second.heartbeatsReceived++;
    it->second.lastHeartbeatHeight = height;

    LogPrintf("TrustScoreManager: Processed heartbeat from validator at height %d\n", height);
    return true;
}

void TrustScoreManager::UpdateHeartbeatExpectations(int height) {
    currentHeight = height;

    for (auto& [id, info] : validators) {
        if (!info.isActive) continue;

        // Calculate expected heartbeats since registration
        int blocksSinceRegistration = height - info.registrationHeight;
        if (blocksSinceRegistration > 0) {
            info.heartbeatsExpected = blocksSinceRegistration / consensusParams.nHeartbeatInterval;
        }

        // Apply uptime window limit
        int windowBlocks = std::min(blocksSinceRegistration, consensusParams.nUptimeWindow);
        if (windowBlocks > 0) {
            info.heartbeatsExpected = windowBlocks / consensusParams.nHeartbeatInterval;
        }
    }
}

const ValidatorInfo* TrustScoreManager::GetValidator(const CKeyID& validatorId) const {
    auto it = validators.find(validatorId);
    if (it == validators.end()) {
        return nullptr;
    }
    return &it->second;
}

TrustTier TrustScoreManager::GetValidatorTier(const CKeyID& validatorId) const {
    const ValidatorInfo* info = GetValidator(validatorId);
    if (!info) {
        return TrustTier::NONE;
    }
    return info->GetTrustTier(consensusParams);
}

int TrustScoreManager::GetValidatorRewardMultiplier(const CKeyID& validatorId) const {
    const ValidatorInfo* info = GetValidator(validatorId);
    if (!info) {
        return 0;
    }
    return info->GetRewardMultiplier(consensusParams);
}

bool TrustScoreManager::IsValidatorEligible(const CKeyID& validatorId) const {
    const ValidatorInfo* info = GetValidator(validatorId);
    if (!info) {
        return false;
    }
    return info->IsEligibleForStaking(consensusParams);
}

std::vector<ValidatorInfo> TrustScoreManager::GetActiveValidators() const {
    std::vector<ValidatorInfo> result;
    for (const auto& [id, info] : validators) {
        if (info.isActive) {
            result.push_back(info);
        }
    }
    return result;
}

std::vector<ValidatorInfo> TrustScoreManager::GetValidatorsByTier(TrustTier tier) const {
    std::vector<ValidatorInfo> result;
    for (const auto& [id, info] : validators) {
        if (info.isActive && info.GetTrustTier(consensusParams) == tier) {
            result.push_back(info);
        }
    }
    return result;
}

bool TrustScoreManager::DeactivateValidator(const CKeyID& validatorId) {
    auto it = validators.find(validatorId);
    if (it == validators.end()) {
        return false;
    }
    it->second.isActive = false;
    return true;
}

//////////////////////////////////////////////////
// WATTx IP-Based Trust & Peer Discovery
//////////////////////////////////////////////////

bool TrustScoreManager::UpdateValidatorAddress(const CKeyID& validatorId, const CService& address, int64_t timestamp) {
    auto it = validators.find(validatorId);
    if (it == validators.end()) {
        LogPrintf("TrustScoreManager: Cannot update address for unknown validator\n");
        return false;
    }

    if (!address.IsValid()) {
        LogPrintf("TrustScoreManager: Invalid address for validator check-in\n");
        return false;
    }

    // Update validator's address info
    it->second.lastKnownAddress = address;
    it->second.lastCheckInTime = timestamp;
    it->second.consecutiveCheckIns++;

    LogPrintf("TrustScoreManager: Validator %s checked in from %s (consecutive: %d)\n",
              validatorId.ToString(), address.ToStringAddrPort(), it->second.consecutiveCheckIns);

    // Notify peer discovery manager
    if (g_peer_discovery) {
        g_peer_discovery->ProcessValidatorAddress(address, validatorId);
    }

    return true;
}

std::vector<CService> TrustScoreManager::GetValidatorAddresses() const {
    std::vector<CService> addresses;
    for (const auto& [id, info] : validators) {
        if (info.isActive && info.lastKnownAddress.IsValid()) {
            addresses.push_back(info.lastKnownAddress);
        }
    }
    return addresses;
}

std::vector<CService> TrustScoreManager::GetTrustedValidatorAddresses(TrustTier minTier) const {
    std::vector<CService> addresses;
    for (const auto& [id, info] : validators) {
        if (info.isActive && info.lastKnownAddress.IsValid()) {
            TrustTier tier = info.GetTrustTier(consensusParams);
            if (static_cast<int>(tier) >= static_cast<int>(minTier)) {
                addresses.push_back(info.lastKnownAddress);
            }
        }
    }
    return addresses;
}

bool TrustScoreManager::IsValidatorAddress(const CService& address) const {
    for (const auto& [id, info] : validators) {
        if (info.isActive && info.lastKnownAddress == address) {
            return true;
        }
    }
    return false;
}

CKeyID TrustScoreManager::GetValidatorIdByAddress(const CService& address) const {
    for (const auto& [id, info] : validators) {
        if (info.lastKnownAddress == address) {
            return info.validatorId;
        }
    }
    return CKeyID();
}

void TrustScoreManager::RecordMissedCheckIns(int currentHeight) {
    int expectedInterval = consensusParams.nHeartbeatInterval;

    for (auto& [id, info] : validators) {
        if (!info.isActive) continue;

        // Check if validator should have checked in by now
        int blocksSinceLastCheckIn = currentHeight - info.lastHeartbeatHeight;
        if (blocksSinceLastCheckIn > expectedInterval * 2) {
            // Missed at least one check-in
            info.missedCheckIns++;
            info.consecutiveCheckIns = 0;
            LogPrintf("TrustScoreManager: Validator %s missed check-in (total missed: %d)\n",
                      id.ToString(), info.missedCheckIns);
        }
    }
}

//////////////////////////////////////////////////
// PeerDiscoveryManager Implementation
//////////////////////////////////////////////////

PeerDiscoveryManager::PeerDiscoveryManager() {}

void PeerDiscoveryManager::SetConfigPath(const std::string& path) {
    LOCK(cs_peers);
    configFilePath = path;
}

bool PeerDiscoveryManager::ProcessValidatorAddress(const CService& address, const CKeyID& validatorId) {
    LOCK(cs_peers);

    if (!address.IsValid()) {
        return false;
    }

    // Check if we already know this peer
    if (knownValidatorPeers.count(address) > 0) {
        return false; // Already known
    }

    // Add to pending list for addnode
    pendingAdditions.insert(address);
    knownValidatorPeers.insert(address);

    LogPrintf("PeerDiscovery: New validator peer discovered: %s (validator: %s)\n",
              address.ToStringAddrPort(), validatorId.ToString());

    return true;
}

std::vector<CService> PeerDiscoveryManager::GetPendingPeers() {
    LOCK(cs_peers);
    std::vector<CService> result(pendingAdditions.begin(), pendingAdditions.end());
    return result;
}

void PeerDiscoveryManager::MarkPeerAdded(const CService& address) {
    LOCK(cs_peers);
    pendingAdditions.erase(address);
}

bool PeerDiscoveryManager::SavePeersToConfig() {
    LOCK(cs_peers);

    if (configFilePath.empty()) {
        return false;
    }

    try {
        std::ofstream file(configFilePath, std::ios::out | std::ios::trunc);
        if (!file.is_open()) {
            LogPrintf("PeerDiscovery: Failed to open config file for writing: %s\n", configFilePath);
            return false;
        }

        file << "# WATTx Validator Peers - Auto-generated\n";
        file << "# These peers were discovered from validator heartbeats\n";
        file << "# Format: addnode=IP:PORT\n\n";

        for (const auto& peer : knownValidatorPeers) {
            file << "addnode=" << peer.ToStringAddrPort() << "\n";
        }

        file.close();
        LogPrintf("PeerDiscovery: Saved %d validator peers to %s\n",
                  knownValidatorPeers.size(), configFilePath);
        return true;
    } catch (const std::exception& e) {
        LogPrintf("PeerDiscovery: Error saving peers: %s\n", e.what());
        return false;
    }
}

bool PeerDiscoveryManager::LoadPeersFromConfig() {
    LOCK(cs_peers);

    if (configFilePath.empty()) {
        return false;
    }

    try {
        std::ifstream file(configFilePath);
        if (!file.is_open()) {
            // File doesn't exist yet, that's okay
            return true;
        }

        std::string line;
        int loadedCount = 0;

        while (std::getline(file, line)) {
            // Skip comments and empty lines
            if (line.empty() || line[0] == '#') {
                continue;
            }

            // Parse addnode=IP:PORT format
            size_t pos = line.find("addnode=");
            if (pos == std::string::npos) {
                continue;
            }

            std::string addrStr = line.substr(pos + 8);
            // Trim whitespace
            addrStr.erase(0, addrStr.find_first_not_of(" \t"));
            addrStr.erase(addrStr.find_last_not_of(" \t\r\n") + 1);

            if (!addrStr.empty()) {
                CService addr = LookupNumeric(addrStr, 18888);
                if (addr.IsValid()) {
                    knownValidatorPeers.insert(addr);
                    loadedCount++;
                }
            }
        }

        file.close();
        LogPrintf("PeerDiscovery: Loaded %d validator peers from %s\n", loadedCount, configFilePath);
        return true;
    } catch (const std::exception& e) {
        LogPrintf("PeerDiscovery: Error loading peers: %s\n", e.what());
        return false;
    }
}

std::string PeerDiscoveryManager::GetAddNodeCommand(const CService& address) {
    return "addnode \"" + address.ToStringAddrPort() + "\" add";
}

bool PeerDiscoveryManager::IsKnownPeer(const CService& address) const {
    LOCK(cs_peers);
    return knownValidatorPeers.count(address) > 0;
}

size_t PeerDiscoveryManager::GetKnownPeerCount() const {
    LOCK(cs_peers);
    return knownValidatorPeers.size();
}

} // namespace trust
