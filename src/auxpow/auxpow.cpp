// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <auxpow/auxpow.h>
#include <arith_uint256.h>
#include <hash.h>
#include <logging.h>
#include <node/randomx_miner.h>
#include <streams.h>
#include <util/strencodings.h>

#include <cstring>

// ============================================================================
// CMoneroBlockHeader
// ============================================================================

uint256 CMoneroBlockHeader::GetHash() const {
    // Monero uses a different serialization for hashing
    // This creates the "blob" that gets hashed
    DataStream ss{};
    ss << major_version;
    ss << minor_version;
    ss << VARINT(timestamp);
    ss << prev_id;
    ss << nonce;
    // Note: Monero's actual hashing is more complex with tree hash
    // This is simplified for merged mining purposes
    return Hash(ss);
}

uint256 CMoneroBlockHeader::GetPoWHash() const {
    // Create the blob for RandomX hashing
    // Monero hashing blob format (76 bytes):
    //   - major_version: 1 byte
    //   - minor_version: 1 byte
    //   - timestamp: varint (typically 5 bytes for current timestamps)
    //   - prev_id: 32 bytes
    //   - nonce: 4 bytes
    //   - tree_root (merkle_root): 32 bytes
    //   - tx_count as varint: 1 byte (for tree hash calculation context)
    //
    // Total: ~76 bytes (varies slightly due to varint encoding)

    std::vector<unsigned char> blob;
    blob.reserve(76);

    // Major version (1 byte)
    blob.push_back(major_version);

    // Minor version (1 byte)
    blob.push_back(minor_version);

    // Timestamp as varint
    uint64_t ts = timestamp;
    while (ts >= 0x80) {
        blob.push_back((ts & 0x7F) | 0x80);
        ts >>= 7;
    }
    blob.push_back(static_cast<uint8_t>(ts));

    // Previous block hash (32 bytes)
    blob.insert(blob.end(), prev_id.begin(), prev_id.end());

    // Nonce (4 bytes, little-endian)
    blob.push_back((nonce >> 0) & 0xFF);
    blob.push_back((nonce >> 8) & 0xFF);
    blob.push_back((nonce >> 16) & 0xFF);
    blob.push_back((nonce >> 24) & 0xFF);

    // Tree root / merkle_root (32 bytes)
    blob.insert(blob.end(), merkle_root.begin(), merkle_root.end());

    // Pad to 76 bytes if needed (Monero expects fixed size for RandomX)
    while (blob.size() < 76) {
        blob.push_back(0);
    }

    // Calculate RandomX hash
    uint256 hash;
    auto& miner = node::GetRandomXMiner();
    if (miner.IsInitialized()) {
        miner.CalculateHash(blob.data(), blob.size(), hash.data());
    } else {
        // Fallback: use SHA256d if RandomX not initialized
        hash = Hash(blob);
        LogPrintf("AuxPoW: Warning - RandomX not initialized, using SHA256d fallback\n");
    }

    return hash;
}

// ============================================================================
// CMerkleBranch
// ============================================================================

uint256 CMerkleBranch::GetRoot(const uint256& leaf) const {
    if (vHash.empty()) {
        return leaf;
    }

    uint256 hash = leaf;
    int idx = nIndex;

    for (const auto& branchHash : vHash) {
        if (idx & 1) {
            hash = Hash(branchHash, hash);
        } else {
            hash = Hash(hash, branchHash);
        }
        idx >>= 1;
    }

    return hash;
}

// ============================================================================
// CAuxPow
// ============================================================================

bool CAuxPow::Check(const uint256& hashAuxBlock, int expectedChainId) const {
    // 1. Verify chain ID matches
    if (nChainId != expectedChainId) {
        LogPrintf("AuxPoW: Chain ID mismatch (got %d, expected %d)\n",
                  nChainId, expectedChainId);
        return false;
    }

    // 2. Extract merkle root from coinbase extra field
    uint256 auxMerkleRoot;
    if (!GetAuxChainMerkleRoot(auxMerkleRoot)) {
        LogPrintf("AuxPoW: Failed to extract aux merkle root from coinbase\n");
        return false;
    }

    // 3. Calculate expected aux chain merkle root
    uint256 expectedRoot = auxpow::CalcAuxChainMerkleRoot(hashAuxBlock, nChainId);

    // 4. For single aux chain (depth 0), the merkle root should match directly
    //    For multiple chains, verify merkle path
    uint256 calculatedRoot;
    if (auxChainBranch.IsNull()) {
        // Single aux chain
        calculatedRoot = expectedRoot;
    } else {
        // Multiple aux chains - calculate root from branch
        calculatedRoot = auxChainBranch.GetRoot(expectedRoot);
    }

    if (calculatedRoot != auxMerkleRoot) {
        LogPrintf("AuxPoW: Aux merkle root mismatch\n");
        LogPrintf("  Expected: %s\n", expectedRoot.GetHex());
        LogPrintf("  Got:      %s\n", auxMerkleRoot.GetHex());
        return false;
    }

    // 5. Verify coinbase is in parent block
    uint256 coinbaseHash = GetCoinbaseTx().GetHash();
    uint256 calculatedMerkleRoot = coinbaseBranch.GetRoot(coinbaseHash);

    if (calculatedMerkleRoot != parentBlock.merkle_root) {
        LogPrintf("AuxPoW: Coinbase merkle proof failed\n");
        LogPrintf("  Parent merkle root: %s\n", parentBlock.merkle_root.GetHex());
        LogPrintf("  Calculated:         %s\n", calculatedMerkleRoot.GetHex());
        return false;
    }

    // 6. Verify the coinbase transaction looks valid
    if (GetCoinbaseTx().vin.empty()) {
        LogPrintf("AuxPoW: Coinbase has no inputs\n");
        return false;
    }

    LogPrintf("AuxPoW: Proof valid for aux block %s\n", hashAuxBlock.GetHex().substr(0, 16));
    return true;
}

uint256 CAuxPow::GetParentBlockPoWHash() const {
    return parentBlock.GetPoWHash();
}

bool CAuxPow::GetAuxChainMerkleRoot(uint256& hashOut) const {
    // Look for merge mining tag in coinbase
    // The tag is in the coinbase's scriptSig or a special output

    // Store coinbase tx locally to avoid dangling references from temporaries
    const CTransaction coinbaseTx = GetCoinbaseTx();

    // Check coinbase input scriptSig
    if (!coinbaseTx.vin.empty()) {
        const auto& scriptSig = coinbaseTx.vin[0].scriptSig;
        std::vector<uint8_t> data(scriptSig.begin(), scriptSig.end());

        uint8_t depth;
        if (auxpow::ParseMergeMiningTag(data, hashOut, depth)) {
            return true;
        }
    }

    // Check transaction outputs for OP_RETURN with merge mining data
    for (const auto& out : coinbaseTx.vout) {
        const auto& script = out.scriptPubKey;
        if (script.size() >= 35 && script[0] == 0x6a) {  // OP_RETURN
            std::vector<uint8_t> data(script.begin() + 1, script.end());
            uint8_t depth;
            if (auxpow::ParseMergeMiningTag(data, hashOut, depth)) {
                return true;
            }
        }
    }

    return false;
}

// ============================================================================
// CAuxPowBlockHeader
// ============================================================================

uint256 CAuxPowBlockHeader::GetPoWHash() const {
    if (IsAuxPow() && auxpow) {
        // Merged-mined block: use parent block's PoW hash
        return auxpow->GetParentBlockPoWHash();
    } else {
        // Standard block: use our own RandomX hash
        auto blob = node::RandomXMiner::SerializeBlockHeader(*this);
        uint256 hash;
        auto& miner = node::GetRandomXMiner();
        if (miner.IsInitialized()) {
            miner.CalculateHash(blob.data(), blob.size(), hash.data());
        } else {
            hash = Hash(blob);
        }
        return hash;
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

namespace auxpow {

CAuxPow CreateAuxPow(const CBlockHeader& wattxHeader,
                      const CMoneroBlockHeader& moneroHeader,
                      const CTransaction& coinbaseTx,
                      const std::vector<uint256>& coinbaseMerklePath,
                      int coinbaseIndex) {
    CAuxPow pow;

    pow.parentBlock = moneroHeader;
    pow.coinbaseTxMut = CMutableTransaction(coinbaseTx);
    pow.coinbaseBranch.vHash = coinbaseMerklePath;
    pow.coinbaseBranch.nIndex = coinbaseIndex;
    pow.nChainId = CAuxPowBlockHeader::WATTX_CHAIN_ID;

    // For single aux chain, no aux chain branch needed
    pow.auxChainBranch.SetNull();

    return pow;
}

bool CheckProofOfWork(const CAuxPowBlockHeader& block, uint32_t nBits) {
    // Get the PoW hash (from parent block if AuxPoW, else from this block)
    uint256 hash = block.GetPoWHash();

    // Calculate target from nBits
    arith_uint256 target;
    bool fNegative, fOverflow;
    target.SetCompact(nBits, &fNegative, &fOverflow);

    if (fNegative || fOverflow || target == 0) {
        LogPrintf("AuxPoW: Invalid nBits target\n");
        return false;
    }

    // Check if hash meets target
    arith_uint256 hashArith = UintToArith256(hash);
    if (hashArith > target) {
        LogPrintf("AuxPoW: Hash doesn't meet target\n");
        LogPrintf("  Hash:   %s\n", hash.GetHex());
        LogPrintf("  Target: %s\n", ArithToUint256(target).GetHex());
        return false;
    }

    // If AuxPoW, also verify the aux proof
    if (block.IsAuxPow()) {
        if (!block.auxpow) {
            LogPrintf("AuxPoW: Block marked as AuxPoW but no proof provided\n");
            return false;
        }

        uint256 hashAuxBlock = block.GetHash();
        if (!block.auxpow->Check(hashAuxBlock, CAuxPowBlockHeader::WATTX_CHAIN_ID)) {
            LogPrintf("AuxPoW: Aux proof validation failed\n");
            return false;
        }
    }

    return true;
}

uint256 CalcAuxChainMerkleRoot(const uint256& hashAuxBlock, int nChainId) {
    // Combine the aux block hash with chain ID to prevent cross-chain attacks
    DataStream ss{};
    ss << hashAuxBlock;
    ss << nChainId;
    return Hash(ss);
}

bool ParseMergeMiningTag(const std::vector<uint8_t>& extra,
                          uint256& merkleRoot,
                          uint8_t& depth) {
    // Search for merge mining tag: [0x03] [depth] [32-byte merkle root]
    for (size_t i = 0; i + 34 <= extra.size(); i++) {
        if (extra[i] == TX_EXTRA_MERGE_MINING_TAG) {
            depth = extra[i + 1];
            std::memcpy(merkleRoot.data(), &extra[i + 2], 32);
            return true;
        }
    }
    return false;
}

std::vector<uint8_t> BuildMergeMiningTag(const uint256& merkleRoot, uint8_t depth) {
    std::vector<uint8_t> tag;
    tag.reserve(34);

    tag.push_back(TX_EXTRA_MERGE_MINING_TAG);
    tag.push_back(depth);
    tag.insert(tag.end(), merkleRoot.begin(), merkleRoot.end());

    return tag;
}

}  // namespace auxpow
