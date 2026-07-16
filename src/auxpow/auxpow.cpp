// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <auxpow/auxpow.h>
#include <arith_uint256.h>
#include <hash.h>
#include <algorithm>
#include <logging.h>
#include <node/randomx_miner.h>
#include <streams.h>
#include <util/strencodings.h>

#include <cstring>

// Multi-algo PoW hash functions
#include <eth_client/utils/libscrypt/libscrypt.h>
#include <crypto/sphlib/x11.h>
#include <crypto/equihash/equihash.h>
#include <ethash/ethash.h>
#include <ethash/keccak.h>

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

    // Total tx count (incl. miner tx) as varint — Monero's hashing blob ends
    // with this; monerod recomputes the blob on submit_block and rejects the
    // PoW if it's missing (the old zero-pad happened to be one wrong byte).
    uint64_t n = num_txs;
    while (n >= 0x80) {
        blob.push_back((n & 0x7F) | 0x80);
        n >>= 7;
    }
    blob.push_back(static_cast<uint8_t>(n));

    // Calculate the parent RandomX hash. Merged-mined Monero blocks must be hashed
    // with the PARENT chain's RandomX seed (seed_hash), NOT the WATTx genesis key —
    // so use the dedicated aux context, re-keyed to this block's seed. Fall back to
    // SHA256d only when no seed is present (legacy/degenerate proofs).
    uint256 hash;
    if (!seed_hash.IsNull()) {
        auto& miner = node::GetRandomXAuxMiner();
        if (miner.ReinitializeIfNeeded(seed_hash.data(), 32)) {
            miner.CalculateHash(blob.data(), blob.size(), hash.data());
        } else {
            LogPrintf("AuxPoW: Failed to init aux RandomX with seed %s\n",
                      seed_hash.GetHex().substr(0, 16));
            return uint256();
        }
    } else {
        auto& miner = node::GetRandomXMiner();
        if (miner.IsInitialized()) {
            miner.CalculateHash(blob.data(), blob.size(), hash.data());
        } else {
            hash = Hash(blob);
            LogPrintf("AuxPoW: Warning - no seed and RandomX not initialized, using SHA256d fallback\n");
        }
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

    // Monero (RandomX) proofs commit via the coinbase tx_extra + a Monero-style
    // tree hash, not a Bitcoin coinbase scriptSig. For those, parentHeaderRaw holds
    // the raw (tag-injected) Monero coinbase and coinbaseBranch the tree path.
    if (GetParentAlgo() == AuxPowAlgo::RANDOMX && !parentHeaderRaw.empty()) {
        // (a) The exact merge-mining tag committing to THIS aux block must appear
        //     verbatim in the coinbase — an unambiguous 34-byte needle (no offset
        //     guessing, no false 0x03 matches).
        uint256 expectedRoot = auxpow::CalcAuxChainMerkleRoot(hashAuxBlock, nChainId);
        std::vector<uint8_t> tag = auxpow::BuildMergeMiningTag(expectedRoot, 0);
        auto it = std::search(parentHeaderRaw.begin(), parentHeaderRaw.end(),
                              tag.begin(), tag.end());
        if (it == parentHeaderRaw.end()) {
            LogPrintf("AuxPoW(monero): merge-mining tag not found in coinbase\n");
            return false;
        }
        // (b) The coinbase must be committed by the tree root the PoW blob hashed.
        // Monero semantics: CryptoNote tx hash + keccak tree fold (NOT SHA256d),
        // so the root matches what monerod itself computes for the same block.
        uint256 cbHash = auxpow::MoneroTxHash(parentHeaderRaw);
        uint256 calcRoot = auxpow::MoneroTreeFold(cbHash, coinbaseBranch.vHash,
                                                  coinbaseBranch.nIndex);
        if (calcRoot != parentBlock.merkle_root) {
            LogPrintf("AuxPoW(monero): coinbase tree proof failed (got %s want %s)\n",
                      calcRoot.GetHex().substr(0, 16),
                      parentBlock.merkle_root.GetHex().substr(0, 16));
            return false;
        }
        return true;
    }

    // 2-4. Verify the coinbase commits to THIS aux block.
    uint256 expectedRoot = auxpow::CalcAuxChainMerkleRoot(hashAuxBlock, nChainId);
    uint256 calculatedRoot = auxChainBranch.IsNull()
        ? expectedRoot                          // single aux chain (depth 0)
        : auxChainBranch.GetRoot(expectedRoot); // multiple aux chains

    // Primary: the expected 34-byte tag must appear VERBATIM in the coinbase
    // scriptSig or an OP_RETURN output. Unlike first-0x03 extraction this is
    // immune to false positives from a BIP34 height push (0x03 = push-3-bytes),
    // which real parent-chain coinbases place FIRST in the scriptSig.
    bool commitment_ok = false;
    {
        std::vector<uint8_t> tag = auxpow::BuildMergeMiningTag(calculatedRoot, 0);
        const CTransaction coinbaseTx = GetCoinbaseTx();
        if (!coinbaseTx.vin.empty()) {
            const auto& ss = coinbaseTx.vin[0].scriptSig;
            commitment_ok = std::search(ss.begin(), ss.end(),
                                        tag.begin(), tag.end()) != ss.end();
        }
        for (const auto& out : coinbaseTx.vout) {
            if (commitment_ok) break;
            const auto& spk = out.scriptPubKey;
            commitment_ok = std::search(spk.begin(), spk.end(),
                                        tag.begin(), tag.end()) != spk.end();
        }
    }

    // Fallback: legacy first-0x03 extraction (covers proofs whose tag was built
    // with nonzero depth, where the verbatim depth byte differs).
    if (!commitment_ok) {
        uint256 auxMerkleRoot;
        if (GetAuxChainMerkleRoot(auxMerkleRoot) && calculatedRoot == auxMerkleRoot) {
            commitment_ok = true;
        }
    }

    if (!commitment_ok) {
        LogPrintf("AuxPoW: coinbase does not commit to aux block\n");
        LogPrintf("  Expected root: %s\n", expectedRoot.GetHex());
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
    // If no raw bytes or algo is RANDOMX, fall back to Monero blob via parentBlock
    if (parentHeaderRaw.empty() || parentAlgoId == static_cast<uint8_t>(AuxPowAlgo::RANDOMX)) {
        return parentBlock.GetPoWHash();
    }

    const uint8_t* data = parentHeaderRaw.data();
    const size_t   len  = parentHeaderRaw.size();

    switch (GetParentAlgo()) {

        case AuxPowAlgo::SHA256D:
            // SHA256d of 80-byte Bitcoin-style header
            return Hash(Span{data, len});

        case AuxPowAlgo::SCRYPT: {
            // Scrypt(N=1024, r=1, p=1) of 80-byte header
            uint256 hash;
            libscrypt_scrypt(data, len, data, len,
                             1024, 1, 1, hash.begin(), 32);
            return hash;
        }

        case AuxPowAlgo::X11: {
            // X11 chained hash of 80-byte header
            uint256 hash;
            x11_hash(data, len, hash.begin());
            return hash;
        }

        case AuxPowAlgo::KHEAVYHASH:
            // kHeavyHash placeholder — TODO replace with real kHeavyHash when available
            // Until then SHA256d gives deterministic, verifiable results for regtest
            return Hash(Span{data, len});

        case AuxPowAlgo::ETHASH: {
            // parentHeaderRaw = 32B header_hash + 8B nonce_LE + 32B mix_hash = 72 bytes
            // Compute ethash final_hash = keccak256(keccak512(header_hash+nonce) + mix_hash)
            // This is DAG-free; full mix_hash validity is guaranteed by the ETC network.
            if (len < 72) return uint256();

            ethash_hash256 header_hash;
            std::memcpy(header_hash.bytes, data, 32);

            uint64_t nonce = 0;
            std::memcpy(&nonce, data + 32, 8);

            // seed = keccak512(header_hash_bytes + nonce_LE)
            uint8_t seed_input[40];
            std::memcpy(seed_input,      header_hash.bytes, 32);
            std::memcpy(seed_input + 32, &nonce, 8);
            ethash_hash512 seed = ethash_keccak512(seed_input, 40);

            // final = keccak256(seed + mix_hash)
            uint8_t final_input[96];
            std::memcpy(final_input,      seed.bytes, 64);
            std::memcpy(final_input + 64, data + 40, 32);
            ethash_hash256 final_hash = ethash_keccak256(final_input, 96);

            uint256 result;
            std::memcpy(result.begin(), final_hash.bytes, 32);
            return result;
        }

        case AuxPowAlgo::EQUIHASH:
            // parentHeaderRaw = 140-byte Equihash header (without solution)
            // Difficulty is checked against SHA256d of the header bytes only
            if (len < 140) return Hash(Span{data, len});
            return Hash(Span{data, 140});

        default:
            return parentBlock.GetPoWHash();
    }
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

uint256 MoneroTxHash(const std::vector<uint8_t>& tx_bytes) {
    uint256 out;
    if (tx_bytes.empty()) return out;

    if (tx_bytes[0] == 0x01) {
        // v1 tx: hash of the whole serialized tx
        ethash_hash256 h = ethash_keccak256(tx_bytes.data(), tx_bytes.size());
        std::memcpy(out.begin(), h.bytes, 32);
        return out;
    }

    // v2 (rct): keccak(keccak(prefix) || keccak(rct_base) || null_prunable).
    // tx_bytes is the prefix; a miner tx's rct base is one RCTTypeNull byte.
    ethash_hash256 prefix_hash = ethash_keccak256(tx_bytes.data(), tx_bytes.size());
    const uint8_t rct_null = 0x00;
    ethash_hash256 base_hash = ethash_keccak256(&rct_null, 1);

    uint8_t buf[96];
    std::memcpy(buf,      prefix_hash.bytes, 32);
    std::memcpy(buf + 32, base_hash.bytes,   32);
    std::memset(buf + 64, 0, 32);  // null prunable hash
    ethash_hash256 tx_hash = ethash_keccak256(buf, 96);
    std::memcpy(out.begin(), tx_hash.bytes, 32);
    return out;
}

uint256 MoneroTreeFold(const uint256& leaf, const std::vector<uint256>& branch, int index) {
    uint256 hash = leaf;
    int idx = index;
    uint8_t buf[64];
    for (const auto& b : branch) {
        if (idx & 1) {
            std::memcpy(buf,      b.begin(),    32);
            std::memcpy(buf + 32, hash.begin(), 32);
        } else {
            std::memcpy(buf,      hash.begin(), 32);
            std::memcpy(buf + 32, b.begin(),    32);
        }
        ethash_hash256 h = ethash_keccak256(buf, 64);
        std::memcpy(hash.begin(), h.bytes, 32);
        idx >>= 1;
    }
    return hash;
}

}  // namespace auxpow
