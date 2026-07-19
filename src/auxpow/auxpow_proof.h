// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WATTX_AUXPOW_PROOF_H
#define WATTX_AUXPOW_PROOF_H

// AuxPoW proof types that do NOT depend on CBlock/CBlockHeader, split out of
// auxpow.h so primitives/block.h can include them and serialize a CAuxPow
// inline without an include cycle (auxpow.h includes primitives/block.h).

#include <primitives/transaction.h>
#include <serialize.h>
#include <uint256.h>
#include <cstdint>
#include <vector>

/**
 * Monero Block Header structure for AuxPoW
 * This represents the parent chain (Monero) block header
 */
struct CMoneroBlockHeader {
    uint8_t major_version;
    uint8_t minor_version;
    uint64_t timestamp;
    uint256 prev_id;           // Previous block hash
    uint32_t nonce;
    uint256 merkle_root;       // Transaction merkle root
    uint256 seed_hash;         // RandomX seed for this block's epoch (Monero seed_hash)
    uint64_t num_txs{1};       // Total tx count incl. miner tx — the hashing blob
                               // ends with this varint; monerod rejects PoW otherwise

    SERIALIZE_METHODS(CMoneroBlockHeader, obj) {
        READWRITE(obj.major_version);
        READWRITE(obj.minor_version);
        READWRITE(VARINT(obj.timestamp));
        READWRITE(obj.prev_id);
        READWRITE(obj.nonce);
        READWRITE(obj.merkle_root);
        READWRITE(obj.seed_hash);
        READWRITE(VARINT(obj.num_txs));
    }

    uint256 GetHash() const;
    uint256 GetPoWHash() const;  // RandomX hash for PoW validation

    void SetNull() {
        major_version = 0;
        minor_version = 0;
        timestamp = 0;
        prev_id.SetNull();
        nonce = 0;
        merkle_root.SetNull();
        seed_hash.SetNull();
        num_txs = 1;
    }

    bool IsNull() const {
        return prev_id.IsNull();
    }
};

/**
 * Merkle branch for proving transaction inclusion
 */
class CMerkleBranch {
public:
    std::vector<uint256> vHash;
    int nIndex;  // Index of the item in the tree

    CMerkleBranch() : nIndex(-1) {}

    SERIALIZE_METHODS(CMerkleBranch, obj) {
        READWRITE(obj.vHash);
        READWRITE(obj.nIndex);
    }

    /**
     * Calculate the root hash given a leaf hash
     */
    uint256 GetRoot(const uint256& leaf) const;

    bool IsNull() const { return vHash.empty(); }
    void SetNull() { vHash.clear(); nIndex = -1; }
};

/**
 * Merge mining tag in Monero coinbase extra field
 */
static const uint8_t TX_EXTRA_MERGE_MINING_TAG = 0x03;

/**
 * Parent chain algorithm identifier for multi-algo AuxPoW.
 * Each value selects the PoW hash function used in GetParentBlockPoWHash().
 */
enum class AuxPowAlgo : uint8_t {
    RANDOMX    = 0,  // Monero RandomX (original, default for backward compat)
    SHA256D    = 1,  // Bitcoin SHA256d  — 80-byte header
    SCRYPT     = 2,  // Litecoin Scrypt  — 80-byte header
    ETHASH     = 3,  // ETC Ethash       — 32B header_hash + 8B nonce + 32B mix_hash
    EQUIHASH   = 4,  // Zcash Equihash   — 140-byte header + solution bytes
    X11        = 5,  // Dash X11         — 80-byte header
    KHEAVYHASH = 6,  // Kaspa kHeavyHash — kaspa-specific header bytes
};

/**
 * Auxiliary Proof of Work
 * Contains all data needed to prove merged mining with a parent chain.
 * Supports 7 parent chain algorithms via parentAlgoId + parentHeaderRaw.
 */
class CAuxPow {
public:
    // The parent chain coinbase transaction containing the aux chain commitment
    CMutableTransaction coinbaseTxMut;

    // Merkle branch proving coinbase is in parent block
    CMerkleBranch coinbaseBranch;

    // Merkle branch for multiple aux chains (depth 0 for single chain)
    CMerkleBranch auxChainBranch;

    // The parent (Monero) block header — kept for backward compat and Check() merkle root
    CMoneroBlockHeader parentBlock;

    // Chain ID for this aux chain (prevents cross-chain replay)
    int32_t nChainId;

    // ---- Multi-algo AuxPoW fields ----
    // Which algorithm the parent chain uses (AuxPowAlgo cast to uint8_t)
    uint8_t parentAlgoId{0};  // 0 = RANDOMX (default, backward compat)

    // Raw parent block header bytes for PoW verification (format varies by algo):
    //   RANDOMX:    Monero hashing blob (76+ bytes)
    //   SHA256D/SCRYPT/X11/KHEAVYHASH: 80-byte Bitcoin-style header
    //   ETHASH:     32B header_hash + 8B nonce_LE + 32B mix_hash = 72 bytes
    //   EQUIHASH:   140-byte header (without solution) + solution bytes
    std::vector<uint8_t> parentHeaderRaw;

    CAuxPow() : nChainId(0) {}

    AuxPowAlgo GetParentAlgo() const { return static_cast<AuxPowAlgo>(parentAlgoId); }

    // Get coinbase as immutable transaction
    CTransaction GetCoinbaseTx() const { return CTransaction(coinbaseTxMut); }

    SERIALIZE_METHODS(CAuxPow, obj) {
        READWRITE(obj.coinbaseTxMut);
        READWRITE(obj.coinbaseBranch);
        READWRITE(obj.auxChainBranch);
        READWRITE(obj.parentBlock);
        READWRITE(obj.nChainId);
        READWRITE(obj.parentAlgoId);
        READWRITE(obj.parentHeaderRaw);
    }

    /**
     * Check if the auxiliary proof of work is valid
     * @param hashAuxBlock Hash of the aux chain (WATTx) block header
     * @param nChainId Expected chain ID
     * @param params Chain parameters for target validation
     * @return true if valid
     */
    bool Check(const uint256& hashAuxBlock, int nChainId) const;

    /**
     * Get the parent block's PoW hash (for difficulty comparison)
     */
    uint256 GetParentBlockPoWHash() const;

    /**
     * Extract the aux chain merkle root from coinbase extra field
     */
    bool GetAuxChainMerkleRoot(uint256& hashOut) const;

    void SetNull() {
        coinbaseTxMut = CMutableTransaction();
        coinbaseBranch.SetNull();
        auxChainBranch.SetNull();
        parentBlock.SetNull();
        nChainId = 0;
    }
};

#endif // WATTX_AUXPOW_PROOF_H
