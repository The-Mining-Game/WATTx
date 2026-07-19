// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WATTX_AUXPOW_H
#define WATTX_AUXPOW_H

#include <primitives/block.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <uint256.h>
#include <vector>
#include <auxpow/auxpow_proof.h>

/**
 * Extended block header with optional AuxPoW
 */
class CAuxPowBlockHeader : public CBlockHeader {
public:
    // AuxPoW data (only present if this is a merged-mined block)
    std::shared_ptr<CAuxPow> auxpow;

    CAuxPowBlockHeader() : auxpow(nullptr) {}

    CAuxPowBlockHeader(const CBlockHeader& header)
        : CBlockHeader(header), auxpow(nullptr) {}

    SERIALIZE_METHODS(CAuxPowBlockHeader, obj) {
        // Serialize base class CBlockHeader fields
        READWRITE(obj.nVersion, obj.hashPrevBlock, obj.hashMerkleRoot, obj.nTime, obj.nBits, obj.nNonce, obj.hashStateRoot, obj.hashUTXORoot, obj.prevoutStake, obj.vchBlockSigDlgt, obj.nShift, obj.nAdder, obj.nGapSize);
        // Serialize AuxPoW if present
        if (obj.IsAuxPow()) {
            if (!obj.auxpow) {
                obj.auxpow = std::make_shared<CAuxPow>();
            }
            READWRITE(*obj.auxpow);
        }
    }

    /**
     * Check if this block uses AuxPoW (merged mining)
     * Determined by version bits
     */
    bool IsAuxPow() const {
        return (nVersion & AUXPOW_VERSION_FLAG) != 0;
    }

    /**
     * Set the AuxPoW flag in version
     */
    void SetAuxPowFlag() {
        nVersion |= AUXPOW_VERSION_FLAG;
    }

    /**
     * Clear the AuxPoW flag
     */
    void ClearAuxPowFlag() {
        nVersion &= ~AUXPOW_VERSION_FLAG;
    }

    /**
     * Get the proof-of-work hash
     * For AuxPoW blocks, this is the parent block's RandomX hash
     * For standard blocks, this is the block header's RandomX hash
     */
    uint256 GetPoWHash() const;

    // Version flag indicating AuxPoW block
    static constexpr int32_t AUXPOW_VERSION_FLAG = 0x00010000;

    // Chain ID for WATTx (prevents cross-chain attacks)
    static constexpr int32_t WATTX_CHAIN_ID = 0x5754;  // "WT" in hex
};

/**
 * Full block with AuxPoW support
 */
class CAuxPowBlock : public CAuxPowBlockHeader {
public:
    std::vector<CTransactionRef> vtx;

    CAuxPowBlock() {}

    CAuxPowBlock(const CBlock& block)
        : CAuxPowBlockHeader(block), vtx(block.vtx) {}

    SERIALIZE_METHODS(CAuxPowBlock, obj) {
        // Serialize CAuxPowBlockHeader (includes base CBlockHeader and optional auxpow)
        READWRITE(obj.nVersion, obj.hashPrevBlock, obj.hashMerkleRoot, obj.nTime, obj.nBits, obj.nNonce, obj.hashStateRoot, obj.hashUTXORoot, obj.prevoutStake, obj.vchBlockSigDlgt, obj.nShift, obj.nAdder, obj.nGapSize);
        if (obj.IsAuxPow()) {
            if (!obj.auxpow) {
                obj.auxpow = std::make_shared<CAuxPow>();
            }
            READWRITE(*obj.auxpow);
        }
        READWRITE(obj.vtx);
    }

    CBlock GetBlock() const {
        CBlock block;
        block.nVersion = nVersion;
        block.hashPrevBlock = hashPrevBlock;
        block.hashMerkleRoot = hashMerkleRoot;
        block.nTime = nTime;
        block.nBits = nBits;
        block.nNonce = nNonce;
        block.hashStateRoot = hashStateRoot;
        block.hashUTXORoot = hashUTXORoot;
        block.prevoutStake = prevoutStake;
        block.vchBlockSigDlgt = vchBlockSigDlgt;
        block.nShift = nShift;
        block.nAdder = nAdder;
        block.nGapSize = nGapSize;
        block.vtx = vtx;
        return block;
    }
};

/**
 * Utility functions for AuxPoW
 */
namespace auxpow {

/**
 * Create an AuxPoW proof for a WATTx block using a Monero block
 */
CAuxPow CreateAuxPow(const CBlockHeader& wattxHeader,
                      const CMoneroBlockHeader& moneroHeader,
                      const CTransaction& coinbaseTx,
                      const std::vector<uint256>& coinbaseMerklePath,
                      int coinbaseIndex);

/**
 * Check if a block header meets the target difficulty
 */
bool CheckProofOfWork(const CAuxPowBlockHeader& block, uint32_t nBits);

/**
 * Calculate the merkle root for a coinbase extra field commitment
 */
uint256 CalcAuxChainMerkleRoot(const uint256& hashAuxBlock, int nChainId);

/**
 * Parse the merge mining tag from coinbase extra field
 * Returns true if found and outputs the merkle root
 */
bool ParseMergeMiningTag(const std::vector<uint8_t>& extra,
                          uint256& merkleRoot,
                          uint8_t& depth);

/**
 * Build the merge mining tag for coinbase extra field
 */
std::vector<uint8_t> BuildMergeMiningTag(const uint256& merkleRoot, uint8_t depth = 0);

/**
 * Monero (CryptoNote) transaction hash of a miner tx.
 * v1: keccak256 of the whole serialized tx.
 * v2 (rct, modern): keccak(keccak(prefix) || keccak(rct_base) || null_prunable) —
 * a miner tx's rct base is the single byte RCTTypeNull (0x00) and its prunable
 * hash is null. `tx_bytes` holds the tx PREFIX (version..extra), as parsed from
 * the block template.
 */
uint256 MoneroTxHash(const std::vector<uint8_t>& tx_bytes);

/**
 * Fold a leaf hash up a Monero tree-hash branch (keccak256 pairs, left/right by
 * index parity). Empty branch => the leaf itself (single-tx block).
 */
uint256 MoneroTreeFold(const uint256& leaf, const std::vector<uint256>& branch, int index);

}  // namespace auxpow

#endif  // WATTX_AUXPOW_H
