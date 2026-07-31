// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_BLOCK_H
#define BITCOIN_PRIMITIVES_BLOCK_H

#include <primitives/transaction.h>
#include <serialize.h>
#include <uint256.h>
#include <util/time.h>
#include <auxpow/auxpow_proof.h>

#include <memory>

/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 */
class CBlockHeader
{
public:
    // header
    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;
    uint256 hashStateRoot; // qtum
    uint256 hashUTXORoot; // qtum
    // proof-of-stake specific fields
    COutPoint prevoutStake;
    std::vector<unsigned char> vchBlockSigDlgt; // The delegate is 65 bytes or 0 bytes, it can be added in the signature paramether at the end to avoid compatibility problems

    // DEPRECATED: Gapcoin fields - kept for backward compatibility with pre-fork blocks
    // These fields are unused after X25X hard fork but must remain for block deserialization
    uint32_t nShift;           // DEPRECATED: Was for Gapcoin prime calculation
    uint256 nAdder;            // DEPRECATED: Was for Gapcoin prime candidate offset
    uint32_t nGapSize;         // DEPRECATED: Was for Gapcoin prime gap size

    CBlockHeader()
    {
        SetNull();
    }

    SERIALIZE_METHODS(CBlockHeader, obj) { READWRITE(obj.nVersion, obj.hashPrevBlock, obj.hashMerkleRoot, obj.nTime, obj.nBits, obj.nNonce, obj.hashStateRoot, obj.hashUTXORoot, obj.prevoutStake, obj.vchBlockSigDlgt, obj.nShift, obj.nAdder, obj.nGapSize); }

    void SetNull()
    {
        nVersion = 0;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        nTime = 0;
        nBits = 0;
        nNonce = 0;
        hashStateRoot.SetNull(); // qtum
        hashUTXORoot.SetNull(); // qtum
        vchBlockSigDlgt.clear();
        prevoutStake.SetNull();
        // DEPRECATED Gapcoin fields (kept for serialization compatibility)
        nShift = 0;
        nAdder.SetNull();
        nGapSize = 0;
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    uint256 GetHash() const;

    uint256 GetHashWithoutSign() const;

    std::string GetWithoutSign() const;

    NodeSeconds Time() const
    {
        return NodeSeconds{std::chrono::seconds{nTime}};
    }

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }

    // ppcoin: two types of block: proof-of-work or proof-of-stake
    bool IsProofOfStake() const //qtum
    {
        return !prevoutStake.IsNull();
    }

    bool IsProofOfWork() const
    {
        return !IsProofOfStake();
    }

    // DEPRECATED: Gapcoin functions - kept for backward compatibility
    // Always returns false after X25X fork since Gapcoin is no longer used
    bool HasGapcoinProof() const
    {
        return false; // Gapcoin removed - X25X multi-algo mining used instead
    }

    // DEPRECATED: Hybrid consensus now uses X25X PoW + PoS
    bool IsHybridConsensusComplete() const
    {
        return false; // Use IsProofOfStake() for PoS validation
    }

    uint32_t StakeTime() const
    {
        uint32_t ret = 0;
        if(IsProofOfStake())
        {
            ret = nTime;
        }
        return ret;
    }

    void SetBlockSignature(const std::vector<unsigned char>& vchSign);
    std::vector<unsigned char> GetBlockSignature() const;

    void SetProofOfDelegation(const std::vector<unsigned char>& vchPoD);
    std::vector<unsigned char> GetProofOfDelegation() const;

    bool HasProofOfDelegation() const;
};


// AuxPoW version flag (must match CAuxPowBlockHeader::AUXPOW_VERSION_FLAG)
static constexpr int32_t AUXPOW_VERSION_FLAG = 0x00010000;

class CBlock : public CBlockHeader
{
public:
    // network and disk
    std::vector<CTransactionRef> vtx;

    // Optional AuxPoW proof for merged-mined blocks (memory-only, not serialized with standard CBlock)
    // This is set when validating AuxPoW blocks and used by CheckHeaderPoWAtHeight
    mutable std::shared_ptr<CAuxPow> auxpow;

    // Memory-only flags for caching expensive checks
    mutable bool fChecked;                            // CheckBlock()
    mutable bool m_checked_witness_commitment{false}; // CheckWitnessCommitment()
    mutable bool m_checked_merkle_root{false};        // CheckMerkleRoot()

    CBlock()
    {
        SetNull();
    }

    CBlock(const CBlockHeader &header)
    {
        SetNull();
        *(static_cast<CBlockHeader*>(this)) = header;
    }

    SERIALIZE_METHODS(CBlock, obj)
    {
        READWRITE(AsBase<CBlockHeader>(obj), obj.vtx);
        // Merged-mined blocks carry their AuxPoW proof after the transactions so
        // that peers (via the `block` message) and disk reads reconstruct the
        // parent-chain proof and can verify it in CheckBlock. The block hash is
        // computed from CBlockHeader alone, so this does NOT change block
        // identity. The vtx.empty() gate keeps `headers` messages bare: their
        // entries are CBlocks with no transactions (net_processing uses CBlock
        // for the trailing tx-count byte), while any real block carries at
        // least its coinbase — and the receiver reads vtx before this point,
        // so both sides agree on whether an AuxPoW follows. `auxpow` is
        // mutable, so this compiles on the const serialize path.
        if (obj.HasAuxPowFlag() && !obj.vtx.empty()) {
            if (!obj.auxpow) {
                obj.auxpow = std::make_shared<CAuxPow>();
            }
            READWRITE(*obj.auxpow);
        }
    }

    void SetNull()
    {
        CBlockHeader::SetNull();
        vtx.clear();
        auxpow.reset();
        fChecked = false;
        m_checked_witness_commitment = false;
        m_checked_merkle_root = false;
    }

    /**
     * Check if this block has the AuxPoW version flag set
     */
    bool HasAuxPowFlag() const
    {
        return (nVersion & AUXPOW_VERSION_FLAG) != 0;
    }

    /**
     * Check if this block has valid AuxPoW data attached
     */
    bool HasAuxPow() const
    {
        return HasAuxPowFlag() && auxpow != nullptr;
    }

    /**
     * Set the AuxPoW proof for this block
     */
    void SetAuxPow(std::shared_ptr<CAuxPow> proof)
    {
        auxpow = std::move(proof);
        if (auxpow) {
            nVersion |= AUXPOW_VERSION_FLAG;
        }
    }

    std::pair<COutPoint, unsigned int> GetProofOfStake() const //qtum
    {
        return IsProofOfStake()? std::make_pair(prevoutStake, nTime) : std::make_pair(COutPoint(), (unsigned int)0);
    }

    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader block;
        block.nVersion       = nVersion;
        block.hashPrevBlock  = hashPrevBlock;
        block.hashMerkleRoot = hashMerkleRoot;
        block.nTime          = nTime;
        block.nBits          = nBits;
        block.nNonce         = nNonce;
        block.hashStateRoot  = hashStateRoot; // qtum
        block.hashUTXORoot   = hashUTXORoot; // qtum
        block.vchBlockSigDlgt    = vchBlockSigDlgt;
        block.prevoutStake   = prevoutStake;
        // DEPRECATED Gapcoin fields (kept for serialization compatibility)
        block.nShift         = nShift;
        block.nAdder         = nAdder;
        block.nGapSize       = nGapSize;
        return block;
    }

    std::string ToString() const;
};

/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
struct CBlockLocator
{
    /** Historically CBlockLocator's version field has been written to network
     * streams as the negotiated protocol version and to disk streams as the
     * client version, but the value has never been used.
     *
     * Hard-code to the highest protocol version ever written to a network stream.
     * SerParams can be used if the field requires any meaning in the future,
     **/
    static constexpr int DUMMY_VERSION = 70016;

    std::vector<uint256> vHave;

    CBlockLocator() = default;

    explicit CBlockLocator(std::vector<uint256>&& have) : vHave(std::move(have)) {}

    SERIALIZE_METHODS(CBlockLocator, obj)
    {
        int nVersion = DUMMY_VERSION;
        READWRITE(nVersion);
        READWRITE(obj.vHave);
    }

    void SetNull()
    {
        vHave.clear();
    }

    bool IsNull() const
    {
        return vHave.empty();
    }
};

#endif // BITCOIN_PRIMITIVES_BLOCK_H
