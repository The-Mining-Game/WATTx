// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef WATTX_STRATUM_PARENT_CHAIN_H
#define WATTX_STRATUM_PARENT_CHAIN_H

#include <auxpow/auxpow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <uint256.h>

#include <memory>
#include <string>
#include <vector>

namespace merged_stratum {

/**
 * Supported parent chain algorithms for merged mining
 */
enum class ParentChainAlgo {
    RANDOMX,     // Monero
    SHA256D,     // Bitcoin, BCH, BSV
    SCRYPT,      // Litecoin, Dogecoin
    ETHASH,      // Ethereum Classic, Altcoinchain, Octaspace
    EQUIHASH,    // Zcash, Horizen
    X11,         // Dash
    KHEAVYHASH,  // Kaspa
};

/**
 * Parent chain configuration
 */
struct ParentChainConfig {
    std::string name;              // e.g., "monero", "litecoin", "bitcoin"
    ParentChainAlgo algo;
    std::string daemon_host;
    uint16_t daemon_port;
    std::string daemon_user;       // For RPC auth
    std::string daemon_password;
    std::string wallet_address;    // Pool's address on parent chain
    uint32_t chain_id;             // Unique ID to prevent cross-chain replay
    bool enabled{true};
};

/**
 * Parsed coinbase data from parent chain block template
 */
struct ParentCoinbaseData {
    std::vector<uint8_t> coinbase_tx;       // Serialized coinbase transaction
    std::vector<uint256> merkle_branch;     // Merkle path to block root
    int coinbase_index{0};                  // Index in block (always 0)
    uint256 merkle_root;                    // Block's merkle root

    // Reserve space info for merge mining tag
    size_t reserve_offset{0};
    size_t reserve_size{0};

    // Offset of the 8-byte extranonce region within coinbase_tx (0 = none).
    // Only set when a REAL parent coinbase was built (true merged mining);
    // Bitcoin-stratum miners fill it via coinb1/coinb2, XMRig miners leave zeros.
    size_t extranonce_offset{0};

    // The parent chain's ACTUAL block target from its template, snapshot at
    // template time. Null = derive from difficulty (which floors at diff-1 and
    // makes easy regtest targets unreachable — difficulty rounds to 0).
    uint256 parent_target;

    // Raw non-coinbase transactions for full block submission (Bitcoin-style chains)
    std::vector<std::vector<uint8_t>> raw_transactions;

    // Snapshot of the parent block header taken at template time (Bitcoin-style
    // chains). BuildHashingBlob (the header the miner grinds) and CreateAuxPow
    // (the AuxPoW proof the validator checks) both rebuild the parent header from
    // THIS snapshot instead of the handler's live m_current_header, so a poller
    // refresh between job creation and share submit cannot desync the two headers.
    // The merkle root and nonce are filled in per job / per share.
    int32_t  parent_version{0};
    uint256  parent_prevhash;
    uint32_t parent_time{0};
    uint32_t parent_bits{0};
    uint64_t parent_height{0};
    bool     header_snapshot{false};

    // Monero (RandomX) header snapshot, frozen at template time so the mined blob
    // and the AuxPoW proof agree even though monerod bumps the template timestamp
    // every poll. mono_seed holds the RandomX seed bytes in ParseHex order (the raw
    // key fed to randomx_init_cache — NOT uint256 display order).
    uint8_t  mono_major{0};
    uint8_t  mono_minor{0};
    uint64_t mono_timestamp{0};
    uint256  mono_prev_id;
    uint256  mono_seed;
    uint64_t mono_tx_count{1};  // total txs incl. miner tx (hashing blob tail varint)

    bool IsValid() const { return !coinbase_tx.empty() || header_snapshot; }
};

/**
 * Parent block header - abstract base for different chain formats
 */
class IParentBlockHeader {
public:
    virtual ~IParentBlockHeader() = default;

    // Get the block hash (for identification)
    virtual uint256 GetHash() const = 0;

    // Get the PoW hash (for difficulty comparison)
    virtual uint256 GetPoWHash() const = 0;

    // Serialize for network transmission
    virtual std::vector<uint8_t> Serialize() const = 0;

    // Get nonce
    virtual uint32_t GetNonce() const = 0;
    virtual void SetNonce(uint32_t nonce) = 0;
};

/**
 * Abstract base class for parent chain handlers
 * Each supported parent chain implements this interface
 */
class IParentChainHandler {
public:
    virtual ~IParentChainHandler() = default;

    // Get chain info
    virtual std::string GetName() const = 0;
    virtual ParentChainAlgo GetAlgo() const = 0;
    virtual uint32_t GetChainId() const = 0;

    // Block template operations
    virtual bool GetBlockTemplate(
        std::string& hashing_blob,
        std::string& full_template,
        std::string& seed_hash,  // For RandomX, empty for others
        uint64_t& height,
        uint64_t& difficulty,
        ParentCoinbaseData& coinbase_data
    ) = 0;

    // Parse block template blob
    virtual bool ParseBlockTemplate(
        const std::string& template_blob,
        ParentCoinbaseData& coinbase_data
    ) = 0;

    // Build hashing blob with merge mining tag injected
    virtual std::string BuildHashingBlob(
        const ParentCoinbaseData& coinbase_data,
        const std::vector<uint8_t>& merge_mining_tag
    ) = 0;

    // Calculate PoW hash for a blob
    virtual uint256 CalculatePoWHash(
        const std::vector<uint8_t>& hashing_blob,
        const std::string& seed_hash = ""  // For RandomX
    ) = 0;

    // Build parent block header from template and nonce
    virtual std::unique_ptr<IParentBlockHeader> BuildBlockHeader(
        const ParentCoinbaseData& coinbase_data,
        uint32_t nonce
    ) = 0;

    // Submit block to parent chain
    virtual bool SubmitBlock(const std::string& block_blob) = 0;

    // Create AuxPoW proof.
    // extra_data carries algo-specific data not captured by the other params.
    // Ethash: "nonce64_hex:mix_hash_hex"  (nonce as 16 hex chars + mix as 64 hex chars)
    // All others: empty string
    virtual CAuxPow CreateAuxPow(
        const CBlockHeader& wattx_header,
        const ParentCoinbaseData& coinbase_data,
        uint32_t nonce,
        const std::vector<uint8_t>& merge_mining_tag,
        const std::string& extra_data = ""
    ) = 0;

    // Calculate target from difficulty
    virtual uint256 DifficultyToTarget(uint64_t difficulty) = 0;

    // HTTP/RPC helpers
    virtual std::string HttpPost(const std::string& path, const std::string& body) = 0;
    virtual std::string JsonRpcCall(const std::string& method, const std::string& params = "[]") = 0;

protected:
    ParentChainConfig m_config;
};

/**
 * Factory to create parent chain handlers
 */
class ParentChainFactory {
public:
    static std::unique_ptr<IParentChainHandler> Create(const ParentChainConfig& config);
    static std::vector<ParentChainAlgo> GetSupportedAlgos();
    static std::string AlgoToString(ParentChainAlgo algo);
    static ParentChainAlgo StringToAlgo(const std::string& name);
};

}  // namespace merged_stratum

#endif  // WATTX_STRATUM_PARENT_CHAIN_H
