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
#include <crypto/x11dash/x11dash.h>  // canonical Dash X11 for the x11 parent path
#include <crypto/equihash/equihash_canon.h>  // canonical Zcash/BitcoinZ validator
#include <crypto/kheavyhash/kheavyhash.h>    // canonical Kaspa kHeavyHash + hashing
#include <ethash/ethash.h>
#include <ethash/ethash.hpp>
#include <ethash/global_context.hpp>
#include <ethash/keccak.h>
#include <auxpow/ethash_seal.h>

namespace {

// Fail-closed sentinel for PoW-hash error paths: an all-FF hash can never meet
// a target, whereas a default uint256 (all zeros) would meet EVERY target.
uint256 MaxHash() {
    uint256 h;
    std::memset(h.begin(), 0xFF, 32);
    return h;
}

// EQUIHASH parentHeaderRaw layout (see EquihashChainHandler::CreateAuxPow):
//   [0..4)    Equihash n (LE32)
//   [4..8)    Equihash k (LE32)
//   [8..148)  140-byte Zcash-style header (version, prev, merkleroot,
//             reserved, time, bits, 32-byte nonce)
//   [148..)   CompactSize(sol_len) + solution
//   [rest]    raw serialized parent coinbase transaction
// header..solution is contiguous and equals the parent chain's block-hash
// preimage; the coinbase rides as opaque bytes because zcash-family (v4
// sapling) transactions cannot be represented as a CTransaction.
struct EquihashRawParts {
    uint32_t n{0}, k{0};
    const uint8_t* header{nullptr};       // 140 bytes
    const uint8_t* solution{nullptr};
    size_t solution_len{0};
    size_t pow_len{0};                    // header..end-of-solution (hash preimage)
    const uint8_t* coinbase{nullptr};
    size_t coinbase_len{0};
};

bool ParseEquihashRaw(const std::vector<uint8_t>& raw, EquihashRawParts& out) {
    if (raw.size() < 8 + 140 + 1) return false;
    const uint8_t* d = raw.data();
    out.n = d[0] | (uint32_t(d[1]) << 8) | (uint32_t(d[2]) << 16) | (uint32_t(d[3]) << 24);
    out.k = d[4] | (uint32_t(d[5]) << 8) | (uint32_t(d[6]) << 16) | (uint32_t(d[7]) << 24);
    // Parameter sanity: bounds keep 1<<k and the length formula well-defined.
    if (out.k < 1 || out.k > 12 || out.n < 24 || out.n > 256 ||
        out.n % 8 != 0 || out.n % (out.k + 1) != 0) return false;
    out.header = d + 8;

    size_t pos = 148;
    uint64_t sol_len = d[pos];
    pos += 1;
    if (sol_len == 0xFD) {
        if (raw.size() < pos + 2) return false;
        sol_len = d[pos] | (uint64_t(d[pos + 1]) << 8);
        pos += 2;
    } else if (sol_len > 0xFC) {
        return false;  // solutions never need 4/8-byte CompactSize
    }
    const size_t expected = (size_t(1) << out.k) * (out.n / (out.k + 1) + 1) / 8;
    if (sol_len != expected) return false;
    if (raw.size() < pos + sol_len) return false;

    out.solution = d + pos;
    out.solution_len = sol_len;
    out.pow_len = (pos + sol_len) - 8;
    out.coinbase = d + pos + sol_len;
    out.coinbase_len = raw.size() - (pos + sol_len);
    return true;
}

// KHEAVYHASH parentHeaderRaw layout (see KaspaChainHandler::CreateAuxPow):
//   [u32 LE preimage_len][preimage]  keyed-blake2b "BlockHash" preimage with the
//                                    REAL nonce + timestamp (kaspa hashes a
//                                    structured serialization, not a fixed header)
//   [u32 LE coinbase_len][coinbase]  serialized kaspa coinbase (TransactionHash
//                                    encoding; the WATTx MM tag rides in the
//                                    payload as hex-ASCII via kaspad extraData)
//   [u8 branch_count][32B x count]   MerkleBranchHash siblings for leaf 0
struct KaspaRawParts {
    const uint8_t* preimage{nullptr};
    size_t preimage_len{0};
    const uint8_t* coinbase{nullptr};
    size_t coinbase_len{0};
    std::vector<std::vector<uint8_t>> branch;
    kheavyhash::HeaderPreimageInfo info;  // offsets inside preimage
};

bool ParseKaspaRaw(const std::vector<uint8_t>& raw, KaspaRawParts& out) {
    const uint8_t* d = raw.data();
    size_t len = raw.size();
    auto get_u32 = [d](size_t pos) {
        return uint32_t(d[pos]) | (uint32_t(d[pos + 1]) << 8) |
               (uint32_t(d[pos + 2]) << 16) | (uint32_t(d[pos + 3]) << 24);
    };
    if (len < 4) return false;
    uint32_t pre_len = get_u32(0);
    if (pre_len < 172 || pre_len > 65536 || len < 4 + size_t(pre_len) + 4) return false;
    out.preimage = d + 4;
    out.preimage_len = pre_len;
    size_t pos = 4 + pre_len;
    uint32_t cb_len = get_u32(pos);
    pos += 4;
    if (cb_len == 0 || cb_len > 1 << 20 || len < pos + cb_len + 1) return false;
    out.coinbase = d + pos;
    out.coinbase_len = cb_len;
    pos += cb_len;
    uint8_t branch_count = d[pos++];
    if (len != pos + size_t(branch_count) * 32) return false;
    out.branch.clear();
    for (uint8_t i = 0; i < branch_count; i++) {
        out.branch.emplace_back(d + pos, d + pos + 32);
        pos += 32;
    }
    return kheavyhash::ParseHeaderPreimage(out.preimage, out.preimage_len, out.info);
}

}  // namespace

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
            // Fail closed: all-FF never meets a target; a default (zero)
            // uint256 here would grant a free block on any RandomX init error.
            uint256 fail;
            std::memset(fail.begin(), 0xFF, 32);
            return fail;
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

// Defined below GetParentBlockPoWHash; used by both Check() and that function.
static bool ParseEthashV2(const std::vector<uint8_t>& raw,
                          std::array<uint8_t, 32>& sealHash,
                          uint8_t nonce8[8], uint8_t mix32[32],
                          std::vector<uint8_t>& extraOut,
                          uint64_t& blockNumberOut);

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

    // Equihash (Zcash-family) proofs carry the parent coinbase as opaque raw
    // bytes in parentHeaderRaw (v4 sapling txs can't deserialize into a
    // CTransaction), so verify commitment + solution here instead of via the
    // generic coinbaseTxMut path.
    if (GetParentAlgo() == AuxPowAlgo::EQUIHASH && !parentHeaderRaw.empty()) {
        EquihashRawParts p;
        if (!ParseEquihashRaw(parentHeaderRaw, p) || p.coinbase_len == 0) {
            LogPrintf("AuxPoW(equihash): malformed parentHeaderRaw\n");
            return false;
        }
        // (a) The Equihash solution must be canonically valid for the mined
        //     140-byte header — this is what binds the proof to real parent-
        //     chain work rather than a bare SHA256d grind.
        if (!equihash_canon::Verify(p.n, p.k, p.header, 140,
                                    p.solution, p.solution_len)) {
            LogPrintf("AuxPoW(equihash): invalid solution (n=%u k=%u)\n", p.n, p.k);
            return false;
        }
        // (b) The exact 34-byte merge-mining tag for THIS aux block must appear
        //     verbatim in the coinbase bytes.
        uint256 expectedRoot = auxpow::CalcAuxChainMerkleRoot(hashAuxBlock, nChainId);
        std::vector<uint8_t> tag = auxpow::BuildMergeMiningTag(expectedRoot, 0);
        auto it = std::search(p.coinbase, p.coinbase + p.coinbase_len,
                              tag.begin(), tag.end());
        if (it == p.coinbase + p.coinbase_len) {
            LogPrintf("AuxPoW(equihash): merge-mining tag not found in coinbase\n");
            return false;
        }
        // (c) The mined header must commit to that coinbase: txid (SHA256d of
        //     the raw serialization — the same rule for zcash-family as for
        //     bitcoin) folded through coinbaseBranch must equal the header's
        //     merkle root, which must also be what parentBlock records.
        uint256 txid = Hash(Span{p.coinbase, p.coinbase_len});
        uint256 root = coinbaseBranch.GetRoot(txid);
        uint256 header_mr;
        std::memcpy(header_mr.begin(), p.header + 36, 32);
        if (root != header_mr || parentBlock.merkle_root != header_mr) {
            LogPrintf("AuxPoW(equihash): coinbase merkle proof failed\n");
            return false;
        }
        return true;
    }

    // Kaspa (kHeavyHash) proofs carry the header-hash preimage + serialized
    // coinbase as opaque raw bytes (kaspa txs can't be a CTransaction, and the
    // header is a structured serialization). The MM tag was embedded by kaspad
    // itself via GetBlockTemplate extraData — a protobuf string — so it appears
    // in the coinbase payload as the tag's 68-char hex-ASCII form.
    if (GetParentAlgo() == AuxPowAlgo::KHEAVYHASH && !parentHeaderRaw.empty()) {
        KaspaRawParts p;
        if (!ParseKaspaRaw(parentHeaderRaw, p)) {
            LogPrintf("AuxPoW(kaspa): malformed parentHeaderRaw\n");
            return false;
        }
        // (a) The hex-ASCII merge-mining tag for THIS aux block must appear
        //     verbatim in the coinbase bytes.
        uint256 expectedRoot = auxpow::CalcAuxChainMerkleRoot(hashAuxBlock, nChainId);
        std::vector<uint8_t> tag = auxpow::BuildMergeMiningTag(expectedRoot, 0);
        std::string tag_ascii = HexStr(tag);
        auto it = std::search(p.coinbase, p.coinbase + p.coinbase_len,
                              tag_ascii.begin(), tag_ascii.end());
        if (it == p.coinbase + p.coinbase_len) {
            LogPrintf("AuxPoW(kaspa): merge-mining tag not found in coinbase\n");
            return false;
        }
        // (b) The mined header must commit to that coinbase: TransactionHash
        //     (keyed blake2b) folded through the MerkleBranchHash path must
        //     equal the header preimage's merkle root — the same tree kaspad
        //     verifies — which must also be what parentBlock records.
        uint8_t txh[32], root_calc[32];
        kheavyhash::TransactionHash(p.coinbase, p.coinbase_len, txh);
        kheavyhash::MerkleFold(txh, p.branch, coinbaseBranch.nIndex, root_calc);
        if (std::memcmp(root_calc, p.preimage + p.info.merkle_root_off, 32) != 0 ||
            std::memcmp(parentBlock.merkle_root.begin(),
                        p.preimage + p.info.merkle_root_off, 32) != 0) {
            LogPrintf("AuxPoW(kaspa): coinbase merkle proof failed\n");
            return false;
        }
        return true;
    }

    // Ethash (Altcoinchain/ETC): TRUSTLESS full-header path. The parent block's
    // OWN extraData carries the WATTx aux commitment (the ALT hybrid engine
    // writes it in Prepare), and the ethash PoW — checked in CheckAuxProofOfWork
    // via GetParentBlockPoWHash — is computed over the seal hash recomputed from
    // this same full header. So a valid PoW proves work on a header that commits
    // to THIS aux block; the pool can no longer assert an unbound synthetic
    // coinbase (the old forgeable path). The 72-byte legacy format fails
    // ParseEthashV2 and is rejected here.
    if (GetParentAlgo() == AuxPowAlgo::ETHASH) {
        std::array<uint8_t, 32> sealHash;
        uint8_t nonce_b[8], mix_b[32];
        std::vector<uint8_t> extra;
        uint64_t blockNumber = 0;
        if (!ParseEthashV2(parentHeaderRaw, sealHash, nonce_b, mix_b, extra, blockNumber)) {
            LogPrintf("AuxPoW(ethash): malformed full-header proof\n");
            return false;
        }
        // extraData must equal the aux-chain merkle root committing to THIS block.
        uint256 expectedRoot = auxpow::CalcAuxChainMerkleRoot(hashAuxBlock, nChainId);
        if (extra.size() != 32 ||
            std::memcmp(extra.data(), expectedRoot.begin(), 32) != 0) {
            LogPrintf("AuxPoW(ethash): parent extraData does not commit to aux block\n");
            return false;
        }
        return true;
    }

    // SECURITY: bind the proof-of-work to the commitment for the 80-byte-header
    // parent chains (sha256d/scrypt/x11). GetParentBlockPoWHash() hashes the raw
    // 80-byte header, so its merkle-root field (bytes 36..68) MUST equal the
    // merkle root the coinbase proof folds to (parentBlock.merkle_root). Without
    // this, a forger could grind any throwaway header to meet the (easy) aux
    // target and attach an unrelated coinbase committing to their own aux block,
    // minting WATTx blocks with no real parent-chain work. (equihash and kaspa
    // enforce the equivalent in their branches above; monero binds via the PoW
    // blob. ethash is NOT covered here — its synthetic-coinbase path is being
    // replaced by a full-header design; until then it is testnet-only.)
    {
        const AuxPowAlgo a = GetParentAlgo();
        if (a == AuxPowAlgo::SHA256D || a == AuxPowAlgo::SCRYPT || a == AuxPowAlgo::X11) {
            if (parentHeaderRaw.size() < 80) {
                LogPrintf("AuxPoW: 80-byte parent header required for algo %d\n", (int)a);
                return false;
            }
            uint256 header_mr;
            std::memcpy(header_mr.begin(), parentHeaderRaw.data() + 36, 32);
            if (parentBlock.merkle_root != header_mr) {
                LogPrintf("AuxPoW: parent-header merkle root != committed merkle root "
                          "(unbound PoW) algo %d\n", (int)a);
                return false;
            }
        }
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

// Parse the trustless full-header ethash AuxPoW format and recompute geth's
// seal hash. Layout:
//   [u8 marker=0x02][u8 hasBaseFee]
//   {13 or 14 fields, each [u16 LE len][bytes]} in SealHash order:
//     parentHash, uncleHash, coinbase, root, txHash, receiptHash, bloom,
//     difficulty, number, gasLimit, gasUsed, time, extra, [baseFee if hasBaseFee]
//   [8B nonce (ethash/LE order)][32B mix]
// Returns false on any malformed input. Fills sealHash, nonce8, mix32, extra.
static bool ParseEthashV2(const std::vector<uint8_t>& raw,
                          std::array<uint8_t, 32>& sealHash,
                          uint8_t nonce8[8], uint8_t mix32[32],
                          std::vector<uint8_t>& extraOut,
                          uint64_t& blockNumberOut) {
    size_t p = 0;
    auto need = [&](size_t n) { return p + n <= raw.size(); };
    if (!need(2) || raw[p] != 0x02) return false;
    p += 1;
    const uint8_t hasBaseFee = raw[p++];
    ethseal::EthHeaderFields h;
    std::vector<uint8_t>* fields[14] = {
        &h.parentHash, &h.uncleHash, &h.coinbase, &h.root, &h.txHash, &h.receiptHash, &h.bloom,
        &h.difficulty, &h.number, &h.gasLimit, &h.gasUsed, &h.time, &h.extra, &h.baseFee};
    const int nfields = hasBaseFee ? 14 : 13;
    for (int i = 0; i < nfields; ++i) {
        if (!need(2)) return false;
        const uint16_t flen = static_cast<uint16_t>(raw[p] | (raw[p + 1] << 8));
        p += 2;
        if (!need(flen)) return false;
        fields[i]->assign(raw.begin() + p, raw.begin() + p + flen);
        p += flen;
    }
    h.hasBaseFee = hasBaseFee != 0;
    if (h.parentHash.size() != 32 || h.uncleHash.size() != 32 || h.coinbase.size() != 20 ||
        h.root.size() != 32 || h.txHash.size() != 32 || h.receiptHash.size() != 32 ||
        h.bloom.size() != 256)
        return false;
    if (!need(8 + 32)) return false;
    std::memcpy(nonce8, raw.data() + p, 8);
    p += 8;
    std::memcpy(mix32, raw.data() + p, 32);
    sealHash = ethseal::SealHash(h);
    extraOut = std::move(h.extra);
    // Decode the block number (big-endian bytes → uint64) for the ethash epoch.
    blockNumberOut = 0;
    for (uint8_t b : h.number) blockNumberOut = (blockNumberOut << 8) | b;
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
            // Canonical Dash X11 (matches dashd) — consensus must agree with the
            // real parent chain, not the non-canonical sphlib/x11.c used by X25X.
            uint256 hash;
            x11_dash_hash(data, len, hash.begin());
            return hash;
        }

        case AuxPowAlgo::KHEAVYHASH: {
            // Real kaspa kHeavyHash over the carried BlockHash preimage: zero
            // the nonce/timestamp fields for the pre-PoW hash, then cSHAKE256 →
            // heavy matrix → cSHAKE256 with the REAL values. Kaspa compares the
            // result little-endian — the same convention as UintToArith256 —
            // so a hash clearing kaspad's target also clears WATTx's here.
            KaspaRawParts p;
            if (!ParseKaspaRaw(parentHeaderRaw, p)) return MaxHash();
            std::vector<uint8_t> preimage(p.preimage, p.preimage + p.preimage_len);
            uint256 pow;
            if (!kheavyhash::PowFromPreimage(preimage, pow.begin())) return MaxHash();
            return pow;
        }

        case AuxPowAlgo::ETHASH: {
            // Trustless full-header format: recompute geth's seal hash from the
            // carried header (RLP of 14 fields, per ethash_seal.h) so the PoW is
            // over the SAME header whose extraData Check() binds to the WATTx
            // commitment. header_hash is no longer trusted from the wire.
            std::array<uint8_t, 32> sealHash;
            uint8_t nonce_b[8], mix_b[32];
            std::vector<uint8_t> extra;
            uint64_t blockNumber = 0;
            if (!ParseEthashV2(parentHeaderRaw, sealHash, nonce_b, mix_b, extra, blockNumber)) {
                return MaxHash();  // fail closed: zero would pass any target
            }

            // REAL ethash: recompute the mix from the DAG (light cache) and
            // require the submitted mix to match. Without this, WATTx would trust
            // the mix and an attacker could keccak-grind a fake mix to meet the
            // (easy) aux target with no real ethash work — the commitment binds
            // the block but the PoW must be genuine too. get_global_epoch_context
            // caches the ~40 MB light cache per epoch; ethash::hash is ~ms.
            uint64_t nonce_u64 = 0;
            std::memcpy(&nonce_u64, nonce_b, 8);  // nonce carried little-endian
            ethash::hash256 eh_seal;
            std::memcpy(eh_seal.bytes, sealHash.data(), 32);
            const int epoch = ethash::get_epoch_number(static_cast<int>(blockNumber));
            ethash::result r = ethash::hash(ethash::get_global_epoch_context(epoch), eh_seal, nonce_u64);
            if (std::memcmp(r.mix_hash.bytes, mix_b, 32) != 0) {
                return MaxHash();  // fake / invalid mix — not a real ethash solution
            }
            ethash_hash256 final_hash;
            std::memcpy(final_hash.bytes, r.final_hash.bytes, 32);

            // Ethash compares the final hash as a BIG-ENDIAN 256-bit number
            // (Ethereum/geth convention), whereas CheckProofOfWork below reads
            // the uint256 little-endian via UintToArith256. Store the bytes
            // reversed so the numeric value equals geth's — this is what lets a
            // single solution that clears geth's target ALSO clear the (easier)
            // WATTx target, i.e. true dual-earning merged mining. (sha256d/scrypt/
            // x11/randomx are natively little-endian like WATTx and are unchanged.)
            uint256 result;
            for (int i = 0; i < 32; i++) result.begin()[i] = final_hash.bytes[31 - i];
            return result;
        }

        case AuxPowAlgo::EQUIHASH: {
            // SHA256d over header + CompactSize(sol) + solution — byte-identical
            // to the parent chain's block hash preimage, so a hash clearing the
            // parent target is the real parent block hash (dual-earning).
            EquihashRawParts p;
            if (!ParseEquihashRaw(parentHeaderRaw, p)) return MaxHash();
            return Hash(Span{data + 8, p.pow_len});
        }

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
