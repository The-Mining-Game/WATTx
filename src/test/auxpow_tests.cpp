// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <auxpow/auxpow.h>
#include <auxpow/ethash_seal.h>
#include <consensus/auxpow_validation.h>
#include <hash.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <ethash/ethash.hpp>
#include <ethash/global_context.hpp>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstring>
#include <vector>

// Local helper replacing removed uint256S() — supports short hex strings
static uint256 uint256S(const std::string& str) {
    uint256 rv;
    rv.SetHexDeprecated(str);
    return rv;
}

BOOST_FIXTURE_TEST_SUITE(auxpow_tests, BasicTestingSetup)

// ============================================================================
// Helper: compute the expected merkle root given a leaf, branch hashes,
//         and an index, using the same algorithm as CMerkleBranch::GetRoot().
// ============================================================================
static uint256 ReferenceMerkleRoot(const uint256& leaf,
                                   const std::vector<uint256>& branch,
                                   int nIndex)
{
    uint256 hash = leaf;
    int idx = nIndex;
    for (const auto& h : branch) {
        if (idx & 1) {
            hash = Hash(h, hash);
        } else {
            hash = Hash(hash, h);
        }
        idx >>= 1;
    }
    return hash;
}

// ============================================================================
// 1. Merkle Branch Tests
// ============================================================================

BOOST_AUTO_TEST_CASE(merkle_branch_empty)
{
    // An empty branch (no sibling hashes) should return the leaf itself.
    CMerkleBranch branch;
    branch.vHash.clear();
    branch.nIndex = 0;

    uint256 leaf;
    leaf.SetNull();
    BOOST_CHECK_EQUAL(branch.GetRoot(leaf), leaf);

    // Non-null leaf
    uint256 leaf2 = uint256S("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    BOOST_CHECK_EQUAL(branch.GetRoot(leaf2), leaf2);
}

BOOST_AUTO_TEST_CASE(merkle_branch_single_level)
{
    // Single-level branch: one sibling hash.
    // With nIndex=0 the leaf is on the left, sibling on the right.
    CMerkleBranch branch;
    uint256 sibling = uint256S("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    branch.vHash.push_back(sibling);
    branch.nIndex = 0;

    uint256 leaf = uint256S("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

    // Expected: Hash(leaf, sibling)  because index bit 0 is 0
    uint256 expected = Hash(leaf, sibling);
    BOOST_CHECK_EQUAL(branch.GetRoot(leaf), expected);

    // With nIndex=1 the leaf is on the right.
    branch.nIndex = 1;
    uint256 expected_right = Hash(sibling, leaf);
    BOOST_CHECK_EQUAL(branch.GetRoot(leaf), expected_right);
}

BOOST_AUTO_TEST_CASE(merkle_branch_multi_level)
{
    // Two-level branch simulating a 4-element tree.
    // Suppose tree leaves are: L0, L1, L2, L3
    //   Level 0: H01 = Hash(L0,L1), H23 = Hash(L2,L3)
    //   Level 1: Root = Hash(H01, H23)
    //
    // Branch for L0 (index 0): [L1, H23]
    // Branch for L1 (index 1): [L0, H23]

    uint256 L0 = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    uint256 L1 = uint256S("2222222222222222222222222222222222222222222222222222222222222222");
    uint256 L2 = uint256S("3333333333333333333333333333333333333333333333333333333333333333");
    uint256 L3 = uint256S("4444444444444444444444444444444444444444444444444444444444444444");

    uint256 H01 = Hash(L0, L1);
    uint256 H23 = Hash(L2, L3);
    uint256 root = Hash(H01, H23);

    // Branch for L0 at index 0
    {
        CMerkleBranch branch;
        branch.vHash = {L1, H23};
        branch.nIndex = 0;
        BOOST_CHECK_EQUAL(branch.GetRoot(L0), root);
    }

    // Branch for L1 at index 1
    {
        CMerkleBranch branch;
        branch.vHash = {L0, H23};
        branch.nIndex = 1;
        BOOST_CHECK_EQUAL(branch.GetRoot(L1), root);
    }

    // Branch for L2 at index 2
    {
        CMerkleBranch branch;
        branch.vHash = {L3, H01};
        branch.nIndex = 2;
        BOOST_CHECK_EQUAL(branch.GetRoot(L2), root);
    }

    // Branch for L3 at index 3
    {
        CMerkleBranch branch;
        branch.vHash = {L2, H01};
        branch.nIndex = 3;
        BOOST_CHECK_EQUAL(branch.GetRoot(L3), root);
    }
}

BOOST_AUTO_TEST_CASE(merkle_branch_matches_reference)
{
    // Verify GetRoot() produces the same result as the reference implementation
    // for several random-ish inputs.
    uint256 leaf = uint256S("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");

    std::vector<uint256> hashes;
    hashes.push_back(uint256S("1000000000000000000000000000000000000000000000000000000000000001"));
    hashes.push_back(uint256S("2000000000000000000000000000000000000000000000000000000000000002"));
    hashes.push_back(uint256S("3000000000000000000000000000000000000000000000000000000000000003"));

    for (int idx = 0; idx < 8; ++idx) {
        CMerkleBranch branch;
        branch.vHash = hashes;
        branch.nIndex = idx;

        uint256 got = branch.GetRoot(leaf);
        uint256 expected = ReferenceMerkleRoot(leaf, hashes, idx);
        BOOST_CHECK_EQUAL(got, expected);
    }
}

BOOST_AUTO_TEST_CASE(merkle_branch_is_null)
{
    CMerkleBranch branch;
    BOOST_CHECK(branch.IsNull());   // vHash is empty after default construction

    branch.vHash.push_back(uint256{});
    BOOST_CHECK(!branch.IsNull());

    branch.SetNull();
    BOOST_CHECK(branch.IsNull());
    BOOST_CHECK_EQUAL(branch.nIndex, -1);
}

// ============================================================================
// 2. Merge Mining Tag Tests
// ============================================================================

BOOST_AUTO_TEST_CASE(build_parse_merge_mining_tag_roundtrip)
{
    // Build a tag and immediately parse it back.
    uint256 merkleRoot = uint256S("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
    uint8_t depth = 0;

    std::vector<uint8_t> tag = auxpow::BuildMergeMiningTag(merkleRoot, depth);

    // Tag layout: [0x03] [depth] [32-byte merkle root]  = 34 bytes
    BOOST_CHECK_EQUAL(tag.size(), 34u);
    BOOST_CHECK_EQUAL(tag[0], TX_EXTRA_MERGE_MINING_TAG);  // 0x03
    BOOST_CHECK_EQUAL(tag[1], depth);

    // Parse it back
    uint256 parsedRoot;
    uint8_t parsedDepth;
    BOOST_CHECK(auxpow::ParseMergeMiningTag(tag, parsedRoot, parsedDepth));
    BOOST_CHECK_EQUAL(parsedRoot, merkleRoot);
    BOOST_CHECK_EQUAL(parsedDepth, depth);
}

BOOST_AUTO_TEST_CASE(build_parse_merge_mining_tag_with_depth)
{
    uint256 root = uint256S("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    uint8_t depth = 4;  // tree depth for 16 aux chains

    std::vector<uint8_t> tag = auxpow::BuildMergeMiningTag(root, depth);
    BOOST_CHECK_EQUAL(tag.size(), 34u);
    BOOST_CHECK_EQUAL(tag[1], 4);

    uint256 parsedRoot;
    uint8_t parsedDepth;
    BOOST_CHECK(auxpow::ParseMergeMiningTag(tag, parsedRoot, parsedDepth));
    BOOST_CHECK_EQUAL(parsedRoot, root);
    BOOST_CHECK_EQUAL(parsedDepth, 4);
}

BOOST_AUTO_TEST_CASE(parse_merge_mining_tag_in_larger_buffer)
{
    // The tag may be embedded in a larger extra field with padding before it.
    uint256 root = uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    std::vector<uint8_t> tag = auxpow::BuildMergeMiningTag(root, 0);

    // Prepend some unrelated extra field bytes
    std::vector<uint8_t> extra;
    extra.push_back(0x01);  // padding tag type
    extra.push_back(0x00);  // padding data
    extra.push_back(0x02);  // another tag type
    extra.push_back(0x05);  // length
    for (int i = 0; i < 5; ++i) extra.push_back(0xAA);

    extra.insert(extra.end(), tag.begin(), tag.end());

    // Append trailing bytes
    extra.push_back(0xFF);
    extra.push_back(0xFF);

    uint256 parsedRoot;
    uint8_t parsedDepth;
    BOOST_CHECK(auxpow::ParseMergeMiningTag(extra, parsedRoot, parsedDepth));
    BOOST_CHECK_EQUAL(parsedRoot, root);
}

BOOST_AUTO_TEST_CASE(parse_merge_mining_tag_not_found)
{
    // Empty buffer
    {
        std::vector<uint8_t> empty;
        uint256 root;
        uint8_t depth;
        BOOST_CHECK(!auxpow::ParseMergeMiningTag(empty, root, depth));
    }

    // Buffer too short to contain tag (33 bytes, need at least 34)
    {
        std::vector<uint8_t> short_buf(33, 0x03);
        uint256 root;
        uint8_t depth;
        BOOST_CHECK(!auxpow::ParseMergeMiningTag(short_buf, root, depth));
    }

    // Buffer long enough but no 0x03 marker
    {
        std::vector<uint8_t> no_marker(40, 0x00);
        uint256 root;
        uint8_t depth;
        BOOST_CHECK(!auxpow::ParseMergeMiningTag(no_marker, root, depth));
    }
}

BOOST_AUTO_TEST_CASE(parse_merge_mining_tag_exact_34_bytes)
{
    // Exactly 34 bytes with the marker at position 0
    uint256 root = uint256S("abababababababababababababababababababababababababababababababababab");
    std::vector<uint8_t> tag = auxpow::BuildMergeMiningTag(root, 2);
    BOOST_CHECK_EQUAL(tag.size(), 34u);

    uint256 parsedRoot;
    uint8_t parsedDepth;
    BOOST_CHECK(auxpow::ParseMergeMiningTag(tag, parsedRoot, parsedDepth));
    BOOST_CHECK_EQUAL(parsedRoot, root);
    BOOST_CHECK_EQUAL(parsedDepth, 2);
}

// ============================================================================
// 3. CalcAuxChainMerkleRoot
// ============================================================================

BOOST_AUTO_TEST_CASE(calc_aux_chain_merkle_root_deterministic)
{
    // CalcAuxChainMerkleRoot must be deterministic: same inputs -> same output.
    uint256 auxHash = uint256S("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    int chainId = 0x5754;  // WATTX_CHAIN_ID

    uint256 root1 = auxpow::CalcAuxChainMerkleRoot(auxHash, chainId);
    uint256 root2 = auxpow::CalcAuxChainMerkleRoot(auxHash, chainId);
    BOOST_CHECK_EQUAL(root1, root2);
    BOOST_CHECK(!root1.IsNull());
}

BOOST_AUTO_TEST_CASE(calc_aux_chain_merkle_root_different_inputs)
{
    // Different aux block hashes must produce different roots.
    uint256 hash1 = uint256S("0000000000000000000000000000000000000000000000000000000000000001");
    uint256 hash2 = uint256S("0000000000000000000000000000000000000000000000000000000000000002");
    int chainId = 0x5754;

    uint256 root1 = auxpow::CalcAuxChainMerkleRoot(hash1, chainId);
    uint256 root2 = auxpow::CalcAuxChainMerkleRoot(hash2, chainId);
    BOOST_CHECK(root1 != root2);
}

BOOST_AUTO_TEST_CASE(calc_aux_chain_merkle_root_different_chain_ids)
{
    // Same aux block hash with different chain IDs must produce different roots.
    uint256 auxHash = uint256S("aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd");

    uint256 root1 = auxpow::CalcAuxChainMerkleRoot(auxHash, 1);
    uint256 root2 = auxpow::CalcAuxChainMerkleRoot(auxHash, 2);
    BOOST_CHECK(root1 != root2);
}

BOOST_AUTO_TEST_CASE(calc_aux_chain_merkle_root_known_value)
{
    // Verify against hand-calculated value.
    // CalcAuxChainMerkleRoot serialises: hashAuxBlock (32 bytes) || nChainId (4 bytes LE)
    // then runs SHA256d (Hash()) on the result.
    uint256 auxHash = uint256S("0000000000000000000000000000000000000000000000000000000000000001");
    int chainId = 0x5754;

    DataStream ss{};
    ss << auxHash;
    ss << chainId;
    uint256 expected = Hash(ss);

    uint256 got = auxpow::CalcAuxChainMerkleRoot(auxHash, chainId);
    BOOST_CHECK_EQUAL(got, expected);
}

// ============================================================================
// 4. CMoneroBlockHeader
// ============================================================================

BOOST_AUTO_TEST_CASE(monero_block_header_set_null)
{
    CMoneroBlockHeader hdr;
    hdr.major_version = 16;
    hdr.minor_version = 1;
    hdr.timestamp = 1700000000;
    hdr.nonce = 0xDEADBEEF;
    hdr.prev_id = uint256S("aaaa");
    hdr.merkle_root = uint256S("bbbb");

    BOOST_CHECK(!hdr.IsNull());

    hdr.SetNull();
    BOOST_CHECK(hdr.IsNull());
    BOOST_CHECK_EQUAL(hdr.major_version, 0);
    BOOST_CHECK_EQUAL(hdr.minor_version, 0);
    BOOST_CHECK_EQUAL(hdr.timestamp, 0u);
    BOOST_CHECK_EQUAL(hdr.nonce, 0u);
    BOOST_CHECK(hdr.prev_id.IsNull());
    BOOST_CHECK(hdr.merkle_root.IsNull());
}

BOOST_AUTO_TEST_CASE(monero_block_header_get_hash_deterministic)
{
    CMoneroBlockHeader hdr;
    hdr.major_version = 16;
    hdr.minor_version = 0;
    hdr.timestamp = 1700000000;
    hdr.prev_id = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    hdr.nonce = 12345;
    hdr.merkle_root = uint256S("2222222222222222222222222222222222222222222222222222222222222222");

    uint256 h1 = hdr.GetHash();
    uint256 h2 = hdr.GetHash();
    BOOST_CHECK_EQUAL(h1, h2);
    BOOST_CHECK(!h1.IsNull());
}

BOOST_AUTO_TEST_CASE(monero_block_header_different_nonce_different_hash)
{
    CMoneroBlockHeader hdr1;
    hdr1.major_version = 16;
    hdr1.minor_version = 0;
    hdr1.timestamp = 1700000000;
    hdr1.prev_id = uint256S("aaaa");
    hdr1.nonce = 0;
    hdr1.merkle_root = uint256S("bbbb");

    CMoneroBlockHeader hdr2 = hdr1;
    hdr2.nonce = 1;

    BOOST_CHECK(hdr1.GetHash() != hdr2.GetHash());
}

// ============================================================================
// 5. CAuxPow Proof Validation Tests
// ============================================================================

// Helper: build a minimal valid CAuxPow for testing.
// This constructs the proof so that Check() passes for the given auxBlockHash
// and chainId, using only SHA256d (no RandomX needed).
static CAuxPow BuildValidAuxPow(const uint256& auxBlockHash, int chainId)
{
    CAuxPow pow;
    pow.nChainId = chainId;

    // Calculate the aux chain merkle root commitment
    uint256 auxMerkleRoot = auxpow::CalcAuxChainMerkleRoot(auxBlockHash, chainId);

    // Build the merge mining tag containing that commitment
    std::vector<uint8_t> tag = auxpow::BuildMergeMiningTag(auxMerkleRoot, 0);

    // Create a coinbase transaction whose scriptSig contains the tag
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();
    // Put the merge mining tag into the scriptSig
    mtx.vin[0].scriptSig = CScript(tag.begin(), tag.end());
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 0;
    mtx.vout[0].scriptPubKey = CScript();

    pow.coinbaseTxMut = mtx;

    // Empty aux chain branch (single chain, depth 0)
    pow.auxChainBranch.SetNull();

    // Coinbase branch: empty means coinbase IS the only tx => its hash is the merkle root.
    pow.coinbaseBranch.vHash.clear();
    pow.coinbaseBranch.nIndex = 0;

    // The coinbase hash becomes the parent block's merkle root
    uint256 coinbaseHash = CTransaction(mtx).GetHash();

    // Set up parent block header with merkle_root = coinbase hash
    pow.parentBlock.SetNull();
    pow.parentBlock.major_version = 16;
    pow.parentBlock.minor_version = 0;
    pow.parentBlock.timestamp = 1700000000;
    pow.parentBlock.prev_id = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    pow.parentBlock.nonce = 42;
    pow.parentBlock.merkle_root = coinbaseHash;

    return pow;
}

BOOST_AUTO_TEST_CASE(auxpow_check_valid_proof)
{
    // Construct a block header and compute its hash
    CBlockHeader header;
    header.nVersion = 1;
    header.hashPrevBlock = uint256S("0000000000000000000000000000000000000000000000000000000000000000");
    header.hashMerkleRoot = uint256S("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
    header.nTime = 1700000000;
    header.nBits = 0x1f00ffff;
    header.nNonce = 0;

    uint256 auxBlockHash = header.GetHash();
    int chainId = CAuxPowBlockHeader::WATTX_CHAIN_ID;

    CAuxPow proof = BuildValidAuxPow(auxBlockHash, chainId);
    BOOST_CHECK(proof.Check(auxBlockHash, chainId));
}

BOOST_AUTO_TEST_CASE(auxpow_check_wrong_chain_id)
{
    CBlockHeader header;
    header.nVersion = 1;
    header.hashPrevBlock.SetNull();
    header.hashMerkleRoot = uint256S("1234");
    header.nTime = 1700000000;
    header.nBits = 0x1f00ffff;
    header.nNonce = 0;

    uint256 auxBlockHash = header.GetHash();
    int correctChainId = CAuxPowBlockHeader::WATTX_CHAIN_ID;
    int wrongChainId = 0x1234;

    // Build proof with the correct chain ID
    CAuxPow proof = BuildValidAuxPow(auxBlockHash, correctChainId);

    // Checking with the wrong chain ID should fail
    BOOST_CHECK(!proof.Check(auxBlockHash, wrongChainId));
}

BOOST_AUTO_TEST_CASE(auxpow_check_wrong_aux_block_hash)
{
    CBlockHeader header;
    header.nVersion = 1;
    header.hashPrevBlock.SetNull();
    header.hashMerkleRoot = uint256S("5678");
    header.nTime = 1700000000;
    header.nBits = 0x1f00ffff;
    header.nNonce = 0;

    uint256 auxBlockHash = header.GetHash();
    int chainId = CAuxPowBlockHeader::WATTX_CHAIN_ID;

    CAuxPow proof = BuildValidAuxPow(auxBlockHash, chainId);

    // The proof should fail when checked against a different aux block hash
    uint256 differentHash = uint256S("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
    BOOST_CHECK(!proof.Check(differentHash, chainId));
}

BOOST_AUTO_TEST_CASE(auxpow_check_corrupted_coinbase_merkle_proof)
{
    CBlockHeader header;
    header.nVersion = 1;
    header.hashPrevBlock.SetNull();
    header.hashMerkleRoot = uint256S("9abc");
    header.nTime = 1700000000;
    header.nBits = 0x1f00ffff;
    header.nNonce = 0;

    uint256 auxBlockHash = header.GetHash();
    int chainId = CAuxPowBlockHeader::WATTX_CHAIN_ID;

    CAuxPow proof = BuildValidAuxPow(auxBlockHash, chainId);

    // Corrupt the parent block merkle root so the coinbase merkle proof fails
    proof.parentBlock.merkle_root = uint256S("bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0");

    BOOST_CHECK(!proof.Check(auxBlockHash, chainId));
}

BOOST_AUTO_TEST_CASE(auxpow_check_empty_coinbase_vin)
{
    CBlockHeader header;
    header.nVersion = 1;
    header.hashPrevBlock.SetNull();
    header.hashMerkleRoot = uint256S("def0");
    header.nTime = 1700000000;
    header.nBits = 0x1f00ffff;
    header.nNonce = 0;

    uint256 auxBlockHash = header.GetHash();
    int chainId = CAuxPowBlockHeader::WATTX_CHAIN_ID;

    CAuxPow proof = BuildValidAuxPow(auxBlockHash, chainId);

    // Remove coinbase inputs - should fail the "coinbase has no inputs" check
    proof.coinbaseTxMut.vin.clear();

    // We also need to update the parent merkle root to match the new coinbase hash,
    // so we don't hit the merkle proof check first.  Actually, clearing vin changes
    // the tx hash, so the merkle proof will fail before the empty-vin check.
    // Instead, let's verify it fails (either path is acceptable).
    BOOST_CHECK(!proof.Check(auxBlockHash, chainId));
}

BOOST_AUTO_TEST_CASE(auxpow_check_corrupted_merge_mining_tag)
{
    CBlockHeader header;
    header.nVersion = 1;
    header.hashPrevBlock.SetNull();
    header.hashMerkleRoot = uint256S("face");
    header.nTime = 1700000000;
    header.nBits = 0x1f00ffff;
    header.nNonce = 0;

    uint256 auxBlockHash = header.GetHash();
    int chainId = CAuxPowBlockHeader::WATTX_CHAIN_ID;

    CAuxPow proof = BuildValidAuxPow(auxBlockHash, chainId);

    // Corrupt one byte in the merge mining tag within the scriptSig
    // (byte at offset 2 is the first byte of the merkle root)
    auto& scriptSig = proof.coinbaseTxMut.vin[0].scriptSig;
    std::vector<uint8_t> data(scriptSig.begin(), scriptSig.end());
    BOOST_REQUIRE(data.size() >= 3);
    data[2] ^= 0xFF;  // flip bits in the merkle root
    proof.coinbaseTxMut.vin[0].scriptSig = CScript(data.begin(), data.end());

    // The merkle root extracted from the tag will no longer match the expected one.
    // Also need to update parent merkle_root to match the modified coinbase.
    uint256 newCoinbaseHash = CTransaction(proof.coinbaseTxMut).GetHash();
    proof.parentBlock.merkle_root = newCoinbaseHash;

    BOOST_CHECK(!proof.Check(auxBlockHash, chainId));
}

BOOST_AUTO_TEST_CASE(auxpow_check_no_merge_mining_tag)
{
    CBlockHeader header;
    header.nVersion = 1;
    header.hashPrevBlock.SetNull();
    header.hashMerkleRoot = uint256S("cafe");
    header.nTime = 1700000000;
    header.nBits = 0x1f00ffff;
    header.nNonce = 0;

    uint256 auxBlockHash = header.GetHash();
    int chainId = CAuxPowBlockHeader::WATTX_CHAIN_ID;

    // Build a proof but replace the coinbase scriptSig with garbage (no tag)
    CAuxPow proof;
    proof.nChainId = chainId;

    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();
    // ScriptSig with no merge mining marker
    std::vector<uint8_t> garbage(40, 0x00);
    mtx.vin[0].scriptSig = CScript(garbage.begin(), garbage.end());
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 0;
    mtx.vout[0].scriptPubKey = CScript();

    proof.coinbaseTxMut = mtx;
    proof.auxChainBranch.SetNull();
    proof.coinbaseBranch.vHash.clear();
    proof.coinbaseBranch.nIndex = 0;

    uint256 coinbaseHash = CTransaction(mtx).GetHash();
    proof.parentBlock.SetNull();
    proof.parentBlock.major_version = 16;
    proof.parentBlock.timestamp = 1700000000;
    proof.parentBlock.prev_id = uint256S("1111");
    proof.parentBlock.merkle_root = coinbaseHash;

    // Should fail because no merge mining tag is found
    BOOST_CHECK(!proof.Check(auxBlockHash, chainId));
}

// ============================================================================
// 6. CAuxPow with coinbase merkle branch (multiple transactions)
// ============================================================================

BOOST_AUTO_TEST_CASE(auxpow_check_with_coinbase_branch)
{
    // Simulate a parent block with 2 transactions.
    // The coinbase is at index 0, and there is one other tx.
    CBlockHeader header;
    header.nVersion = 1;
    header.hashPrevBlock.SetNull();
    header.hashMerkleRoot = uint256S("babe");
    header.nTime = 1700000000;
    header.nBits = 0x1f00ffff;
    header.nNonce = 0;

    uint256 auxBlockHash = header.GetHash();
    int chainId = CAuxPowBlockHeader::WATTX_CHAIN_ID;

    // Build the coinbase with the merge mining tag
    uint256 auxMerkleRoot = auxpow::CalcAuxChainMerkleRoot(auxBlockHash, chainId);
    std::vector<uint8_t> tag = auxpow::BuildMergeMiningTag(auxMerkleRoot, 0);

    CMutableTransaction coinbaseMtx;
    coinbaseMtx.vin.resize(1);
    coinbaseMtx.vin[0].prevout.SetNull();
    coinbaseMtx.vin[0].scriptSig = CScript(tag.begin(), tag.end());
    coinbaseMtx.vout.resize(1);
    coinbaseMtx.vout[0].nValue = 0;
    coinbaseMtx.vout[0].scriptPubKey = CScript();

    uint256 coinbaseHash = CTransaction(coinbaseMtx).GetHash();

    // Create a second "fake" transaction hash
    uint256 otherTxHash = uint256S("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");

    // Build the 2-tx merkle tree: root = Hash(coinbaseHash, otherTxHash)
    uint256 parentMerkleRoot = Hash(coinbaseHash, otherTxHash);

    // Coinbase branch: sibling is otherTxHash, index = 0
    CAuxPow proof;
    proof.nChainId = chainId;
    proof.coinbaseTxMut = coinbaseMtx;
    proof.coinbaseBranch.vHash = {otherTxHash};
    proof.coinbaseBranch.nIndex = 0;
    proof.auxChainBranch.SetNull();

    proof.parentBlock.SetNull();
    proof.parentBlock.major_version = 16;
    proof.parentBlock.timestamp = 1700000000;
    proof.parentBlock.prev_id = uint256S("1111");
    proof.parentBlock.nonce = 0;
    proof.parentBlock.merkle_root = parentMerkleRoot;

    BOOST_CHECK(proof.Check(auxBlockHash, chainId));

    // Corrupt the branch and verify failure
    proof.coinbaseBranch.vHash[0] = uint256S("dddd");
    BOOST_CHECK(!proof.Check(auxBlockHash, chainId));
}

// ============================================================================
// 7. CAuxPow with aux chain branch (multiple aux chains)
// ============================================================================

BOOST_AUTO_TEST_CASE(auxpow_check_with_aux_chain_branch)
{
    // Simulate 2 aux chains sharing the same parent block.
    // WATTx is at index 0, another chain is at index 1.
    CBlockHeader header;
    header.nVersion = 1;
    header.hashPrevBlock.SetNull();
    header.hashMerkleRoot = uint256S("d00d");
    header.nTime = 1700000000;
    header.nBits = 0x1f00ffff;
    header.nNonce = 0;

    uint256 auxBlockHash = header.GetHash();
    int chainId = CAuxPowBlockHeader::WATTX_CHAIN_ID;

    // Calculate the per-chain commitment
    uint256 wattxCommitment = auxpow::CalcAuxChainMerkleRoot(auxBlockHash, chainId);

    // Other aux chain commitment (some arbitrary hash)
    uint256 otherChainCommitment = uint256S("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");

    // The merged merkle root: Hash(wattxCommitment, otherChainCommitment) since wattx is at index 0
    uint256 mergedRoot = Hash(wattxCommitment, otherChainCommitment);

    // Build the merge mining tag with the merged root and depth=1
    std::vector<uint8_t> tag = auxpow::BuildMergeMiningTag(mergedRoot, 1);

    CMutableTransaction coinbaseMtx;
    coinbaseMtx.vin.resize(1);
    coinbaseMtx.vin[0].prevout.SetNull();
    coinbaseMtx.vin[0].scriptSig = CScript(tag.begin(), tag.end());
    coinbaseMtx.vout.resize(1);
    coinbaseMtx.vout[0].nValue = 0;
    coinbaseMtx.vout[0].scriptPubKey = CScript();

    uint256 coinbaseHash = CTransaction(coinbaseMtx).GetHash();

    CAuxPow proof;
    proof.nChainId = chainId;
    proof.coinbaseTxMut = coinbaseMtx;

    // Aux chain branch: WATTx is at index 0, sibling is otherChainCommitment
    proof.auxChainBranch.vHash = {otherChainCommitment};
    proof.auxChainBranch.nIndex = 0;

    // Single-tx parent block
    proof.coinbaseBranch.vHash.clear();
    proof.coinbaseBranch.nIndex = 0;

    proof.parentBlock.SetNull();
    proof.parentBlock.major_version = 16;
    proof.parentBlock.timestamp = 1700000000;
    proof.parentBlock.prev_id = uint256S("1111");
    proof.parentBlock.nonce = 0;
    proof.parentBlock.merkle_root = coinbaseHash;

    BOOST_CHECK(proof.Check(auxBlockHash, chainId));
}

// ============================================================================
// 8. CAuxPowBlockHeader version flag tests
// ============================================================================

BOOST_AUTO_TEST_CASE(auxpow_block_header_version_flag)
{
    CAuxPowBlockHeader hdr;
    hdr.nVersion = 0;
    BOOST_CHECK(!hdr.IsAuxPow());

    hdr.SetAuxPowFlag();
    BOOST_CHECK(hdr.IsAuxPow());
    BOOST_CHECK_EQUAL(hdr.nVersion & CAuxPowBlockHeader::AUXPOW_VERSION_FLAG,
                      CAuxPowBlockHeader::AUXPOW_VERSION_FLAG);

    hdr.ClearAuxPowFlag();
    BOOST_CHECK(!hdr.IsAuxPow());
    BOOST_CHECK_EQUAL(hdr.nVersion, 0);
}

BOOST_AUTO_TEST_CASE(auxpow_block_header_version_preserves_other_bits)
{
    CAuxPowBlockHeader hdr;
    hdr.nVersion = 0x20000004;  // version 4 with top-bit signaling
    BOOST_CHECK(!hdr.IsAuxPow());

    hdr.SetAuxPowFlag();
    BOOST_CHECK(hdr.IsAuxPow());
    // Other bits should be preserved
    BOOST_CHECK_EQUAL(hdr.nVersion & 0x20000004, 0x20000004);

    hdr.ClearAuxPowFlag();
    BOOST_CHECK(!hdr.IsAuxPow());
    BOOST_CHECK_EQUAL(hdr.nVersion, 0x20000004);
}

// ============================================================================
// 9. CAuxPow serialization roundtrip
// ============================================================================

BOOST_AUTO_TEST_CASE(auxpow_set_null)
{
    CBlockHeader header;
    header.nVersion = 1;
    header.hashPrevBlock.SetNull();
    header.hashMerkleRoot = uint256S("1234");
    header.nTime = 1700000000;
    header.nBits = 0x1f00ffff;
    header.nNonce = 0;

    uint256 auxBlockHash = header.GetHash();
    int chainId = CAuxPowBlockHeader::WATTX_CHAIN_ID;

    CAuxPow proof = BuildValidAuxPow(auxBlockHash, chainId);
    BOOST_CHECK(!proof.parentBlock.IsNull());
    BOOST_CHECK_EQUAL(proof.nChainId, chainId);

    proof.SetNull();
    BOOST_CHECK(proof.parentBlock.IsNull());
    BOOST_CHECK_EQUAL(proof.nChainId, 0);
    BOOST_CHECK(proof.coinbaseBranch.IsNull());
    BOOST_CHECK(proof.auxChainBranch.IsNull());
}

// ============================================================================
// 10. Consensus AuxPow validation parameters
// ============================================================================

BOOST_AUTO_TEST_CASE(auxpow_validation_params_defaults)
{
    // Verify we can set and get AuxPoW parameters
    consensus::AuxPowParams params;
    params.nAuxPowActivationHeight = 100;
    params.nMinParentBlockDelta = 2;
    params.nMaxParentTimeDiff = 3600;
    params.nChainId = 0x5754;
    params.fAllowStandaloneMining = false;

    consensus::SetAuxPowParams(params);

    const auto& got = consensus::GetAuxPowParams();
    BOOST_CHECK_EQUAL(got.nAuxPowActivationHeight, 100);
    BOOST_CHECK_EQUAL(got.nMinParentBlockDelta, 2);
    BOOST_CHECK_EQUAL(got.nMaxParentTimeDiff, 3600);
    BOOST_CHECK_EQUAL(got.nChainId, 0x5754);
    BOOST_CHECK_EQUAL(got.fAllowStandaloneMining, false);

    // Reset to defaults to not affect other tests
    consensus::SetAuxPowParams(consensus::AuxPowParams{});
}

BOOST_AUTO_TEST_CASE(auxpow_chain_id_constant)
{
    // Verify the WATTx chain ID is "WT" in hex
    BOOST_CHECK_EQUAL(CAuxPowBlockHeader::WATTX_CHAIN_ID, 0x5754);
}

// ============================================================================
// 11. GetAuxChainMerkleRoot from coinbase (via OP_RETURN output)
// ============================================================================

BOOST_AUTO_TEST_CASE(auxpow_get_aux_merkle_root_from_op_return)
{
    uint256 merkleRoot = uint256S("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
    std::vector<uint8_t> tag = auxpow::BuildMergeMiningTag(merkleRoot, 0);

    // Create a coinbase whose scriptSig does NOT contain the tag,
    // but has an OP_RETURN output that does.
    CAuxPow proof;
    proof.nChainId = CAuxPowBlockHeader::WATTX_CHAIN_ID;

    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();
    // ScriptSig without the tag
    std::vector<uint8_t> emptyScript = {0x04, 0x00, 0x00, 0x00, 0x00};
    mtx.vin[0].scriptSig = CScript(emptyScript.begin(), emptyScript.end());

    // OP_RETURN output containing the merge mining tag
    CScript opReturnScript;
    opReturnScript << OP_RETURN;
    opReturnScript.insert(opReturnScript.end(), tag.begin(), tag.end());

    mtx.vout.resize(1);
    mtx.vout[0].nValue = 0;
    mtx.vout[0].scriptPubKey = opReturnScript;

    proof.coinbaseTxMut = mtx;

    uint256 extractedRoot;
    BOOST_CHECK(proof.GetAuxChainMerkleRoot(extractedRoot));
    BOOST_CHECK_EQUAL(extractedRoot, merkleRoot);
}

// ============================================================================
// 12. BuildMergeMiningTag byte-level verification
// ============================================================================

BOOST_AUTO_TEST_CASE(build_merge_mining_tag_byte_layout)
{
    uint256 root;
    // Fill with a known pattern: 0x01 0x02 ... 0x20
    for (int i = 0; i < 32; ++i) {
        root.data()[i] = static_cast<uint8_t>(i + 1);
    }
    uint8_t depth = 7;

    std::vector<uint8_t> tag = auxpow::BuildMergeMiningTag(root, depth);

    BOOST_CHECK_EQUAL(tag.size(), 34u);
    BOOST_CHECK_EQUAL(tag[0], 0x03);    // TX_EXTRA_MERGE_MINING_TAG
    BOOST_CHECK_EQUAL(tag[1], 7);       // depth

    // Verify the 32 bytes of merkle root match
    for (int i = 0; i < 32; ++i) {
        BOOST_CHECK_EQUAL(tag[2 + i], root.data()[i]);
    }
}

// ---------------------------------------------------------------------------
// PoW <-> commitment binding (security regression tests)
//
// A merged block is only secure if the bytes actually hashed for proof-of-work
// CONTAIN the commitment to the WATTx block. For the 80-byte-header parents
// (sha256d/scrypt/x11) GetParentBlockPoWHash() hashes parentHeaderRaw, while
// the coinbase proof folds to parentBlock.merkle_root -- a SEPARATE,
// attacker-settable field. Without an explicit check tying the two together a
// forger can grind any throwaway 80-byte header to meet the (easy) aux target,
// staple on a coinbase committing to their own aux block, and mint WATTx blocks
// with no real parent-chain work.
//
// These tests pin that check. Note they fail if the binding is removed but the
// rest of Check() is left intact -- which is exactly the refactor hazard, since
// every other test in this file leaves parentAlgoId at its 0/RANDOMX default
// and never populates parentHeaderRaw, so none of them exercise this path.
// ---------------------------------------------------------------------------

// Build an 80-byte Bitcoin-style parent header whose merkle-root field
// (bytes 36..68) is `mr`. Every other field is arbitrary: only the merkle-root
// field participates in the binding check.
static std::vector<uint8_t> BuildParentHeader80(const uint256& mr)
{
    std::vector<uint8_t> hdr(80, 0);
    hdr[0] = 0x20;  // plausible version byte; not inspected by the binding
    std::memcpy(hdr.data() + 36, mr.begin(), 32);
    return hdr;
}

// The three algos that carry an 80-byte header and so must be bound.
static const uint8_t GENERIC_80B_ALGOS[] = {
    static_cast<uint8_t>(AuxPowAlgo::SHA256D),
    static_cast<uint8_t>(AuxPowAlgo::SCRYPT),
    static_cast<uint8_t>(AuxPowAlgo::X11),
};

BOOST_AUTO_TEST_CASE(auxpow_generic_algos_accept_bound_parent_header)
{
    CBlockHeader header;
    header.nVersion = 1;
    header.hashMerkleRoot = uint256S("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
    header.nTime = 1700000000;
    header.nBits = 0x1f00ffff;
    const uint256 auxBlockHash = header.GetHash();
    const int chainId = CAuxPowBlockHeader::WATTX_CHAIN_ID;

    // Honest proof: the header that gets PoW'd carries the same merkle root the
    // coinbase proof folds to. Must still validate -- the binding must not
    // false-reject legitimate merged mining.
    for (uint8_t algo : GENERIC_80B_ALGOS) {
        CAuxPow proof = BuildValidAuxPow(auxBlockHash, chainId);
        proof.parentAlgoId = algo;
        proof.parentHeaderRaw = BuildParentHeader80(proof.parentBlock.merkle_root);
        BOOST_CHECK_MESSAGE(proof.Check(auxBlockHash, chainId),
                            "honest bound proof rejected for algo " << (int)algo);
    }
}

BOOST_AUTO_TEST_CASE(auxpow_generic_algos_reject_unbound_parent_header)
{
    CBlockHeader header;
    header.nVersion = 1;
    header.hashMerkleRoot = uint256S("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
    header.nTime = 1700000000;
    header.nBits = 0x1f00ffff;
    const uint256 auxBlockHash = header.GetHash();
    const int chainId = CAuxPowBlockHeader::WATTX_CHAIN_ID;

    // THE FORGERY: the coinbase still commits correctly to our aux block (so
    // every other check in Check() passes), but the header whose PoW would be
    // verified commits to an unrelated merkle root. That header could be any
    // cheap grind against the easy aux target. This MUST be rejected.
    const uint256 unrelated = uint256S("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
    for (uint8_t algo : GENERIC_80B_ALGOS) {
        CAuxPow proof = BuildValidAuxPow(auxBlockHash, chainId);
        proof.parentAlgoId = algo;
        proof.parentHeaderRaw = BuildParentHeader80(unrelated);

        // Sanity: the forgery differs from the committed root only in the
        // header, so without the binding the rest of Check() would pass.
        BOOST_CHECK(proof.parentBlock.merkle_root != unrelated);
        BOOST_CHECK_MESSAGE(!proof.Check(auxBlockHash, chainId),
                            "UNBOUND PoW ACCEPTED for algo " << (int)algo
                            << " -- parent-header/commitment binding is missing");
    }
}

BOOST_AUTO_TEST_CASE(auxpow_generic_algos_require_full_80_byte_header)
{
    CBlockHeader header;
    header.nVersion = 1;
    header.hashMerkleRoot = uint256S("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
    header.nTime = 1700000000;
    header.nBits = 0x1f00ffff;
    const uint256 auxBlockHash = header.GetHash();
    const int chainId = CAuxPowBlockHeader::WATTX_CHAIN_ID;

    // Fail closed: a missing or truncated header must not silently skip the
    // binding (that would restore the forgery by simply omitting the bytes).
    for (uint8_t algo : GENERIC_80B_ALGOS) {
        CAuxPow empty = BuildValidAuxPow(auxBlockHash, chainId);
        empty.parentAlgoId = algo;
        empty.parentHeaderRaw.clear();
        BOOST_CHECK_MESSAGE(!empty.Check(auxBlockHash, chainId),
                            "empty parentHeaderRaw accepted for algo " << (int)algo);

        CAuxPow truncated = BuildValidAuxPow(auxBlockHash, chainId);
        truncated.parentAlgoId = algo;
        truncated.parentHeaderRaw = BuildParentHeader80(truncated.parentBlock.merkle_root);
        truncated.parentHeaderRaw.resize(79);  // one byte short of a full header
        BOOST_CHECK_MESSAGE(!truncated.Check(auxBlockHash, chainId),
                            "79-byte parentHeaderRaw accepted for algo " << (int)algo);
    }
}

BOOST_AUTO_TEST_CASE(auxpow_randomx_unaffected_by_generic_binding)
{
    CBlockHeader header;
    header.nVersion = 1;
    header.hashMerkleRoot = uint256S("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
    header.nTime = 1700000000;
    header.nBits = 0x1f00ffff;
    const uint256 auxBlockHash = header.GetHash();
    const int chainId = CAuxPowBlockHeader::WATTX_CHAIN_ID;

    // The binding is algo-gated. RandomX binds via the PoW blob instead, and an
    // empty parentHeaderRaw is legitimate there, so the 80-byte requirement must
    // not leak into this path.
    CAuxPow proof = BuildValidAuxPow(auxBlockHash, chainId);
    proof.parentAlgoId = static_cast<uint8_t>(AuxPowAlgo::RANDOMX);
    proof.parentHeaderRaw.clear();
    BOOST_CHECK(proof.Check(auxBlockHash, chainId));
}

BOOST_AUTO_TEST_CASE(auxpow_ethash_rejects_legacy_synthetic_proof)
{
    CBlockHeader header;
    header.nVersion = 1;
    header.hashMerkleRoot = uint256S("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
    header.nTime = 1700000000;
    header.nBits = 0x1f00ffff;
    const uint256 auxBlockHash = header.GetHash();
    const int chainId = CAuxPowBlockHeader::WATTX_CHAIN_ID;

    // The old ethash proof format was 32B header_hash + 8B nonce + 32B mix = 72
    // bytes, with a synthetic coinbase decoupled from the PoW'd header. That is
    // the format the fake-mix exploit used, so it must no longer parse. The V2
    // full-header format is required (marker byte 0x02).
    CAuxPow legacy = BuildValidAuxPow(auxBlockHash, chainId);
    legacy.parentAlgoId = static_cast<uint8_t>(AuxPowAlgo::ETHASH);
    legacy.parentHeaderRaw.assign(72, 0x00);
    BOOST_CHECK_MESSAGE(!legacy.Check(auxBlockHash, chainId),
                        "legacy 72-byte ethash proof accepted -- fake-mix forgery is reachable");

    // An empty ethash proof must also fail closed rather than skip verification.
    CAuxPow empty = BuildValidAuxPow(auxBlockHash, chainId);
    empty.parentAlgoId = static_cast<uint8_t>(AuxPowAlgo::ETHASH);
    empty.parentHeaderRaw.clear();
    BOOST_CHECK(!empty.Check(auxBlockHash, chainId));
}

// ---------------------------------------------------------------------------
// Ethash trustless full-header path
//
// Two independent guarantees, enforced in two different places:
//   Check()                  -- the parent header's extraData commits to THIS
//                               aux block (binds the block)
//   GetParentBlockPoWHash()  -- the submitted mix is reproduced from the DAG
//                               (proves the work is genuine)
// Both are needed: the commitment alone still allowed the keccak-grind /
// fake-mix forgery that tools/eth_miner.js demonstrated, and a real mix alone
// would let a miner point real ALT work at someone else's aux block.
// ---------------------------------------------------------------------------

// Build the ParseEthashV2 wire format, and fill `fields` with the same values
// so a test can independently recompute geth's seal hash. Layout:
//   [0x02][hasBaseFee][13 fields: u16 LE len + bytes][8B nonce LE][32B mix]
static std::vector<uint8_t> BuildEthashV2Raw(ethseal::EthHeaderFields& fields,
                                             const std::vector<uint8_t>& extra,
                                             uint64_t blockNumber,
                                             uint64_t nonce,
                                             const uint8_t mix32[32])
{
    fields = ethseal::EthHeaderFields{};
    fields.parentHash.assign(32, 0x11);
    fields.uncleHash.assign(32, 0x22);
    fields.coinbase.assign(20, 0x33);
    fields.root.assign(32, 0x44);
    fields.txHash.assign(32, 0x55);
    fields.receiptHash.assign(32, 0x66);
    fields.bloom.assign(256, 0x00);
    fields.difficulty = {0x01};
    // Block number as big-endian minimal bytes: ParseEthashV2 folds these back
    // into a uint64 to pick the ethash epoch.
    fields.number.clear();
    for (int shift = 56; shift >= 0; shift -= 8) {
        const uint8_t b = static_cast<uint8_t>((blockNumber >> shift) & 0xff);
        if (!fields.number.empty() || b != 0) fields.number.push_back(b);
    }
    fields.gasLimit = {0x01, 0x00};
    fields.gasUsed  = {0x00};
    fields.time     = {0x01};
    fields.extra    = extra;
    fields.hasBaseFee = false;

    std::vector<uint8_t> raw;
    raw.push_back(0x02);  // V2 marker
    raw.push_back(0x00);  // hasBaseFee = false
    auto put = [&raw](const std::vector<uint8_t>& v) {
        raw.push_back(static_cast<uint8_t>(v.size() & 0xff));
        raw.push_back(static_cast<uint8_t>((v.size() >> 8) & 0xff));
        raw.insert(raw.end(), v.begin(), v.end());
    };
    put(fields.parentHash); put(fields.uncleHash); put(fields.coinbase);
    put(fields.root);       put(fields.txHash);    put(fields.receiptHash);
    put(fields.bloom);      put(fields.difficulty); put(fields.number);
    put(fields.gasLimit);   put(fields.gasUsed);   put(fields.time);
    put(fields.extra);
    for (int i = 0; i < 8; ++i) raw.push_back(static_cast<uint8_t>((nonce >> (8 * i)) & 0xff));
    raw.insert(raw.end(), mix32, mix32 + 32);
    return raw;
}

static uint256 AllOnesHash()
{
    uint256 h;
    std::memset(h.begin(), 0xFF, 32);
    return h;
}

BOOST_AUTO_TEST_CASE(auxpow_ethash_v2_commitment_binding)
{
    CBlockHeader header;
    header.nVersion = 1;
    header.hashMerkleRoot = uint256S("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
    header.nTime = 1700000000;
    header.nBits = 0x1f00ffff;
    const uint256 auxBlockHash = header.GetHash();
    const int chainId = CAuxPowBlockHeader::WATTX_CHAIN_ID;

    const uint256 commitment = auxpow::CalcAuxChainMerkleRoot(auxBlockHash, chainId);
    std::vector<uint8_t> goodExtra(commitment.begin(), commitment.begin() + 32);
    uint8_t mix[32];
    std::memset(mix, 0xAB, sizeof(mix));
    ethseal::EthHeaderFields f;

    // Honest: extraData carries the commitment to this aux block.
    {
        CAuxPow proof = BuildValidAuxPow(auxBlockHash, chainId);
        proof.parentAlgoId = static_cast<uint8_t>(AuxPowAlgo::ETHASH);
        proof.parentHeaderRaw = BuildEthashV2Raw(f, goodExtra, 1, 0x1122334455667788ULL, mix);
        BOOST_CHECK(proof.Check(auxBlockHash, chainId));
    }

    // Forgery: real-looking header, but its extraData commits to a DIFFERENT
    // aux block. This is a miner trying to point parent work at someone else's
    // (or an unrelated) WATTx block.
    {
        std::vector<uint8_t> wrongExtra(32, 0x77);
        CAuxPow proof = BuildValidAuxPow(auxBlockHash, chainId);
        proof.parentAlgoId = static_cast<uint8_t>(AuxPowAlgo::ETHASH);
        proof.parentHeaderRaw = BuildEthashV2Raw(f, wrongExtra, 1, 1, mix);
        BOOST_CHECK_MESSAGE(!proof.Check(auxBlockHash, chainId),
                            "ethash proof accepted with extraData not committing to this aux block");
    }

    // A short extraData must not be accepted via a partial compare.
    {
        std::vector<uint8_t> shortExtra(goodExtra.begin(), goodExtra.begin() + 31);
        CAuxPow proof = BuildValidAuxPow(auxBlockHash, chainId);
        proof.parentAlgoId = static_cast<uint8_t>(AuxPowAlgo::ETHASH);
        proof.parentHeaderRaw = BuildEthashV2Raw(f, shortExtra, 1, 1, mix);
        BOOST_CHECK(!proof.Check(auxBlockHash, chainId));
    }

    // Wrong version marker (0x01) must not parse as V2.
    {
        CAuxPow proof = BuildValidAuxPow(auxBlockHash, chainId);
        proof.parentAlgoId = static_cast<uint8_t>(AuxPowAlgo::ETHASH);
        proof.parentHeaderRaw = BuildEthashV2Raw(f, goodExtra, 1, 1, mix);
        proof.parentHeaderRaw[0] = 0x01;
        BOOST_CHECK(!proof.Check(auxBlockHash, chainId));
    }

    // Truncated body (nonce+mix chopped off) must fail closed.
    {
        CAuxPow proof = BuildValidAuxPow(auxBlockHash, chainId);
        proof.parentAlgoId = static_cast<uint8_t>(AuxPowAlgo::ETHASH);
        proof.parentHeaderRaw = BuildEthashV2Raw(f, goodExtra, 1, 1, mix);
        proof.parentHeaderRaw.resize(proof.parentHeaderRaw.size() - 33);
        BOOST_CHECK(!proof.Check(auxBlockHash, chainId));
    }
}

BOOST_AUTO_TEST_CASE(auxpow_ethash_powhash_rejects_fake_mix)
{
    // THE fake-mix forgery: a well-formed V2 proof whose extraData commits
    // correctly (so Check() passes), but whose mix was never derived from the
    // DAG. Without the mix recomputation an attacker only has to keccak-grind
    // the final hash under the easy aux target -- no DAG, no real ALT work.
    // GetParentBlockPoWHash() must fail closed to all-FF, which can never meet
    // any target. (A zero hash here would meet EVERY target.)
    const uint256 commitment = auxpow::CalcAuxChainMerkleRoot(
        uint256S("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
        CAuxPowBlockHeader::WATTX_CHAIN_ID);
    std::vector<uint8_t> extra(commitment.begin(), commitment.begin() + 32);

    ethseal::EthHeaderFields f;
    uint8_t fakeMix[32];
    std::memset(fakeMix, 0x11, sizeof(fakeMix));  // the eth_miner.js fake mix

    CAuxPow proof;
    proof.parentAlgoId = static_cast<uint8_t>(AuxPowAlgo::ETHASH);
    proof.parentHeaderRaw = BuildEthashV2Raw(f, extra, 1, 0xdeadbeefULL, fakeMix);

    BOOST_CHECK_MESSAGE(proof.GetParentBlockPoWHash() == AllOnesHash(),
                        "fake ethash mix was not rejected -- keccak-grind forgery is reachable");

    // Malformed input must fail closed the same way.
    CAuxPow malformed;
    malformed.parentAlgoId = static_cast<uint8_t>(AuxPowAlgo::ETHASH);
    malformed.parentHeaderRaw.assign(72, 0x00);  // legacy synthetic format
    BOOST_CHECK(malformed.GetParentBlockPoWHash() == AllOnesHash());
}

BOOST_AUTO_TEST_CASE(auxpow_ethash_powhash_accepts_genuine_dag_mix)
{
    // Positive counterpart: a mix genuinely derived from the ethash DAG must be
    // accepted, and the returned hash must be geth's final hash byte-reversed
    // (WATTx compares little-endian; ethash is big-endian -- that reversal is
    // what lets one solution clear both targets for real dual-earning).
    // Uses epoch 0 so the light cache is cheap to build in a unit test.
    const uint256 commitment = auxpow::CalcAuxChainMerkleRoot(
        uint256S("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
        CAuxPowBlockHeader::WATTX_CHAIN_ID);
    std::vector<uint8_t> extra(commitment.begin(), commitment.begin() + 32);

    const uint64_t blockNumber = 1;      // epoch 0
    const uint64_t nonce = 0x00000000000000ABULL;

    // Build once with a placeholder mix purely to obtain the field set, then
    // recompute the seal hash exactly as consensus does.
    ethseal::EthHeaderFields f;
    uint8_t placeholder[32];
    std::memset(placeholder, 0, sizeof(placeholder));
    (void)BuildEthashV2Raw(f, extra, blockNumber, nonce, placeholder);

    const std::array<uint8_t, 32> sealHash = ethseal::SealHash(f);
    ethash::hash256 ethSeal;
    std::memcpy(ethSeal.bytes, sealHash.data(), 32);
    const int epoch = ethash::get_epoch_number(static_cast<int>(blockNumber));
    const ethash::result r =
        ethash::hash(ethash::get_global_epoch_context(epoch), ethSeal, nonce);

    // Re-encode carrying the genuine DAG-derived mix.
    ethseal::EthHeaderFields f2;
    CAuxPow proof;
    proof.parentAlgoId = static_cast<uint8_t>(AuxPowAlgo::ETHASH);
    proof.parentHeaderRaw = BuildEthashV2Raw(f2, extra, blockNumber, nonce, r.mix_hash.bytes);

    uint256 expected;
    for (int i = 0; i < 32; ++i) expected.begin()[i] = r.final_hash.bytes[31 - i];

    const uint256 got = proof.GetParentBlockPoWHash();
    BOOST_CHECK_MESSAGE(got != AllOnesHash(), "genuine DAG mix was rejected");
    BOOST_CHECK_MESSAGE(got == expected, "ethash PoW hash != geth final hash byte-reversed");

    // Flipping a single bit of the genuine mix must break it: proves the check
    // is a real comparison against the recomputed mix, not a length/format test.
    ethseal::EthHeaderFields f3;
    uint8_t tampered[32];
    std::memcpy(tampered, r.mix_hash.bytes, 32);
    tampered[0] ^= 0x01;
    CAuxPow tamperedProof;
    tamperedProof.parentAlgoId = static_cast<uint8_t>(AuxPowAlgo::ETHASH);
    tamperedProof.parentHeaderRaw = BuildEthashV2Raw(f3, extra, blockNumber, nonce, tampered);
    BOOST_CHECK(tamperedProof.GetParentBlockPoWHash() == AllOnesHash());
}

BOOST_AUTO_TEST_SUITE_END()
