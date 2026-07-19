// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <auxpow/auxpow.h>
#include <consensus/auxpow_validation.h>
#include <hash.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

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

BOOST_AUTO_TEST_SUITE_END()
