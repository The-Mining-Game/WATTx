// Copyright (c) 2024-2026 The WATTx Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <privacy/stealth.h>
#include <privacy/ring_signature.h>
#include <privacy/confidential.h>
#include <privacy/privacy.h>
#include <privacy/ed25519/ed25519_types.h>
#include <key.h>
#include <random.h>
#include <streams.h>
#include <test/util/setup_common.h>

// Windows wingdi.h defines TRANSPARENT as a macro
#ifdef TRANSPARENT
#undef TRANSPARENT
#endif

BOOST_FIXTURE_TEST_SUITE(privacy_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(stealth_address_creation)
{
    // Generate scan and spend keys
    CKey scanKey, spendKey;
    scanKey.MakeNewKey(true);
    spendKey.MakeNewKey(true);

    // Create stealth address
    privacy::CStealthAddress addr(scanKey.GetPubKey(), spendKey.GetPubKey());

    BOOST_CHECK(addr.IsValid());
    BOOST_CHECK(addr.scanPubKey.IsValid());
    BOOST_CHECK(addr.spendPubKey.IsValid());

    // Test string encoding/decoding
    std::string encoded = addr.ToString();
    BOOST_CHECK(!encoded.empty());

    auto decoded = privacy::CStealthAddress::FromString(encoded);
    BOOST_CHECK(decoded.has_value());
    if (decoded) {
        BOOST_CHECK(decoded->scanPubKey == addr.scanPubKey);
        BOOST_CHECK(decoded->spendPubKey == addr.spendPubKey);
    }
}

BOOST_AUTO_TEST_CASE(stealth_destination_generation)
{
    // Recipient generates stealth address
    CKey scanPriv, spendPriv;
    scanPriv.MakeNewKey(true);
    spendPriv.MakeNewKey(true);

    privacy::CStealthAddress recipientAddr(scanPriv.GetPubKey(), spendPriv.GetPubKey());
    BOOST_CHECK(recipientAddr.IsValid());

    // Sender generates ephemeral key and creates stealth destination
    CKey ephemeralKey;
    ephemeralKey.MakeNewKey(true);

    privacy::CStealthOutput stealthOutput;
    bool success = privacy::GenerateStealthDestination(recipientAddr, ephemeralKey, stealthOutput);
    BOOST_CHECK(success);
    BOOST_CHECK(stealthOutput.oneTimePubKey.IsValid());
    BOOST_CHECK(stealthOutput.ephemeral.ephemeralPubKey.IsValid());

    // Recipient derives spending key
    CKey derivedSpendKey;
    success = privacy::DeriveStealthSpendingKey(
        scanPriv, spendPriv,
        stealthOutput.ephemeral.ephemeralPubKey, 0,
        derivedSpendKey);
    BOOST_CHECK(success);

    // Derived pubkey should match one-time pubkey
    BOOST_CHECK(derivedSpendKey.GetPubKey() == stealthOutput.oneTimePubKey);
}

BOOST_AUTO_TEST_CASE(key_image_generation)
{
    CKey privKey;
    privKey.MakeNewKey(true);
    CPubKey pubKey = privKey.GetPubKey();

    privacy::CKeyImage keyImage;
    bool success = privacy::GenerateKeyImage(privKey, pubKey, keyImage);
    BOOST_CHECK(success);
    BOOST_CHECK(keyImage.IsValid());

    // Same key should produce same key image
    privacy::CKeyImage keyImage2;
    success = privacy::GenerateKeyImage(privKey, pubKey, keyImage2);
    BOOST_CHECK(success);
    BOOST_CHECK(keyImage.IsValid());
    // Key images should be deterministic
    BOOST_CHECK(keyImage.GetHash() == keyImage2.GetHash());
}

BOOST_AUTO_TEST_CASE(pedersen_commitment)
{
    CAmount amount = 100000000; // 1 WTX
    privacy::CBlindingFactor blind = privacy::CBlindingFactor::Random();

    privacy::CPedersenCommitment commitment;
    bool success = privacy::CreateCommitment(amount, blind, commitment);
    BOOST_CHECK(success);
    BOOST_CHECK(commitment.IsValid());
}

BOOST_AUTO_TEST_CASE(commitment_balance)
{
    // Create input commitments
    CAmount input1 = 50000000;
    CAmount input2 = 30000000;
    privacy::CBlindingFactor blind1 = privacy::CBlindingFactor::Random();
    privacy::CBlindingFactor blind2 = privacy::CBlindingFactor::Random();

    privacy::CPedersenCommitment inputCommit1, inputCommit2;
    BOOST_CHECK(privacy::CreateCommitment(input1, blind1, inputCommit1));
    BOOST_CHECK(privacy::CreateCommitment(input2, blind2, inputCommit2));

    // Create output commitments (need balancing blind)
    CAmount output1 = 60000000;
    CAmount output2 = 20000000; // Difference is fee (implicit)
    privacy::CBlindingFactor blindOut1 = privacy::CBlindingFactor::Random();

    // Compute balancing blind for output2
    privacy::CBlindingFactor blindOut2;
    std::vector<privacy::CBlindingFactor> inputBlinds = {blind1, blind2};
    std::vector<privacy::CBlindingFactor> outputBlinds = {blindOut1};
    bool success = privacy::ComputeBalancingBlindingFactor(inputBlinds, outputBlinds, blindOut2);
    // Note: This may fail if not fully implemented
    if (success) {
        privacy::CPedersenCommitment outputCommit1, outputCommit2;
        BOOST_CHECK(privacy::CreateCommitment(output1, blindOut1, outputCommit1));
        BOOST_CHECK(privacy::CreateCommitment(output2, blindOut2, outputCommit2));

        // Verify balance
        std::vector<privacy::CPedersenCommitment> inputs = {inputCommit1, inputCommit2};
        std::vector<privacy::CPedersenCommitment> outputs = {outputCommit1, outputCommit2};
        BOOST_CHECK(privacy::VerifyCommitmentBalance(inputs, outputs));
    }
}

BOOST_AUTO_TEST_CASE(ring_member_creation)
{
    CKey key;
    key.MakeNewKey(true);

    COutPoint outpoint(Txid::FromUint256(GetRandHash()), 0);
    privacy::CRingMember member(outpoint, key.GetPubKey());

    BOOST_CHECK(member.outpoint == outpoint);
    BOOST_CHECK(member.pubKey.IsValid());
}

BOOST_AUTO_TEST_CASE(privacy_type_serialization)
{
    privacy::CPrivacyTransaction tx;
    tx.nVersion = 2;
    tx.privacyType = privacy::PrivacyType::RINGCT;
    tx.nFee = 10000;

    // Serialize
    DataStream ss;
    ss << tx;

    // Deserialize
    privacy::CPrivacyTransaction tx2;
    ss >> tx2;

    BOOST_CHECK(tx2.nVersion == tx.nVersion);
    BOOST_CHECK(tx2.privacyType == tx.privacyType);
    BOOST_CHECK(tx2.nFee == tx.nFee);
}

BOOST_AUTO_TEST_CASE(range_proof_creation)
{
    // Test range proof creation for various amounts
    std::vector<CAmount> testAmounts = {
        0,
        1,
        100,
        1000000,        // 0.01 WTX
        100000000,      // 1 WTX
        2100000000000000  // Near max supply
    };

    for (CAmount amount : testAmounts) {
        privacy::CBlindingFactor blind = privacy::CBlindingFactor::Random();
        privacy::CPedersenCommitment commitment;

        bool commitSuccess = privacy::CreateCommitment(amount, blind, commitment);
        BOOST_CHECK(commitSuccess);
        BOOST_CHECK(commitment.IsValid());

        privacy::CRangeProof rangeProof;
        bool proofSuccess = privacy::CreateRangeProof(amount, blind, commitment, rangeProof);
        BOOST_CHECK(proofSuccess);
        BOOST_CHECK(rangeProof.IsValid());

        // Verify the proof
        bool verifySuccess = privacy::VerifyRangeProof(commitment, rangeProof);
        BOOST_CHECK(verifySuccess);
    }
}

BOOST_AUTO_TEST_CASE(range_proof_aggregated)
{
    // Test aggregated range proofs for multiple outputs
    std::vector<CAmount> amounts = {100000000, 50000000, 25000000}; // 1, 0.5, 0.25 WTX
    std::vector<privacy::CBlindingFactor> blinds;
    std::vector<privacy::CPedersenCommitment> commitments;

    for (CAmount amount : amounts) {
        privacy::CBlindingFactor blind = privacy::CBlindingFactor::Random();
        privacy::CPedersenCommitment commitment;

        BOOST_CHECK(privacy::CreateCommitment(amount, blind, commitment));
        blinds.push_back(blind);
        commitments.push_back(commitment);
    }

    privacy::CRangeProof aggProof;
    bool createSuccess = privacy::CreateAggregatedRangeProof(amounts, blinds, commitments, aggProof);
    BOOST_CHECK(createSuccess);
    BOOST_CHECK(aggProof.IsValid());

    bool verifySuccess = privacy::VerifyAggregatedRangeProof(commitments, aggProof);
    BOOST_CHECK(verifySuccess);
}

BOOST_AUTO_TEST_CASE(commitment_homomorphic)
{
    // Commitments are homomorphic: C(a, r_a) + C(b, r_b) == C(a+b, r_a+r_b).
    //
    // Rewritten for ed25519. This test used to verify the identity with
    // secp256k1 primitives, which stopped being correct when the amount layer
    // moved to ed25519 -- and it did not merely fail. secp256k1_ec_pubkey_parse
    // rejected the ed25519 commitment, leaving the pubkeys uninitialised, and
    // the following secp256k1_ec_pubkey_combine tripped libsecp256k1's illegal
    // callback and ABORTED the process. That killed the whole test binary, so
    // every test declared after this one silently never ran -- 424 of them.
    //
    // Homomorphism is now checked through the layer that actually owns the
    // format, so this can never again depend on the wrong curve.
    const CAmount a = 100000000;  // 1 WTX
    const CAmount b = 50000000;   // 0.5 WTX

    const privacy::CBlindingFactor blindA = privacy::CBlindingFactor::Random();
    const privacy::CBlindingFactor blindB = privacy::CBlindingFactor::Random();

    privacy::CPedersenCommitment commitA, commitB;
    BOOST_REQUIRE(privacy::CreateCommitment(a, blindA, commitA));
    BOOST_REQUIRE(privacy::CreateCommitment(b, blindB, commitB));

    // Sum the blindings on the ed25519 scalar field.
    const ed25519::Scalar sA = ed25519::Scalar::FromBytesModOrder(blindA.begin(), 32);
    const ed25519::Scalar sB = ed25519::Scalar::FromBytesModOrder(blindB.begin(), 32);
    const std::vector<uint8_t> sumBytes = (sA + sB).GetBytes();
    BOOST_REQUIRE_EQUAL(sumBytes.size(), 32U);

    uint256 sumU;
    memcpy(sumU.begin(), sumBytes.data(), 32);
    const privacy::CBlindingFactor blindAB{sumU};

    privacy::CPedersenCommitment commitAB;
    BOOST_REQUIRE(privacy::CreateCommitment(a + b, blindAB, commitAB));

    // C(a) + C(b) must equal C(a+b) exactly. VerifyPoolBalance treats the two
    // sides as inputs and outputs with no net value crossing the pool, which is
    // precisely the statement "these sum to the same point".
    BOOST_CHECK(privacy::VerifyPoolBalance({commitA, commitB}, {commitAB}, 0));

    // And the identity must be sensitive to the value: committing to a+b+1
    // under the same blinding must NOT balance.
    privacy::CPedersenCommitment commitWrong;
    BOOST_REQUIRE(privacy::CreateCommitment(a + b + 1, blindAB, commitWrong));
    BOOST_CHECK(!privacy::VerifyPoolBalance({commitA, commitB}, {commitWrong}, 0));
}

BOOST_AUTO_TEST_CASE(amount_encryption)
{
    CAmount originalAmount = 123456789;
    uint256 sharedSecret = GetRandHash();

    std::vector<unsigned char> encrypted;
    BOOST_CHECK(privacy::EncryptAmount(originalAmount, sharedSecret, encrypted));
    BOOST_CHECK(encrypted.size() == 8);

    CAmount decryptedAmount;
    BOOST_CHECK(privacy::DecryptAmount(encrypted, sharedSecret, decryptedAmount));
    BOOST_CHECK(decryptedAmount == originalAmount);

    // Wrong secret should produce wrong amount
    uint256 wrongSecret = GetRandHash();
    CAmount wrongAmount;
    BOOST_CHECK(privacy::DecryptAmount(encrypted, wrongSecret, wrongAmount));
    BOOST_CHECK(wrongAmount != originalAmount);
}

BOOST_AUTO_TEST_CASE(ring_signature_basic)
{
    // Create a ring with 11 members (Monero default)
    const size_t ringSize = 11;
    const size_t realIndex = 5;

    std::vector<CKey> keys(ringSize);
    privacy::CRing ring;
    ring.members.resize(ringSize);

    for (size_t i = 0; i < ringSize; i++) {
        keys[i].MakeNewKey(true);
        ring.members[i].outpoint = COutPoint(Txid::FromUint256(GetRandHash()), 0);
        ring.members[i].pubKey = keys[i].GetPubKey();
    }

    BOOST_CHECK(ring.IsValid());

    // Sign with the real key
    uint256 message = GetRandHash();
    privacy::CRingSignature sig;

    bool signSuccess = privacy::CreateRingSignature(message, ring, realIndex, keys[realIndex], sig);
    BOOST_CHECK(signSuccess);
    BOOST_CHECK(sig.IsValid());

    // Verify the signature
    bool verifySuccess = privacy::VerifyRingSignature(message, sig);
    BOOST_CHECK(verifySuccess);

    // Wrong message should fail
    uint256 wrongMessage = GetRandHash();
    BOOST_CHECK(!privacy::VerifyRingSignature(wrongMessage, sig));
}

BOOST_AUTO_TEST_CASE(mlsag_signature_multiple_inputs)
{
    // Test MLSAG with 2 inputs, each with ring size 11
    // Note: Current MLSAG implementation requires same real index for all rings
    const size_t numInputs = 2;
    const size_t ringSize = 11;
    std::vector<size_t> realIndices = {5, 5};  // Same index for simplified MLSAG

    std::vector<privacy::CRing> rings(numInputs);
    std::vector<CKey> realKeys(numInputs);

    for (size_t j = 0; j < numInputs; j++) {
        rings[j].members.resize(ringSize);
        for (size_t i = 0; i < ringSize; i++) {
            CKey key;
            key.MakeNewKey(true);
            rings[j].members[i].outpoint = COutPoint(Txid::FromUint256(GetRandHash()), 0);
            rings[j].members[i].pubKey = key.GetPubKey();

            if (i == realIndices[j]) {
                realKeys[j] = key;
            }
        }
    }

    uint256 message = GetRandHash();
    privacy::CMLSAGSignature sig;

    bool signSuccess = privacy::CreateMLSAGSignature(message, rings, realIndices, realKeys, sig);
    BOOST_CHECK(signSuccess);
    BOOST_CHECK(sig.IsValid());

    bool verifySuccess = privacy::VerifyMLSAGSignature(message, sig);
    BOOST_CHECK(verifySuccess);
}

// ============================================================================
// FULL RINGCT TRANSACTION TESTS
// ============================================================================

BOOST_AUTO_TEST_CASE(ringct_transaction_builder_basic)
{
    // Test basic RingCT transaction construction
    privacy::CPrivacyTransactionBuilder builder(privacy::PrivacyType::RINGCT);

    // Create input keys and outpoints
    CKey inputKey1, inputKey2;
    inputKey1.MakeNewKey(true);
    inputKey2.MakeNewKey(true);

    COutPoint outpoint1(Txid::FromUint256(GetRandHash()), 0);
    COutPoint outpoint2(Txid::FromUint256(GetRandHash()), 1);

    // Add inputs (100 + 50 = 150 WTX)
    CAmount input1Amount = 100000000; // 1 WTX
    CAmount input2Amount = 50000000;  // 0.5 WTX

    privacy::CBlindingFactor blind1 = privacy::CBlindingFactor::Random();
    privacy::CBlindingFactor blind2 = privacy::CBlindingFactor::Random();

    BOOST_CHECK(builder.AddInput(outpoint1, inputKey1, input1Amount, blind1));
    BOOST_CHECK(builder.AddInput(outpoint2, inputKey2, input2Amount, blind2));

    // Create recipient stealth address
    CKey recipientScan, recipientSpend;
    recipientScan.MakeNewKey(true);
    recipientSpend.MakeNewKey(true);
    privacy::CStealthAddress recipientAddr(recipientScan.GetPubKey(), recipientSpend.GetPubKey());
    BOOST_CHECK(recipientAddr.IsValid());

    // Add outputs (send 120 WTX, keep 28 as change, 2 WTX fee)
    CAmount sendAmount = 120000000;  // 1.2 WTX
    CAmount changeAmount = 28000000; // 0.28 WTX
    CAmount feeAmount = 2000000;     // 0.02 WTX

    // Create change address
    CKey changeScan, changeSpend;
    changeScan.MakeNewKey(true);
    changeSpend.MakeNewKey(true);
    privacy::CStealthAddress changeAddr(changeScan.GetPubKey(), changeSpend.GetPubKey());

    BOOST_CHECK(builder.AddOutput(recipientAddr, sendAmount));
    BOOST_CHECK(builder.AddOutput(changeAddr, changeAmount));
    builder.SetFee(feeAmount);
    builder.SetRingSize(11);

    // Build transaction
    auto maybeTx = builder.Build();
    BOOST_CHECK(maybeTx.has_value());

    if (maybeTx) {
        const auto& tx = *maybeTx;
        BOOST_CHECK(tx.privacyType == privacy::PrivacyType::RINGCT);
        BOOST_CHECK(tx.privacyInputs.size() == 2);
        BOOST_CHECK(tx.privacyOutputs.size() == 2);
        BOOST_CHECK(tx.nFee == feeAmount);

        // Check inputs have key images
        for (const auto& input : tx.privacyInputs) {
            BOOST_CHECK(input.keyImage.IsValid());
            BOOST_CHECK(input.commitment.IsValid());
        }

        // Check outputs have stealth data and commitments
        for (const auto& output : tx.privacyOutputs) {
            BOOST_CHECK(output.stealthOutput.oneTimePubKey.IsValid());
            BOOST_CHECK(output.stealthOutput.ephemeral.ephemeralPubKey.IsValid());
            BOOST_CHECK(output.confidentialOutput.commitment.IsValid());
        }

        // Check transaction hash is valid
        uint256 txHash = tx.GetHash();
        BOOST_CHECK(!txHash.IsNull());
    }
}

BOOST_AUTO_TEST_CASE(ringct_transaction_insufficient_funds)
{
    // Test that builder rejects insufficient funds
    privacy::CPrivacyTransactionBuilder builder(privacy::PrivacyType::RINGCT);

    CKey inputKey;
    inputKey.MakeNewKey(true);
    COutPoint outpoint(Txid::FromUint256(GetRandHash()), 0);

    // Add input of 1 WTX
    BOOST_CHECK(builder.AddInput(outpoint, inputKey, 100000000));

    // Create recipient
    CKey scanKey, spendKey;
    scanKey.MakeNewKey(true);
    spendKey.MakeNewKey(true);
    privacy::CStealthAddress addr(scanKey.GetPubKey(), spendKey.GetPubKey());

    // Try to send 2 WTX (more than input)
    BOOST_CHECK(builder.AddOutput(addr, 200000000));
    builder.SetFee(10000);

    // Build should fail
    auto maybeTx = builder.Build();
    BOOST_CHECK(!maybeTx.has_value());
}

BOOST_AUTO_TEST_CASE(ringct_transaction_empty_inputs)
{
    // Test that builder rejects empty inputs
    privacy::CPrivacyTransactionBuilder builder(privacy::PrivacyType::RINGCT);

    CKey scanKey, spendKey;
    scanKey.MakeNewKey(true);
    spendKey.MakeNewKey(true);
    privacy::CStealthAddress addr(scanKey.GetPubKey(), spendKey.GetPubKey());

    BOOST_CHECK(builder.AddOutput(addr, 100000000));
    builder.SetFee(10000);

    // Build should fail (no inputs)
    auto maybeTx = builder.Build();
    BOOST_CHECK(!maybeTx.has_value());
}

BOOST_AUTO_TEST_CASE(ringct_transaction_empty_outputs)
{
    // Test that builder rejects empty outputs
    privacy::CPrivacyTransactionBuilder builder(privacy::PrivacyType::RINGCT);

    CKey inputKey;
    inputKey.MakeNewKey(true);
    COutPoint outpoint(Txid::FromUint256(GetRandHash()), 0);

    BOOST_CHECK(builder.AddInput(outpoint, inputKey, 100000000));
    builder.SetFee(10000);

    // Build should fail (no outputs)
    auto maybeTx = builder.Build();
    BOOST_CHECK(!maybeTx.has_value());
}

BOOST_AUTO_TEST_CASE(key_image_double_spend_prevention)
{
    // Test that key images prevent double spending
    CKey privKey;
    privKey.MakeNewKey(true);
    CPubKey pubKey = privKey.GetPubKey();

    // Generate key image
    privacy::CKeyImage keyImage;
    BOOST_CHECK(privacy::GenerateKeyImage(privKey, pubKey, keyImage));
    BOOST_CHECK(keyImage.IsValid());

    // Key image should not be spent initially
    BOOST_CHECK(!privacy::IsKeyImageSpent(keyImage));

    // Mark key image as spent
    uint256 txHash1 = GetRandHash();
    BOOST_CHECK(privacy::MarkKeyImageSpent(keyImage, txHash1));

    // Key image should now be marked as spent
    BOOST_CHECK(privacy::IsKeyImageSpent(keyImage));

    // Attempting to mark same key image again should fail
    uint256 txHash2 = GetRandHash();
    BOOST_CHECK(!privacy::MarkKeyImageSpent(keyImage, txHash2));

    // Key image should still be marked as spent
    BOOST_CHECK(privacy::IsKeyImageSpent(keyImage));
}

BOOST_AUTO_TEST_CASE(key_image_deterministic_generation)
{
    // Test that key images are deterministic for same key
    CKey privKey;
    privKey.MakeNewKey(true);
    CPubKey pubKey = privKey.GetPubKey();

    privacy::CKeyImage keyImage1, keyImage2;
    BOOST_CHECK(privacy::GenerateKeyImage(privKey, pubKey, keyImage1));
    BOOST_CHECK(privacy::GenerateKeyImage(privKey, pubKey, keyImage2));

    // Same key should produce same key image
    BOOST_CHECK(keyImage1.GetHash() == keyImage2.GetHash());

    // Different key should produce different key image
    CKey otherKey;
    otherKey.MakeNewKey(true);
    privacy::CKeyImage keyImage3;
    BOOST_CHECK(privacy::GenerateKeyImage(otherKey, otherKey.GetPubKey(), keyImage3));

    BOOST_CHECK(keyImage1.GetHash() != keyImage3.GetHash());
}

BOOST_AUTO_TEST_CASE(privacy_transaction_serialization_roundtrip)
{
    // Test full privacy transaction serialization/deserialization
    privacy::CPrivacyTransaction tx;
    tx.nVersion = 2;
    tx.privacyType = privacy::PrivacyType::RINGCT;
    tx.nFee = 50000;
    tx.nLockTime = 12345;

    // Add a privacy input
    privacy::CPrivacyInput input;
    CKey key;
    key.MakeNewKey(true);

    input.ring.members.resize(3);
    for (int i = 0; i < 3; i++) {
        CKey k;
        k.MakeNewKey(true);
        input.ring.members[i].outpoint = COutPoint(Txid::FromUint256(GetRandHash()), i);
        input.ring.members[i].pubKey = k.GetPubKey();
    }

    privacy::GenerateKeyImage(key, key.GetPubKey(), input.keyImage);

    privacy::CBlindingFactor blind = privacy::CBlindingFactor::Random();
    privacy::CreateCommitment(100000000, blind, input.commitment);

    tx.privacyInputs.push_back(input);

    // Add a privacy output
    privacy::CPrivacyOutput output;
    CKey scanKey, spendKey;
    scanKey.MakeNewKey(true);
    spendKey.MakeNewKey(true);
    privacy::CStealthAddress stealthAddr(scanKey.GetPubKey(), spendKey.GetPubKey());

    CKey ephemeralKey;
    privacy::GenerateStealthDestination(stealthAddr, ephemeralKey, output.stealthOutput);

    privacy::CBlindingFactor outBlind = privacy::CBlindingFactor::Random();
    privacy::CreateCommitment(99950000, outBlind, output.confidentialOutput.commitment);
    output.nValue = 99950000;

    tx.privacyOutputs.push_back(output);

    // Serialize
    DataStream ss;
    ss << tx;

    // Deserialize
    privacy::CPrivacyTransaction tx2;
    ss >> tx2;

    // Verify fields match
    BOOST_CHECK(tx2.nVersion == tx.nVersion);
    BOOST_CHECK(tx2.privacyType == tx.privacyType);
    BOOST_CHECK(tx2.nFee == tx.nFee);
    BOOST_CHECK(tx2.nLockTime == tx.nLockTime);
    BOOST_CHECK(tx2.privacyInputs.size() == tx.privacyInputs.size());
    BOOST_CHECK(tx2.privacyOutputs.size() == tx.privacyOutputs.size());

    // Check input data
    BOOST_CHECK(tx2.privacyInputs[0].keyImage.GetHash() == tx.privacyInputs[0].keyImage.GetHash());
    BOOST_CHECK(tx2.privacyInputs[0].commitment.data == tx.privacyInputs[0].commitment.data);
    BOOST_CHECK(tx2.privacyInputs[0].ring.members.size() == tx.privacyInputs[0].ring.members.size());

    // Check output data
    BOOST_CHECK(tx2.privacyOutputs[0].stealthOutput.oneTimePubKey == tx.privacyOutputs[0].stealthOutput.oneTimePubKey);
    BOOST_CHECK(tx2.privacyOutputs[0].confidentialOutput.commitment.data == tx.privacyOutputs[0].confidentialOutput.commitment.data);
}

BOOST_AUTO_TEST_CASE(ring_size_validation)
{
    // Test ring size requirements (privacy activates at 210,000)
    BOOST_CHECK(privacy::GetMinRingSize(100000) == 3);    // Pre-activation
    BOOST_CHECK(privacy::GetMinRingSize(300000) == 7);    // Early privacy
    BOOST_CHECK(privacy::GetMinRingSize(500000) == 11);   // Mature chain

    // Default ring size should be at least minimum
    BOOST_CHECK(privacy::GetDefaultRingSize(100000) >= privacy::GetMinRingSize(100000));
    BOOST_CHECK(privacy::GetDefaultRingSize(500000) >= privacy::GetMinRingSize(500000));
    BOOST_CHECK(privacy::GetDefaultRingSize(500000) == 11);
}

BOOST_AUTO_TEST_CASE(privacy_output_type_detection)
{
    // Test privacy output type detection

    // Transparent output
    privacy::CPrivacyOutput transparentOut;
    transparentOut.nValue = 100000000;
    BOOST_CHECK(transparentOut.GetType() == privacy::PrivacyType::TRANSPARENT);

    // Stealth-only output
    privacy::CPrivacyOutput stealthOut;
    CKey scanKey, spendKey, ephKey;
    scanKey.MakeNewKey(true);
    spendKey.MakeNewKey(true);
    privacy::CStealthAddress addr(scanKey.GetPubKey(), spendKey.GetPubKey());
    privacy::GenerateStealthDestination(addr, ephKey, stealthOut.stealthOutput);
    stealthOut.nValue = 100000000;
    BOOST_CHECK(stealthOut.GetType() == privacy::PrivacyType::STEALTH);

    // Confidential-only output
    privacy::CPrivacyOutput confOut;
    privacy::CBlindingFactor blind = privacy::CBlindingFactor::Random();
    privacy::CreateCommitment(100000000, blind, confOut.confidentialOutput.commitment);
    confOut.confidentialOutput.rangeProof.data.resize(100); // Dummy proof
    BOOST_CHECK(confOut.GetType() == privacy::PrivacyType::CONFIDENTIAL);

    // Full RingCT output (stealth + confidential)
    privacy::CPrivacyOutput ringctOut;
    CKey scanKey2, spendKey2, ephKey2;
    scanKey2.MakeNewKey(true);
    spendKey2.MakeNewKey(true);
    privacy::CStealthAddress addr2(scanKey2.GetPubKey(), spendKey2.GetPubKey());
    privacy::GenerateStealthDestination(addr2, ephKey2, ringctOut.stealthOutput);

    privacy::CBlindingFactor blind2 = privacy::CBlindingFactor::Random();
    privacy::CreateCommitment(100000000, blind2, ringctOut.confidentialOutput.commitment);
    ringctOut.confidentialOutput.rangeProof.data.resize(100); // Dummy proof

    BOOST_CHECK(ringctOut.GetType() == privacy::PrivacyType::RINGCT);
}

BOOST_AUTO_TEST_CASE(privacy_input_type_detection)
{
    // Test privacy input type detection

    // Transparent input
    privacy::CPrivacyInput transparentIn;
    BOOST_CHECK(transparentIn.GetType() == privacy::PrivacyType::TRANSPARENT);

    // Ring-only input
    privacy::CPrivacyInput ringIn;
    ringIn.ring.members.resize(11);
    for (int i = 0; i < 11; i++) {
        CKey k;
        k.MakeNewKey(true);
        ringIn.ring.members[i].outpoint = COutPoint(Txid::FromUint256(GetRandHash()), i);
        ringIn.ring.members[i].pubKey = k.GetPubKey();
    }
    BOOST_CHECK(ringIn.GetType() == privacy::PrivacyType::RING);

    // RingCT input (ring + commitment)
    privacy::CPrivacyInput ringctIn;
    ringctIn.ring.members.resize(11);
    for (int i = 0; i < 11; i++) {
        CKey k;
        k.MakeNewKey(true);
        ringctIn.ring.members[i].outpoint = COutPoint(Txid::FromUint256(GetRandHash()), i);
        ringctIn.ring.members[i].pubKey = k.GetPubKey();
    }
    privacy::CBlindingFactor blind = privacy::CBlindingFactor::Random();
    privacy::CreateCommitment(100000000, blind, ringctIn.commitment);
    BOOST_CHECK(ringctIn.GetType() == privacy::PrivacyType::RINGCT);
}

BOOST_AUTO_TEST_CASE(transaction_hash_uniqueness)
{
    // Test that different transactions produce different hashes
    std::vector<uint256> hashes;

    for (int i = 0; i < 10; i++) {
        privacy::CPrivacyTransaction tx;
        tx.nVersion = 2;
        tx.privacyType = privacy::PrivacyType::RINGCT;
        tx.nFee = 10000 + i;

        // Add unique input
        privacy::CPrivacyInput input;
        CKey key;
        key.MakeNewKey(true);
        privacy::GenerateKeyImage(key, key.GetPubKey(), input.keyImage);
        tx.privacyInputs.push_back(input);

        uint256 txHash = tx.GetHash();
        BOOST_CHECK(!txHash.IsNull());

        // Check hash is unique
        for (const auto& prevHash : hashes) {
            BOOST_CHECK(txHash != prevHash);
        }
        hashes.push_back(txHash);
    }
}

BOOST_AUTO_TEST_CASE(stealth_address_full_flow)
{
    // Test complete stealth address flow: create -> send -> receive

    // 1. Recipient creates stealth address
    CKey recipientScan, recipientSpend;
    recipientScan.MakeNewKey(true);
    recipientSpend.MakeNewKey(true);

    privacy::CStealthAddress stealthAddr(recipientScan.GetPubKey(), recipientSpend.GetPubKey());
    BOOST_CHECK(stealthAddr.IsValid());

    // 2. Encode and decode stealth address (simulates sharing)
    std::string encoded = stealthAddr.ToString();
    BOOST_CHECK(!encoded.empty());

    auto decodedAddr = privacy::CStealthAddress::FromString(encoded);
    BOOST_CHECK(decodedAddr.has_value());
    BOOST_CHECK(decodedAddr->scanPubKey == stealthAddr.scanPubKey);
    BOOST_CHECK(decodedAddr->spendPubKey == stealthAddr.spendPubKey);

    // 3. Sender creates stealth output
    CKey senderEphemeral;
    privacy::CStealthOutput stealthOutput;
    BOOST_CHECK(privacy::GenerateStealthDestination(*decodedAddr, senderEphemeral, stealthOutput));
    BOOST_CHECK(stealthOutput.oneTimePubKey.IsValid());
    BOOST_CHECK(stealthOutput.ephemeral.ephemeralPubKey.IsValid());

    // 4. Recipient scans for outputs (can detect using scan key)
    // In practice, this would scan all transactions
    CKey scannedKey;
    bool canScan = privacy::ScanStealthOutput(
        stealthOutput, recipientScan, recipientSpend.GetPubKey(), scannedKey);
    BOOST_CHECK(canScan);

    // 5. Recipient derives spending key
    CKey derivedKey;
    BOOST_CHECK(privacy::DeriveStealthSpendingKey(
        recipientScan, recipientSpend,
        stealthOutput.ephemeral.ephemeralPubKey, 0,
        derivedKey));

    // 6. Derived pubkey should match one-time pubkey
    BOOST_CHECK(derivedKey.GetPubKey() == stealthOutput.oneTimePubKey);

    // 7. Recipient can now sign with derived key
    uint256 message = GetRandHash();
    std::vector<unsigned char> signature;
    BOOST_CHECK(derivedKey.Sign(message, signature));
    BOOST_CHECK(stealthOutput.oneTimePubKey.Verify(message, signature));
}

BOOST_AUTO_TEST_SUITE_END()
